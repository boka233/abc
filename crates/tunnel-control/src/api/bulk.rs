//! 线路的批量导入、导出与批量操作。
//!
//! # 导入格式
//!
//! JSON Lines —— 每行一个 JSON 对象，与常见中转面板的导出格式兼容：
//!
//! ```text
//! {"dest":["1.2.3.4:443"],"listen_port":17976,"name":"台湾01","proxy_protocol":2}
//! {"dest":["5.6.7.8:443","9.10.11.12:443"],"listen_port":22420,"name":"香港01"}
//! ```
//!
//! # 为什么逐条处理而不是整批事务
//!
//! 79 条里有 1 条端口冲突时，整批回滚意味着用户要自己找出那一条、改掉、再重来一遍。
//! 逐条处理并返回明细，用户能一眼看到哪条失败、为什么失败，成功的那些已经生效。
//!
//! 代价是部分成功需要用户自己收尾。这比"全有或全无"更适合导入场景：导入本身就是
//! 增量操作，不存在"半个配置不可用"的一致性问题。
//!
//! # proxy_protocol 的处理
//!
//! 本系统不实现 PROXY Protocol。遇到这个字段时**明确报告忽略了几条**，而不是静默
//! 丢弃 —— 落地机如果配了接收端，缺少头部会导致连接全部失败，用户必须知道这件事。

use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use tunnel_storage::models::{AuditEntry, CreateRoute, RouteDto};
use tunnel_storage::routes::RouteRepo;

use crate::api::error::{ApiError, ApiResult};
use crate::api::handlers::{audit, bump_route_groups};
use crate::api::middleware::{AuthUser, ClientAddr};
use crate::state::{AppState, Event};

/// 导入时一条规则的原始形态。
///
/// 字段刻意做得宽松：不同面板导出的键名略有差异，能对上的就用，对不上的报告出来
/// 而不是整行拒绝。
#[derive(Debug, Deserialize)]
pub struct ImportLine {
    /// 目标地址列表，形如 `["1.2.3.4:443"]`。
    #[serde(default, alias = "targets", alias = "remote")]
    pub dest: Vec<String>,
    #[serde(default, alias = "port", alias = "listen")]
    pub listen_port: Option<u16>,
    #[serde(default)]
    pub name: Option<String>,
    /// 本系统不支持。出现时计数并在结果里提示。
    #[serde(default)]
    pub proxy_protocol: Option<u8>,
    /// 该条自己的负载均衡策略，覆盖请求级的默认值。
    ///
    /// 允许逐条指定：一批线路里可能只有少数几条需要 IP 哈希（目标侧有会话状态），
    /// 其余用随机就好。
    #[serde(default, alias = "balance", alias = "lb")]
    pub target_strategy: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ImportRequest {
    /// JSON Lines 文本。空行与 `#` 开头的行被忽略。
    pub content: String,
    /// 导入到哪个设备组。
    pub group_id: String,
    /// 监听地址，所有导入的线路共用。
    #[serde(default = "default_listen_address")]
    pub listen_address: String,
    /// `direct`（默认）或 `tunnel`。导入格式里没有隧道信息，所以默认直连。
    #[serde(default = "default_mode")]
    pub mode: String,
    /// 隧道模式时的出口组与隧道地址。直连模式忽略。
    #[serde(default)]
    pub exit_group_id: Option<String>,
    #[serde(default)]
    pub endpoint_ids: Vec<String>,
    /// 出站源 IP，所有导入的线路共用。
    #[serde(default)]
    pub egress_source_ip: Option<String>,
    /// 多目标的负载均衡策略，所有导入的线路共用。逐条给了 `target_strategy` 时以
    /// 该条为准。
    #[serde(default = "default_target_strategy")]
    pub target_strategy: String,
}

fn default_listen_address() -> String {
    "0.0.0.0".into()
}
fn default_mode() -> String {
    "direct".into()
}
fn default_target_strategy() -> String {
    "random".into()
}

#[derive(Debug, Serialize)]
pub struct ImportFailure {
    /// 原文行号，从 1 开始，便于用户回到原文件定位。
    pub line: usize,
    pub name: Option<String>,
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct ImportResponse {
    pub total: usize,
    pub created: usize,
    pub failed: usize,
    pub failures: Vec<ImportFailure>,
    /// 有多少条带了 proxy_protocol。
    pub proxy_protocol_ignored: usize,
    /// 需要用户注意的说明，逐条列出。
    pub notes: Vec<String>,
}

pub async fn import_routes(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    client: ClientAddr,
    Json(req): Json<ImportRequest>,
) -> ApiResult<Json<ImportResponse>> {
    user.require_password_rotated()?;
    user.require_admin()?;

    let repo = RouteRepo::new(&state.db);
    let mut created = 0usize;
    let mut failures = Vec::new();
    let mut proxy_ignored = 0usize;
    let mut total = 0usize;
    let mut touched_routes: Vec<String> = Vec::new();

    for (offset, raw) in req.content.lines().enumerate() {
        let line_no = offset + 1;
        let trimmed = raw.trim();
        // 空行与注释：导出文件常带这些，不该算作失败。
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }
        total += 1;

        let parsed: ImportLine = match serde_json::from_str(trimmed) {
            Ok(p) => p,
            Err(e) => {
                failures.push(ImportFailure {
                    line: line_no,
                    name: None,
                    reason: format!("JSON 解析失败: {e}"),
                });
                continue;
            }
        };

        if parsed.proxy_protocol.is_some_and(|v| v != 0) {
            proxy_ignored += 1;
        }

        let targets: Vec<String> = parsed
            .dest
            .iter()
            .map(|d| d.trim().to_string())
            .filter(|d| !d.is_empty())
            .collect();
        if targets.is_empty() {
            failures.push(ImportFailure {
                line: line_no,
                name: parsed.name.clone(),
                reason: "缺少目标地址（dest 为空）".into(),
            });
            continue;
        }

        // 名称缺失时用行号兜底 —— 名称在库里唯一，不能为空。
        let name = parsed
            .name
            .as_deref()
            .map(|n| n.trim())
            .filter(|n| !n.is_empty())
            .map(|n| n.to_string())
            .unwrap_or_else(|| format!("导入线路-{line_no}"));

        // target_host/port 由 storage 层从 targets[0] 取，这里给占位值即可。
        let input = CreateRoute {
            name: name.clone(),
            mode: req.mode.clone(),
            entry_group_id: req.group_id.clone(),
            listen_address: req.listen_address.clone(),
            listen_port: parsed.listen_port,
            exit_group_id: req.exit_group_id.clone(),
            target_host: String::new(),
            target_port: 0,
            targets,
            // 逐条指定的优先，否则用请求级默认。非法值由 storage 层拒绝并指出
            // 合法取值，所以这里不做二次校验。
            target_strategy: parsed
                .target_strategy
                .clone()
                .unwrap_or_else(|| req.target_strategy.clone()),
            endpoint_ids: req.endpoint_ids.clone(),
            tunnel_pool_size: 8,
            load_balance: "round_robin".into(),
            max_connections: 0,
            egress_source_ip: req.egress_source_ip.clone(),
            egress_interface: None,
        };

        match repo.create(input).await {
            Ok(route) => {
                created += 1;
                touched_routes.push(route.id);
            }
            Err(e) => failures.push(ImportFailure {
                line: line_no,
                name: Some(name),
                reason: e.to_string(),
            }),
        }
    }

    // 一次性递增受影响组的配置版本，而不是每条线路都递增 —— 79 条导入会让 agent
    // 白重载 79 次。
    if created > 0 {
        if let Some(first) = touched_routes.first() {
            bump_route_groups(&state, first).await;
        }
        state.broadcast(Event::ConfigChanged {
            entity: "routes".into(),
        });
    }

    let mut notes = Vec::new();
    if proxy_ignored > 0 {
        notes.push(format!(
            "有 {proxy_protocol} 条带 proxy_protocol 字段，本系统不支持 PROXY Protocol，\
             该设置已被忽略。如果对应落地机配置了接收 PROXY Protocol，这些线路会连不通 —— \
             请在落地机上关闭该选项。",
            proxy_protocol = proxy_ignored
        ));
    }
    if req.mode == "direct" {
        notes.push(
            "导入的线路为直连模式：本机接受连接后直接拨目标，不建加密隧道。".into(),
        );
    }
    let auto_ports = created; // 端口留空的条目由系统分配，这里给出提示
    if auto_ports > 0 {
        notes.push(
            "未指定 listen_port 的条目已由系统在 2000-65535 间自动分配未占用端口。".into(),
        );
    }

    audit(
        &state,
        AuditEntry::new("route.import")
            .actor(
                Some(user.user_id().to_string()),
                Some(user.username().to_string()),
            )
            .source_ip(client.to_audit_string())
            .detail(serde_json::json!({
                "total": total,
                "created": created,
                "failed": failures.len(),
                "proxy_protocol_ignored": proxy_ignored,
            })),
    )
    .await;

    Ok(Json(ImportResponse {
        total,
        created,
        failed: failures.len(),
        failures,
        proxy_protocol_ignored: proxy_ignored,
        notes,
    }))
}

#[derive(Debug, Deserialize)]
pub struct ExportQuery {
    /// 只导出该组的线路。省略则导出全部。
    #[serde(default)]
    pub group_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ExportResponse {
    /// JSON Lines 文本，格式与导入一致，可直接回灌。
    pub content: String,
    pub count: usize,
}

pub async fn export_routes(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    axum::extract::Query(q): axum::extract::Query<ExportQuery>,
) -> ApiResult<Json<ExportResponse>> {
    user.require_admin()?;

    let routes = RouteRepo::new(&state.db).list().await?;
    let filtered: Vec<&RouteDto> = routes
        .iter()
        .filter(|r| match &q.group_id {
            Some(g) => &r.entry_group_id == g,
            None => true,
        })
        .collect();

    // 导出成与导入一致的格式，保证能直接回灌。不写 proxy_protocol —— 本系统不支持，
    // 导出它会让人误以为生效了。
    let mut lines = Vec::with_capacity(filtered.len());
    for r in &filtered {
        let mut line = serde_json::json!({
            "name": r.name,
            "listen_port": r.listen_port,
            "dest": r.targets,
        });
        // 只在多目标时写策略：单目标时它不起作用，写出来反而让人以为有影响。
        // 不写的话导出→导入会把策略静默重置成随机。
        if r.targets.len() > 1 {
            line["target_strategy"] = serde_json::Value::String(r.target_strategy.clone());
        }
        lines.push(line.to_string());
    }

    Ok(Json(ExportResponse {
        count: lines.len(),
        content: lines.join("\n"),
    }))
}

#[derive(Debug, Deserialize)]
pub struct BulkIdsRequest {
    pub route_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct BulkResult {
    pub succeeded: usize,
    pub failed: usize,
    pub errors: Vec<String>,
}

/// 批量删除。
///
/// 逐条删除并汇总结果，理由同导入：一条失败不该让其余的也回滚。
pub async fn bulk_delete_routes(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    client: ClientAddr,
    Json(req): Json<BulkIdsRequest>,
) -> ApiResult<Json<BulkResult>> {
    user.require_password_rotated()?;
    user.require_admin()?;

    if req.route_ids.is_empty() {
        return Err(ApiError::bad_request("没有选中任何线路"));
    }

    let repo = RouteRepo::new(&state.db);
    let mut succeeded = 0usize;
    let mut errors = Vec::new();
    // 删除前先收集受影响的组，删完就查不到了。
    let mut affected: std::collections::HashSet<String> = Default::default();

    for id in &req.route_ids {
        if let Ok(groups) = repo.affected_groups(id).await {
            affected.extend(groups);
        }
        match repo.delete(id).await {
            Ok(()) => succeeded += 1,
            Err(e) => errors.push(format!("{id}: {e}")),
        }
    }

    let groups = tunnel_storage::groups::DeviceGroupRepo::new(&state.db);
    for g in affected {
        let _ = groups.bump_revision(&g).await;
    }

    audit(
        &state,
        AuditEntry::new("route.bulk_delete")
            .actor(
                Some(user.user_id().to_string()),
                Some(user.username().to_string()),
            )
            .source_ip(client.to_audit_string())
            .detail(serde_json::json!({
                "requested": req.route_ids.len(),
                "succeeded": succeeded,
            })),
    )
    .await;
    state.broadcast(Event::ConfigChanged {
        entity: "routes".into(),
    });

    Ok(Json(BulkResult {
        succeeded,
        failed: errors.len(),
        errors,
    }))
}

#[derive(Debug, Deserialize)]
pub struct BulkEnabledRequest {
    pub route_ids: Vec<String>,
    pub enabled: bool,
}

/// 批量改组。
///
/// 三个字段都可选，只改给出的那些：
/// * `entry_group_id` —— 把这批线路挪到另一组机器上。
/// * `exit_group_id` —— 换出口组，同时必须给 `endpoint_ids`（原隧道地址属于旧组）。
/// * `mode` —— `direct` 把整批改成直连（清空隧道地址），`tunnel` 则需要出口组与隧道地址。
#[derive(Debug, Deserialize)]
pub struct BulkRegroupRequest {
    pub route_ids: Vec<String>,
    #[serde(default)]
    pub entry_group_id: Option<String>,
    #[serde(default)]
    pub exit_group_id: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
    /// 换出口组或切到隧道模式时用的隧道地址，整批共用。
    #[serde(default)]
    pub endpoint_ids: Option<Vec<String>>,
}

/// 批量修改入口组、出口组或转发模式。
///
/// 为什么需要它：导入 79 条线路后发现挪错了组，逐条编辑要开 79 次弹窗。
///
/// 逐条处理并汇总，理由同导入 —— 某一条撞上端口冲突（目标组里已有线路占着同一个
/// 端口）不该让其余的也回滚。
pub async fn bulk_regroup_routes(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    client: ClientAddr,
    Json(req): Json<BulkRegroupRequest>,
) -> ApiResult<Json<BulkResult>> {
    user.require_password_rotated()?;
    user.require_admin()?;

    if req.route_ids.is_empty() {
        return Err(ApiError::bad_request("没有选中任何线路"));
    }
    if req.entry_group_id.is_none() && req.exit_group_id.is_none() && req.mode.is_none() {
        return Err(ApiError::bad_request(
            "没有指定要修改的内容：请至少选择入口组、出口组或转发模式之一",
        ));
    }

    let repo = RouteRepo::new(&state.db);
    let mut succeeded = 0usize;
    let mut errors = Vec::new();
    let mut affected: std::collections::HashSet<String> = Default::default();

    for id in &req.route_ids {
        // 改组前后的组都要递增版本：老组要停掉这条线路，新组要起它。
        if let Ok(groups) = repo.affected_groups(id).await {
            affected.extend(groups);
        }

        let name = repo.get(id).await.map(|r| r.name).unwrap_or_else(|_| id.clone());
        let input = tunnel_storage::models::UpdateRoute {
            entry_group_id: req.entry_group_id.clone(),
            exit_group_id: req.exit_group_id.clone(),
            mode: req.mode.clone(),
            endpoint_ids: req.endpoint_ids.clone(),
            ..Default::default()
        };
        match repo.update(id, input).await {
            Ok(_) => {
                succeeded += 1;
                if let Ok(groups) = repo.affected_groups(id).await {
                    affected.extend(groups);
                }
            }
            Err(e) => errors.push(format!("{name}: {e}")),
        }
    }

    let groups = tunnel_storage::groups::DeviceGroupRepo::new(&state.db);
    for g in affected {
        let _ = groups.bump_revision(&g).await;
    }

    audit(
        &state,
        AuditEntry::new("route.bulk_regroup")
            .actor(
                Some(user.user_id().to_string()),
                Some(user.username().to_string()),
            )
            .source_ip(client.to_audit_string())
            .detail(serde_json::json!({
                "requested": req.route_ids.len(),
                "succeeded": succeeded,
                "entry_group_id": req.entry_group_id,
                "exit_group_id": req.exit_group_id,
                "mode": req.mode,
            })),
    )
    .await;
    state.broadcast(Event::ConfigChanged {
        entity: "routes".into(),
    });

    Ok(Json(BulkResult {
        succeeded,
        failed: errors.len(),
        errors,
    }))
}

/// 批量启停。
pub async fn bulk_set_enabled(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    client: ClientAddr,
    Json(req): Json<BulkEnabledRequest>,
) -> ApiResult<Json<BulkResult>> {
    user.require_password_rotated()?;
    user.require_admin()?;

    if req.route_ids.is_empty() {
        return Err(ApiError::bad_request("没有选中任何线路"));
    }

    let repo = RouteRepo::new(&state.db);
    let mut succeeded = 0usize;
    let mut errors = Vec::new();
    let mut affected: std::collections::HashSet<String> = Default::default();

    for id in &req.route_ids {
        match repo.set_enabled(id, req.enabled).await {
            Ok(_) => {
                succeeded += 1;
                if let Ok(groups) = repo.affected_groups(id).await {
                    affected.extend(groups);
                }
            }
            Err(e) => errors.push(format!("{id}: {e}")),
        }
    }

    let groups = tunnel_storage::groups::DeviceGroupRepo::new(&state.db);
    for g in affected {
        let _ = groups.bump_revision(&g).await;
    }

    audit(
        &state,
        AuditEntry::new(if req.enabled {
            "route.bulk_enable"
        } else {
            "route.bulk_disable"
        })
        .actor(
            Some(user.user_id().to_string()),
            Some(user.username().to_string()),
        )
        .source_ip(client.to_audit_string())
        .detail(serde_json::json!({
            "requested": req.route_ids.len(),
            "succeeded": succeeded,
        })),
    )
    .await;
    state.broadcast(Event::ConfigChanged {
        entity: "routes".into(),
    });

    Ok(Json(BulkResult {
        succeeded,
        failed: errors.len(),
        errors,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 用户提供的真实导入数据样本。
    const SAMPLE: &str = r#"
{"dest":["185.220.236.37:21334"],"listen_port":17976,"name":"台湾01","proxy_protocol":2}
{"dest":["64.118.136.104:23441"],"listen_port":46732,"name":"新加坡 03"}
{"dest":["64.118.153.48:443"],"listen_port":64901,"name":"美国 04 ddn"}
"#;

    #[test]
    fn parses_the_real_world_format() {
        let lines: Vec<ImportLine> = SAMPLE
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_str(l).expect("样本应能解析"))
            .collect();

        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0].dest, vec!["185.220.236.37:21334"]);
        assert_eq!(lines[0].listen_port, Some(17976));
        assert_eq!(lines[0].name.as_deref(), Some("台湾01"));
        assert_eq!(lines[0].proxy_protocol, Some(2));
        // 没有 proxy_protocol 的条目解析为 None，不是报错。
        assert_eq!(lines[1].proxy_protocol, None);
        // 端口在高位区间（64901），说明原先 10000-30000 的限制过窄。
        assert_eq!(lines[2].listen_port, Some(64901));
    }

    #[test]
    fn multiple_destinations_are_preserved() {
        let line: ImportLine =
            serde_json::from_str(r#"{"dest":["1.2.3.4:443","5.6.7.8:443"],"name":"多目标"}"#)
                .unwrap();
        assert_eq!(line.dest.len(), 2);
    }

    #[test]
    fn missing_port_is_allowed_and_means_auto_assign() {
        let line: ImportLine =
            serde_json::from_str(r#"{"dest":["1.2.3.4:443"],"name":"无端口"}"#).unwrap();
        assert!(line.listen_port.is_none());
    }

    #[test]
    fn alternative_key_names_are_accepted() {
        // 不同面板导出的键名略有差异。
        let a: ImportLine =
            serde_json::from_str(r#"{"targets":["1.2.3.4:443"],"port":1234}"#).unwrap();
        assert_eq!(a.dest, vec!["1.2.3.4:443"]);
        assert_eq!(a.listen_port, Some(1234));

        let b: ImportLine =
            serde_json::from_str(r#"{"remote":["1.2.3.4:443"],"listen":5678}"#).unwrap();
        assert_eq!(b.dest, vec!["1.2.3.4:443"]);
        assert_eq!(b.listen_port, Some(5678));
    }

    #[test]
    fn a_per_line_strategy_is_parsed() {
        // 一批线路里可能只有少数几条需要 IP 哈希，其余用随机。
        let line: ImportLine = serde_json::from_str(
            r#"{"dest":["1.2.3.4:443","5.6.7.8:443"],"target_strategy":"ip_hash"}"#,
        )
        .unwrap();
        assert_eq!(line.target_strategy.as_deref(), Some("ip_hash"));

        // 别名同样接受。
        for text in [
            r#"{"dest":["1.2.3.4:443"],"balance":"least_conn"}"#,
            r#"{"dest":["1.2.3.4:443"],"lb":"least_conn"}"#,
        ] {
            let l: ImportLine = serde_json::from_str(text).unwrap();
            assert_eq!(l.target_strategy.as_deref(), Some("least_conn"), "{text}");
        }

        // 没给时是 None，由请求级默认接管。
        let plain: ImportLine =
            serde_json::from_str(r#"{"dest":["1.2.3.4:443"]}"#).unwrap();
        assert!(plain.target_strategy.is_none());
    }

    #[test]
    fn the_request_level_strategy_defaults_to_random() {
        let req: ImportRequest = serde_json::from_str(
            r#"{"content":"","group_id":"g1"}"#,
        )
        .unwrap();
        assert_eq!(req.target_strategy, "random");
        // 导入格式里没有隧道信息，所以默认直连。
        assert_eq!(req.mode, "direct");
        assert_eq!(req.listen_address, "0.0.0.0");
    }

    #[test]
    fn unknown_fields_do_not_break_parsing() {
        // 上游面板会带一堆我们不认识的字段，不该整行拒绝。
        let line: ImportLine = serde_json::from_str(
            r#"{"dest":["1.2.3.4:443"],"name":"x","weird_field":42,"another":{"a":1}}"#,
        )
        .unwrap();
        assert_eq!(line.name.as_deref(), Some("x"));
    }

    #[test]
    fn malformed_json_is_reported_not_panicking() {
        assert!(serde_json::from_str::<ImportLine>("{not json").is_err());
        assert!(serde_json::from_str::<ImportLine>("").is_err());
    }
}
