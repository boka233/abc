//! REST handlers.
//!
//! Conventions across this module:
//!
//! * Mutating endpoints call [`AuthUser::require_password_rotated`], so a
//!   deployment cannot be driven with the generated first-run credentials.
//! * Mutating endpoints write an audit entry. Detail payloads are redacted by
//!   the audit repository, not here, so a forgetful handler cannot leak a secret.
//! * Config changes bump the affected nodes' revisions and broadcast a
//!   `config_changed` event, which is how agents and the panel learn to refetch.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::request::Parts;
use axum::Json;
use chrono::{Duration as ChronoDuration, NaiveDate};
use serde::{Deserialize, Serialize};
use tunnel_storage::audit::AuditRepo;
use tunnel_storage::models::{
    AuditEntry, CreateEndpoint, CreateNode, CreateRoute, UpdateEndpoint, UpdateNode, UpdateRoute,
};
use tunnel_storage::nodes::{EndpointRepo, NodeRepo};
use tunnel_storage::routes::RouteRepo;
use tunnel_storage::settings::{keys, SettingsRepo};
use tunnel_storage::stats::StatsRepo;
use tunnel_storage::users::UserRepo;

use crate::api::error::{ApiError, ApiResult};
use crate::api::middleware::{AuthAgent, AuthUser, ClientAddr};
use crate::distribute;
use crate::state::{AppState, Event};

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

pub(crate) async fn audit(state: &AppState, entry: AuditEntry) {
    if let Err(e) = AuditRepo::new(&state.db).record(entry).await {
        // A failed audit write must not fail the operation that succeeded, but it
        // must be visible.
        tracing::error!(error = %e, "failed to write audit entry");
    }
}

/// 拼装一键对接命令。
///
/// 形态刻意和 relay-panel 对齐：`bash <(curl -fsSL ...)` 一行，参数只有令牌和面板
/// 地址。不用 `curl | bash` 是因为那样脚本无法读取 stdin，而我们的脚本要在改动
/// sysctl 前向用户确认。
pub(crate) fn install_command_for(state: &AppState, token: &str) -> String {
    let panel = state.panel_url();
    format!(
        "bash <(curl -fsSL {panel}/api/agent/install.sh) -t {token} -u {panel}"
    )
}

/// 递增线路两端组的配置版本，组内 agent 下次轮询时重载。
///
/// 递增到组级别而非机器级别：组内所有 agent 共享一个版本号，一次变更让整组同步。
pub(crate) async fn bump_route_groups(state: &AppState, route_id: &str) {
    let repo = RouteRepo::new(&state.db);
    match repo.affected_groups(route_id).await {
        Ok(group_ids) => {
            let groups = tunnel_storage::groups::DeviceGroupRepo::new(&state.db);
            for id in group_ids {
                if let Err(e) = groups.bump_revision(&id).await {
                    tracing::warn!(group = %id, error = %e, "无法递增配置版本");
                }
            }
        }
        Err(e) => tracing::warn!(error = %e, "无法解析受影响的设备组"),
    }
}

// ---------------------------------------------------------------------------
// auth
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub expires_in_secs: u64,
    pub username: String,
    pub role: String,
    pub must_change_password: bool,
}

pub async fn login(
    State(state): State<Arc<AppState>>,
    client: ClientAddr,
    Json(req): Json<LoginRequest>,
) -> ApiResult<Json<LoginResponse>> {
    let ip = client.for_throttle();

    // Throttle before touching Argon2: verification is intentionally expensive,
    // so an unthrottled login endpoint is a CPU-exhaustion vector as well as a
    // credential-stuffing one.
    state.throttle.check(ip)?;

    let users = UserRepo::new(&state.db);
    let user = users.verify_login(&req.username, &req.password).await?;

    let Some(user) = user else {
        state.throttle.record_failure(ip);
        audit(
            &state,
            AuditEntry::new("auth.login")
                .actor(None, Some(req.username.clone()))
                .source_ip(client.to_audit_string())
                .failed(),
        )
        .await;
        return Err(ApiError::Unauthorized);
    };

    state.throttle.record_success(ip);
    let token = state.tokens.issue(&user.id, &user.username, &user.role)?;

    audit(
        &state,
        AuditEntry::new("auth.login")
            .actor(Some(user.id.clone()), Some(user.username.clone()))
            .source_ip(client.to_audit_string()),
    )
    .await;

    Ok(Json(LoginResponse {
        token,
        expires_in_secs: state.tokens.ttl().as_secs(),
        username: user.username,
        role: user.role,
        must_change_password: user.must_change_password,
    }))
}

#[derive(Serialize)]
pub struct MeResponse {
    pub user_id: String,
    pub username: String,
    pub role: String,
    pub must_change_password: bool,
}

pub async fn me(user: AuthUser) -> ApiResult<Json<MeResponse>> {
    Ok(Json(MeResponse {
        user_id: user.claims.sub.clone(),
        username: user.claims.username.clone(),
        role: user.claims.role.clone(),
        must_change_password: user.must_change_password,
    }))
}

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

pub async fn change_password(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    client: ClientAddr,
    Json(req): Json<ChangePasswordRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    // Deliberately *not* gated on require_password_rotated: this is the endpoint
    // a user with a forced rotation must be able to call.
    UserRepo::new(&state.db)
        .change_password(user.user_id(), &req.current_password, &req.new_password)
        .await?;

    audit(
        &state,
        AuditEntry::new("auth.change_password")
            .actor(
                Some(user.user_id().to_string()),
                Some(user.username().to_string()),
            )
            .source_ip(client.to_audit_string()),
    )
    .await;

    Ok(Json(serde_json::json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// dashboard
// ---------------------------------------------------------------------------

pub async fn dashboard(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
) -> ApiResult<Json<serde_json::Value>> {
    let cfg = state.config();
    let stale = std::time::Duration::from_secs(cfg.agent.stale_after_secs);
    let summary = state.summary(stale);

    let routes = RouteRepo::new(&state.db).list().await?;
    let nodes = NodeRepo::new(&state.db).list().await?;
    let (total_rx, total_tx) = StatsRepo::new(&state.db).lifetime_totals().await?;

    // Nodes that have never reported are offline but absent from live telemetry,
    // so the count comes from the database rather than the report map.
    let configured_nodes = nodes.len() as u32;
    let offline = configured_nodes.saturating_sub(summary.nodes_online);

    Ok(Json(serde_json::json!({
        "nodes_total": configured_nodes,
        "nodes_online": summary.nodes_online,
        "nodes_offline": offline,
        "nodes_degraded": summary.nodes_degraded,
        "routes_total": routes.len(),
        "routes_enabled": routes.iter().filter(|r| r.enabled).count(),
        "tunnels_online": summary.tunnels_online,
        "tunnels_total": summary.tunnels_total,
        "connections": summary.connections,
        "rx_bps": summary.rx_bps,
        "tx_bps": summary.tx_bps,
        "total_rx_bytes": total_rx,
        "total_tx_bytes": total_tx,
        "uptime_secs": state.uptime().as_secs(),
        "psk_configured": distribute::psk_configured(&cfg.tunnel_psk),
        "production": cfg.production,
    })))
}

// ---------------------------------------------------------------------------
// nodes
// ---------------------------------------------------------------------------

pub async fn list_nodes(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
) -> ApiResult<Json<serde_json::Value>> {
    let nodes = NodeRepo::new(&state.db).list().await?;
    let cfg = state.config();
    let stale = std::time::Duration::from_secs(cfg.agent.stale_after_secs);

    // Overlay live telemetry so the list reflects reality between heartbeat
    // persists.
    let enriched: Vec<serde_json::Value> = nodes
        .into_iter()
        .map(|n| {
            let live = state.report_for(&n.id).filter(|r| r.age() <= stale);
            let mut value = serde_json::to_value(&n).unwrap_or_default();
            if let (Some(live), Some(obj)) = (live, value.as_object_mut()) {
                let r = &live.report;
                obj.insert("status".into(), serde_json::json!("online"));
                obj.insert("connections".into(), serde_json::json!(r.connections));
                obj.insert("rx_bps".into(), serde_json::json!(r.rx_bps));
                obj.insert("tx_bps".into(), serde_json::json!(r.tx_bps));
                obj.insert("rx_bytes".into(), serde_json::json!(r.rx_bytes));
                obj.insert("tx_bytes".into(), serde_json::json!(r.tx_bytes));
                obj.insert(
                    "tunnels_total".into(),
                    serde_json::json!(r.tunnels.len()),
                );
                obj.insert(
                    "tunnels_online".into(),
                    serde_json::json!(r
                        .tunnels
                        .iter()
                        .filter(|t| t.state == tunnel_common::model::TunnelState::Online)
                        .count()),
                );
                obj.insert("cpu_percent".into(), serde_json::json!(r.host.cpu_percent));
                obj.insert(
                    "memory_used_bytes".into(),
                    serde_json::json!(r.host.memory_used_bytes),
                );
                obj.insert(
                    "memory_total_bytes".into(),
                    serde_json::json!(r.host.memory_total_bytes),
                );
                obj.insert("uptime_secs".into(), serde_json::json!(r.host.uptime_secs));
                obj.insert(
                    "interfaces".into(),
                    serde_json::to_value(&r.interfaces).unwrap_or_default(),
                );
                obj.insert(
                    "agent_version".into(),
                    serde_json::json!(r.agent_version.clone()),
                );
            }
            value
        })
        .collect();

    Ok(Json(serde_json::json!({ "nodes": enriched })))
}

pub async fn get_node(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let node = NodeRepo::new(&state.db).get(&id).await?;
    let live = state.report_for(&id);
    let routes = RouteRepo::new(&state.db).list().await?;
    let endpoints = EndpointRepo::new(&state.db).list_for_node(&id).await?;

    Ok(Json(serde_json::json!({
        "node": node,
        "endpoints": endpoints.iter().map(|e| e.to_model()).collect::<Vec<_>>(),
        "routes": routes
            .iter()
            .filter(|r| r.entry_group_id == node.group_id || r.exit_group_id == node.group_id)
            .collect::<Vec<_>>(),
        "tunnels": live.as_ref().map(|l| l.report.tunnels.clone()).unwrap_or_default(),
        "live_routes": live.as_ref().map(|l| l.report.routes.clone()).unwrap_or_default(),
        "report_age_secs": live.as_ref().map(|l| l.age().as_secs()),
    })))
}

pub async fn create_node(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    client: ClientAddr,
    Json(input): Json<CreateNode>,
) -> ApiResult<Json<serde_json::Value>> {
    user.require_password_rotated()?;
    user.require_admin()?;

    let name = input.name.clone();
    let node = NodeRepo::new(&state.db).create(input).await?;

    audit(
        &state,
        AuditEntry::new("node.create")
            .actor(
                Some(user.user_id().to_string()),
                Some(user.username().to_string()),
            )
            .target("node", &node.id, Some(name))
            .source_ip(client.to_audit_string()),
    )
    .await;
    state.broadcast(Event::ConfigChanged {
        entity: "groups".into(),
    });

    // 不再返回令牌 —— 凭据在组上。装机请用组的一键对接命令。
    Ok(Json(serde_json::json!({
        "node": node,
        "note": "手工添加的机器需要 agent 用该组的一键对接命令上线后才会变为在线。"
    })))
}

pub async fn update_node(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    client: ClientAddr,
    Path(id): Path<String>,
    Json(input): Json<UpdateNode>,
) -> ApiResult<Json<serde_json::Value>> {
    user.require_password_rotated()?;
    user.require_admin()?;

    let node = NodeRepo::new(&state.db).update(&id, input).await?;
    audit(
        &state,
        AuditEntry::new("node.update")
            .actor(
                Some(user.user_id().to_string()),
                Some(user.username().to_string()),
            )
            .target("node", &id, Some(node.name.clone()))
            .source_ip(client.to_audit_string()),
    )
    .await;
    state.broadcast(Event::ConfigChanged {
        entity: "groups".into(),
    });
    Ok(Json(serde_json::json!({ "node": node })))
}

pub async fn delete_node(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    client: ClientAddr,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    user.require_password_rotated()?;
    user.require_admin()?;

    let node = NodeRepo::new(&state.db).get(&id).await?;
    NodeRepo::new(&state.db).delete(&id).await?;
    state.drop_report(&id);

    audit(
        &state,
        AuditEntry::new("node.delete")
            .actor(
                Some(user.user_id().to_string()),
                Some(user.username().to_string()),
            )
            .target("node", &id, Some(node.name))
            .source_ip(client.to_audit_string()),
    )
    .await;
    state.broadcast(Event::ConfigChanged {
        entity: "groups".into(),
    });
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// 预览某台机器会收到的配置 bundle。用于排查「线路没下发到 agent」。
pub async fn node_config_preview(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    user.require_admin()?;
    let cfg = state.config();
    let mut bundle = distribute::build_bundle(&state.db, &cfg, &id).await?;
    // Never echo the PSK back to a browser, even to an admin.
    bundle.tunnel_psk = None;
    Ok(Json(serde_json::json!({ "config": bundle })))
}

// ---------------------------------------------------------------------------
// endpoints
// ---------------------------------------------------------------------------

pub async fn list_endpoints(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
) -> ApiResult<Json<serde_json::Value>> {
    let endpoints = EndpointRepo::new(&state.db).list().await?;
    Ok(Json(serde_json::json!({ "endpoints": endpoints })))
}

pub async fn create_endpoint(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    client: ClientAddr,
    Json(input): Json<CreateEndpoint>,
) -> ApiResult<Json<serde_json::Value>> {
    user.require_password_rotated()?;
    user.require_admin()?;

    let node_id = input.node_id.clone();
    let endpoint = EndpointRepo::new(&state.db).create(input).await?;
    // The owning node's exit config changed.
    let _ = NodeRepo::new(&state.db).bump_revision(&node_id).await;

    audit(
        &state,
        AuditEntry::new("endpoint.create")
            .actor(
                Some(user.user_id().to_string()),
                Some(user.username().to_string()),
            )
            .target("endpoint", &endpoint.id, Some(endpoint.name.clone()))
            .source_ip(client.to_audit_string())
            .detail(serde_json::json!({
                "address": endpoint.address,
                "port": endpoint.port,
                "kind": endpoint.kind,
            })),
    )
    .await;
    state.broadcast(Event::ConfigChanged {
        entity: "endpoints".into(),
    });
    Ok(Json(serde_json::json!({ "endpoint": endpoint })))
}

pub async fn update_endpoint(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    client: ClientAddr,
    Path(id): Path<String>,
    Json(input): Json<UpdateEndpoint>,
) -> ApiResult<Json<serde_json::Value>> {
    user.require_password_rotated()?;
    user.require_admin()?;

    let endpoint = EndpointRepo::new(&state.db).update(&id, input).await?;
    let _ = NodeRepo::new(&state.db)
        .bump_revision(&endpoint.node_id)
        .await;

    audit(
        &state,
        AuditEntry::new("endpoint.update")
            .actor(
                Some(user.user_id().to_string()),
                Some(user.username().to_string()),
            )
            .target("endpoint", &id, Some(endpoint.name.clone()))
            .source_ip(client.to_audit_string()),
    )
    .await;
    state.broadcast(Event::ConfigChanged {
        entity: "endpoints".into(),
    });
    Ok(Json(serde_json::json!({ "endpoint": endpoint })))
}

pub async fn delete_endpoint(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    client: ClientAddr,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    user.require_password_rotated()?;
    user.require_admin()?;

    let endpoint = EndpointRepo::new(&state.db).get(&id).await?;
    EndpointRepo::new(&state.db).delete(&id).await?;
    let _ = NodeRepo::new(&state.db)
        .bump_revision(&endpoint.node_id)
        .await;

    audit(
        &state,
        AuditEntry::new("endpoint.delete")
            .actor(
                Some(user.user_id().to_string()),
                Some(user.username().to_string()),
            )
            .target("endpoint", &id, Some(endpoint.name))
            .source_ip(client.to_audit_string()),
    )
    .await;
    state.broadcast(Event::ConfigChanged {
        entity: "endpoints".into(),
    });
    Ok(Json(serde_json::json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// routes
// ---------------------------------------------------------------------------

pub async fn list_routes(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
) -> ApiResult<Json<serde_json::Value>> {
    let routes = RouteRepo::new(&state.db).list().await?;
    let cfg = state.config();
    let stale = std::time::Duration::from_secs(cfg.agent.stale_after_secs);

    // 一条线路的入口组里可能有多台机器，各自都在转发这条线路，所以实时数据要跨
    // 机器求和，而不是取某一台的读数。
    let nodes = NodeRepo::new(&state.db);
    let mut enriched = Vec::with_capacity(routes.len());
    for r in routes {
        let members = nodes.list_for_group(&r.entry_group_id).await?;
        let live = aggregate_route_live(&state, &members, &r.id, stale);
        enriched.push(serde_json::json!({ "route": r, "live": live }));
    }

    Ok(Json(serde_json::json!({ "routes": enriched })))
}

/// 一个目标在整组机器上的汇总健康状态。
#[derive(Debug, Default, serde::Serialize)]
struct TargetHealthAgg {
    addr: String,
    /// 是否还有机器在往这个目标分配连接。
    available: bool,
    /// 是否有机器把它熔断了。
    tripped: bool,
    /// 有几台机器熔断了它。1 台异常和全组异常是两回事。
    tripped_on_machines: u32,
    /// 有几台机器上报了这个目标，作为上面那个数的分母。
    machines: u32,
    active: u64,
    consecutive_failures: u32,
    total_ok: u64,
    total_failed: u64,
}

/// 把组内各机器上报的目标健康状态按地址合并。
///
/// 组内每台入口机各自维护熔断状态 —— 一台机器到某个目标的网络有问题，另一台可能
/// 好着。所以：
///
/// * 计数求和：全组的总量才是用户关心的。
/// * `tripped` 取「任一台认为已熔断」：这正是需要被看见的异常，取「全部熔断」会把
///   一台机器的故障藏起来。
/// * `available` 取「任一台仍在用」：反映流量其实还在流。
///
/// 两者可以同时为真，表示部分机器绕开了这个目标 —— `tripped_on_machines` 给出具体
/// 有几台，因为「1 台异常」和「全组异常」是两回事。
fn merge_target_health(
    per_machine: &[Vec<tunnel_common::model::TargetHealth>],
) -> Vec<TargetHealthAgg> {
    let mut merged: std::collections::HashMap<String, TargetHealthAgg> = Default::default();
    for machine in per_machine {
        for t in machine {
            let slot = merged
                .entry(t.addr.clone())
                .or_insert_with(|| TargetHealthAgg {
                    addr: t.addr.clone(),
                    ..Default::default()
                });
            slot.available |= t.available;
            slot.tripped |= t.tripped;
            slot.active += t.active;
            slot.total_ok += t.total_ok;
            slot.total_failed += t.total_failed;
            slot.consecutive_failures = slot.consecutive_failures.max(t.consecutive_failures);
            slot.machines += 1;
            if t.tripped {
                slot.tripped_on_machines += 1;
            }
        }
    }
    // 顺序稳定：按地址排序，否则面板上的目标列表每次刷新都在跳。
    let mut out: Vec<TargetHealthAgg> = merged.into_values().collect();
    out.sort_by(|a, b| a.addr.cmp(&b.addr));
    out
}

/// 跨入口组内所有机器汇总一条线路的实时数据。
///
/// 字节与速率求和，隧道数求和，活动端点取第一台上报的 —— 同组机器应当选中同一个
/// 端点，若不同则说明正在故障转移过程中，取任一台都不算错。
fn aggregate_route_live(
    state: &AppState,
    members: &[tunnel_storage::models::NodeDto],
    route_id: &str,
    stale: std::time::Duration,
) -> Option<serde_json::Value> {
    let mut found = false;
    let mut connections = 0u32;
    let (mut rx_bps, mut tx_bps, mut rx_bytes, mut tx_bytes) = (0u64, 0u64, 0u64, 0u64);
    let (mut tunnels_online, mut tunnels_total) = (0u32, 0u32);
    let (mut accepted, mut rejected, mut failed) = (0u64, 0u64, 0u64);
    let mut active_endpoint: Option<String> = None;
    let mut per_machine_targets: Vec<Vec<tunnel_common::model::TargetHealth>> = Vec::new();

    for m in members {
        let Some(live) = state.report_for(&m.id).filter(|l| l.age() <= stale) else {
            continue;
        };
        let Some(rs) = live.report.routes.iter().find(|rs| rs.route_id == route_id) else {
            continue;
        };
        found = true;
        connections += rs.connections;
        rx_bps += rs.rx_bps;
        tx_bps += rs.tx_bps;
        rx_bytes += rs.rx_bytes;
        tx_bytes += rs.tx_bytes;
        tunnels_online += rs.tunnels_online;
        tunnels_total += rs.tunnels_total;
        accepted += rs.accepted_total;
        rejected += rs.rejected_total;
        failed += rs.failed_total;
        if active_endpoint.is_none() {
            active_endpoint = rs.active_endpoint_id.clone();
        }

        per_machine_targets.push(rs.targets.clone());
    }

    let targets = merge_target_health(&per_machine_targets);

    found.then(|| {
        serde_json::json!({
            "targets": targets,
            "route_id": route_id,
            "connections": connections,
            "rx_bps": rx_bps,
            "tx_bps": tx_bps,
            "rx_bytes": rx_bytes,
            "tx_bytes": tx_bytes,
            "tunnels_online": tunnels_online,
            "tunnels_total": tunnels_total,
            "accepted_total": accepted,
            "rejected_total": rejected,
            "failed_total": failed,
            "active_endpoint_id": active_endpoint,
            // 有几台机器在实际承载这条线路，面板可据此提示「部分机器未上报」。
            "reporting_machines": members
                .iter()
                .filter(|m| state.report_for(&m.id).map(|l| l.age() <= stale).unwrap_or(false))
                .count(),
        })
    })
}

pub async fn get_route(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let route = RouteRepo::new(&state.db).get(&id).await?;
    let cfg = state.config();
    let stale = std::time::Duration::from_secs(cfg.agent.stale_after_secs);
    let members = NodeRepo::new(&state.db)
        .list_for_group(&route.entry_group_id)
        .await?;

    // 收集组内所有机器上属于该线路的隧道，并标注隧道在哪台机器上。
    let mut tunnels = Vec::new();
    for m in &members {
        let Some(live) = state.report_for(&m.id).filter(|l| l.age() <= stale) else {
            continue;
        };
        for t in live.report.tunnels.iter().filter(|t| t.route_id == id) {
            let mut value = serde_json::to_value(t).unwrap_or_default();
            if let Some(obj) = value.as_object_mut() {
                obj.insert("node_id".into(), serde_json::json!(m.id));
                obj.insert("node_name".into(), serde_json::json!(m.name));
            }
            tunnels.push(value);
        }
    }

    let live = aggregate_route_live(&state, &members, &id, stale);
    Ok(Json(serde_json::json!({
        "route": route,
        "tunnels": tunnels,
        "live": live,
    })))
}

pub async fn create_route(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    client: ClientAddr,
    Json(input): Json<CreateRoute>,
) -> ApiResult<Json<serde_json::Value>> {
    user.require_password_rotated()?;
    user.require_admin()?;

    let route = RouteRepo::new(&state.db).create(input).await?;
    bump_route_groups(&state, &route.id).await;

    audit(
        &state,
        AuditEntry::new("route.create")
            .actor(
                Some(user.user_id().to_string()),
                Some(user.username().to_string()),
            )
            .target("route", &route.id, Some(route.name.clone()))
            .source_ip(client.to_audit_string())
            .detail(serde_json::json!({
                "listen": format!("{}:{}", route.listen_address, route.listen_port),
                "target": format!("{}:{}", route.target_host, route.target_port),
                "pool_size": route.tunnel_pool_size,
            })),
    )
    .await;
    state.broadcast(Event::ConfigChanged {
        entity: "routes".into(),
    });
    Ok(Json(serde_json::json!({ "route": route })))
}

pub async fn update_route(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    client: ClientAddr,
    Path(id): Path<String>,
    Json(input): Json<UpdateRoute>,
) -> ApiResult<Json<serde_json::Value>> {
    user.require_password_rotated()?;
    user.require_admin()?;

    let route = RouteRepo::new(&state.db).update(&id, input).await?;
    bump_route_groups(&state, &id).await;

    audit(
        &state,
        AuditEntry::new("route.update")
            .actor(
                Some(user.user_id().to_string()),
                Some(user.username().to_string()),
            )
            .target("route", &id, Some(route.name.clone()))
            .source_ip(client.to_audit_string()),
    )
    .await;
    state.broadcast(Event::ConfigChanged {
        entity: "routes".into(),
    });
    Ok(Json(serde_json::json!({ "route": route })))
}

#[derive(Deserialize)]
pub struct EnabledRequest {
    pub enabled: bool,
}

pub async fn set_route_enabled(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    client: ClientAddr,
    Path(id): Path<String>,
    Json(req): Json<EnabledRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    user.require_password_rotated()?;
    user.require_admin()?;

    let route = RouteRepo::new(&state.db)
        .set_enabled(&id, req.enabled)
        .await?;
    bump_route_groups(&state, &id).await;

    audit(
        &state,
        AuditEntry::new(if req.enabled {
            "route.enable"
        } else {
            "route.disable"
        })
        .actor(
            Some(user.user_id().to_string()),
            Some(user.username().to_string()),
        )
        .target("route", &id, Some(route.name.clone()))
        .source_ip(client.to_audit_string()),
    )
    .await;
    state.broadcast(Event::ConfigChanged {
        entity: "routes".into(),
    });
    Ok(Json(serde_json::json!({ "route": route })))
}

/// Restart a route by bumping its revision.
///
/// The control plane cannot reach into an agent's process; it signals intent and
/// the agent reapplies on its next poll. That indirection is deliberate — see
/// the decoupling note in the crate docs.
pub async fn restart_route(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    client: ClientAddr,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    user.require_password_rotated()?;
    user.require_admin()?;

    let route = RouteRepo::new(&state.db).get(&id).await?;
    bump_route_groups(&state, &id).await;

    audit(
        &state,
        AuditEntry::new("route.restart")
            .actor(
                Some(user.user_id().to_string()),
                Some(user.username().to_string()),
            )
            .target("route", &id, Some(route.name))
            .source_ip(client.to_audit_string()),
    )
    .await;

    Ok(Json(serde_json::json!({
        "ok": true,
        "note": "Agents will rebuild this route on their next configuration poll."
    })))
}

pub async fn delete_route(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    client: ClientAddr,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    user.require_password_rotated()?;
    user.require_admin()?;

    let route = RouteRepo::new(&state.db).get(&id).await?;
    // Resolve affected nodes *before* deleting, or the lookup finds nothing.
    // 删除前先解析受影响的组，删完就查不到了。
    let affected = RouteRepo::new(&state.db).affected_groups(&id).await?;
    RouteRepo::new(&state.db).delete(&id).await?;

    let groups = tunnel_storage::groups::DeviceGroupRepo::new(&state.db);
    for group_id in affected {
        let _ = groups.bump_revision(&group_id).await;
    }

    audit(
        &state,
        AuditEntry::new("route.delete")
            .actor(
                Some(user.user_id().to_string()),
                Some(user.username().to_string()),
            )
            .target("route", &id, Some(route.name))
            .source_ip(client.to_audit_string()),
    )
    .await;
    state.broadcast(Event::ConfigChanged {
        entity: "routes".into(),
    });
    Ok(Json(serde_json::json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// tunnels & connections
// ---------------------------------------------------------------------------

pub async fn list_tunnels(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
) -> ApiResult<Json<serde_json::Value>> {
    let cfg = state.config();
    let stale = std::time::Duration::from_secs(cfg.agent.stale_after_secs);
    let mut tunnels = Vec::new();
    for live in state.all_reports() {
        if live.age() > stale {
            continue;
        }
        let node_id = live.report.node_id.clone();
        for t in &live.report.tunnels {
            let mut value = serde_json::to_value(t).unwrap_or_default();
            if let Some(obj) = value.as_object_mut() {
                obj.insert("node_id".into(), serde_json::json!(node_id));
            }
            tunnels.push(value);
        }
    }
    Ok(Json(serde_json::json!({ "tunnels": tunnels })))
}

#[derive(Deserialize)]
pub struct LimitQuery {
    #[serde(default)]
    pub limit: Option<usize>,
}

pub async fn list_connections(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
    Query(q): Query<LimitQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    let cfg = state.config();
    let stale = std::time::Duration::from_secs(cfg.agent.stale_after_secs);
    // Bounded so a request cannot ask for an unbounded response.
    let limit = q.limit.unwrap_or(200).clamp(1, 1000);
    let connections = state.connections(limit, stale);
    Ok(Json(serde_json::json!({
        "connections": connections,
        "limit": limit,
    })))
}

// ---------------------------------------------------------------------------
// traffic
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct TrafficQuery {
    #[serde(default)]
    pub minutes: Option<i64>,
    #[serde(default)]
    pub node_id: Option<String>,
    #[serde(default)]
    pub route_id: Option<String>,
}

pub async fn traffic(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
    Query(q): Query<TrafficQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    // Clamped so a single request cannot ask for years of samples.
    let minutes = q.minutes.unwrap_or(60).clamp(1, 60 * 24 * 7);
    let repo = StatsRepo::new(&state.db);

    let series = match (&q.node_id, &q.route_id) {
        (_, Some(route_id)) => repo.series_for_route(route_id, minutes).await?,
        (Some(node_id), None) => repo.series_for_node(node_id, minutes).await?,
        (None, None) => repo.series_total(minutes).await?,
    };

    Ok(Json(serde_json::json!({
        "minutes": minutes,
        "series": series,
    })))
}

#[derive(Deserialize)]
pub struct DailyTrafficQuery {
    pub date: String,
    /// Minutes east of UTC, supplied by the browser (e.g. 480 for UTC+8).
    pub utc_offset_minutes: i32,
}

fn daily_utc_bounds(date: &str, offset_minutes: i32) -> ApiResult<(String, String)> {
    if !(-840..=840).contains(&offset_minutes) {
        return Err(ApiError::bad_request("时区偏移超出范围"));
    }
    let day = NaiveDate::parse_from_str(date, "%Y-%m-%d")
        .map_err(|_| ApiError::bad_request("日期必须是 YYYY-MM-DD"))?;
    let local_midnight = day
        .and_hms_opt(0, 0, 0)
        .ok_or_else(|| ApiError::bad_request("无效日期"))?
        .and_utc();
    let start = local_midnight
        .checked_sub_signed(ChronoDuration::minutes(offset_minutes.into()))
        .ok_or_else(|| ApiError::bad_request("日期超出范围"))?;
    let end = start
        .checked_add_signed(ChronoDuration::days(1))
        .ok_or_else(|| ApiError::bad_request("日期超出范围"))?;
    Ok((start.to_rfc3339(), end.to_rfc3339()))
}

pub async fn daily_traffic(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
    Query(q): Query<DailyTrafficQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    let (start, end) = daily_utc_bounds(&q.date, q.utc_offset_minutes)?;
    let routes = StatsRepo::new(&state.db).daily_routes(&start, &end).await?;
    let rx_bytes: i64 = routes.iter().map(|route| route.rx_bytes).sum();
    let tx_bytes: i64 = routes.iter().map(|route| route.tx_bytes).sum();
    Ok(Json(serde_json::json!({
        "date": q.date,
        "utc_offset_minutes": q.utc_offset_minutes,
        "rx_bytes": rx_bytes,
        "tx_bytes": tx_bytes,
        "total_bytes": rx_bytes + tx_bytes,
        "routes": routes,
    })))
}

// ---------------------------------------------------------------------------
// audit log
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct AuditQuery {
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub action: Option<String>,
}

pub async fn audit_logs(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Query(q): Query<AuditQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    user.require_admin()?;
    let entries = AuditRepo::new(&state.db)
        .list(q.limit.unwrap_or(100), q.action.as_deref())
        .await?;
    Ok(Json(serde_json::json!({ "entries": entries })))
}

// ---------------------------------------------------------------------------
// settings
// ---------------------------------------------------------------------------

pub async fn get_settings(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> ApiResult<Json<serde_json::Value>> {
    user.require_admin()?;
    let repo = SettingsRepo::new(&state.db);
    let effective = repo.effective().await?;
    let cfg = state.config();

    Ok(Json(serde_json::json!({
        "settings": effective,
        // Deployment-level values are shown read-only: they come from the config
        // file, and letting the panel change them could lock an operator out.
        "deployment": {
            "listen": cfg.listen,
            "production": cfg.production,
            "psk_configured": distribute::psk_configured(&cfg.tunnel_psk),
            "agent_heartbeat_secs": cfg.agent.heartbeat_interval.as_secs(),
            "stale_after_secs": cfg.agent.stale_after_secs,
            "tls_ca_configured": cfg.agent_tls.ca_path.is_some(),
            "mtls_required": cfg.agent_tls.require_client_auth,
            "limits": cfg.limits,
        }
    })))
}

#[derive(Deserialize)]
pub struct UpdateSettingsRequest {
    #[serde(default)]
    pub node_stale_secs: Option<i64>,
    #[serde(default)]
    pub traffic_retention_days: Option<i64>,
    #[serde(default)]
    pub audit_retention_days: Option<i64>,
    #[serde(default)]
    pub stats_interval_secs: Option<i64>,
}

pub async fn update_settings(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    client: ClientAddr,
    Json(req): Json<UpdateSettingsRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    user.require_password_rotated()?;
    user.require_admin()?;
    let repo = SettingsRepo::new(&state.db);

    if let Some(v) = req.node_stale_secs {
        repo.set_i64_bounded(keys::NODE_STALE_SECS, v, 10, 3600)
            .await?;
    }
    if let Some(v) = req.traffic_retention_days {
        repo.set_i64_bounded(keys::TRAFFIC_RETENTION_DAYS, v, 1, 3650)
            .await?;
    }
    if let Some(v) = req.audit_retention_days {
        repo.set_i64_bounded(keys::AUDIT_RETENTION_DAYS, v, 1, 3650)
            .await?;
    }
    if let Some(v) = req.stats_interval_secs {
        repo.set_i64_bounded(keys::STATS_INTERVAL_SECS, v, 1, 300)
            .await?;
    }

    audit(
        &state,
        AuditEntry::new("settings.update")
            .actor(
                Some(user.user_id().to_string()),
                Some(user.username().to_string()),
            )
            .source_ip(client.to_audit_string()),
    )
    .await;

    Ok(Json(serde_json::json!({ "settings": repo.effective().await? })))
}

// ---------------------------------------------------------------------------
// users
// ---------------------------------------------------------------------------

pub async fn list_users(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> ApiResult<Json<serde_json::Value>> {
    user.require_admin()?;
    let users = UserRepo::new(&state.db).list().await?;
    Ok(Json(serde_json::json!({ "users": users })))
}

#[derive(Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
    #[serde(default = "default_role")]
    pub role: String,
}

fn default_role() -> String {
    "admin".into()
}

pub async fn create_user(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    client: ClientAddr,
    Json(req): Json<CreateUserRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    user.require_password_rotated()?;
    user.require_admin()?;

    let created = UserRepo::new(&state.db)
        .create(&req.username, &req.password, &req.role, true)
        .await?;

    audit(
        &state,
        AuditEntry::new("user.create")
            .actor(
                Some(user.user_id().to_string()),
                Some(user.username().to_string()),
            )
            .target("user", &created.id, Some(created.username.clone()))
            .source_ip(client.to_audit_string()),
    )
    .await;
    Ok(Json(serde_json::json!({ "user": created })))
}

pub async fn delete_user(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    client: ClientAddr,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    user.require_password_rotated()?;
    user.require_admin()?;

    if id == user.user_id() {
        return Err(ApiError::bad_request("you cannot delete your own account"));
    }
    UserRepo::new(&state.db).delete(&id).await?;

    audit(
        &state,
        AuditEntry::new("user.delete")
            .actor(
                Some(user.user_id().to_string()),
                Some(user.username().to_string()),
            )
            .target("user", &id, None)
            .source_ip(client.to_audit_string()),
    )
    .await;
    Ok(Json(serde_json::json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// agent endpoints
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct AgentRegisterResponse {
    pub node_id: String,
    pub node_name: String,
    pub group_id: String,
    pub group_name: String,
    pub role: String,
    pub heartbeat_interval_secs: u64,
    pub config: tunnel_common::model::AgentConfigBundle,
}

/// agent 注册：凭组令牌认证（机器记录由提取器按需创建），返回完整配置。
pub async fn agent_register(
    State(state): State<Arc<AppState>>,
    agent: AuthAgent,
) -> ApiResult<Json<AgentRegisterResponse>> {
    let cfg = state.config();
    let bundle = distribute::build_bundle(&state.db, &cfg, &agent.node.id).await?;

    tracing::info!(
        node = %agent.node.name,
        group = %agent.group.name,
        role = %agent.node.role,
        revision = bundle.revision,
        routes = bundle.routes.len(),
        "agent 已注册"
    );

    audit(
        &state,
        AuditEntry::new("agent.register")
            .target("node", &agent.node.id, Some(agent.node.name.clone()))
            .detail(serde_json::json!({
                "group": agent.group.name,
                "role": agent.node.role,
                "hostname": agent.node.hostname,
            })),
    )
    .await;
    state.broadcast(Event::ConfigChanged {
        entity: "groups".into(),
    });

    Ok(Json(AgentRegisterResponse {
        node_id: agent.node.id.clone(),
        node_name: agent.node.name.clone(),
        group_id: agent.group.id.clone(),
        group_name: agent.group.name.clone(),
        role: agent.node.role.clone(),
        heartbeat_interval_secs: cfg.agent.heartbeat_interval.as_secs(),
        config: bundle,
    }))
}

#[derive(Deserialize)]
pub struct ConfigQuery {
    /// Revision the agent already holds. When it matches, the response omits the
    /// bundle so an idle fleet does not re-serialise config every few seconds.
    #[serde(default)]
    pub known_revision: Option<u64>,
}

pub async fn agent_config(
    State(state): State<Arc<AppState>>,
    agent: AuthAgent,
    Query(q): Query<ConfigQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    let cfg = state.config();
    // 版本号取自**组**：组内所有机器共享一个版本，一次变更让整组同步重载。
    let current = agent.group.config_revision.max(0) as u64;

    if let Some(known) = q.known_revision {
        if known == current {
            return Ok(Json(serde_json::json!({
                "revision": current,
                "unchanged": true,
            })));
        }
    }

    let bundle = distribute::build_bundle(&state.db, &cfg, &agent.node.id).await?;
    Ok(Json(serde_json::json!({
        "revision": bundle.revision,
        "unchanged": false,
        "config": bundle,
    })))
}

/// Heartbeat: store telemetry in memory and persist the summary row.
pub async fn agent_heartbeat(
    State(state): State<Arc<AppState>>,
    agent: AuthAgent,
    Json(report): Json<tunnel_common::model::AgentReport>,
) -> ApiResult<Json<serde_json::Value>> {
    // agent 只能上报自己。少了这个检查，一台被攻破的机器就能伪造整个集群的遥测。
    //
    // 组令牌是多机共享的，所以这条检查在分组模型下更重要：拿到组令牌的机器只能
    // 冒充自己，不能冒充同组的其他机器。
    if report.node_id != agent.node.id {
        return Err(ApiError::Forbidden(
            "上报的 node_id 与已认证的机器不一致".into(),
        ));
    }

    let status = tunnel_storage::models::NodeStatusRow {
        node_id: agent.node.id.clone(),
        status: "online".into(),
        cpu_percent: report.host.cpu_percent as f64,
        memory_used_bytes: report.host.memory_used_bytes as i64,
        memory_total_bytes: report.host.memory_total_bytes as i64,
        uptime_secs: report.host.uptime_secs as i64,
        connections: report.connections as i64,
        rx_bytes: report.rx_bytes as i64,
        tx_bytes: report.tx_bytes as i64,
        rx_bps: report.rx_bps as i64,
        tx_bps: report.tx_bps as i64,
        tunnels_online: report
            .tunnels
            .iter()
            .filter(|t| t.state == tunnel_common::model::TunnelState::Online)
            .count() as i64,
        tunnels_total: report.tunnels.len() as i64,
        agent_version: Some(report.agent_version.clone()),
        config_revision: report.config_revision as i64,
        interfaces_json: serde_json::to_string(&report.interfaces).ok(),
        last_heartbeat_at: None,
    };

    NodeRepo::new(&state.db).record_heartbeat(status).await?;
    state.ingest_report(&agent.node.name, report);

    Ok(Json(serde_json::json!({
        "ok": true,
        // 让 agent 不必额外轮询就能发现配置变更。取组的版本号。
        "config_revision": agent.group.config_revision.max(0) as u64,
    })))
}

/// 返回 agent 安装脚本。
///
/// 一键对接命令里的 `curl` 指向这里，所以脚本必须**不需要认证**即可获取 —— 目标
/// 机器上还没有任何凭据。脚本本身不含密钥，令牌是作为命令行参数传入的。
pub async fn agent_install_script() -> impl axum::response::IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "text/x-shellscript; charset=utf-8")],
        include_str!("../../../../scripts/agent-install.sh"),
    )
}

// ---------------------------------------------------------------------------
// health
// ---------------------------------------------------------------------------

/// Unauthenticated liveness probe.
///
/// Deliberately minimal: no version, no counts, nothing that helps an
/// unauthenticated scanner profile the deployment.
pub async fn health(State(state): State<Arc<AppState>>) -> ApiResult<Json<serde_json::Value>> {
    state
        .db
        .ping()
        .await
        .map_err(|e| ApiError::internal(format!("database unreachable: {e}")))?;
    Ok(Json(serde_json::json!({ "status": "ok" })))
}

/// Suppress the unused-import warning for `Parts`, which the extractors use.
#[allow(dead_code)]
fn _parts_marker(_: &Parts) {}

#[cfg(test)]
mod tests {
    use super::*;
    use tunnel_common::model::TargetHealth;

    #[test]
    fn daily_bounds_follow_the_browser_calendar_day() {
        let (start, end) = daily_utc_bounds("2026-09-26", 480).unwrap();
        assert_eq!(start, "2026-09-25T16:00:00+00:00");
        assert_eq!(end, "2026-09-26T16:00:00+00:00");
        assert!(daily_utc_bounds("2026-02-30", 480).is_err());
        assert!(daily_utc_bounds("2026-09-26", 900).is_err());
    }

    fn health(addr: &str, tripped: bool, ok: u64, failed: u64, active: u64) -> TargetHealth {
        TargetHealth {
            addr: addr.into(),
            available: !tripped,
            tripped,
            active,
            consecutive_failures: if tripped { 3 } else { 0 },
            total_ok: ok,
            total_failed: failed,
        }
    }

    #[test]
    fn target_health_merges_counters_across_machines() {
        // 两台入口机各承载同一条线路，计数要求和而不是取其一。
        let merged = merge_target_health(&[
            vec![health("1.1.1.1:443", false, 10, 0, 2)],
            vec![health("1.1.1.1:443", false, 7, 1, 3)],
        ]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].total_ok, 17);
        assert_eq!(merged[0].total_failed, 1);
        assert_eq!(merged[0].active, 5);
        assert_eq!(merged[0].machines, 2);
        assert!(merged[0].available && !merged[0].tripped);
    }

    #[test]
    fn a_target_tripped_on_one_machine_is_reported_as_tripped() {
        // 取「全部熔断」会把一台机器的网络故障藏起来 —— 那恰恰是要被看见的。
        let merged = merge_target_health(&[
            vec![health("1.1.1.1:443", true, 0, 9, 0)],
            vec![health("1.1.1.1:443", false, 20, 0, 4)],
        ]);
        assert!(merged[0].tripped, "一台熔断就该报出来");
        assert_eq!(merged[0].tripped_on_machines, 1);
        assert_eq!(merged[0].machines, 2);
        // 另一台还在用，所以流量其实还在流。
        assert!(merged[0].available);
        // 连续失败取最大值：面板显示的是最坏的那台。
        assert_eq!(merged[0].consecutive_failures, 3);
    }

    #[test]
    fn a_target_down_everywhere_is_not_available() {
        let merged = merge_target_health(&[
            vec![health("1.1.1.1:443", true, 0, 9, 0)],
            vec![health("1.1.1.1:443", true, 0, 6, 0)],
        ]);
        assert!(merged[0].tripped);
        assert!(!merged[0].available, "全组熔断时不该显示为可用");
        assert_eq!(merged[0].tripped_on_machines, 2);
    }

    #[test]
    fn merged_targets_are_ordered_stably() {
        // HashMap 的遍历顺序每次都不同，不排序的话面板上的列表会一直跳。
        let machines = vec![vec![
            health("9.9.9.9:443", false, 1, 0, 0),
            health("1.1.1.1:443", false, 1, 0, 0),
            health("5.5.5.5:443", false, 1, 0, 0),
        ]];
        for _ in 0..8 {
            let merged = merge_target_health(&machines);
            let addrs: Vec<&str> = merged.iter().map(|t| t.addr.as_str()).collect();
            assert_eq!(addrs, vec!["1.1.1.1:443", "5.5.5.5:443", "9.9.9.9:443"]);
        }
    }

    #[test]
    fn machines_reporting_different_target_lists_are_all_included() {
        // 配置刚变更时，组内机器可能一时间跑着不同版本的目标列表。
        let merged = merge_target_health(&[
            vec![health("1.1.1.1:443", false, 5, 0, 1)],
            vec![
                health("1.1.1.1:443", false, 5, 0, 1),
                health("2.2.2.2:443", false, 3, 0, 2),
            ],
        ]);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].machines, 2);
        assert_eq!(merged[1].machines, 1, "只有一台在跑这个新目标");
    }

    #[test]
    fn no_targets_reported_merges_to_an_empty_list() {
        // 隧道线路的目标由出口拨号，入口侧报空列表 —— 不该变成一个假的目标。
        assert!(merge_target_health(&[vec![], vec![]]).is_empty());
        assert!(merge_target_health(&[]).is_empty());
    }
}
