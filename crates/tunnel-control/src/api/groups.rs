//! 设备组接口，含一键对接命令。
//!
//! # 一键对接为什么是这个形态
//!
//! 面板生成一条自带令牌的 shell 命令，管理员复制到服务器执行即可。原先的流程是
//! 「建节点 → 手抄 token → 登服务器 → 手改 config.toml」，四步里有三步是人工
//! 搬运，而且每台机器都要重复一遍。
//!
//! 令牌挂在组上，所以同一条命令可以在多台机器上跑，它们自动加入同一个组并领到
//! 相同的线路配置。

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use tunnel_storage::groups::DeviceGroupRepo;
use tunnel_storage::models::{AuditEntry, CreateDeviceGroup, UpdateDeviceGroup};
use tunnel_storage::nodes::{EndpointRepo, NodeRepo};
use tunnel_storage::routes::RouteRepo;

use crate::api::error::{ApiError, ApiResult};
use crate::api::handlers::{audit, install_command_for};
use crate::api::middleware::{AuthUser, ClientAddr};
use crate::state::{AppState, Event};

pub async fn list_groups(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
) -> ApiResult<Json<serde_json::Value>> {
    let groups = DeviceGroupRepo::new(&state.db).list().await?;
    let cfg = state.config();
    let stale = std::time::Duration::from_secs(cfg.agent.stale_after_secs);
    let nodes = NodeRepo::new(&state.db);

    // 用内存里的实时遥测覆盖数据库的在线数：心跳落库有延迟，面板应显示当下状态。
    let mut out = Vec::with_capacity(groups.len());
    for group in groups {
        let members = nodes.list_for_group(&group.id).await?;
        let online = members
            .iter()
            .filter(|m| {
                state
                    .report_for(&m.id)
                    .map(|r| r.age() <= stale)
                    .unwrap_or(false)
            })
            .count() as i64;
        let (rx_bps, tx_bps, connections) = members.iter().fold((0u64, 0u64, 0u32), |acc, m| {
            match state.report_for(&m.id).filter(|r| r.age() <= stale) {
                Some(live) => (
                    acc.0 + live.report.rx_bps,
                    acc.1 + live.report.tx_bps,
                    acc.2 + live.report.connections,
                ),
                None => acc,
            }
        });

        let mut value = serde_json::to_value(&group).unwrap_or_default();
        if let Some(obj) = value.as_object_mut() {
            obj.insert("nodes_online".into(), serde_json::json!(online));
            obj.insert("rx_bps".into(), serde_json::json!(rx_bps));
            obj.insert("tx_bps".into(), serde_json::json!(tx_bps));
            obj.insert("connections".into(), serde_json::json!(connections));
        }
        out.push(value);
    }

    Ok(Json(serde_json::json!({ "groups": out })))
}

/// 组详情：成员机器（含探针数据）、隧道地址、相关线路。
///
/// 隧道地址收在这里而不是单独占一级导航 —— 它是出口机器的属性，不是和「设备组」
/// 「线路」平级的概念。
pub async fn get_group(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let group = DeviceGroupRepo::new(&state.db).get(&id).await?;
    let members = NodeRepo::new(&state.db).list_for_group(&id).await?;
    let cfg = state.config();
    let stale = std::time::Duration::from_secs(cfg.agent.stale_after_secs);

    // 逐台机器叠加实时遥测与它自己的隧道地址。
    let endpoints_repo = EndpointRepo::new(&state.db);
    let stats_repo = tunnel_storage::stats::StatsRepo::new(&state.db);
    let mut machines = Vec::with_capacity(members.len());
    for m in &members {
        let endpoints = endpoints_repo.list_for_node(&m.id).await?;
        let (total_rx_bytes, total_tx_bytes) = stats_repo.node_lifetime_totals(&m.id).await?;
        let live = state.report_for(&m.id).filter(|r| r.age() <= stale);

        let mut value = serde_json::to_value(m).unwrap_or_default();
        if let Some(obj) = value.as_object_mut() {
            obj.insert("total_rx_bytes".into(), serde_json::json!(total_rx_bytes));
            obj.insert("total_tx_bytes".into(), serde_json::json!(total_tx_bytes));
            obj.insert(
                "endpoints".into(),
                serde_json::to_value(
                    endpoints.iter().map(|e| e.to_model()).collect::<Vec<_>>(),
                )
                .unwrap_or_default(),
            );
            if let Some(live) = live {
                let r = &live.report;
                obj.insert("status".into(), serde_json::json!("online"));
                obj.insert("connections".into(), serde_json::json!(r.connections));
                obj.insert("rx_bps".into(), serde_json::json!(r.rx_bps));
                obj.insert("tx_bps".into(), serde_json::json!(r.tx_bps));
                obj.insert("rx_bytes".into(), serde_json::json!(r.rx_bytes));
                obj.insert("tx_bytes".into(), serde_json::json!(r.tx_bytes));
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
                obj.insert("host_uptime_secs".into(), serde_json::json!(r.host.host_uptime_secs));
                obj.insert("disk_used_bytes".into(), serde_json::json!(r.host.disk_used_bytes));
                obj.insert("disk_total_bytes".into(), serde_json::json!(r.host.disk_total_bytes));
                obj.insert(
                    "interfaces".into(),
                    serde_json::to_value(&r.interfaces).unwrap_or_default(),
                );
                obj.insert(
                    "tunnels".into(),
                    serde_json::to_value(&r.tunnels).unwrap_or_default(),
                );
                obj.insert(
                    "agent_version".into(),
                    serde_json::json!(r.agent_version.clone()),
                );
                obj.insert(
                    "report_age_secs".into(),
                    serde_json::json!(live.age().as_secs()),
                );
            }
        }
        machines.push(value);
    }

    attach_regions(&state, &members, &mut machines).await?;

    let routes = RouteRepo::new(&state.db).list().await?;
    let related: Vec<_> = routes
        .iter()
        .filter(|r| r.entry_group_id == id || r.exit_group_id == id)
        .collect();

    Ok(Json(serde_json::json!({
        "group": group,
        "machines": machines,
        "routes": related,
    })))
}

/// 给每台机器补上 `v4_region` / `v6_region`（ISO 国家代码，如 `HK`）。
///
/// 地址的选取用与心跳里触发查询**同一个**函数，保证查的和显示的是同一个 IP。
/// 全部机器的国家代码一次查询取出，不是每台一次。
///
/// 缓存里还没有的（首次心跳刚触发、查询还在进行，或查询失败）字段为 null，
/// 面板据此显示「识别中」或「—」。
async fn attach_regions(
    state: &AppState,
    members: &[tunnel_storage::models::NodeDto],
    machines: &mut [serde_json::Value],
) -> ApiResult<()> {
    let stale = std::time::Duration::from_secs(state.config().agent.stale_after_secs);

    // 每台机器的 (v4, v6) 候选。
    let per_machine: Vec<(Option<String>, Option<String>)> = members
        .iter()
        .map(|m| {
            let observed = m.observed_ip.as_deref().and_then(|s| s.parse().ok());
            // 优先用实时上报里的网卡列表（类型化的），拿不到时再解析存储的 JSON。
            let interfaces: Vec<tunnel_common::model::InterfaceInfo> = state
                .report_for(&m.id)
                .filter(|r| r.age() <= stale)
                .map(|r| r.report.interfaces.clone())
                .or_else(|| serde_json::from_value(m.interfaces.clone()).ok())
                .unwrap_or_default();
            let ips = crate::api::handlers::candidate_public_ips(
                observed,
                m.public_address.as_deref(),
                m.management_address.as_deref(),
                &interfaces,
            );
            let v4 = ips.iter().find(|ip| ip.is_ipv4()).map(|ip| ip.to_string());
            let v6 = ips.iter().find(|ip| ip.is_ipv6()).map(|ip| ip.to_string());
            (v4, v6)
        })
        .collect();

    let wanted: Vec<String> = per_machine
        .iter()
        .flat_map(|(a, b)| a.iter().chain(b.iter()).cloned())
        .collect();
    let countries = tunnel_storage::geo::GeoRepo::new(&state.db)
        .countries_for(&wanted)
        .await?;

    for (value, (v4, v6)) in machines.iter_mut().zip(per_machine) {
        if let Some(obj) = value.as_object_mut() {
            let region = |ip: &Option<String>| {
                ip.as_ref()
                    .and_then(|ip| countries.get(ip))
                    .map(|c| serde_json::json!(c))
                    .unwrap_or(serde_json::Value::Null)
            };
            obj.insert("v4_region".into(), region(&v4));
            obj.insert("v6_region".into(), region(&v6));
            // 同时下发选中的地址：面板直接显示它，不必再用自己的规则重算一遍 ——
            // 两边规则一旦漂移，显示的 IP 与地区就会对不上。
            obj.insert("public_v4".into(), serde_json::json!(v4));
            obj.insert("public_v6".into(), serde_json::json!(v6));
        }
    }
    Ok(())
}

pub async fn create_group(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    client: ClientAddr,
    Json(input): Json<CreateDeviceGroup>,
) -> ApiResult<Json<serde_json::Value>> {
    user.require_password_rotated()?;
    user.require_admin()?;

    let name = input.name.clone();
    let (group, token) = DeviceGroupRepo::new(&state.db).create(input).await?;

    audit(
        &state,
        AuditEntry::new("group.create")
            .actor(
                Some(user.user_id().to_string()),
                Some(user.username().to_string()),
            )
            .target("group", &group.id, Some(name))
            .source_ip(client.to_audit_string()),
    )
    .await;
    state.broadcast(Event::ConfigChanged {
        entity: "groups".into(),
    });

    // 令牌只在此处返回一次；库里只有哈希。顺手把一键对接命令一起给出，省掉用户
    // 自己拼接的步骤。
    Ok(Json(serde_json::json!({
        "group": group,
        "enroll_token": token,
        "install_command": install_command_for(&state, &token),
        "note": "请立即保存该令牌。库中只存哈希，无法再次查看，只能轮换。"
    })))
}

pub async fn update_group(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    client: ClientAddr,
    Path(id): Path<String>,
    Json(input): Json<UpdateDeviceGroup>,
) -> ApiResult<Json<serde_json::Value>> {
    user.require_password_rotated()?;
    user.require_admin()?;

    let group = DeviceGroupRepo::new(&state.db).update(&id, input).await?;
    audit(
        &state,
        AuditEntry::new("group.update")
            .actor(
                Some(user.user_id().to_string()),
                Some(user.username().to_string()),
            )
            .target("group", &id, Some(group.name.clone()))
            .source_ip(client.to_audit_string()),
    )
    .await;
    state.broadcast(Event::ConfigChanged {
        entity: "groups".into(),
    });
    Ok(Json(serde_json::json!({ "group": group })))
}

pub async fn delete_group(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    client: ClientAddr,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    user.require_password_rotated()?;
    user.require_admin()?;

    let group = DeviceGroupRepo::new(&state.db).get(&id).await?;
    // 先取成员，删完后要清掉它们的内存遥测。
    let members = NodeRepo::new(&state.db).list_for_group(&id).await?;
    DeviceGroupRepo::new(&state.db).delete(&id).await?;
    for m in members {
        state.drop_report(&m.id);
    }

    audit(
        &state,
        AuditEntry::new("group.delete")
            .actor(
                Some(user.user_id().to_string()),
                Some(user.username().to_string()),
            )
            .target("group", &id, Some(group.name))
            .source_ip(client.to_audit_string()),
    )
    .await;
    state.broadcast(Event::ConfigChanged {
        entity: "groups".into(),
    });
    Ok(Json(serde_json::json!({ "ok": true })))
}

#[derive(Serialize)]
pub struct InstallCommandResponse {
    pub command: String,
    /// 面板推断出的、agent 应当连接的地址。
    pub panel_url: String,
    /// 当推断出的地址是回环地址时给出警告 —— 其他主机连不上它。
    pub warning: Option<String>,
}

/// 返回该组的一键对接命令。
///
/// 每次调用都会签发一个新令牌，旧机器继续使用自己的令牌。
pub async fn install_command(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    client: ClientAddr,
    Path(id): Path<String>,
) -> ApiResult<Json<InstallCommandResponse>> {
    user.require_admin()?;

    // 只存哈希，无法取回旧命令；新令牌与旧令牌并行有效。
    let token = DeviceGroupRepo::new(&state.db).issue_token(&id).await?;
    let group = DeviceGroupRepo::new(&state.db).get(&id).await?;

    audit(
        &state,
        AuditEntry::new("group.install_command")
            .actor(
                Some(user.user_id().to_string()),
                Some(user.username().to_string()),
            )
            .target("group", &id, Some(group.name))
            .source_ip(client.to_audit_string()),
    )
    .await;

    let panel_url = state.panel_url();
    let warning = if panel_url.contains("127.0.0.1")
        || panel_url.contains("localhost")
        || panel_url.contains("0.0.0.0")
    {
        Some(format!(
            "面板地址被推断为 {panel_url}，其他主机无法连接。请在控制面配置中设置 \
             public_url，或手工把命令里的地址改成本机的对外地址。"
        ))
    } else {
        None
    };

    Ok(Json(InstallCommandResponse {
        command: install_command_for(&state, &token),
        panel_url,
        warning,
    }))
}

#[derive(Deserialize)]
pub struct RotateResponse {}

/// 显式轮换组令牌，旧令牌立即失效。
pub async fn rotate_group_token(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    client: ClientAddr,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    user.require_password_rotated()?;
    user.require_admin()?;

    let token = DeviceGroupRepo::new(&state.db).rotate_token(&id).await?;
    audit(
        &state,
        AuditEntry::new("group.rotate_token")
            .actor(
                Some(user.user_id().to_string()),
                Some(user.username().to_string()),
            )
            .target("group", &id, None)
            .source_ip(client.to_audit_string()),
    )
    .await;

    Ok(Json(serde_json::json!({
        "enroll_token": token,
        "install_command": install_command_for(&state, &token),
        "note": "组内所有旧令牌已失效；请更新每台机器配置中的 enroll_token 并重启 agent。"
    })))
}

/// 从组内移除一台机器。
///
/// 线路引用的是组，所以移除单台机器不影响线路 —— 组内其余机器继续承载。
pub async fn remove_machine(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    client: ClientAddr,
    Path((group_id, node_id)): Path<(String, String)>,
) -> ApiResult<Json<serde_json::Value>> {
    user.require_password_rotated()?;
    user.require_admin()?;

    let nodes = NodeRepo::new(&state.db);
    let node = nodes.get(&node_id).await?;
    if node.group_id != group_id {
        return Err(ApiError::bad_request("该机器不属于这个设备组"));
    }
    nodes.delete(&node_id).await?;
    state.drop_report(&node_id);

    audit(
        &state,
        AuditEntry::new("group.remove_machine")
            .actor(
                Some(user.user_id().to_string()),
                Some(user.username().to_string()),
            )
            .target("node", &node_id, Some(node.name))
            .source_ip(client.to_audit_string()),
    )
    .await;
    state.broadcast(Event::ConfigChanged {
        entity: "groups".into(),
    });

    Ok(Json(serde_json::json!({
        "ok": true,
        "note": "该机器的隧道地址已随之删除；组内其余机器继续承载相关线路。"
    })))
}
