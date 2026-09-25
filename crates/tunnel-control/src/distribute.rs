//! Config bundle assembly.
//!
//! Given a node id, build the [`AgentConfigBundle`] that node needs. The
//! interesting part is deciding *which* endpoints go in which list:
//!
//! * **`listen_endpoints`** — endpoints that live on this node, when it acts as
//!   an exit. It binds these.
//! * **`remote_endpoints`** — endpoints on the *peer* exits of routes this node
//!   enters. It dials these.
//!
//! A node that is both entry and exit gets both, and they must not be confused:
//! binding a peer's address fails, and dialling your own does nothing useful.
//!
//! The bundle is validated before it is handed out, so a configuration mistake
//! surfaces here rather than on the agent.

use tunnel_common::model::{AgentConfigBundle, Endpoint, Limits, Route};
use tunnel_common::{Result, Secret};
use tunnel_storage::nodes::{EndpointRepo, NodeRepo};
use tunnel_storage::routes::RouteRepo;
use tunnel_storage::Database;

use crate::api::provision;
use crate::config::ControlConfig;

/// 为一台机器装配配置 bundle。
///
/// # 一组多机下的装配规则
///
/// 线路引用的是**组**，所以组内每台机器拿到的线路列表是一样的。差异只在两处：
///
/// * `listen_endpoints` —— 只含**本机**的隧道地址。出口组里三台机器各自绑自己的
///   地址，把同组其他机器的地址塞进来会导致 bind 失败。
/// * `node` 里的 role —— 受组类型约束，由注册时钳制。
///
/// `Route.entry_node_id` / `exit_node_id` 填的是组 id，agent 用它和自己的组 id
/// 比对，决定本机该起监听还是该起出口。
pub async fn build_bundle(
    db: &Database,
    cfg: &ControlConfig,
    node_id: &str,
) -> Result<AgentConfigBundle> {
    let nodes = NodeRepo::new(db);
    let endpoints = EndpointRepo::new(db);
    let route_repo = RouteRepo::new(db);
    let groups = tunnel_storage::groups::DeviceGroupRepo::new(db);

    let node_row = nodes
        .get_row(node_id)
        .await
        .map_err(|e| tunnel_common::Error::NotFound(e.to_string()))?;
    let group_row = groups
        .get_row(&node_row.group_id)
        .await
        .map_err(|e| tunnel_common::Error::NotFound(e.to_string()))?;

    let mut node = node_row.to_model();
    // 下发给 agent 的 node.id 换成**组 id**，这样 agent 可以直接用
    // `route.entry_node_id == node.id` 判断本机是否该起监听，无需理解分组概念。
    let group_id = group_row.id.clone();
    node.id = group_id.clone();

    let entry_routes = route_repo
        .list_for_entry_group(&group_id)
        .await
        .map_err(to_common)?;
    let exit_routes = route_repo
        .list_for_exit_group(&group_id)
        .await
        .map_err(to_common)?;

    let mut routes: Vec<Route> = Vec::new();
    let mut remote_endpoints: Vec<Endpoint> = Vec::new();

    for row in &entry_routes {
        let endpoint_rows = route_repo.endpoints_for(&row.id).await.map_err(to_common)?;
        let endpoint_ids: Vec<String> = endpoint_rows.iter().map(|e| e.id.clone()).collect();
        for ep in &endpoint_rows {
            // 这些地址在对端出口机器上，本机去拨它们。出口组有多台机器时，这里会
            // 收到多个地址，隧道池在它们之间做负载与故障转移。
            if !remote_endpoints.iter().any(|e| e.id == ep.id) {
                let mut endpoint = ep.to_model();
                if provision::managed_marker(cfg, &ep.node_id).is_file() {
                    endpoint.tls_server_name = provision::server_name(&ep.node_id);
                }
                remote_endpoints.push(endpoint);
            }
        }
        routes.push(row.to_model(endpoint_ids));
    }

    for row in &exit_routes {
        // 入口组与出口组是同一个组时（自环），跳过已添加的，避免 agent 看到重复
        // 的 route id。
        if routes.iter().any(|r| r.id == row.id) {
            continue;
        }
        let endpoint_ids = route_repo
            .endpoint_ids_for(&row.id)
            .await
            .map_err(to_common)?;
        routes.push(row.to_model(endpoint_ids));
    }

    // 本机作为出口时要绑定的地址。只取**本机**的 —— 绑同组其他机器的地址会失败。
    let listen_endpoints: Vec<Endpoint> = if node.role.can_exit() {
        endpoints
            .list_for_node(node_id)
            .await
            .map_err(to_common)?
            .iter()
            .map(|e| e.to_model())
            .collect()
    } else {
        Vec::new()
    };

    let bundle = AgentConfigBundle {
        // 版本号取组的：组内所有机器共享，一次变更让整组同步重载。
        revision: group_row.config_revision.max(0) as u64,
        model_version: tunnel_common::MODEL_VERSION,
        node,
        listen_endpoints,
        remote_endpoints,
        routes,
        limits: cfg.limits.clone(),
        tls: cfg.agent_tls.to_model(),
        tunnel_psk: cfg.tunnel_psk.clone(),
        issued_at: Some(chrono::Utc::now()),
    };

    // 在这里就把配置错误拦下来，让它以可报告的形式暴露给管理员，而不是让每台
    // agent 各自拒绝一次推送。
    bundle.validate()?;
    Ok(bundle)
}

fn to_common(e: tunnel_storage::DbError) -> tunnel_common::Error {
    tunnel_common::Error::other(e.to_string())
}

/// Effective limits for a node, so the API can show what an agent will use.
pub fn effective_limits(cfg: &ControlConfig) -> Limits {
    cfg.limits.clone()
}

/// Is a PSK configured at all? Used by the API to warn an operator, without
/// revealing the value.
pub fn psk_configured(psk: &Option<Secret>) -> bool {
    psk.as_ref().map(|p| !p.is_empty()).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunnel_storage::models::{CreateEndpoint, CreateNode, CreateRoute};

    struct Fixture {
        db: Database,
        cfg: ControlConfig,
        entry_group: String,
        exit_group: String,
        /// 入口组里的机器 id，用于按机器装配 bundle。
        entry_node: String,
        exit_node: String,
        iepl_ep: String,
        public_ep: String,
    }

    async fn make_group(db: &Database, name: &str, kind: &str) -> String {
        tunnel_storage::groups::DeviceGroupRepo::new(db)
            .create(tunnel_storage::models::CreateDeviceGroup {
                name: name.into(),
                region: "test".into(),
                kind: kind.into(),
                note: None,
            })
            .await
            .unwrap()
            .0
            .id
    }

    async fn fixture() -> Fixture {
        let db = Database::connect_in_memory().await.unwrap();
        let nodes = NodeRepo::new(&db);
        let endpoints = EndpointRepo::new(&db);

        let entry_group = make_group(&db, "上海入口", "inbound").await;
        let exit_group = make_group(&db, "香港出口", "outbound").await;

        let entry = nodes
            .create(CreateNode {
                group_id: entry_group.clone(),
                name: "sh-01".into(),
                region: "cn-sh".into(),
                role: "entry".into(),
                public_address: Some("203.0.113.1".into()),
                management_address: None,
                note: None,
            })
            .await
            .unwrap();
        let exit = nodes
            .create(CreateNode {
                group_id: exit_group.clone(),
                name: "hk-01".into(),
                region: "hk".into(),
                role: "exit".into(),
                public_address: Some("203.0.113.9".into()),
                management_address: None,
                note: None,
            })
            .await
            .unwrap();

        let iepl = endpoints
            .create(CreateEndpoint {
                node_id: exit.id.clone(),
                name: "hk-iepl".into(),
                address: "10.20.0.2".into(),
                port: 5000,
                kind: "iepl".into(),
                priority: "primary".into(),
                interface: Some("eth1".into()),
                source_ip: Some("10.20.0.1".into()),
                tls_server_name: Some("exit.internal".into()),
            })
            .await
            .unwrap();
        let public = endpoints
            .create(CreateEndpoint {
                node_id: exit.id.clone(),
                name: "hk-public".into(),
                address: "203.0.113.9".into(),
                port: 5000,
                kind: "public".into(),
                priority: "backup".into(),
                interface: Some("eth0".into()),
                source_ip: None,
                tls_server_name: Some("exit.internal".into()),
            })
            .await
            .unwrap();

        let mut cfg = ControlConfig::default();
        cfg.ensure_jwt_secret();
        cfg.tunnel_psk = Some(Secret::new("a-shared-psk-of-sufficient-length"));

        Fixture {
            db,
            cfg,
            entry_group,
            exit_group,
            entry_node: entry.id,
            exit_node: exit.id,
            iepl_ep: iepl.id,
            public_ep: public.id,
        }
    }

    async fn add_route(f: &Fixture, eps: Vec<String>) -> String {
        RouteRepo::new(&f.db)
            .create(CreateRoute {
                name: "sh-hk".into(),
                mode: "tunnel".into(),
                entry_group_id: f.entry_group.clone(),
                listen_address: "0.0.0.0".into(),
                listen_port: Some(443),
                exit_group_id: Some(f.exit_group.clone()),
                target_host: "127.0.0.1".into(),
                target_port: 8443,
                targets: vec![],
                target_strategy: "random".into(),
                endpoint_ids: eps,
                tunnel_pool_size: 8,
                load_balance: "round_robin".into(),
                max_connections: 0,
                egress_source_ip: Some("203.0.113.9".into()),
                egress_interface: None,
            })
            .await
            .unwrap()
            .id
    }

    #[tokio::test]
    async fn entry_bundle_carries_remote_endpoints_to_dial() {
        let f = fixture().await;
        add_route(&f, vec![f.iepl_ep.clone(), f.public_ep.clone()]).await;

        let bundle = build_bundle(&f.db, &f.cfg, &f.entry_node).await.unwrap();
        assert_eq!(bundle.routes.len(), 1);
        assert_eq!(bundle.remote_endpoints.len(), 2);
        assert!(
            bundle.listen_endpoints.is_empty(),
            "an entry-only node must not be told to bind endpoints"
        );
        // Failover order must survive distribution.
        assert_eq!(bundle.remote_endpoints[0].name, "hk-iepl");
        assert_eq!(bundle.remote_endpoints[1].name, "hk-public");
    }

    #[tokio::test]
    async fn managed_exit_uses_its_issued_tls_name() {
        let mut f = fixture().await;
        add_route(&f, vec![f.iepl_ep.clone()]).await;
        let dir = std::env::temp_dir().join(format!("tunnel-bundle-{}", uuid::Uuid::new_v4()));
        f.cfg.database_path = dir.join("control.db");
        let marker = provision::managed_marker(&f.cfg, &f.exit_node);
        std::fs::create_dir_all(marker.parent().unwrap()).unwrap();
        std::fs::write(&marker, "managed").unwrap();
        let bundle = build_bundle(&f.db, &f.cfg, &f.entry_node).await.unwrap();
        assert_eq!(
            bundle.remote_endpoints[0].tls_server_name,
            provision::server_name(&f.exit_node)
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn exit_bundle_carries_listen_endpoints_to_bind() {
        let f = fixture().await;
        add_route(&f, vec![f.iepl_ep.clone()]).await;

        let bundle = build_bundle(&f.db, &f.cfg, &f.exit_node).await.unwrap();
        assert_eq!(bundle.routes.len(), 1);
        assert_eq!(
            bundle.listen_endpoints.len(),
            2,
            "the exit binds every endpoint on its own node"
        );
        assert!(
            bundle.remote_endpoints.is_empty(),
            "an exit-only node has nothing to dial"
        );
    }

    #[tokio::test]
    async fn bundle_is_valid_and_carries_the_psk() {
        let f = fixture().await;
        add_route(&f, vec![f.iepl_ep.clone()]).await;
        let bundle = build_bundle(&f.db, &f.cfg, &f.entry_node).await.unwrap();

        bundle.validate().unwrap();
        assert_eq!(bundle.model_version, tunnel_common::MODEL_VERSION);
        assert!(psk_configured(&bundle.tunnel_psk));
        assert!(bundle.issued_at.is_some());
    }

    #[tokio::test]
    async fn bundle_never_disables_tls_verification() {
        let f = fixture().await;
        add_route(&f, vec![f.iepl_ep.clone()]).await;
        let bundle = build_bundle(&f.db, &f.cfg, &f.entry_node).await.unwrap();
        assert!(
            !bundle.tls.insecure_skip_verify,
            "a distributed bundle must never turn off certificate verification"
        );
    }

    #[tokio::test]
    async fn revision_tracks_the_node_row() {
        let f = fixture().await;
        add_route(&f, vec![f.iepl_ep.clone()]).await;
        let before = build_bundle(&f.db, &f.cfg, &f.entry_node).await.unwrap();

        // 版本号在组上，所以递增的是组而非机器。
        tunnel_storage::groups::DeviceGroupRepo::new(&f.db)
            .bump_revision(&f.entry_group)
            .await
            .unwrap();
        let after = build_bundle(&f.db, &f.cfg, &f.entry_node).await.unwrap();
        assert!(
            after.revision > before.revision,
            "agents rely on the revision to detect changes"
        );
    }

    #[tokio::test]
    async fn egress_binding_reaches_the_exit() {
        // The IEPL-in / public-out behaviour depends entirely on this field
        // surviving into the exit's bundle.
        let f = fixture().await;
        add_route(&f, vec![f.iepl_ep.clone()]).await;
        let bundle = build_bundle(&f.db, &f.cfg, &f.exit_node).await.unwrap();
        let route = &bundle.routes[0];
        assert_eq!(
            route.egress_source_ip.map(|ip| ip.to_string()).as_deref(),
            Some("203.0.113.9")
        );
    }

    #[tokio::test]
    async fn source_ip_reaches_the_entry() {
        // The entry binds this to force the tunnel out of the IEPL NIC.
        let f = fixture().await;
        add_route(&f, vec![f.iepl_ep.clone()]).await;
        let bundle = build_bundle(&f.db, &f.cfg, &f.entry_node).await.unwrap();
        let ep = &bundle.remote_endpoints[0];
        assert_eq!(ep.source_ip.map(|ip| ip.to_string()).as_deref(), Some("10.20.0.1"));
        assert_eq!(ep.interface.as_deref(), Some("eth1"));
    }

    #[tokio::test]
    async fn node_with_no_routes_gets_an_empty_but_valid_bundle() {
        let f = fixture().await;
        let bundle = build_bundle(&f.db, &f.cfg, &f.entry_node).await.unwrap();
        assert!(bundle.routes.is_empty());
        bundle.validate().unwrap();
    }

    #[tokio::test]
    async fn every_machine_in_a_group_gets_the_same_routes() {
        // 一组多机的核心语义：组内每台机器拿到相同的线路列表。
        let f = fixture().await;
        add_route(&f, vec![f.iepl_ep.clone()]).await;

        // 往出口组再加一台机器。
        let hk2 = NodeRepo::new(&f.db)
            .register(&f.exit_group, "hk-02", Some("hk-02.internal".into()), "exit")
            .await
            .unwrap();

        let first = build_bundle(&f.db, &f.cfg, &f.exit_node).await.unwrap();
        let second = build_bundle(&f.db, &f.cfg, &hk2.id).await.unwrap();

        assert_eq!(first.routes.len(), second.routes.len());
        assert_eq!(first.routes[0].id, second.routes[0].id);
        // 版本号取自组，所以两台一致 —— 一次变更让整组同步重载。
        assert_eq!(first.revision, second.revision);
    }

    #[tokio::test]
    async fn a_machine_only_binds_its_own_endpoints() {
        // 绑同组其他机器的地址会 bind 失败，所以 listen_endpoints 必须按机器隔离。
        let f = fixture().await;
        add_route(&f, vec![f.iepl_ep.clone()]).await;

        let hk2 = NodeRepo::new(&f.db)
            .register(&f.exit_group, "hk-02", None, "exit")
            .await
            .unwrap();
        // 给第二台机器一个自己的隧道地址。
        EndpointRepo::new(&f.db)
            .create(CreateEndpoint {
                node_id: hk2.id.clone(),
                name: "hk2-iepl".into(),
                address: "10.20.0.3".into(),
                port: 5000,
                kind: "iepl".into(),
                priority: "primary".into(),
                interface: Some("eth1".into()),
                source_ip: None,
                tls_server_name: Some("exit.internal".into()),
            })
            .await
            .unwrap();

        let first = build_bundle(&f.db, &f.cfg, &f.exit_node).await.unwrap();
        let second = build_bundle(&f.db, &f.cfg, &hk2.id).await.unwrap();

        // 第一台绑自己的两个地址（iepl + public），不含 hk2 的。
        assert!(first.listen_endpoints.iter().all(|e| e.address != "10.20.0.3"));
        // 第二台只绑自己的那一个。
        assert_eq!(second.listen_endpoints.len(), 1);
        assert_eq!(second.listen_endpoints[0].address, "10.20.0.3");
    }

    #[tokio::test]
    async fn the_entry_dials_every_exit_machine_in_the_group() {
        // 出口组有多台机器时，入口应拿到所有机器的隧道地址，由隧道池在其间做
        // 负载与故障转移。
        let f = fixture().await;
        let hk2 = NodeRepo::new(&f.db)
            .register(&f.exit_group, "hk-02", None, "exit")
            .await
            .unwrap();
        let ep2 = EndpointRepo::new(&f.db)
            .create(CreateEndpoint {
                node_id: hk2.id.clone(),
                name: "hk2-iepl".into(),
                address: "10.20.0.3".into(),
                port: 5000,
                kind: "iepl".into(),
                priority: "primary".into(),
                interface: None,
                source_ip: None,
                tls_server_name: Some("exit.internal".into()),
            })
            .await
            .unwrap();

        // 一条线路同时引用两台机器的地址。
        add_route(&f, vec![f.iepl_ep.clone(), ep2.id.clone()]).await;

        let bundle = build_bundle(&f.db, &f.cfg, &f.entry_node).await.unwrap();
        assert_eq!(bundle.remote_endpoints.len(), 2);
        let addrs: Vec<&str> = bundle
            .remote_endpoints
            .iter()
            .map(|e| e.address.as_str())
            .collect();
        assert!(addrs.contains(&"10.20.0.2") && addrs.contains(&"10.20.0.3"));
    }

    #[tokio::test]
    async fn route_ends_reference_group_ids_not_machine_ids() {
        // agent 用 `route.entry_node_id == node.id` 判断本机是否该起监听，而
        // bundle 里的 node.id 被换成了组 id，两者必须对得上。
        let f = fixture().await;
        add_route(&f, vec![f.iepl_ep.clone()]).await;

        let bundle = build_bundle(&f.db, &f.cfg, &f.entry_node).await.unwrap();
        assert_eq!(
            bundle.node.id, f.entry_group,
            "bundle 里的 node.id 应是组 id"
        );
        assert_eq!(bundle.routes[0].entry_node_id, f.entry_group);
        assert_eq!(bundle.routes[0].exit_node_id, f.exit_group);
        // validate 会检查 entry 侧线路的 endpoint 可解析，这里必须通过。
        bundle.validate().unwrap();
    }

    #[tokio::test]
    async fn a_both_role_node_gets_one_copy_of_a_self_route() {
        // A node relaying to itself appears in both the entry and exit listings;
        // the route must not be duplicated in its bundle.
        let db = Database::connect_in_memory().await.unwrap();
        let nodes = NodeRepo::new(&db);
        let endpoints = EndpointRepo::new(&db);
        let g = make_group(&db, "自环组", "both").await;
        let node = nodes
            .create(CreateNode {
                group_id: g.clone(),
                name: "solo".into(),
                region: "x".into(),
                role: "both".into(),
                public_address: None,
                management_address: None,
                note: None,
            })
            .await
            .unwrap();
        let ep = endpoints
            .create(CreateEndpoint {
                node_id: node.id.clone(),
                name: "loop".into(),
                address: "127.0.0.1".into(),
                port: 5000,
                kind: "private".into(),
                priority: "primary".into(),
                interface: None,
                source_ip: None,
                tls_server_name: Some("localhost".into()),
            })
            .await
            .unwrap();
        RouteRepo::new(&db)
            .create(CreateRoute {
                name: "self".into(),
                mode: "tunnel".into(),
                entry_group_id: g.clone(),
                listen_address: "127.0.0.1".into(),
                listen_port: Some(4443),
                exit_group_id: Some(g.clone()),
                target_host: "127.0.0.1".into(),
                target_port: 9000,
                targets: vec![],
                target_strategy: "random".into(),
                endpoint_ids: vec![ep.id],
                tunnel_pool_size: 2,
                load_balance: "round_robin".into(),
                max_connections: 0,
                egress_source_ip: None,
                egress_interface: None,
            })
            .await
            .unwrap();

        let mut cfg = ControlConfig::default();
        cfg.ensure_jwt_secret();
        let bundle = build_bundle(&db, &cfg, &node.id).await.unwrap();
        assert_eq!(bundle.routes.len(), 1, "route duplicated in the bundle");
        assert_eq!(bundle.listen_endpoints.len(), 1);
        assert_eq!(bundle.remote_endpoints.len(), 1);
        bundle.validate().unwrap();
    }

    #[tokio::test]
    async fn unknown_node_is_not_found() {
        let f = fixture().await;
        let err = build_bundle(&f.db, &f.cfg, "no-such-node").await.unwrap_err();
        assert!(matches!(err, tunnel_common::Error::NotFound(_)), "{err:?}");
    }

    #[tokio::test]
    async fn invalid_limits_are_caught_before_distribution() {
        // A bad limits block must fail here, not on every agent.
        let f = fixture().await;
        add_route(&f, vec![f.iepl_ep.clone()]).await;
        let mut cfg = f.cfg.clone();
        cfg.limits.stream_window = 128;
        cfg.limits.max_frame_payload = 65535;

        let err = build_bundle(&f.db, &cfg, &f.entry_node).await.unwrap_err();
        assert!(matches!(err, tunnel_common::Error::Config(_)), "{err:?}");
    }

    #[tokio::test]
    async fn psk_detection_does_not_require_exposing_it() {
        assert!(!psk_configured(&None));
        assert!(!psk_configured(&Some(Secret::new(""))));
        assert!(psk_configured(&Some(Secret::new("x"))));
    }
}
