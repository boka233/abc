//! HTTP API surface.
//!
//! # Route layout
//!
//! * `/api/auth/*` — login and session; `login` is the only unauthenticated
//!   mutating endpoint, and it is throttled per IP.
//! * `/api/*` — panel endpoints, requiring a session token.
//! * `/api/agent/*` — agent endpoints, requiring node id + enrolment token.
//!   Deliberately a separate namespace with separate credentials: an agent must
//!   never be able to call panel endpoints, and a panel session must never be
//!   able to impersonate a node.
//! * `/ws` — telemetry stream, token in the query string.
//! * `/health` — unauthenticated liveness probe, minimal by design.
//!
//! The SPA is served last as a fallback so client-side routes like `/routes`
//! resolve to `index.html` instead of a 404, without shadowing the API.

pub mod bulk;
pub mod download;
pub mod error;
pub mod groups;
pub mod handlers;
pub mod middleware;
pub mod provision;
pub mod ws;

use std::sync::Arc;

use axum::routing::{delete, get, patch, post, put};
use axum::Router;
use tower_http::compression::CompressionLayer;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

use crate::state::AppState;

pub fn router(state: Arc<AppState>) -> Router {
    let web_root = state.config().web_root.clone();

    let api = Router::new()
        // --- auth ---
        .route("/auth/login", post(handlers::login))
        .route("/auth/me", get(handlers::me))
        .route("/auth/password", post(handlers::change_password))
        // --- dashboard ---
        .route("/dashboard", get(handlers::dashboard))
        // --- 设备组：管理机器的主入口 ---
        .route(
            "/groups",
            get(groups::list_groups).post(groups::create_group),
        )
        .route(
            "/groups/{id}",
            get(groups::get_group)
                .patch(groups::update_group)
                .delete(groups::delete_group),
        )
        // 一键对接命令。GET 会轮换令牌（只有哈希，无法还原明文），响应里说明这点。
        .route("/groups/{id}/install-command", get(groups::install_command))
        .route("/groups/{id}/token", post(groups::rotate_group_token))
        .route(
            "/groups/{group_id}/machines/{node_id}",
            delete(groups::remove_machine),
        )
        // --- 机器：多为组详情页的补充操作 ---
        .route("/nodes", get(handlers::list_nodes).post(handlers::create_node))
        .route(
            "/nodes/{id}",
            get(handlers::get_node)
                .patch(handlers::update_node)
                .delete(handlers::delete_node),
        )
        .route("/nodes/{id}/config", get(handlers::node_config_preview))
        // --- endpoints ---
        .route(
            "/endpoints",
            get(handlers::list_endpoints).post(handlers::create_endpoint),
        )
        .route(
            "/endpoints/{id}",
            patch(handlers::update_endpoint).delete(handlers::delete_endpoint),
        )
        // --- routes ---
        .route("/routes", get(handlers::list_routes).post(handlers::create_route))
        .route(
            "/routes/{id}",
            get(handlers::get_route)
                .patch(handlers::update_route)
                .delete(handlers::delete_route),
        )
        .route("/routes/{id}/enabled", put(handlers::set_route_enabled))
        .route("/routes/{id}/restart", post(handlers::restart_route))
        // --- 批量操作。放在 /routes/{id} 之后注册，避免 "import" 被当成 id ---
        .route("/routes/import", post(bulk::import_routes))
        .route("/routes/export", get(bulk::export_routes))
        .route("/routes/bulk-delete", post(bulk::bulk_delete_routes))
        .route("/routes/bulk-enabled", post(bulk::bulk_set_enabled))
        .route("/routes/bulk-regroup", post(bulk::bulk_regroup_routes))
        // --- live views ---
        .route("/tunnels", get(handlers::list_tunnels))
        .route("/connections", get(handlers::list_connections))
        .route("/traffic", get(handlers::traffic))
        // --- administration ---
        .route("/logs/audit", get(handlers::audit_logs))
        .route(
            "/settings",
            get(handlers::get_settings).patch(handlers::update_settings),
        )
        .route("/users", get(handlers::list_users).post(handlers::create_user))
        .route("/users/{id}", delete(handlers::delete_user))
        // --- agent 接口，独立凭据（组令牌） ---
        .route("/agent/register", post(handlers::agent_register))
        .route("/agent/config", get(handlers::agent_config))
        .route("/agent/heartbeat", post(handlers::agent_heartbeat))
        .route("/agent/ca.pem", get(provision::ca_certificate))
        .route("/agent/certificate", post(provision::issue_certificate))
        // 一键对接脚本。刻意**不需要认证**：目标机器上还没有任何凭据，令牌是
        // 作为命令行参数传入的，脚本本身不含密钥。
        .route("/agent/install.sh", get(handlers::agent_install_script))
        // agent 二进制下载。同样不需要认证，理由见 download.rs 的模块文档：
        // 下载发生在注册之前，此时机器上还没有凭据，而把令牌放进 URL 会让它进入
        // shell 历史与代理日志。
        .route(
            "/agent/download/tunnel-agent-{arch}",
            get(download::download_agent),
        );

    let mut app = Router::new()
        .route("/health", get(handlers::health))
        .route("/ws", get(ws::ws_handler))
        .nest("/api", api)
        // Compression matters here: a fleet-wide node list with telemetry is
        // mostly repetitive JSON.
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http())
        // Same-origin by default. The panel is served by this process, so no
        // cross-origin access is needed and none is granted.
        .layer(CorsLayer::very_permissive().allow_credentials(false))
        .with_state(state);

    // SPA last, so it cannot shadow /api or /ws.
    if let Some(root) = web_root {
        if root.is_dir() {
            let index = root.join("index.html");
            let serve = tower_http::services::ServeDir::new(&root)
                .not_found_service(tower_http::services::ServeFile::new(index));
            app = app.fallback_service(serve);
        } else {
            tracing::warn!(
                path = %root.display(),
                "web_root does not exist; serving the API only"
            );
        }
    }

    app
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ControlConfig;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;
    use tunnel_storage::Database;

    async fn app() -> Router {
        let db = Database::connect_in_memory().await.unwrap();
        let mut cfg = ControlConfig::default();
        cfg.ensure_jwt_secret();
        router(AppState::new(db, cfg))
    }

    async fn get(app: &Router, uri: &str) -> StatusCode {
        app.clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn health_needs_no_authentication() {
        assert_eq!(get(&app().await, "/health").await, StatusCode::OK);
    }

    #[tokio::test]
    async fn panel_endpoints_require_a_session() {
        // Every one of these must refuse an anonymous caller.
        let app = app().await;
        for uri in [
            "/api/dashboard",
            "/api/nodes",
            "/api/endpoints",
            "/api/routes",
            "/api/tunnels",
            "/api/connections",
            "/api/traffic",
            "/api/logs/audit",
            "/api/settings",
            "/api/users",
            "/api/auth/me",
        ] {
            assert_eq!(
                get(&app, uri).await,
                StatusCode::UNAUTHORIZED,
                "{uri} is reachable without a token"
            );
        }
    }

    #[tokio::test]
    async fn agent_endpoints_reject_a_missing_token() {
        let app = app().await;
        assert_eq!(get(&app, "/api/agent/ca.pem").await, StatusCode::UNAUTHORIZED);
        assert_eq!(get(&app, "/api/agent/config").await, StatusCode::UNAUTHORIZED);

        let status = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/agent/register")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .status();
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let status = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/agent/certificate")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .status();
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn agent_endpoints_reject_a_panel_session_token() {
        // A panel token must not be usable as agent credentials.
        let db = Database::connect_in_memory().await.unwrap();
        let mut cfg = ControlConfig::default();
        cfg.ensure_jwt_secret();
        let state = AppState::new(db, cfg);
        let token = state.tokens.issue("u1", "admin", "admin").unwrap();
        let app = router(state);

        let status = app
            .oneshot(
                Request::builder()
                    .uri("/api/agent/config")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .status();
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn websocket_upgrade_requires_a_token() {
        // Without a token the handler rejects before any upgrade happens.
        let status = get(&app().await, "/ws").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn unknown_api_path_is_a_404_not_the_spa() {
        // With no web_root configured there is no fallback, and an unknown API
        // path must not be answered by something else.
        assert_eq!(get(&app().await, "/api/does-not-exist").await, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn login_is_reachable_without_authentication() {
        let app = app().await;
        let status = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"username":"nobody","password":"wrong-password"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap()
            .status();
        // Reachable, and correctly refuses bad credentials rather than 401ing on
        // the route itself.
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn the_agent_download_endpoint_needs_no_authentication() {
        // 一键对接在注册之前就要取二进制，此时机器上没有任何凭据。所以这里必须
        // 可匿名访问 —— 但没配目录时是 404，不是 401。
        let status = get(&app().await, "/api/agent/download/tunnel-agent-x86_64").await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "未配置 agent_binary_dir 时应为 404"
        );
    }

    #[tokio::test]
    async fn the_agent_download_endpoint_serves_a_real_binary() {
        let dir = std::env::temp_dir().join(format!("tunnel-dl-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(dir.join("tunnel-agent-x86_64"), b"fake-binary-contents").unwrap();

        let db = Database::connect_in_memory().await.unwrap();
        let mut cfg = ControlConfig::default();
        cfg.ensure_jwt_secret();
        cfg.agent_binary_dir = Some(dir.clone());
        let app = router(AppState::new(db, cfg));

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/agent/download/tunnel-agent-x86_64")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // 脚本靠这个头校验完整性，缺了它下载就等于无校验。
        let digest = response
            .headers()
            .get(super::download::SHA256_HEADER)
            .expect("缺少 sha256 响应头")
            .to_str()
            .unwrap()
            .to_string();
        assert_eq!(digest.len(), 64, "sha256 应为 64 位十六进制: {digest}");

        let body = axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap();
        assert_eq!(&body[..], b"fake-binary-contents");

        // 另一个架构没放文件，必须是 404 而不是拿到上面那个。
        assert_eq!(
            get(&app, "/api/agent/download/tunnel-agent-aarch64").await,
            StatusCode::NOT_FOUND
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn the_agent_download_endpoint_refuses_path_traversal() {
        // 真实地放一个敏感文件到目录外，再尝试用各种方式读它。
        let base = std::env::temp_dir().join(format!("tunnel-dl-evil-{}", std::process::id()));
        let bin_dir = base.join("agent-bin");
        let _ = std::fs::create_dir_all(&bin_dir);
        std::fs::write(base.join("secret.txt"), b"TOP-SECRET").unwrap();

        let db = Database::connect_in_memory().await.unwrap();
        let mut cfg = ControlConfig::default();
        cfg.ensure_jwt_secret();
        cfg.agent_binary_dir = Some(bin_dir.clone());
        let app = router(AppState::new(db, cfg));

        for evil in [
            "/api/agent/download/tunnel-agent-../secret.txt",
            "/api/agent/download/tunnel-agent-..%2fsecret.txt",
            "/api/agent/download/tunnel-agent-/etc/passwd",
            "/api/agent/download/tunnel-agent-x86",
            "/api/agent/download/tunnel-agent-",
        ] {
            let status = get(&app, evil).await;
            assert!(
                status == StatusCode::NOT_FOUND,
                "{evil} 应为 404，实际 {status}"
            );
        }

        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn an_empty_agent_binary_is_not_served() {
        // 构建中断或 rsync 失败会留下 0 字节文件。装上去是个跑不起来的 agent，
        // 不如直接 404 让脚本报「面板未提供二进制」。
        let dir = std::env::temp_dir().join(format!("tunnel-dl-empty-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(dir.join("tunnel-agent-x86_64"), b"").unwrap();

        let db = Database::connect_in_memory().await.unwrap();
        let mut cfg = ControlConfig::default();
        cfg.ensure_jwt_secret();
        cfg.agent_binary_dir = Some(dir.clone());
        let app = router(AppState::new(db, cfg));

        assert_eq!(
            get(&app, "/api/agent/download/tunnel-agent-x86_64").await,
            StatusCode::NOT_FOUND
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_missing_web_root_does_not_break_the_api() {
        let db = Database::connect_in_memory().await.unwrap();
        let mut cfg = ControlConfig::default();
        cfg.ensure_jwt_secret();
        cfg.web_root = Some(std::path::PathBuf::from("/nonexistent/web/root"));
        let app = router(AppState::new(db, cfg));
        assert_eq!(get(&app, "/health").await, StatusCode::OK);
    }
}
