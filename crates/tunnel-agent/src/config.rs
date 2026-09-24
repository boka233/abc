//! Agent configuration: the local file, plus the last-known-good cache.
//!
//! # Two kinds of configuration
//!
//! 1. **Local file** (`/etc/tunnel-agent/config.toml`) — identity, control-plane
//!    URL, credentials, TLS paths, logging. Operator-owned, never overwritten by
//!    the agent.
//! 2. **Distributed bundle** — routes, endpoints, limits, PSK. Comes from the
//!    control plane and is cached on disk.
//!
//! # Why the cache exists
//!
//! The requirement is explicit and it is the right one: a control-plane outage
//! must not take the data plane down. On boot the agent loads its cached bundle
//! and starts serving *before* it has talked to the control plane. If the control
//! plane is unreachable, it keeps serving that configuration indefinitely.
//!
//! # Why the cache is written atomically
//!
//! A bundle is written to a temporary file in the same directory, then renamed
//! over the target. `rename` within a filesystem is atomic, so a crash or power
//! loss mid-write leaves either the old complete file or the new complete file —
//! never a truncated one. A truncated cache would mean an agent that cannot
//! start without the control plane, which defeats the entire point.
//!
//! Only bundles that validated *and applied cleanly* are cached, so the cache
//! cannot hold a configuration known to be broken.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tunnel_common::logging::LogConfig;
use tunnel_common::model::{AgentConfigBundle, NodeRole, TlsConfig};
use tunnel_common::{Error, Result, Secret};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentConfig {
    /// 设备组注册令牌。同一个令牌可用于组内多台机器 —— 这是一键对接的前提。
    /// 从不写入日志。
    pub enroll_token: Secret,
    /// 本机在组内的名称。为空时用主机名。
    ///
    /// 组内按名称唯一：同名重复注册会更新原记录而不是新增一台，所以重装 agent
    /// 不会在面板上堆出重复条目。
    pub node_name: String,
    /// Control-plane base URL, e.g. `http://10.0.0.5:8080`.
    pub control_url: String,
    /// Role override. `None` uses the role the control plane reports.
    pub role: Option<NodeRole>,
    /// Where the last-known-good bundle is cached.
    pub cache_path: PathBuf,
    /// TLS material for the tunnel. Local, because private keys must not transit
    /// the control plane.
    pub tls: TlsConfig,
    /// Fallback PSK for when the control plane has never been reached. Normally
    /// the distributed bundle supplies it.
    pub tunnel_psk: Option<Secret>,
    #[serde(with = "humantime_serde")]
    pub heartbeat_interval: Duration,
    #[serde(with = "humantime_serde")]
    pub config_poll_interval: Duration,
    #[serde(with = "humantime_serde")]
    pub control_timeout: Duration,
    /// Live connections reported per heartbeat. Bounded so a busy node does not
    /// post a multi-megabyte report.
    pub connection_sample_limit: usize,
    /// Run without a control plane, using only a local bundle file.
    pub standalone: bool,
    /// Bundle to load in standalone mode.
    pub standalone_config: Option<PathBuf>,
    pub log: LogConfig,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            enroll_token: Secret::new(""),
            node_name: String::new(),
            control_url: "http://127.0.0.1:8080".into(),
            role: None,
            cache_path: PathBuf::from("/var/lib/tunnel-agent/last-known-good.json"),
            tls: TlsConfig::default(),
            tunnel_psk: None,
            heartbeat_interval: Duration::from_secs(10),
            config_poll_interval: Duration::from_secs(30),
            control_timeout: Duration::from_secs(10),
            connection_sample_limit: 200,
            standalone: false,
            standalone_config: None,
            log: LogConfig::default(),
        }
    }
}

impl AgentConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::config(format!("cannot read config {}: {e}", path.display())))?;
        let cfg: AgentConfig = toml::from_str(&text)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        if self.standalone {
            if self.standalone_config.is_none() {
                return Err(Error::config(
                    "standalone mode requires standalone_config to point at a bundle file",
                ));
            }
        } else {
            // node_id 不再需要：agent 凭组令牌注册，控制面按机器名登记。
            if self.enroll_token.is_empty() {
                return Err(Error::config(
                    "enroll_token 必填 —— 请用面板上设备组的一键对接命令生成配置",
                ));
            }
            if !self.control_url.starts_with("http://") && !self.control_url.starts_with("https://")
            {
                return Err(Error::config(
                    "control_url must start with http:// or https://",
                ));
            }
        }
        if self.heartbeat_interval.as_secs() == 0 {
            return Err(Error::config("heartbeat_interval must be >= 1s"));
        }
        if self.config_poll_interval.as_secs() == 0 {
            return Err(Error::config("config_poll_interval must be >= 1s"));
        }
        if self.connection_sample_limit > 5000 {
            return Err(Error::config(
                "connection_sample_limit must be <= 5000; larger reports waste \
                 bandwidth and are unreadable in the panel",
            ));
        }
        Ok(())
    }

    /// Effective role: the local override wins, so an operator can demote a node
    /// without waiting for a control-plane change.
    pub fn effective_role(&self, from_control: NodeRole) -> NodeRole {
        self.role.unwrap_or(from_control)
    }

    /// 本机上报的名称。配置为空时回落到主机名。
    ///
    /// 一键对接脚本会把主机名写进配置，所以这里的回落只在手写配置时用到。
    pub fn effective_node_name(&self) -> String {
        let configured = self.node_name.trim();
        if !configured.is_empty() {
            return configured.to_string();
        }
        hostname().unwrap_or_else(|| "unnamed".to_string())
    }

    pub fn sample_toml() -> String {
        let cfg = AgentConfig {
            enroll_token: Secret::new("粘贴面板上设备组的注册令牌"),
            node_name: "本机在组内的名称，留空则用主机名".into(),
            control_url: "http://10.0.0.5:8080".into(),
            tls: TlsConfig {
                cert_path: Some("/etc/tunnel/exit.pem".into()),
                key_path: Some("/etc/tunnel/exit.key".into()),
                ca_path: Some("/etc/tunnel/ca.pem".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        toml::to_string_pretty(&cfg).unwrap_or_default()
    }
}

/// 读取本机主机名。
///
/// 不引入额外依赖：Linux 上读 `/etc/hostname`，失败则退回环境变量。拿不到时调用方
/// 用占位名 —— 让 agent 因为一个展示字段而无法上线是不值得的。
pub fn hostname() -> Option<String> {
    if let Ok(text) = std::fs::read_to_string("/proc/sys/kernel/hostname") {
        let trimmed = text.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    if let Ok(text) = std::fs::read_to_string("/etc/hostname") {
        let trimmed = text.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    // Windows 与部分容器环境走这里，便于本地开发。
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .ok()
        .filter(|s| !s.trim().is_empty())
}

/// On-disk cache of the last bundle that applied cleanly.
pub struct ConfigCache {
    path: PathBuf,
}

impl ConfigCache {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// 缓存文件路径。诊断用 —— 排查「agent 从哪个文件恢复的配置」时需要它。
    ///
    /// 目前没有调用方，但保留：它是 ConfigCache 唯一的路径出口，删掉之后下次要打印
    /// 缓存位置就得重新把字段暴露出去。（不用 `reason =` 是因为 workspace 的
    /// rust-version 是 1.80，那个语法要 1.81+。）
    #[allow(dead_code)]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Load the cached bundle.
    ///
    /// A missing file is `Ok(None)` — a first boot, not an error. A *corrupt*
    /// file is also `Ok(None)` with a warning: refusing to start because of an
    /// unreadable cache would be worse than starting empty and waiting for the
    /// control plane.
    pub fn load(&self) -> Option<AgentConfigBundle> {
        let text = match std::fs::read_to_string(&self.path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::info!(
                    path = %self.path.display(),
                    "no cached configuration; waiting for the control plane"
                );
                return None;
            }
            Err(e) => {
                tracing::warn!(
                    path = %self.path.display(),
                    error = %e,
                    "cannot read the cached configuration"
                );
                return None;
            }
        };

        match serde_json::from_str::<AgentConfigBundle>(&text) {
            Ok(bundle) => match bundle.validate() {
                Ok(()) => {
                    tracing::info!(
                        revision = bundle.revision,
                        routes = bundle.routes.len(),
                        "loaded cached configuration"
                    );
                    Some(bundle)
                }
                Err(e) => {
                    // Can happen after an upgrade tightens validation.
                    tracing::warn!(error = %e, "cached configuration is no longer valid");
                    None
                }
            },
            Err(e) => {
                tracing::warn!(error = %e, "cached configuration is corrupt");
                None
            }
        }
    }

    /// Write the bundle atomically.
    pub fn store(&self, bundle: &AgentConfigBundle) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                Error::config(format!(
                    "cannot create cache directory {}: {e}",
                    parent.display()
                ))
            })?;
        }

        let json = serde_json::to_string_pretty(bundle)?;

        // Temp file in the *same* directory: rename is only atomic within one
        // filesystem, and /tmp is often a different mount.
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, json.as_bytes()).map_err(|e| {
            Error::config(format!("cannot write {}: {e}", tmp.display()))
        })?;

        // The cache contains the tunnel PSK, so keep it owner-only.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }

        std::fs::rename(&tmp, &self.path).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            Error::config(format!(
                "cannot replace {}: {e}",
                self.path.display()
            ))
        })?;

        tracing::debug!(
            revision = bundle.revision,
            path = %self.path.display(),
            "cached configuration"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunnel_common::model::{Endpoint, EndpointKind, EndpointPriority, Limits, Node, Route};

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tunnel-agent-test-{}-{}",
            name,
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn bundle(revision: u64) -> AgentConfigBundle {
        AgentConfigBundle {
            revision,
            model_version: tunnel_common::MODEL_VERSION,
            node: Node {
                id: "n1".into(),
                name: "sh-01".into(),
                region: "cn".into(),
                role: NodeRole::Entry,
                public_address: None,
                management_address: None,
                agent_version: None,
                note: None,
            },
            listen_endpoints: vec![],
            remote_endpoints: vec![Endpoint {
                id: "e1".into(),
                node_id: "n2".into(),
                name: "hk-iepl".into(),
                address: "10.20.0.2".into(),
                port: 5000,
                kind: EndpointKind::Iepl,
                priority: EndpointPriority::Primary,
                interface: Some("eth1".into()),
                source_ip: None,
                tls_server_name: Some("exit.internal".into()),
                enabled: true,
            }],
            routes: vec![Route {
                id: "r1".into(),
                name: "sh-hk".into(),
                mode: Default::default(),
                entry_node_id: "n1".into(),
                listen_address: "0.0.0.0".into(),
                listen_port: 443,
                exit_node_id: "n2".into(),
                target_host: "127.0.0.1".into(),
                target_port: 8443,
                targets: vec![],
                target_strategy: Default::default(),
                endpoint_ids: vec!["e1".into()],
                tunnel_pool_size: 8,
                load_balance: Default::default(),
                max_connections: 0,
                egress_source_ip: None,
                egress_interface: None,
                enabled: true,
            }],
            limits: Limits::default(),
            tls: TlsConfig::default(),
            tunnel_psk: Some(Secret::new("a-shared-psk")),
            issued_at: None,
        }
    }

    fn valid_config() -> AgentConfig {
        AgentConfig {
            enroll_token: Secret::new("a-group-enrol-token"),
            node_name: "sh-01".into(),
            control_url: "http://10.0.0.5:8080".into(),
            ..Default::default()
        }
    }

    #[test]
    fn valid_config_passes() {
        valid_config().validate().unwrap();
    }

    #[test]
    fn a_missing_enrol_token_is_rejected() {
        // 令牌是唯一必填的凭据 —— node_id 不再需要手工填写。
        let mut cfg = valid_config();
        cfg.enroll_token = Secret::new("");
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn an_empty_node_name_falls_back_to_the_hostname() {
        // 手写配置时留空是常见的，不该因此拒绝启动。
        let mut cfg = valid_config();
        cfg.node_name = "   ".into();
        cfg.validate().unwrap();
        let name = cfg.effective_node_name();
        assert!(!name.trim().is_empty(), "回落后的名称不应为空");
    }

    #[test]
    fn a_configured_node_name_wins_over_the_hostname() {
        let cfg = valid_config();
        assert_eq!(cfg.effective_node_name(), "sh-01");
    }

    #[test]
    fn control_url_scheme_is_checked() {
        let mut cfg = valid_config();
        cfg.control_url = "10.0.0.5:8080".into();
        assert!(cfg.validate().is_err());
        cfg.control_url = "https://control.internal".into();
        cfg.validate().unwrap();
    }

    #[test]
    fn standalone_mode_needs_a_bundle_path() {
        let mut cfg = AgentConfig {
            standalone: true,
            ..Default::default()
        };
        // No node_id or token needed, but a bundle path is.
        assert!(cfg.validate().is_err());
        cfg.standalone_config = Some(PathBuf::from("/etc/tunnel-agent/bundle.json"));
        cfg.validate().unwrap();
    }

    #[test]
    fn absurd_intervals_and_limits_are_rejected() {
        let mut cfg = valid_config();
        cfg.heartbeat_interval = Duration::ZERO;
        assert!(cfg.validate().is_err());

        let mut cfg = valid_config();
        cfg.config_poll_interval = Duration::ZERO;
        assert!(cfg.validate().is_err());

        let mut cfg = valid_config();
        cfg.connection_sample_limit = 100_000;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn local_role_override_wins() {
        let mut cfg = valid_config();
        assert_eq!(cfg.effective_role(NodeRole::Exit), NodeRole::Exit);
        cfg.role = Some(NodeRole::Entry);
        assert_eq!(
            cfg.effective_role(NodeRole::Exit),
            NodeRole::Entry,
            "the local override must win so an operator can demote a node locally"
        );
    }

    #[test]
    fn token_is_redacted_in_debug_output() {
        let cfg = valid_config();
        let debug = format!("{cfg:?}");
        assert!(!debug.contains("a-token"), "agent token leaked: {debug}");
        assert!(debug.contains("***"));
    }

    #[test]
    fn sample_config_round_trips() {
        let text = AgentConfig::sample_toml();
        let parsed: AgentConfig = toml::from_str(&text).unwrap();
        // The sample is a template; it validates structurally.
        parsed.validate().unwrap();
    }

    #[test]
    fn cache_round_trips() {
        let dir = temp_dir("cache-roundtrip");
        let cache = ConfigCache::new(dir.join("lkg.json"));

        assert!(cache.load().is_none(), "empty cache should yield None");
        cache.store(&bundle(7)).unwrap();

        let loaded = cache.load().expect("cached bundle should load");
        assert_eq!(loaded.revision, 7);
        assert_eq!(loaded.routes.len(), 1);
        assert_eq!(loaded.remote_endpoints.len(), 1);
        assert_eq!(
            loaded.tunnel_psk.as_ref().map(|p| p.expose()),
            Some("a-shared-psk"),
            "the PSK must survive caching or the agent cannot reconnect offline"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn store_replaces_the_previous_bundle() {
        let dir = temp_dir("cache-replace");
        let cache = ConfigCache::new(dir.join("lkg.json"));
        cache.store(&bundle(1)).unwrap();
        cache.store(&bundle(2)).unwrap();
        assert_eq!(cache.load().unwrap().revision, 2);

        // No temp file left behind.
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains("tmp"))
            .collect();
        assert!(leftovers.is_empty(), "temporary file was not cleaned up");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_cache_does_not_prevent_startup() {
        // The agent must come up and wait for the control plane rather than
        // refusing to start.
        let dir = temp_dir("cache-corrupt");
        let path = dir.join("lkg.json");
        std::fs::write(&path, b"{ this is not valid json").unwrap();

        let cache = ConfigCache::new(&path);
        assert!(cache.load().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn truncated_cache_does_not_prevent_startup() {
        let dir = temp_dir("cache-truncated");
        let path = dir.join("lkg.json");
        let json = serde_json::to_string_pretty(&bundle(3)).unwrap();
        std::fs::write(&path, &json.as_bytes()[..json.len() / 2]).unwrap();

        assert!(ConfigCache::new(&path).load().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cache_holding_an_invalid_bundle_is_rejected() {
        // Simulates an upgrade that tightened validation: the old cache parses
        // but no longer passes, and must not be applied.
        let dir = temp_dir("cache-invalid");
        let path = dir.join("lkg.json");
        let mut bad = bundle(4);
        bad.limits.stream_window = 1; // smaller than one frame
        std::fs::write(&path, serde_json::to_string(&bad).unwrap()).unwrap();

        assert!(ConfigCache::new(&path).load().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cache_directory_is_created_on_demand() {
        let dir = temp_dir("cache-mkdir");
        let cache = ConfigCache::new(dir.join("nested/deeper/lkg.json"));
        cache.store(&bundle(1)).unwrap();
        assert_eq!(cache.load().unwrap().revision, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_wrong_model_version_is_refused() {
        let dir = temp_dir("cache-version");
        let path = dir.join("lkg.json");
        let mut future = bundle(5);
        future.model_version = tunnel_common::MODEL_VERSION + 99;
        std::fs::write(&path, serde_json::to_string(&future).unwrap()).unwrap();

        assert!(
            ConfigCache::new(&path).load().is_none(),
            "a bundle from an incompatible version must not be applied"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
