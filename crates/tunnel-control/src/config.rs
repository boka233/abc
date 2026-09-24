//! Control-plane configuration, loaded from TOML with environment overrides.
//!
//! Deployment-level settings live here rather than in the database, because a
//! value that could lock an operator out of the panel must not be editable from
//! the panel. Runtime-tunable values (retention, intervals) live in the
//! `settings` table instead.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tunnel_common::logging::LogConfig;
use tunnel_common::{Error, Result, Secret};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ControlConfig {
    /// HTTP bind address for the API and the admin panel.
    pub listen: String,
    /// SQLite file path.
    pub database_path: PathBuf,
    /// Directory containing the built Vue app. Served when present; the API
    /// works without it.
    pub web_root: Option<PathBuf>,
    /// Address agents should use to reach the control plane, e.g.
    /// `https://panel.example.com`.
    ///
    /// Needed because `listen` is often `127.0.0.1:8080` behind a reverse proxy —
    /// the address an operator types in a browser is not the address a remote
    /// agent can connect to. The install command embeds this; when unset it falls
    /// back to `listen` and the API warns that a loopback address will not work
    /// from another host.
    pub public_url: Option<String>,
    /// 存放供 agent 下载的二进制的目录。
    ///
    /// 一键对接脚本在注册**之前**就要取到 `tunnel-agent`，此时目标机器上既没有源码
    /// 也没有编译工具链。控制面从这个目录按 `tunnel-agent-x86_64` /
    /// `tunnel-agent-aarch64` 的固定命名提供下载。
    ///
    /// 为什么用目录而不是把二进制编进控制面：agent 与控制面各自迭代，编进去意味着
    /// 换一个 agent 版本就要重新发布控制面；两个架构的二进制也会让控制面体积翻倍，
    /// 而多数部署只用到其中一个。放在目录里，升级 agent 只需替换文件。
    pub agent_binary_dir: Option<PathBuf>,
    /// 可信反向代理的地址段，用 CIDR 写法，如 `172.18.0.0/16`。
    ///
    /// # 为什么需要它
    ///
    /// `X-Forwarded-For` 默认只在对端是回环地址时才被采信 —— 那覆盖了「nginx 与
    /// 控制面同机」这种最常见的形态，且不给远程客户端伪造地址的机会。
    ///
    /// 但用 Docker 时反代与控制面在两个容器里，对端是容器网段（`172.x.x.x`）而不是
    /// 回环。此时若不采信该头，每个请求的来源都会被算成反代容器的地址，按 IP 的登录
    /// 限流就退化成了全局限流：一个人连续输错密码会把所有人一起锁在门外。
    ///
    /// # 为什么必须显式配置
    ///
    /// 不默认信任任何私网段。把 `172.16.0.0/12` 之类无条件加进白名单，在「控制面
    /// 直接暴露在内网」的部署里等于让同网段的任何机器都能伪造来源 IP 绕过限流。
    /// 只有管理员知道自己的反代究竟在哪个网段。
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    pub auth: AuthConfig,
    pub agent: AgentApiConfig,
    /// PSK distributed to agents for the tunnel handshake. Never logged.
    pub tunnel_psk: Option<Secret>,
    /// TLS paths pushed to agents. The control plane does not read these files;
    /// it only tells agents where to find theirs.
    pub agent_tls: AgentTlsPaths,
    pub limits: tunnel_common::model::Limits,
    pub log: LogConfig,
    /// Marks the deployment as production, which enables extra refusals:
    /// default secrets and `insecure_skip_verify` become hard errors.
    pub production: bool,
}

impl Default for ControlConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:8080".into(),
            database_path: PathBuf::from("/var/lib/tunnel-control/control.db"),
            web_root: None,
            public_url: None,
            agent_binary_dir: Some(PathBuf::from("/var/lib/tunnel-control/agent-bin")),
            // 默认空：只信任回环。Docker 部署要显式写上容器网段。
            trusted_proxies: Vec::new(),
            auth: AuthConfig::default(),
            agent: AgentApiConfig::default(),
            tunnel_psk: None,
            agent_tls: AgentTlsPaths::default(),
            limits: tunnel_common::model::Limits::default(),
            log: LogConfig::default(),
            production: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AuthConfig {
    /// HMAC signing key for session tokens.
    pub jwt_secret: Secret,
    /// Session lifetime.
    #[serde(with = "humantime_serde")]
    pub token_ttl: Duration,
    /// Username of the account created on first start.
    pub bootstrap_username: String,
    /// Failed logins from one IP before it is throttled.
    pub login_attempt_limit: u32,
    /// How long a throttled IP stays throttled.
    #[serde(with = "humantime_serde")]
    pub login_lockout: Duration,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            // Empty rather than a hardcoded placeholder: a shipped default
            // signing key is a forgeable-session vulnerability waiting to be
            // deployed. Startup generates one and warns.
            jwt_secret: Secret::new(""),
            token_ttl: Duration::from_secs(12 * 3600),
            bootstrap_username: "admin".into(),
            login_attempt_limit: 10,
            login_lockout: Duration::from_secs(300),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentApiConfig {
    /// Seconds without a heartbeat before a node is shown offline.
    pub stale_after_secs: u64,
    /// Requested agent heartbeat interval, sent in the config bundle.
    #[serde(with = "humantime_serde")]
    pub heartbeat_interval: Duration,
}

impl Default for AgentApiConfig {
    fn default() -> Self {
        Self {
            stale_after_secs: 45,
            heartbeat_interval: Duration::from_secs(10),
        }
    }
}

/// Paths an agent should load its TLS material from. Distributed as paths, not
/// contents: private keys never transit the control plane.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentTlsPaths {
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
    pub ca_path: Option<String>,
    pub require_client_auth: bool,
    pub client_cert_path: Option<String>,
    pub client_key_path: Option<String>,
}

impl AgentTlsPaths {
    pub fn to_model(&self) -> tunnel_common::model::TlsConfig {
        tunnel_common::model::TlsConfig {
            cert_path: self.cert_path.clone(),
            key_path: self.key_path.clone(),
            ca_path: self.ca_path.clone(),
            require_client_auth: self.require_client_auth,
            client_cert_path: self.client_cert_path.clone(),
            client_key_path: self.client_key_path.clone(),
            // Never distributed as true. A lab operator sets it in the agent's
            // own config file, where it is visible locally.
            insecure_skip_verify: false,
        }
    }
}

impl ControlConfig {
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            Error::config(format!("cannot read config {}: {e}", path.display()))
        })?;
        let mut cfg: ControlConfig = toml::from_str(&text)?;
        warn_misplaced_top_level_keys(&text);
        cfg.apply_env();
        cfg.validate()?;
        Ok(cfg)
    }

    /// Environment overrides, for container deployments where mounting a config
    /// file is awkward. Secrets via env are preferable to secrets in a file that
    /// might get committed.
    fn apply_env(&mut self) {
        if let Ok(v) = std::env::var("TUNNEL_CONTROL_LISTEN") {
            self.listen = v;
        }
        if let Ok(v) = std::env::var("TUNNEL_CONTROL_DATABASE") {
            self.database_path = PathBuf::from(v);
        }
        if let Ok(v) = std::env::var("TUNNEL_CONTROL_WEB_ROOT") {
            self.web_root = Some(PathBuf::from(v));
        }
        if let Ok(v) = std::env::var("TUNNEL_CONTROL_PUBLIC_URL") {
            self.public_url = Some(v);
        }
        if let Ok(v) = std::env::var("TUNNEL_CONTROL_JWT_SECRET") {
            self.auth.jwt_secret = Secret::new(v);
        }
        if let Ok(v) = std::env::var("TUNNEL_PSK") {
            self.tunnel_psk = Some(Secret::new(v));
        }
        if let Ok(v) = std::env::var("TUNNEL_CONTROL_PRODUCTION") {
            self.production = matches!(v.as_str(), "1" | "true" | "yes");
        }
        if let Ok(v) = std::env::var("TUNNEL_CONTROL_AGENT_BINARY_DIR") {
            self.agent_binary_dir = Some(PathBuf::from(v));
        }
        // 逗号分隔，如 `172.18.0.0/16,10.0.0.0/8`。Docker 部署里反代与控制面在不同
        // 容器，必须声明容器网段可信，否则按 IP 的登录限流会退化成全局限流。
        if let Ok(v) = std::env::var("TUNNEL_CONTROL_TRUSTED_PROXIES") {
            self.trusted_proxies = v
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.listen_addr()?;
        self.limits.validate()?;

        if self.auth.token_ttl < Duration::from_secs(60) {
            return Err(Error::config("auth.token_ttl must be at least 60s"));
        }
        if self.auth.login_attempt_limit == 0 {
            return Err(Error::config("auth.login_attempt_limit must be >= 1"));
        }
        if self.agent.stale_after_secs < 10 {
            return Err(Error::config(
                "agent.stale_after_secs must be >= 10, or nodes will flap between \
                 online and offline",
            ));
        }
        if self.agent.heartbeat_interval.as_secs() == 0 {
            return Err(Error::config("agent.heartbeat_interval must be >= 1s"));
        }
        if self.agent.stale_after_secs <= self.agent.heartbeat_interval.as_secs() * 2 {
            return Err(Error::config(
                "agent.stale_after_secs should exceed twice the heartbeat interval, \
                 otherwise one dropped heartbeat marks a healthy node offline",
            ));
        }

        if self.production {
            // Refusals that only apply in production, where a weak default is a
            // real exposure rather than a lab inconvenience.
            if self.auth.jwt_secret.len() < 32 {
                return Err(Error::config(
                    "production requires auth.jwt_secret of at least 32 characters",
                ));
            }
            match &self.tunnel_psk {
                None => {
                    return Err(Error::config(
                        "production requires tunnel_psk to be set",
                    ))
                }
                Some(psk) if psk.len() < 32 => {
                    return Err(Error::config(
                        "production requires tunnel_psk of at least 32 characters",
                    ))
                }
                Some(_) => {}
            }
            if self.agent_tls.ca_path.is_none() {
                return Err(Error::config(
                    "production requires agent_tls.ca_path so agents verify a pinned CA \
                     rather than the public trust store",
                ));
            }
        }
        Ok(())
    }

    pub fn listen_addr(&self) -> Result<SocketAddr> {
        self.listen
            .parse()
            .map_err(|_| Error::config(format!("invalid listen address `{}`", self.listen)))
    }

    /// Generate a signing key when none is configured.
    ///
    /// Returns `true` if one was generated, so the caller can warn that sessions
    /// will not survive a restart.
    pub fn ensure_jwt_secret(&mut self) -> bool {
        if !self.auth.jwt_secret.is_empty() {
            return false;
        }
        self.auth.jwt_secret = Secret::new(random_secret(48));
        true
    }

    /// Serialise a starter config. Secrets are emitted as empty placeholders.
    pub fn sample_toml() -> String {
        let cfg = ControlConfig {
            database_path: PathBuf::from("/var/lib/tunnel-control/control.db"),
            web_root: Some(PathBuf::from("/usr/share/tunnel-control/web")),
            agent_tls: AgentTlsPaths {
                ca_path: Some("/etc/tunnel/ca.pem".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        toml::to_string_pretty(&cfg).unwrap_or_default()
    }
}

/// Top-level keys that are silently swallowed if written after a `[table]`.
///
/// `serde` cannot help here: `tunnel_psk` placed after `[auth]` parses as
/// `auth.tunnel_psk`, which `AuthConfig` ignores via `#[serde(default)]`. The
/// result is a config that loads cleanly while the PSK is empty — no error, and
/// agents end up with TLS-only authentication when the operator believed a PSK
/// was in force. That is exactly the kind of silent security downgrade worth a
/// loud warning.
const TOP_LEVEL_KEYS: &[&str] = &[
    "listen",
    "database_path",
    "web_root",
    "production",
    "tunnel_psk",
];

/// Warn when a top-level key appears after the first `[table]` header.
///
/// A lint, not a hard error: refusing to start would break a deployment whose
/// config happens to trip a false positive (a key of the same name legitimately
/// inside a table we do not know about).
fn warn_misplaced_top_level_keys(text: &str) {
    let mut current_table: Option<String> = None;

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            current_table = Some(line.trim_matches(['[', ']']).to_string());
            continue;
        }
        let Some(table) = current_table.as_deref() else {
            continue; // still in the top-level section, which is correct
        };
        let Some((key, _)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if TOP_LEVEL_KEYS.contains(&key) {
            tracing::warn!(
                key,
                table,
                "`{key}` is a top-level setting but appears under [{table}], so it was \
                 parsed as `{table}.{key}` and the real setting is still unset. \
                 Move it above the first [table] header."
            );
        }
    }
}

pub fn random_secret(len: usize) -> String {
    use rand::Rng;
    const ALPHABET: &[u8] =
        b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn production_config() -> ControlConfig {
        ControlConfig {
            production: true,
            auth: AuthConfig {
                jwt_secret: Secret::new(random_secret(48)),
                ..Default::default()
            },
            tunnel_psk: Some(Secret::new(random_secret(48))),
            agent_tls: AgentTlsPaths {
                ca_path: Some("/etc/tunnel/ca.pem".into()),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn default_config_validates_in_development() {
        ControlConfig::default().validate().unwrap();
    }

    #[test]
    fn no_hardcoded_default_secret_exists() {
        // A shipped signing key would let anyone forge a session on any
        // deployment that did not override it.
        let cfg = ControlConfig::default();
        assert!(
            cfg.auth.jwt_secret.is_empty(),
            "the default config must not carry a usable signing key"
        );
        assert!(cfg.tunnel_psk.is_none());
    }

    #[test]
    fn generated_secret_is_long_and_random() {
        let mut a = ControlConfig::default();
        assert!(a.ensure_jwt_secret(), "should generate when empty");
        assert!(a.auth.jwt_secret.len() >= 48);
        // Calling again must not rotate an existing key out from under live
        // sessions.
        assert!(!a.ensure_jwt_secret());

        let mut b = ControlConfig::default();
        b.ensure_jwt_secret();
        assert_ne!(
            a.auth.jwt_secret.expose(),
            b.auth.jwt_secret.expose(),
            "generated secrets must differ between instances"
        );
    }

    #[test]
    fn production_requires_real_secrets() {
        let mut cfg = production_config();
        cfg.auth.jwt_secret = Secret::new("short");
        assert!(cfg.validate().is_err(), "weak jwt secret accepted");

        let mut cfg = production_config();
        cfg.tunnel_psk = None;
        assert!(cfg.validate().is_err(), "missing psk accepted");

        let mut cfg = production_config();
        cfg.tunnel_psk = Some(Secret::new("tiny"));
        assert!(cfg.validate().is_err(), "weak psk accepted");
    }

    #[test]
    fn production_requires_a_pinned_ca() {
        let mut cfg = production_config();
        cfg.agent_tls.ca_path = None;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn full_production_config_validates() {
        production_config().validate().unwrap();
    }

    #[test]
    fn distributed_tls_never_disables_verification() {
        let paths = AgentTlsPaths {
            ca_path: Some("/etc/tunnel/ca.pem".into()),
            ..Default::default()
        };
        assert!(
            !paths.to_model().insecure_skip_verify,
            "the control plane must never push insecure_skip_verify to an agent"
        );
    }

    #[test]
    fn stale_threshold_must_exceed_two_heartbeats() {
        // Otherwise a single lost heartbeat marks a healthy node offline and the
        // dashboard flaps.
        let mut cfg = ControlConfig::default();
        cfg.agent.heartbeat_interval = Duration::from_secs(30);
        cfg.agent.stale_after_secs = 45;
        assert!(cfg.validate().is_err());

        cfg.agent.stale_after_secs = 90;
        cfg.validate().unwrap();
    }

    #[test]
    fn absurd_thresholds_are_rejected() {
        let mut cfg = ControlConfig::default();
        cfg.agent.stale_after_secs = 3;
        assert!(cfg.validate().is_err());

        let mut cfg = ControlConfig::default();
        cfg.auth.token_ttl = Duration::from_secs(5);
        assert!(cfg.validate().is_err());

        let mut cfg = ControlConfig::default();
        cfg.auth.login_attempt_limit = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn invalid_listen_address_is_rejected() {
        let mut cfg = ControlConfig {
            listen: "not-an-address".into(),
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
        cfg.listen = "0.0.0.0:8080".into();
        cfg.validate().unwrap();
    }

    #[test]
    fn sample_config_round_trips() {
        let toml_text = ControlConfig::sample_toml();
        assert!(toml_text.contains("listen"));
        let parsed: ControlConfig = toml::from_str(&toml_text).unwrap();
        parsed.validate().unwrap();
        // The sample must not ship a secret.
        assert!(parsed.auth.jwt_secret.is_empty());
    }

    #[test]
    fn secrets_are_redacted_in_debug_output() {
        let mut cfg = production_config();
        cfg.ensure_jwt_secret();
        let debug = format!("{cfg:?}");
        assert!(
            !debug.contains(cfg.auth.jwt_secret.expose()),
            "jwt secret leaked into Debug output"
        );
        assert!(debug.contains("***"));
    }

    #[test]
    fn a_top_level_key_after_a_table_is_silently_swallowed() {
        // Documents the trap the lint exists for: this parses cleanly, but the
        // PSK lands in `auth` and the real field stays empty. Found while
        // standing up a local demo — the dashboard reported psk_configured=false
        // with a PSK plainly visible in the file.
        let cfg: ControlConfig = toml::from_str(
            "listen = \"127.0.0.1:8080\"\n\
             [auth]\n\
             token_ttl = \"12h\"\n\
             tunnel_psk = \"this-lands-inside-auth-not-at-the-top-level\"\n",
        )
        .unwrap();
        assert!(
            cfg.tunnel_psk.is_none(),
            "if this ever becomes Some, TOML semantics changed and the lint can go"
        );
    }

    #[test]
    fn correct_placement_is_picked_up() {
        let cfg: ControlConfig = toml::from_str(
            "listen = \"127.0.0.1:8080\"\n\
             tunnel_psk = \"a-psk-written-before-any-table-header\"\n\
             [auth]\n\
             token_ttl = \"12h\"\n",
        )
        .unwrap();
        assert_eq!(
            cfg.tunnel_psk.as_ref().map(|p| p.expose()),
            Some("a-psk-written-before-any-table-header")
        );
    }

    #[test]
    fn the_lint_flags_misplaced_keys_and_leaves_correct_ones_alone() {
        // The function only logs, so assert on its parsing decisions by calling
        // it against both shapes; a panic or hang here would fail the test.
        warn_misplaced_top_level_keys(
            "listen = \"0.0.0.0:80\"\n[auth]\ntunnel_psk = \"x\"\nproduction = true\n",
        );
        warn_misplaced_top_level_keys(
            "listen = \"0.0.0.0:80\"\ntunnel_psk = \"x\"\n[auth]\ntoken_ttl = \"1h\"\n",
        );
        // Comments and blank lines must not be mistaken for assignments.
        warn_misplaced_top_level_keys("# tunnel_psk = \"commented out\"\n\n[auth]\n");
    }

    #[test]
    fn the_shipped_example_places_top_level_keys_correctly() {
        // Guards the example file itself: it had this exact bug, which would have
        // shipped a config where the PSK looks set but is not.
        let example = include_str!("../../../configs/control.example.toml");
        let mut seen_table = false;
        for raw in example.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line.starts_with('[') {
                seen_table = true;
                continue;
            }
            if let Some((key, _)) = line.split_once('=') {
                let key = key.trim();
                if TOP_LEVEL_KEYS.contains(&key) {
                    assert!(
                        !seen_table,
                        "configs/control.example.toml puts top-level key `{key}` after a \
                         [table]; it will be silently ignored"
                    );
                }
            }
        }
    }

    #[test]
    fn partial_toml_uses_defaults() {
        // An operator should be able to set one field without restating the rest.
        let cfg: ControlConfig = toml::from_str("listen = \"0.0.0.0:9000\"\n").unwrap();
        assert_eq!(cfg.listen, "0.0.0.0:9000");
        assert_eq!(cfg.auth.bootstrap_username, "admin");
        assert!(!cfg.production);
    }
}
