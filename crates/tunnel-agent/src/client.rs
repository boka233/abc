//! Minimal HTTP/1.1 client for talking to the control plane.
//!
//! # Why not a full HTTP client crate
//!
//! The agent makes exactly three request shapes against one known endpoint:
//! `POST /api/agent/register`, `GET /api/agent/config`, `POST
//! /api/agent/heartbeat`. All are small JSON bodies to a server we control. A
//! general-purpose client would add a large dependency tree — connection pooling,
//! redirects, cookies, compression, proxy handling — to a binary that sits in the
//! data path, for none of which there is a use here.
//!
//! What this does implement, because it matters:
//!
//! * Explicit timeouts on connect and on the whole exchange. An agent that hangs
//!   on a wedged control plane stops heartbeating and looks dead.
//! * A bounded response body, so a hostile or broken server cannot make the agent
//!   allocate without limit.
//! * `Connection: close` and a fresh connection per request. Keep-alive would
//!   save a handshake every 10 seconds and cost half-open-connection handling;
//!   not worth it at this request rate.
//!
//! # Transport security
//!
//! Only `http://` is implemented. The control-plane connection is expected to be
//! on a private/management network, or fronted by a TLS-terminating reverse proxy.
//! [`ControlClient::new`] refuses `https://` loudly rather than silently
//! downgrading to plaintext — a silent downgrade would send the agent token in
//! the clear.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tunnel_common::model::{AgentConfigBundle, AgentReport};
use tunnel_common::{Error, Result, Secret};

/// Cap on a response body. A config bundle for a large fleet is tens of KiB;
/// 8 MiB is generous and still bounded.
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// `Debug` is derived rather than hand-written: `token` is a [`Secret`], which
/// renders as `***`, so the whole struct is safe to log.
#[derive(Debug)]
pub struct ControlClient {
    host: String,
    port: u16,
    /// 本机在组内的名称。控制面按 (组, 名称) 登记机器，重复注册会更新原记录。
    node_name: String,
    hostname: Option<String>,
    /// 本机声明的角色。控制面会按组类型收敛它。
    role: Option<String>,
    /// 设备组注册令牌。不含组 id —— 让用户从面板复制两个值是多余的摩擦。
    token: Secret,
    timeout: Duration,
}

/// 注册结果。
#[derive(Debug)]
pub struct Registration {
    /// 控制面分配的机器 id，心跳时用它标识自己。
    pub node_id: String,
    /// 所属设备组名，仅用于日志。
    pub group_name: String,
    pub bundle: AgentConfigBundle,
}

/// Reply to a config poll.
#[derive(Debug)]
pub enum ConfigPoll {
    /// The agent's revision is current; nothing to apply.
    Unchanged,
    Updated(Box<AgentConfigBundle>),
}

impl ControlClient {
    pub fn new(
        control_url: &str,
        node_name: impl Into<String>,
        token: Secret,
        timeout: Duration,
    ) -> Result<Self> {
        if control_url.starts_with("https://") {
            return Err(Error::config(
                "https control_url is not supported by the built-in client; \
                 terminate TLS at a local reverse proxy and point control_url at it, \
                 or use a private network",
            ));
        }
        let rest = control_url
            .strip_prefix("http://")
            .ok_or_else(|| Error::config("control_url must start with http://"))?;

        // Strip any path; the endpoints are fixed.
        let authority = rest.split('/').next().unwrap_or(rest);
        let (host, port) = match authority.rsplit_once(':') {
            // Guard against an IPv6 literal without a port.
            Some((h, p)) if !h.ends_with(']') || p.chars().all(|c| c.is_ascii_digit()) => {
                let port = p
                    .parse::<u16>()
                    .map_err(|_| Error::config(format!("invalid port in `{control_url}`")))?;
                (h.to_string(), port)
            }
            _ => (authority.to_string(), 80),
        };

        if host.is_empty() {
            return Err(Error::config(format!("no host in `{control_url}`")));
        }

        Ok(Self {
            host,
            port,
            node_name: node_name.into(),
            hostname: None,
            role: None,
            token,
            timeout,
        })
    }

    /// 附带本机主机名，仅用于面板展示。
    pub fn with_hostname(mut self, hostname: Option<String>) -> Self {
        self.hostname = hostname;
        self
    }

    /// 声明本机角色。控制面会按组类型收敛它 —— 出口组里的机器即使声明 both 也只
    /// 会得到 exit。
    pub fn with_role(mut self, role: Option<String>) -> Self {
        self.role = role;
        self
    }

    pub fn endpoint(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// 注册并取回初始配置。
    ///
    /// 返回控制面分配的机器 id 与配置 bundle。agent 事先不知道自己的 id ——
    /// 它凭组令牌注册，由控制面按 (组, 机器名) 登记后回传。
    pub async fn register(&self) -> Result<Registration> {
        let body = self
            .request("POST", "/api/agent/register", Some(b"{}"))
            .await?;
        let value: serde_json::Value = serde_json::from_slice(&body)?;

        let node_id = value
            .get("node_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::protocol("注册响应缺少 node_id 字段"))?
            .to_string();
        let group_name = value
            .get("group_name")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_string();

        let config = value
            .get("config")
            .ok_or_else(|| Error::protocol("注册响应缺少 config 字段"))?;
        let bundle: AgentConfigBundle = serde_json::from_value(config.clone())?;
        bundle.validate()?;

        Ok(Registration {
            node_id,
            group_name,
            bundle,
        })
    }

    /// Poll for configuration, skipping the transfer when unchanged.
    pub async fn poll_config(&self, known_revision: Option<u64>) -> Result<ConfigPoll> {
        let path = match known_revision {
            Some(rev) => format!("/api/agent/config?known_revision={rev}"),
            None => "/api/agent/config".to_string(),
        };
        let body = self.request("GET", &path, None).await?;
        let value: serde_json::Value = serde_json::from_slice(&body)?;

        if value
            .get("unchanged")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            return Ok(ConfigPoll::Unchanged);
        }

        let config = value
            .get("config")
            .ok_or_else(|| Error::protocol("config response has no `config` field"))?;
        let bundle: AgentConfigBundle = serde_json::from_value(config.clone())?;
        // Validate before the caller can apply it, so a bad push never reaches
        // the running data plane.
        bundle.validate()?;
        Ok(ConfigPoll::Updated(Box::new(bundle)))
    }

    /// Send a heartbeat. Returns the control plane's current config revision, so
    /// the agent can notice a change without a separate poll.
    pub async fn heartbeat(&self, report: &AgentReport) -> Result<Option<u64>> {
        let payload = serde_json::to_vec(report)?;
        let body = self
            .request("POST", "/api/agent/heartbeat", Some(&payload))
            .await?;
        let value: serde_json::Value = serde_json::from_slice(&body)?;
        Ok(value.get("config_revision").and_then(|v| v.as_u64()))
    }

    /// Perform one request/response exchange.
    async fn request(&self, method: &str, path: &str, body: Option<&[u8]>) -> Result<Vec<u8>> {
        let target = self.endpoint();

        let tuning = tunnel_common::net::TcpTuning::default();
        let egress = tunnel_common::net::EgressBinding::default();
        let connect = tunnel_common::net::connect(&target, &tuning, &egress, self.timeout);
        let mut stream = tokio::time::timeout(self.timeout, connect)
            .await
            .map_err(|_| Error::Timeout("control plane connect"))??;

        let mut request = format!(
            "{method} {path} HTTP/1.1\r\n\
             Host: {}\r\n\
             {}: {}\r\n\
             {}: {}\r\n\
             Accept: application/json\r\n\
             Connection: close\r\n",
            target,
            AGENT_TOKEN_HEADER,
            self.token.expose(),
            AGENT_NAME_HEADER,
            self.node_name,
        );
        if let Some(hostname) = &self.hostname {
            request.push_str(&format!("{AGENT_HOSTNAME_HEADER}: {hostname}\r\n"));
        }
        if let Some(role) = &self.role {
            request.push_str(&format!("{AGENT_ROLE_HEADER}: {role}\r\n"));
        }
        if let Some(payload) = body {
            request.push_str("Content-Type: application/json\r\n");
            request.push_str(&format!("Content-Length: {}\r\n", payload.len()));
        }
        request.push_str("\r\n");

        // One write for headers, one for the body.
        let exchange = async {
            stream.write_all(request.as_bytes()).await?;
            if let Some(payload) = body {
                stream.write_all(payload).await?;
            }
            stream.flush().await?;

            // `Connection: close` means EOF delimits the response, so no chunked
            // decoding or Content-Length bookkeeping is needed on the way back.
            let mut buf = Vec::with_capacity(8 * 1024);
            let mut chunk = [0u8; 16 * 1024];
            loop {
                let n = stream.read(&mut chunk).await?;
                if n == 0 {
                    break;
                }
                if buf.len() + n > MAX_RESPONSE_BYTES {
                    return Err(Error::limit(format!(
                        "control plane response exceeded {MAX_RESPONSE_BYTES} bytes"
                    )));
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            Ok::<Vec<u8>, Error>(buf)
        };

        let raw = tokio::time::timeout(self.timeout, exchange)
            .await
            .map_err(|_| Error::Timeout("control plane request"))??;

        parse_response(&raw)
    }
}

/// 请求头名称，必须与控制面的提取器一致。改动会静默破坏所有已部署的 agent。
const AGENT_TOKEN_HEADER: &str = "X-Agent-Token";
const AGENT_NAME_HEADER: &str = "X-Agent-Name";
const AGENT_HOSTNAME_HEADER: &str = "X-Agent-Hostname";
const AGENT_ROLE_HEADER: &str = "X-Agent-Role";

/// Split an HTTP/1.1 response and check the status.
///
/// Handles only what the control plane sends. Anything unexpected is an error
/// rather than a best-effort guess: silently misreading a response would be worse
/// than failing the poll and retrying.
fn parse_response(raw: &[u8]) -> Result<Vec<u8>> {
    let split = find_header_end(raw)
        .ok_or_else(|| Error::protocol("malformed HTTP response: no header terminator"))?;
    let (head, body) = raw.split_at(split.0);
    let body = &body[split.1..];

    let head = String::from_utf8_lossy(head);
    let status_line = head
        .lines()
        .next()
        .ok_or_else(|| Error::protocol("empty HTTP response"))?;

    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| Error::protocol(format!("unparseable status line `{status_line}`")))?;

    match status {
        200..=299 => Ok(body.to_vec()),
        401 | 403 => Err(Error::Auth(
            "control plane rejected the agent credentials",
        )),
        404 => Err(Error::NotFound("control plane endpoint".into())),
        // 5xx and 429 are worth retrying; the supervisor's backoff handles it.
        status => {
            let detail = String::from_utf8_lossy(&body[..body.len().min(200)]);
            Err(Error::other(format!(
                "control plane returned HTTP {status}: {detail}"
            )))
        }
    }
}

/// Locate the end of the header block, tolerating bare-LF line endings.
/// Returns `(offset_of_terminator, terminator_len)`.
fn find_header_end(raw: &[u8]) -> Option<(usize, usize)> {
    if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
        return Some((pos, 4));
    }
    raw.windows(2).position(|w| w == b"\n\n").map(|pos| (pos, 2))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(url: &str) -> Result<ControlClient> {
        ControlClient::new(url, "n1", Secret::new("tok"), Duration::from_secs(5))
    }

    #[test]
    fn url_parsing() {
        let c = client("http://10.0.0.5:8080").unwrap();
        assert_eq!(c.endpoint(), "10.0.0.5:8080");

        // Default port when none is given.
        let c = client("http://control.internal").unwrap();
        assert_eq!(c.endpoint(), "control.internal:80");

        // A trailing path is ignored; endpoints are fixed.
        let c = client("http://10.0.0.5:8080/api/").unwrap();
        assert_eq!(c.endpoint(), "10.0.0.5:8080");
    }

    #[test]
    fn https_is_refused_rather_than_silently_downgraded() {
        // Downgrading would put the agent token on the wire in plaintext.
        let err = client("https://control.internal").unwrap_err();
        assert!(matches!(err, Error::Config(_)));
        assert!(err.to_string().contains("reverse proxy"), "{err}");
    }

    #[test]
    fn malformed_urls_are_rejected() {
        assert!(client("10.0.0.5:8080").is_err());
        assert!(client("ftp://10.0.0.5").is_err());
        assert!(client("http://10.0.0.5:not-a-port").is_err());
        assert!(client("http://").is_err());
    }

    #[test]
    fn successful_response_body_is_extracted() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}";
        let body = parse_response(raw).unwrap();
        assert_eq!(body, b"{\"ok\":true}");
    }

    #[test]
    fn bare_lf_responses_are_tolerated() {
        let raw = b"HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"ok\":true}";
        assert_eq!(parse_response(raw).unwrap(), b"{\"ok\":true}");
    }

    #[test]
    fn empty_body_is_valid() {
        let raw = b"HTTP/1.1 204 No Content\r\n\r\n";
        assert!(parse_response(raw).unwrap().is_empty());
    }

    #[test]
    fn auth_failures_are_classified_and_not_retried() {
        for status in ["401 Unauthorized", "403 Forbidden"] {
            let raw = format!("HTTP/1.1 {status}\r\n\r\n{{}}").into_bytes();
            let err = parse_response(&raw).unwrap_err();
            assert!(matches!(err, Error::Auth(_)), "{status}: {err:?}");
            // A bad token will not fix itself; the supervisor must not spin.
            assert!(!err.is_transient(), "{status} should not be retryable");
        }
    }

    #[test]
    fn server_errors_are_retryable() {
        let raw = b"HTTP/1.1 503 Service Unavailable\r\n\r\nbusy";
        let err = parse_response(raw).unwrap_err();
        assert!(err.to_string().contains("503"), "{err}");
    }

    #[test]
    fn malformed_responses_are_errors_not_panics() {
        for raw in [
            &b""[..],
            &b"not http at all"[..],
            &b"HTTP/1.1\r\n\r\n"[..],
            &b"\r\n\r\n"[..],
            &b"HTTP/1.1 abc OK\r\n\r\n"[..],
        ] {
            assert!(parse_response(raw).is_err(), "accepted {raw:?}");
        }
    }

    #[test]
    fn error_body_is_truncated_in_the_message() {
        let mut raw = b"HTTP/1.1 500 Internal Server Error\r\n\r\n".to_vec();
        raw.extend_from_slice(&vec![b'x'; 10_000]);
        let message = parse_response(&raw).unwrap_err().to_string();
        assert!(message.len() < 400, "error message not bounded: {}", message.len());
    }

    #[test]
    fn token_is_not_exposed_by_accident() {
        let c = client("http://10.0.0.5:8080").unwrap();
        // The struct holds a Secret, so debug output stays redacted.
        assert!(!format!("{:?}", c.token).contains("tok"));
    }

    #[tokio::test]
    async fn connect_failure_is_transient_so_the_agent_retries() {
        let c = ControlClient::new(
            "http://127.0.0.1:1",
            "n1",
            Secret::new("tok"),
            Duration::from_millis(300),
        )
        .unwrap();
        let err = c.poll_config(None).await.unwrap_err();
        assert!(
            err.is_transient(),
            "an unreachable control plane must be retryable: {err:?}"
        );
    }

    /// Serve one canned response and assert the request we produced.
    #[tokio::test]
    async fn request_carries_the_agent_credentials() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = sock.read(&mut buf).await.unwrap();
            let request = String::from_utf8_lossy(&buf[..n]).to_string();
            sock.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"unchanged\":true}",
            )
            .await
            .unwrap();
            sock.shutdown().await.unwrap();
            request
        });

        let c = ControlClient::new(
            &format!("http://{addr}"),
            "hk-01",
            Secret::new("group-enrol-token"),
            Duration::from_secs(5),
        )
        .unwrap()
        .with_hostname(Some("hk-01.internal".into()))
        .with_role(Some("exit".into()));
        let poll = c.poll_config(Some(3)).await.unwrap();
        assert!(matches!(poll, ConfigPoll::Unchanged));

        let request = server.await.unwrap();
        assert!(request.contains("GET /api/agent/config?known_revision=3"));
        // 凭据是组令牌；请求里不再有 node id —— agent 事先并不知道它。
        assert!(request.contains("X-Agent-Token: group-enrol-token"));
        assert!(request.contains("X-Agent-Name: hk-01"));
        assert!(request.contains("X-Agent-Hostname: hk-01.internal"));
        assert!(request.contains("X-Agent-Role: exit"));
        assert!(
            !request.contains("X-Node-Id"),
            "不应再发送 node id：它由控制面在注册时分配"
        );
        assert!(request.contains("Connection: close"));
    }

    #[tokio::test]
    async fn registration_returns_the_assigned_node_id() {
        // agent 凭组令牌注册，由控制面回传它被分配的机器 id。
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let _ = sock.read(&mut buf).await;
            let body = serde_json::json!({
                "node_id": "assigned-id-123",
                "node_name": "hk-01",
                "group_id": "grp-1",
                "group_name": "香港出口",
                "role": "exit",
                "heartbeat_interval_secs": 10,
                "config": {
                    "revision": 7,
                    "model_version": tunnel_common::MODEL_VERSION,
                    "node": {
                        "id": "grp-1",
                        "name": "香港出口",
                        "region": "hk",
                        "role": "exit"
                    },
                    "limits": tunnel_common::model::Limits::default(),
                    "tls": tunnel_common::model::TlsConfig::default(),
                }
            })
            .to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{body}"
            );
            let _ = sock.write_all(response.as_bytes()).await;
            let _ = sock.shutdown().await;
        });

        let c = ControlClient::new(
            &format!("http://{addr}"),
            "hk-01",
            Secret::new("tok"),
            Duration::from_secs(5),
        )
        .unwrap();
        let reg = c.register().await.unwrap();
        assert_eq!(reg.node_id, "assigned-id-123");
        assert_eq!(reg.group_name, "香港出口");
        assert_eq!(reg.bundle.revision, 7);
    }

    #[tokio::test]
    async fn a_registration_without_a_node_id_is_a_protocol_error() {
        // 少了 node_id，agent 就无法上报心跳，必须当成协议错误而不是静默继续。
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let _ = sock.read(&mut buf).await;
            let _ = sock
                .write_all(b"HTTP/1.1 200 OK\r\n\r\n{\"config\":{}}")
                .await;
            let _ = sock.shutdown().await;
        });

        let c = ControlClient::new(
            &format!("http://{addr}"),
            "hk-01",
            Secret::new("tok"),
            Duration::from_secs(5),
        )
        .unwrap();
        assert!(matches!(
            c.register().await.unwrap_err(),
            Error::Protocol(_)
        ));
    }

    #[tokio::test]
    async fn unauthorized_poll_is_reported_as_auth_failure() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let _ = sock.read(&mut buf).await;
            let _ = sock
                .write_all(b"HTTP/1.1 401 Unauthorized\r\n\r\n{\"error\":\"nope\"}")
                .await;
            let _ = sock.shutdown().await;
        });

        let c = ControlClient::new(
            &format!("http://{addr}"),
            "n1",
            Secret::new("bad"),
            Duration::from_secs(5),
        )
        .unwrap();
        assert!(matches!(
            c.poll_config(None).await.unwrap_err(),
            Error::Auth(_)
        ));
    }

    #[tokio::test]
    async fn a_response_without_a_config_field_is_a_protocol_error() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let _ = sock.read(&mut buf).await;
            let _ = sock
                .write_all(b"HTTP/1.1 200 OK\r\n\r\n{\"revision\":5}")
                .await;
            let _ = sock.shutdown().await;
        });

        let c = ControlClient::new(
            &format!("http://{addr}"),
            "n1",
            Secret::new("tok"),
            Duration::from_secs(5),
        )
        .unwrap();
        assert!(matches!(
            c.poll_config(None).await.unwrap_err(),
            Error::Protocol(_)
        ));
    }
}
