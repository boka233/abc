//! Authentication extractors.
//!
//! # Why the account is re-checked on every request
//!
//! JWTs are stateless, so a token stays cryptographically valid until it expires
//! even if the account was disabled a second later. [`AuthUser`] therefore
//! verifies the signature *and* reloads the account, which gives us
//! near-immediate revocation without session storage. The cost is one indexed
//! primary-key lookup per request.
//!
//! # Agent authentication
//!
//! Agents authenticate per request with `node_id` + token rather than holding a
//! session. Long-lived agent sessions would need refresh handling and revocation
//! for no benefit: the token is already long-lived and node-scoped, and an agent
//! that loses its token must be re-enrolled anyway.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;
use tunnel_storage::models::NodeRow;
use tunnel_storage::nodes::NodeRepo;
use tunnel_storage::users::UserRepo;

use crate::api::error::ApiError;
use crate::auth::Claims;
use crate::state::AppState;

/// 组注册令牌。一键对接的命令里只有这一个值。
pub const AGENT_TOKEN_HEADER: &str = "x-agent-token";
/// agent 上报的机器名。首次注册时用它在组内登记自己。
pub const AGENT_NAME_HEADER: &str = "x-agent-name";
/// agent 上报的主机名，仅用于面板展示。
pub const AGENT_HOSTNAME_HEADER: &str = "x-agent-hostname";
/// agent 声明的角色（entry/exit/both），受组类型约束。
pub const AGENT_ROLE_HEADER: &str = "x-agent-role";

/// Client address of the request, for audit entries and login throttling.
///
/// Infallible: a request with no recoverable peer address yields `None` rather
/// than failing, because losing an audit source IP must never reject an
/// otherwise valid operation.
#[derive(Debug, Clone, Copy)]
pub struct ClientAddr(pub Option<IpAddr>);

impl ClientAddr {
    /// Address for throttling. Falls back to loopback so a request with no peer
    /// information is still counted against *something* rather than escaping the
    /// throttle entirely.
    pub fn for_throttle(&self) -> IpAddr {
        self.0.unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
    }

    pub fn to_audit_string(&self) -> Option<String> {
        self.0.map(|ip| ip.to_string())
    }
}

// 特化到 `Arc<AppState>` 而非泛型 `S`：判定 `X-Forwarded-For` 是否可信需要读配置里
// 的 trusted_proxies。与 AuthUser 的做法一致。
impl FromRequestParts<Arc<AppState>> for ClientAddr {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        Ok(ClientAddr(client_ip_with_proxies(
            parts,
            &state.config().trusted_proxies,
        )))
    }
}

/// An authenticated panel user.
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub claims: Claims,
    pub must_change_password: bool,
}

impl AuthUser {
    pub fn user_id(&self) -> &str {
        &self.claims.sub
    }

    pub fn username(&self) -> &str {
        &self.claims.username
    }

    /// Reject the request unless the account has rotated its bootstrap password.
    ///
    /// Applied to mutating endpoints so a deployment cannot be driven with the
    /// generated first-run credentials still in place.
    pub fn require_password_rotated(&self) -> Result<(), ApiError> {
        if self.must_change_password {
            return Err(ApiError::Forbidden(
                "change your password before making changes".into(),
            ));
        }
        Ok(())
    }

    pub fn require_admin(&self) -> Result<(), ApiError> {
        if !self.claims.is_admin() {
            return Err(ApiError::Forbidden("administrator role required".into()));
        }
        Ok(())
    }
}

impl FromRequestParts<Arc<AppState>> for AuthUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let token = bearer_token(parts).ok_or(ApiError::Unauthorized)?;
        let claims = state.tokens.verify(&token)?;

        // Re-check the account so disabling a user takes effect on their next
        // request rather than when their token happens to expire.
        let repo = UserRepo::new(&state.db);
        let user = repo
            .find_by_username(&claims.username)
            .await?
            .ok_or(ApiError::Unauthorized)?;
        if user.disabled != 0 {
            return Err(ApiError::Forbidden("account is disabled".into()));
        }
        // A token that outlived a user id change is not valid for the new one.
        if user.id != claims.sub {
            return Err(ApiError::Unauthorized);
        }

        Ok(AuthUser {
            claims,
            must_change_password: user.must_change_password != 0,
        })
    }
}

/// 已认证的 agent。
///
/// 认证凭据是**组令牌**，机器记录在首次请求时按需创建。这让一键对接成为可能：
/// 同一条安装命令在多台机器上执行，它们各自登记进同一个组，无需回面板逐台签发
/// 凭据。
#[derive(Debug, Clone)]
pub struct AuthAgent {
    pub node: NodeRow,
    pub group: tunnel_storage::models::DeviceGroupRow,
}

/// 机器名的合法字符集。
///
/// agent 上报的名字会进入数据库并显示在面板上，必须限制字符集：它来自网络，
/// 不能假定可信。同时长度设上限，避免一个恶意 agent 用超长名字撑爆表。
fn sanitise_agent_name(raw: &str) -> Option<String> {
    let name: String = raw
        .trim()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
        .take(48)
        .collect();
    (!name.is_empty()).then_some(name)
}

impl FromRequestParts<Arc<AppState>> for AuthAgent {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get(AGENT_TOKEN_HEADER)
            .and_then(|v| v.to_str().ok())
            .ok_or(ApiError::Unauthorized)?
            .to_string();

        // 仅凭令牌定位组。未知令牌与停用组返回同一结果，不给攻击者区分依据。
        let groups = tunnel_storage::groups::DeviceGroupRepo::new(&state.db);
        let group = groups
            .find_by_token(&token)
            .await?
            .ok_or(ApiError::Unauthorized)?;

        let header = |name: &str| {
            parts
                .headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        };

        // 机器名缺失或全是非法字符时用主机名兜底，再不行退化到一个稳定占位名 ——
        // 让 agent 因为一个展示字段而无法上线是不值得的。
        let name = header(AGENT_NAME_HEADER)
            .as_deref()
            .and_then(sanitise_agent_name)
            .or_else(|| header(AGENT_HOSTNAME_HEADER).as_deref().and_then(sanitise_agent_name))
            .unwrap_or_else(|| "unnamed".to_string());
        let hostname = header(AGENT_HOSTNAME_HEADER).as_deref().and_then(sanitise_agent_name);

        // 角色受组类型约束：出口组里的机器不能自称 entry。
        let requested_role = header(AGENT_ROLE_HEADER).unwrap_or_default();
        let role = clamp_role_to_group(&requested_role, &group.kind);

        let repo = NodeRepo::new(&state.db);
        let dto = repo.register(&group.id, &name, hostname, role).await?;
        let node = repo.get_row(&dto.id).await?;

        if node.enabled == 0 {
            // 机器被管理员单独停用：组令牌有效，但这台不该继续服务。
            return Err(ApiError::Forbidden("该机器已被停用".into()));
        }

        Ok(AuthAgent { node, group })
    }
}

/// 把 agent 自报的角色收敛到组类型允许的范围内。
///
/// 防的是配置漂移：一台机器的本地配置写了 `role = both`，但它所在的组只做出口。
/// 若照搬 agent 的声明，它会去监听入口端口 —— 而那条线路的入口在别的组。
fn clamp_role_to_group(requested: &str, group_kind: &str) -> &'static str {
    match group_kind {
        "inbound" => "entry",
        "outbound" => "exit",
        // both 类型的组尊重 agent 的声明，非法值回落到 both。
        _ => match requested.trim() {
            "entry" => "entry",
            "exit" => "exit",
            _ => "both",
        },
    }
}

/// Extract the bearer token from `Authorization`, or from a `token` query
/// parameter.
///
/// The query fallback exists solely for WebSocket connections: the browser
/// WebSocket API cannot set headers. It is accepted only on the WS route.
fn bearer_token(parts: &Parts) -> Option<String> {
    if let Some(value) = parts.headers.get(axum::http::header::AUTHORIZATION) {
        let text = value.to_str().ok()?;
        // Case-insensitive scheme, per RFC 7235.
        let (scheme, token) = text.split_once(' ')?;
        if scheme.eq_ignore_ascii_case("bearer") && !token.trim().is_empty() {
            return Some(token.trim().to_string());
        }
    }
    None
}

/// Token from the `token` query parameter, for WebSocket upgrades.
pub fn query_token(query: Option<&str>) -> Option<String> {
    let query = query?;
    for pair in query.split('&') {
        let mut kv = pair.splitn(2, '=');
        if kv.next()? == "token" {
            let value = kv.next()?;
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// Client IP, honouring `X-Forwarded-For` only for loopback peers.
///
/// Trusting the header unconditionally would let any client spoof its address
/// and defeat per-IP login throttling. Trusting it only when the immediate peer
/// is loopback covers the normal "nginx on the same host" deployment without
/// opening that hole.
pub fn client_ip(parts: &Parts) -> Option<IpAddr> {
    client_ip_with_proxies(parts, &[])
}

/// 同上，但额外信任 `trusted_proxies` 里的地址段。
///
/// Docker 部署中反代与控制面在不同容器里，对端是容器网段而非回环，所以必须能显式
/// 声明哪些来源的 `X-Forwarded-For` 可信。不这么做的话按 IP 限流会退化成全局限流 ——
/// 所有请求都来自反代那一个地址。
pub fn client_ip_with_proxies(parts: &Parts, trusted: &[String]) -> Option<IpAddr> {
    let peer = parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip());

    let peer_trusted = peer
        .map(|ip| ip.is_loopback() || ip_in_any_cidr(ip, trusted))
        .unwrap_or(false);

    if peer_trusted {
        if let Some(forwarded) = parts
            .headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
        {
            // Leftmost entry is the original client.
            if let Some(first) = forwarded.split(',').next() {
                if let Ok(ip) = first.trim().parse::<IpAddr>() {
                    return Some(ip);
                }
            }
        }
    }
    peer
}

/// `ip` 是否落在任一 CIDR 内。
fn ip_in_any_cidr(ip: IpAddr, cidrs: &[String]) -> bool {
    cidrs.iter().any(|c| ip_in_cidr(ip, c))
}

/// 单个 CIDR 匹配，如 `172.18.0.0/16`。
///
/// 自己实现而不引入依赖：逻辑只有几行，而多一个依赖就多一处供应链面。
///
/// 无法解析的 CIDR 返回 `false`（不匹配），而不是放行。配置写错时的后果应当是
/// 「限流按代理地址算」这种可察觉的退化，而不是「任何人都能伪造来源 IP」。
fn ip_in_cidr(ip: IpAddr, cidr: &str) -> bool {
    let cidr = cidr.trim();
    if cidr.is_empty() {
        return false;
    }

    // 没有 `/` 时当成单个地址，等价于 /32 或 /128。
    let (net_str, prefix_str) = match cidr.split_once('/') {
        Some((n, p)) => (n, Some(p)),
        None => (cidr, None),
    };

    let Ok(net) = net_str.trim().parse::<IpAddr>() else {
        return false;
    };

    // IPv4 与 IPv6 不互相匹配。把 IPv4 映射地址也算进 IPv6 网段会带来一类很隐蔽的
    // 绕过，这里不做那种转换。
    match (ip, net) {
        (IpAddr::V4(ip), IpAddr::V4(net)) => {
            let prefix = match prefix_str {
                None => 32,
                Some(p) => match p.trim().parse::<u8>() {
                    Ok(v) if v <= 32 => v,
                    _ => return false,
                },
            };
            // /0 匹配一切。u32 左移 32 位是未定义行为，所以单独处理。
            if prefix == 0 {
                return true;
            }
            let mask = u32::MAX << (32 - prefix);
            (u32::from(ip) & mask) == (u32::from(net) & mask)
        }
        (IpAddr::V6(ip), IpAddr::V6(net)) => {
            let prefix = match prefix_str {
                None => 128,
                Some(p) => match p.trim().parse::<u8>() {
                    Ok(v) if v <= 128 => v,
                    _ => return false,
                },
            };
            if prefix == 0 {
                return true;
            }
            let mask = u128::MAX << (128 - prefix);
            (u128::from(ip) & mask) == (u128::from(net) & mask)
        }
        // 版本不同，不匹配。
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderValue, Request};

    fn parts_with(headers: Vec<(&str, &str)>) -> Parts {
        let mut builder = Request::builder().uri("/");
        for (k, v) in headers {
            builder = builder.header(k, v);
        }
        builder.body(()).unwrap().into_parts().0
    }

    #[test]
    fn bearer_token_is_extracted() {
        let parts = parts_with(vec![("authorization", "Bearer abc.def.ghi")]);
        assert_eq!(bearer_token(&parts).as_deref(), Some("abc.def.ghi"));
    }

    #[test]
    fn bearer_scheme_is_case_insensitive() {
        for scheme in ["Bearer", "bearer", "BEARER"] {
            let parts = parts_with(vec![("authorization", &format!("{scheme} tok"))]);
            assert_eq!(bearer_token(&parts).as_deref(), Some("tok"), "{scheme}");
        }
    }

    #[test]
    fn malformed_authorization_headers_are_ignored() {
        for header in ["", "Bearer", "Bearer   ", "Basic dXNlcjpwYXNz", "tok"] {
            let parts = parts_with(vec![("authorization", header)]);
            assert!(bearer_token(&parts).is_none(), "accepted `{header}`");
        }
    }

    #[test]
    fn missing_authorization_yields_none() {
        assert!(bearer_token(&parts_with(vec![])).is_none());
    }

    #[test]
    fn query_token_is_parsed_for_websockets() {
        assert_eq!(query_token(Some("token=abc")).as_deref(), Some("abc"));
        assert_eq!(
            query_token(Some("foo=1&token=xyz&bar=2")).as_deref(),
            Some("xyz")
        );
        assert!(query_token(Some("foo=1")).is_none());
        assert!(query_token(Some("token=")).is_none());
        assert!(query_token(None).is_none());
    }

    #[test]
    fn forwarded_for_is_ignored_when_the_peer_is_not_local() {
        // The security-relevant case: a remote client claiming to be someone
        // else must not escape login throttling.
        let mut parts = parts_with(vec![("x-forwarded-for", "203.0.113.50")]);
        let remote: SocketAddr = "198.51.100.7:1234".parse().unwrap();
        parts.extensions.insert(ConnectInfo(remote));

        assert_eq!(
            client_ip(&parts),
            Some("198.51.100.7".parse().unwrap()),
            "spoofed X-Forwarded-For was trusted from a remote peer"
        );
    }

    #[test]
    fn forwarded_for_is_honoured_behind_a_local_proxy() {
        let mut parts = parts_with(vec![("x-forwarded-for", "203.0.113.50, 10.0.0.1")]);
        let local: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        parts.extensions.insert(ConnectInfo(local));

        assert_eq!(
            client_ip(&parts),
            Some("203.0.113.50".parse().unwrap()),
            "the original client address should be used behind a local proxy"
        );
    }

    #[test]
    fn malformed_forwarded_for_falls_back_to_the_peer() {
        let mut parts = parts_with(vec![("x-forwarded-for", "not-an-ip")]);
        let local: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        parts.extensions.insert(ConnectInfo(local));
        assert_eq!(client_ip(&parts), Some("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn no_connect_info_yields_none() {
        assert!(client_ip(&parts_with(vec![])).is_none());
    }

    #[test]
    fn cidr_matching_covers_the_docker_case() {
        // Docker 默认桥接网段，这是这个功能存在的直接原因。
        assert!(ip_in_cidr("172.18.0.5".parse().unwrap(), "172.18.0.0/16"));
        assert!(ip_in_cidr("172.18.255.254".parse().unwrap(), "172.18.0.0/16"));
        // 相邻网段不该命中。
        assert!(!ip_in_cidr("172.19.0.5".parse().unwrap(), "172.18.0.0/16"));
        assert!(!ip_in_cidr("203.0.113.9".parse().unwrap(), "172.18.0.0/16"));
    }

    #[test]
    fn cidr_prefix_boundaries_are_exact() {
        // 掩码算错一位就会多信任或少信任一半地址。
        assert!(ip_in_cidr("10.0.0.255".parse().unwrap(), "10.0.0.0/24"));
        assert!(!ip_in_cidr("10.0.1.0".parse().unwrap(), "10.0.0.0/24"));
        assert!(ip_in_cidr("10.0.1.0".parse().unwrap(), "10.0.0.0/23"));
        assert!(!ip_in_cidr("10.0.2.0".parse().unwrap(), "10.0.0.0/23"));

        // /32 只匹配自己。
        assert!(ip_in_cidr("192.168.1.1".parse().unwrap(), "192.168.1.1/32"));
        assert!(!ip_in_cidr("192.168.1.2".parse().unwrap(), "192.168.1.1/32"));

        // /0 匹配一切 —— u32 左移 32 位是未定义行为，这条盯着那个分支。
        assert!(ip_in_cidr("8.8.8.8".parse().unwrap(), "0.0.0.0/0"));
    }

    #[test]
    fn a_bare_address_behaves_as_a_single_host() {
        assert!(ip_in_cidr("127.0.0.1".parse().unwrap(), "127.0.0.1"));
        assert!(!ip_in_cidr("127.0.0.2".parse().unwrap(), "127.0.0.1"));
    }

    #[test]
    fn malformed_cidrs_never_match() {
        // 配置写错的后果应当是「限流按代理地址算」这种可察觉的退化，
        // 而不是「任何人都能伪造来源 IP」。
        let ip: IpAddr = "172.18.0.5".parse().unwrap();
        for bad in [
            "",
            "   ",
            "not-an-ip",
            "172.18.0.0/",
            "172.18.0.0/33", // 超出 IPv4 前缀范围
            "172.18.0.0/-1",
            "172.18.0.0/abc",
            "172.18.0.0/16/24",
            "999.999.999.999/16",
        ] {
            assert!(!ip_in_cidr(ip, bad), "非法 CIDR 却匹配了: {bad:?}");
        }
    }

    #[test]
    fn ipv4_and_ipv6_do_not_cross_match() {
        // 把 IPv4 映射地址算进 IPv6 网段会带来很隐蔽的绕过。
        assert!(!ip_in_cidr("172.18.0.5".parse().unwrap(), "::/0"));
        assert!(!ip_in_cidr("::1".parse().unwrap(), "0.0.0.0/0"));
        assert!(!ip_in_cidr(
            "::ffff:172.18.0.5".parse().unwrap(),
            "172.18.0.0/16"
        ));
    }

    #[test]
    fn ipv6_cidr_matching_works() {
        assert!(ip_in_cidr("fd00::5".parse().unwrap(), "fd00::/8"));
        assert!(!ip_in_cidr("fe00::5".parse().unwrap(), "fd00::/8"));
        assert!(ip_in_cidr("2001:db8::1".parse().unwrap(), "2001:db8::/32"));
        assert!(!ip_in_cidr("2001:db9::1".parse().unwrap(), "2001:db8::/32"));
        assert!(ip_in_cidr("::1".parse().unwrap(), "::/0"));
    }

    #[test]
    fn a_trusted_proxy_peer_may_set_the_forwarded_header() {
        // Docker 场景：对端是容器网段而非回环。不信任它的话，所有请求都会被算成
        // 反代容器的地址，按 IP 的登录限流退化成全局限流 —— 一个人输错密码会把
        // 所有人一起锁在门外。
        let mut parts = parts_with(vec![("x-forwarded-for", "203.0.113.50")]);
        parts
            .extensions
            .insert(ConnectInfo(SocketAddr::from(([172, 18, 0, 3], 54321))));

        // 未配置可信网段时不采信。
        assert_eq!(
            client_ip_with_proxies(&parts, &[]),
            Some("172.18.0.3".parse().unwrap()),
            "未声明可信代理却采信了 X-Forwarded-For"
        );

        // 声明之后采信。
        assert_eq!(
            client_ip_with_proxies(&parts, &["172.18.0.0/16".to_string()]),
            Some("203.0.113.50".parse().unwrap()),
            "已声明可信代理却没有采信 X-Forwarded-For"
        );
    }

    #[test]
    fn an_untrusted_remote_peer_still_cannot_spoof() {
        // 这是这套判定存在的根本原因：公网客户端直接连上来并自带该头。
        let mut parts = parts_with(vec![("x-forwarded-for", "10.0.0.1")]);
        parts
            .extensions
            .insert(ConnectInfo(SocketAddr::from(([203, 0, 113, 77], 443))));
        assert_eq!(
            client_ip_with_proxies(&parts, &["172.18.0.0/16".to_string()]),
            Some("203.0.113.77".parse().unwrap()),
            "不在可信网段内的对端伪造了来源地址"
        );
    }

    #[test]
    fn agent_headers_are_named_consistently() {
        // 这些名字是 agent 契约的一部分，改动会静默破坏所有已部署的 agent。
        assert_eq!(AGENT_TOKEN_HEADER, "x-agent-token");
        assert_eq!(AGENT_NAME_HEADER, "x-agent-name");
        assert_eq!(AGENT_HOSTNAME_HEADER, "x-agent-hostname");
        assert_eq!(AGENT_ROLE_HEADER, "x-agent-role");
        assert!(!HeaderValue::from_static("x").is_empty());
    }

    #[test]
    fn agent_names_are_sanitised() {
        // 名字来自网络，会进数据库并显示在面板上。
        assert_eq!(sanitise_agent_name("hk-01").as_deref(), Some("hk-01"));
        assert_eq!(
            sanitise_agent_name("hk_01.internal").as_deref(),
            Some("hk_01.internal")
        );
        // 路径分隔符、引号、控制字符被剔除。
        assert_eq!(
            sanitise_agent_name("../../etc/passwd").as_deref(),
            Some("....etcpasswd")
        );
        assert_eq!(sanitise_agent_name("a'b\"c;d").as_deref(), Some("abcd"));
        // 长度被截断，避免超长名字撑爆表。
        assert_eq!(sanitise_agent_name(&"x".repeat(500)).unwrap().len(), 48);
        // 全是非法字符或空白时返回 None，由调用方兜底。
        assert!(sanitise_agent_name("   ").is_none());
        assert!(sanitise_agent_name("!@#$%").is_none());
    }

    #[test]
    fn role_is_clamped_to_the_group_kind() {
        // 防配置漂移：出口组里的机器即使自称 both，也只能做出口。
        assert_eq!(clamp_role_to_group("both", "outbound"), "exit");
        assert_eq!(clamp_role_to_group("entry", "outbound"), "exit");
        assert_eq!(clamp_role_to_group("exit", "inbound"), "entry");
        // both 类型的组尊重 agent 的声明。
        assert_eq!(clamp_role_to_group("entry", "both"), "entry");
        assert_eq!(clamp_role_to_group("exit", "both"), "exit");
        // 非法或缺失的声明回落到 both，而不是拒绝上线。
        assert_eq!(clamp_role_to_group("sideways", "both"), "both");
        assert_eq!(clamp_role_to_group("", "both"), "both");
    }

    #[test]
    fn password_rotation_gate_blocks_mutations() {
        let user = AuthUser {
            claims: Claims {
                sub: "u1".into(),
                username: "admin".into(),
                role: "admin".into(),
                exp: 0,
                iat: 0,
            },
            must_change_password: true,
        };
        assert!(user.require_password_rotated().is_err());
        assert!(user.require_admin().is_ok());

        let rotated = AuthUser {
            must_change_password: false,
            ..user
        };
        assert!(rotated.require_password_rotated().is_ok());
    }

    #[test]
    fn non_admin_role_is_refused_admin_actions() {
        let user = AuthUser {
            claims: Claims {
                sub: "u1".into(),
                username: "viewer".into(),
                role: "viewer".into(),
                exp: 0,
                iat: 0,
            },
            must_change_password: false,
        };
        assert!(user.require_admin().is_err());
    }
}
