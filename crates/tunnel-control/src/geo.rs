//! 公网 IP → 国家查询。
//!
//! # 为什么在控制面查，而不是让浏览器查
//!
//! 以前是面板前端直接请求 api.country.is。那样每个打开面板的访客都会把**全部中转机
//! 的公网 IP** 发给第三方；而面板下发的 CSP（`connect-src 'self'`）本来就拦住了这个
//! 请求，所以地区一直显示「—」。
//!
//! 改在控制面查：每个 IP 只查一次，结果进数据库缓存，面板从机器数据里直接拿。
//!
//! # 为什么不引入 HTTP 客户端库
//!
//! 请求只有一种：`GET https://api.country.is/<ip>`，响应是几十字节的 JSON。
//! 为它引入 reqwest 会带进来一整棵依赖树。这里照 agent 的 control client 的做法，
//! 用已有的 rustls + tokio-rustls 发一个 HTTP/1.1 请求 —— 这两个早就是 workspace
//! 依赖了。
//!
//! # 对外部服务的防御
//!
//! 这是本系统唯一一处主动访问第三方的地方，所以：
//! * 总超时 5 秒，拖不住任何东西；
//! * 查询在后台任务里跑，从不阻塞心跳；
//! * 响应体上限 4 KiB，对方返回什么都不会撑爆内存；
//! * 只接受两个大写字母的国家代码，对方返回别的一律当作失败；
//! * 失败后退避一段时间再试，不会对一个查不到的 IP 每 10 秒打一次。

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::OnceCell;
use tokio_rustls::TlsConnector;

use tunnel_storage::geo::GeoRepo;
use tunnel_storage::Database;

const HOST: &str = "api.country.is";
const PORT: u16 = 443;

/// 单次查询的总时限，含 DNS、TCP、TLS 握手与读响应。
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

/// 整个响应（响应头 + 正文）的上限。
///
/// 正文只有约 31 字节，但**响应头**不小：这个 API 走 Cloudflare，实测一次完整响应
/// 752 字节，大头是 `Report-To` / `Nel` 这类 CDN 注入的头。这些头的长度不由对方
/// 服务控制，CDN 那边一次配置变更就可能让它翻倍 —— 上限若卡得太死，所有查询会一起
/// 静默失败。16 KiB 留足余量，同时仍然挡住任何不正常的大响应。
const MAX_RESPONSE: usize = 16 * 1024;

/// 失败后多久才重试。
///
/// 一小时：足够长，不会对查不到的 IP 反复请求；又足够短，网络恢复后当天就能补上。
const RETRY_AFTER_FAILURE: chrono::Duration = chrono::Duration::hours(1);

/// 是否值得查询这个地址。
///
/// 内网、回环、链路本地、保留段查了也没有意义（对方要么返回错误，要么返回一个
/// 无关的结果），而且把内网拓扑发给第三方毫无必要。
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast()
                // 100.64.0.0/10 运营商级 NAT
                || (o[0] == 100 && (64..=127).contains(&o[1]))
                // 198.18.0.0/15 基准测试网段。国内一些 DNS 劫持会把域名解析到这里，
                // 查了也只会得到垃圾结果。
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
                // 240.0.0.0/4 保留
                || o[0] >= 240)
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // fe80::/10 链路本地
                || (s[0] & 0xffc0) == 0xfe80
                // fc00::/7 唯一本地地址
                || (s[0] & 0xfe00) == 0xfc00
                // 2001:db8::/32 文档用
                || (s[0] == 0x2001 && s[1] == 0x0db8)
                // 2001:2::/48 基准测试网段
                || (s[0] == 0x2001 && s[1] == 0x0002 && s[2] == 0)
                // ::ffff:0:0/96 IPv4 映射地址 —— 应按 IPv4 查
                || v6.to_ipv4_mapped().is_some())
        }
    }
}

/// 在缓存里没有、或上次失败已超过退避期时才需要查。
fn needs_lookup(entry: Option<&tunnel_storage::geo::GeoEntry>) -> bool {
    let Some(entry) = entry else {
        return true;
    };
    if !entry.failed {
        // 查到过就不再查。IP 的归属国家基本不会变，重查只是浪费。
        return false;
    }
    match chrono::DateTime::parse_from_rfc3339(&entry.looked_up_at) {
        Ok(at) => chrono::Utc::now().signed_duration_since(at) >= RETRY_AFTER_FAILURE,
        // 时间戳坏了就当作可以重试，不让一行坏数据永远锁住这个 IP。
        Err(_) => true,
    }
}

/// 从响应体里取出国家代码。
///
/// 只接受两个 ASCII 大写字母。对方返回任何别的东西都视为失败 —— 这个值会原样出现
/// 在面板上，不能让第三方往里塞任意字符串。
fn parse_country(body: &[u8]) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct Response {
        country: Option<String>,
    }
    let parsed: Response = serde_json::from_slice(body).ok()?;
    let code = parsed.country?.trim().to_ascii_uppercase();
    (code.len() == 2 && code.bytes().all(|b| b.is_ascii_uppercase())).then_some(code)
}

/// 响应是否已完整收到：响应头结束，且正文达到 `Content-Length` 声明的长度。
///
/// 没有 `Content-Length` 时返回 false，读取会一直进行到对方关闭连接为止。
fn response_complete(raw: &[u8]) -> bool {
    let Some(head_end) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
        return false;
    };
    let Ok(head) = std::str::from_utf8(&raw[..head_end]) else {
        return false;
    };
    let declared = head.lines().skip(1).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<usize>().ok())
            .flatten()
    });
    match declared {
        Some(len) => raw.len() >= head_end + 4 + len,
        None => false,
    }
}

/// 从原始 HTTP 响应里拆出状态码与正文。
///
/// 只处理这个 API 实际会返回的形状：`Content-Length` 或连接关闭。对方若用 chunked
/// 编码，正文里会混着分块长度，JSON 解析会失败 —— 那就是一次失败的查询，退避后重试，
/// 不会产生错误数据。
fn split_response(raw: &[u8]) -> Option<(u16, &[u8])> {
    let head_end = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&raw[..head_end]).ok()?;
    let status: u16 = head.split_whitespace().nth(1)?.parse().ok()?;
    Some((status, &raw[head_end + 4..]))
}

pub struct GeoLookup {
    tls: OnceCell<Option<TlsConnector>>,
    /// 正在查询中的 IP。同一个 IP 的多次心跳不该并发发出多个请求。
    in_flight: dashmap::DashSet<String>,
    /// 已确认查到国家的 IP。命中后连后台任务都不再 spawn。
    ///
    /// 没有它的话，每台机器每次心跳（10 秒一次）都要 spawn 一个任务去读一次缓存表，
    /// 永远如此 —— 即使那个 IP 早就查到了。集合大小以机器数为上限，不会无界增长。
    resolved: dashmap::DashSet<String>,
}

impl GeoLookup {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            tls: OnceCell::new(),
            in_flight: dashmap::DashSet::new(),
            resolved: dashmap::DashSet::new(),
        })
    }

    /// 系统 CA 为空时返回 None —— 控制面不会因此启动失败，只是地区查不了。
    async fn connector(&self) -> Option<&TlsConnector> {
        self.tls
            .get_or_init(|| async {
                let mut roots = RootCertStore::empty();
                for cert in rustls_native_certs::load_native_certs().certs {
                    let _ = roots.add(cert);
                }
                if roots.is_empty() {
                    tracing::warn!("系统 CA 证书为空，无法查询 IP 地区");
                    return None;
                }
                let mut config = ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth();
                config.alpn_protocols = vec![b"http/1.1".to_vec()];
                Some(TlsConnector::from(Arc::new(config)))
            })
            .await
            .as_ref()
    }

    /// 发一次查询。任何失败都返回 None，调用方据此记录失败并退避。
    async fn fetch(&self, ip: IpAddr) -> Option<String> {
        let connector = self.connector().await?;
        let request = format!(
            "GET /{ip} HTTP/1.1\r\n\
             Host: {HOST}\r\n\
             User-Agent: tunnel-control/{}\r\n\
             Accept: application/json\r\n\
             Connection: close\r\n\r\n",
            tunnel_common::AGENT_VERSION
        );

        let work = async {
            let tcp = tokio::net::TcpStream::connect((HOST, PORT)).await.ok()?;
            let server_name = rustls_pki_types::ServerName::try_from(HOST).ok()?.to_owned();
            let mut tls = connector.connect(server_name, tcp).await.ok()?;
            tls.write_all(request.as_bytes()).await.ok()?;

            // 按 Content-Length 读够就停，不等连接关闭。
            //
            // 不能用 read_to_end：TLS 对端常常不发 close_notify 就直接关 TCP，那时
            // read_to_end 返回 unexpected-EOF 错误 —— 响应其实早已完整收到，却被当成
            // 失败，地区就永远停在「识别中」。agent 的 control client 也是这样处理的。
            let mut raw = Vec::with_capacity(1024);
            let mut chunk = [0u8; 4096];
            loop {
                let n = match tls.read(&mut chunk).await {
                    Ok(0) => break,
                    Ok(n) => n,
                    // 已经拿到完整响应时，连接上的错误（多半是缺 close_notify）无关紧要。
                    Err(_) if response_complete(&raw) => break,
                    Err(_) => return None,
                };
                if raw.len() + n > MAX_RESPONSE {
                    return None;
                }
                raw.extend_from_slice(&chunk[..n]);
                if response_complete(&raw) {
                    break;
                }
            }
            let (status, body) = split_response(&raw)?;
            if status != 200 {
                return None;
            }
            parse_country(body)
        };

        tokio::time::timeout(LOOKUP_TIMEOUT, work).await.ok().flatten()
    }

    /// 若需要，就在后台查询这个 IP。立即返回，从不阻塞调用方。
    ///
    /// 在心跳处理里调用。心跳是 10 秒一次的热路径，这里只做一次内存判断与一次
    /// 缓存读取，真正的网络请求在 spawn 出去的任务里。
    pub fn refresh_in_background(self: &Arc<Self>, db: Database, ip: IpAddr) {
        if !is_public(ip) {
            return;
        }
        let key = ip.to_string();
        // 已查到过：绝大多数心跳在这里就返回，只是一次内存查找。
        if self.resolved.contains(&key) {
            return;
        }
        // insert 返回 false 表示已经在查了。
        if !self.in_flight.insert(key.clone()) {
            return;
        }

        let this = self.clone();
        tokio::spawn(async move {
            let repo = GeoRepo::new(&db);
            let entry = match repo.get(&key).await {
                Ok(entry) => entry,
                // 读缓存失败时不查：数据库有问题的时候不该再去打外部 API。
                Err(_) => {
                    this.in_flight.remove(&key);
                    return;
                }
            };
            if needs_lookup(entry.as_ref()) {
                match this.fetch(ip).await {
                    Some(country) => {
                        tracing::debug!(ip = %key, country = %country, "IP 地区查询成功");
                        if repo.record_success(&key, &country).await.is_ok() {
                            this.resolved.insert(key.clone());
                        }
                    }
                    None => {
                        tracing::debug!(ip = %key, "IP 地区查询失败，一小时后重试");
                        let _ = repo.record_failure(&key).await;
                    }
                }
            } else if entry.map(|e| !e.failed).unwrap_or(false) {
                // 缓存里已有成功结果（比如控制面重启后第一次心跳）：记进内存，
                // 此后这个 IP 连后台任务都不再触发。
                this.resolved.insert(key.clone());
            }
            this.in_flight.remove(&key);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunnel_storage::geo::GeoEntry;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn real_public_addresses_are_worth_looking_up() {
        for addr in ["151.244.134.139", "8.8.8.8", "1.1.1.1", "2606:4700::1111"] {
            assert!(is_public(ip(addr)), "{addr} 应视为公网");
        }
    }

    #[test]
    fn private_and_reserved_addresses_are_never_sent_out() {
        // 这些发给第三方要么查不到，要么泄露内网拓扑。
        for addr in [
            "10.0.0.1",
            "172.16.5.5",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1",  // 运营商级 NAT
            "100.127.255.254",
            "198.18.0.89", // 基准测试网段，DNS 劫持常解析到这里
            "198.19.255.1",
            "192.0.2.1",   // 文档用
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "240.0.0.1",
            "::1",
            "::",
            "fe80::1",
            "fd00::1",
            "fc00::1",
            "2001:db8::1",
            "2001:2::58", // 基准测试网段
            "ff02::1",
        ] {
            assert!(!is_public(ip(addr)), "{addr} 不该被查询");
        }
    }

    #[test]
    fn cgnat_boundaries_are_exact() {
        // 100.64.0.0/10 是 100.64.0.0 – 100.127.255.255，两侧都是公网。
        assert!(is_public(ip("100.63.255.255")));
        assert!(!is_public(ip("100.64.0.0")));
        assert!(!is_public(ip("100.127.255.255")));
        assert!(is_public(ip("100.128.0.0")));
    }

    #[test]
    fn ipv4_mapped_ipv6_is_not_queried_as_ipv6() {
        assert!(!is_public(ip("::ffff:8.8.8.8")));
    }

    #[test]
    fn country_codes_are_validated_before_reaching_the_panel() {
        assert_eq!(parse_country(br#"{"ip":"8.8.8.8","country":"US"}"#).as_deref(), Some("US"));
        // 小写也接受，统一转大写。
        assert_eq!(parse_country(br#"{"country":"hk"}"#).as_deref(), Some("HK"));
        // 这个值会原样出现在面板上 —— 不接受任何别的形状。
        for bad in [
            br#"{"country":"USA"}"#.as_slice(),
            br#"{"country":"U"}"#,
            br#"{"country":"<script>"}"#,
            br#"{"country":"1A"}"#,
            br#"{"country":""}"#,
            br#"{"country":null}"#,
            br#"{"error":"not found"}"#,
            b"not json",
            b"",
        ] {
            assert!(
                parse_country(bad).is_none(),
                "接受了非法响应 {:?}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn http_responses_are_split_into_status_and_body() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"country\":\"HK\"}";
        let (status, body) = split_response(raw).unwrap();
        assert_eq!(status, 200);
        assert_eq!(parse_country(body).as_deref(), Some("HK"));

        let (status, _) = split_response(b"HTTP/1.1 429 Too Many Requests\r\n\r\n").unwrap();
        assert_eq!(status, 429);

        assert!(split_response(b"garbage without a header terminator").is_none());
    }

    #[test]
    fn a_response_is_complete_once_content_length_is_satisfied() {
        // 这是不等 close_notify 就结束读取的依据。算错了要么提前截断正文，
        // 要么一直等到超时。
        let head = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 16\r\n\r\n";
        let full = format!("{head}{{\"country\":\"HK\"}}");
        assert!(response_complete(full.as_bytes()));

        // 正文还差几个字节。
        assert!(!response_complete(&full.as_bytes()[..full.len() - 3]));
        // 响应头都还没收完。
        assert!(!response_complete(b"HTTP/1.1 200 OK\r\nContent-Len"));
        // 头名大小写不敏感。
        let lower = "HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok";
        assert!(response_complete(lower.as_bytes()));
        // 没有 Content-Length：只能读到连接关闭为止。
        assert!(!response_complete(b"HTTP/1.1 200 OK\r\n\r\nwhatever"));
    }

    #[test]
    fn a_body_that_looks_like_a_header_does_not_confuse_completion() {
        // 只看响应头里的 Content-Length，正文里出现同名字样不算数。
        // 正文 `Content-Length: 1\r\n\r\n` 正好 21 字节。
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 21\r\n\r\nContent-Length: 1\r\n\r\n";
        assert!(!response_complete(&raw[..raw.len() - 1]));
        assert!(response_complete(raw));
    }

    /// 真实网络请求。默认不跑 —— CI 不该依赖第三方服务可用。
    ///
    /// 上面的单测只覆盖解析；这一条验证的是解析覆盖不到的部分：rustls 在本 crate
    /// 里能否初始化、TLS 握手、以及 CDN 返回的真实响应能否被完整读出。手工运行：
    ///
    ///   cargo test -p tunnel-control --lib geo::tests::live_lookup -- --ignored
    #[tokio::test]
    #[ignore = "需要访问公网 api.country.is"]
    async fn live_lookup_against_the_real_api() {
        let country = GeoLookup::new().fetch("8.8.8.8".parse().unwrap()).await;
        assert_eq!(country.as_deref(), Some("US"));
    }

    /// 等后台任务收尾：in_flight 清空即表示 spawn 出去的任务已经跑完。
    async fn settle(geo: &GeoLookup) {
        for _ in 0..200 {
            if geo.in_flight.is_empty() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("后台查询任务没有结束");
    }

    #[tokio::test]
    async fn a_cached_success_is_remembered_without_any_network_call() {
        // 控制面重启后第一次心跳：缓存里已有结果，应当直接记进内存，而不是再查一次。
        // 这里用文档网段以外、但缓存已命中的地址 —— 若真的发起了网络请求，
        // 缓存行会被改写，下面的断言就会失败。
        let db = Database::connect_in_memory().await.unwrap();
        GeoRepo::new(&db).record_success("151.244.134.139", "HK").await.unwrap();

        let geo = GeoLookup::new();
        geo.refresh_in_background(db.clone(), "151.244.134.139".parse().unwrap());
        settle(&geo).await;

        assert!(geo.resolved.contains("151.244.134.139"), "缓存命中后没有记入内存");
        let row = GeoRepo::new(&db).get("151.244.134.139").await.unwrap().unwrap();
        assert_eq!(row.country.as_deref(), Some("HK"));
        assert!(!row.failed);
    }

    #[tokio::test]
    async fn a_remembered_ip_does_not_even_spawn_a_task() {
        // 心跳 10 秒一次；查到之后的每一次都应该只是一次内存查找。
        let db = Database::connect_in_memory().await.unwrap();
        let geo = GeoLookup::new();
        geo.resolved.insert("8.8.8.8".into());

        geo.refresh_in_background(db.clone(), "8.8.8.8".parse().unwrap());
        assert!(geo.in_flight.is_empty(), "已知 IP 仍然触发了后台任务");
        // 缓存表也没被碰过。
        assert!(GeoRepo::new(&db).get("8.8.8.8").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn a_failure_inside_the_backoff_window_is_not_retried() {
        // 刚失败过的 IP：后台任务读到缓存、判断还在退避期，直接结束，不发请求，
        // 也不记入 resolved —— 退避期过后还要能重试。
        let db = Database::connect_in_memory().await.unwrap();
        GeoRepo::new(&db).record_failure("9.9.9.9").await.unwrap();
        let before = GeoRepo::new(&db).get("9.9.9.9").await.unwrap().unwrap();

        let geo = GeoLookup::new();
        geo.refresh_in_background(db.clone(), "9.9.9.9".parse().unwrap());
        settle(&geo).await;

        assert!(!geo.resolved.contains("9.9.9.9"));
        let after = GeoRepo::new(&db).get("9.9.9.9").await.unwrap().unwrap();
        assert_eq!(after.looked_up_at, before.looked_up_at, "退避期内又发起了查询");
    }

    #[tokio::test]
    async fn private_addresses_never_reach_the_background_task() {
        let db = Database::connect_in_memory().await.unwrap();
        let geo = GeoLookup::new();
        geo.refresh_in_background(db.clone(), "10.0.0.1".parse().unwrap());
        assert!(geo.in_flight.is_empty());
        assert!(GeoRepo::new(&db).get("10.0.0.1").await.unwrap().is_none());
    }

    fn entry(failed: bool, age: chrono::Duration) -> GeoEntry {
        GeoEntry {
            ip: "8.8.8.8".into(),
            country: (!failed).then(|| "US".into()),
            looked_up_at: (chrono::Utc::now() - age).to_rfc3339(),
            failed,
        }
    }

    #[test]
    fn an_unseen_ip_is_looked_up() {
        assert!(needs_lookup(None));
    }

    #[test]
    fn a_resolved_ip_is_never_looked_up_again() {
        // 国家归属基本不会变。一年前查到的也不重查。
        assert!(!needs_lookup(Some(&entry(false, chrono::Duration::days(365)))));
    }

    #[test]
    fn a_failed_ip_waits_out_the_backoff() {
        // 心跳 10 秒一次，失败后若不退避，就是每 10 秒打一次外部 API。
        assert!(!needs_lookup(Some(&entry(true, chrono::Duration::seconds(10)))));
        assert!(!needs_lookup(Some(&entry(true, chrono::Duration::minutes(59)))));
        assert!(needs_lookup(Some(&entry(true, chrono::Duration::minutes(61)))));
    }

    #[test]
    fn a_corrupt_timestamp_does_not_lock_the_ip_forever() {
        let mut e = entry(true, chrono::Duration::zero());
        e.looked_up_at = "not a timestamp".into();
        assert!(needs_lookup(Some(&e)));
    }
}
