//! 多目标选择：五种分配策略 + 失败熔断。
//!
//! # 为什么需要熔断而不只是分配策略
//!
//! 单纯按策略分配在一台目标挂掉时，每 N 个连接就有 1 个必然失败 —— 用户看到的是
//! 「时好时坏」，比完全不可用更难排查。所以失败的目标要被暂时跳过。
//!
//! # 为什么阈值和恢复都要保守
//!
//! 这和 [`crate::health`] 里端点故障转移是同一类问题：目标偶尔拨不通（对端重启、
//! 瞬时丢包）不该立刻把它踢出分配，否则一次抖动就让流量全压在剩下的机器上。所以
//! 要求**连续**失败达到阈值才熔断，一次成功就清零。
//!
//! 熔断后不是永久剔除，而是过一段冷却时间放连接过去试探。成功即恢复，失败则重新
//! 计时。这样目标恢复后能自动回到分配，不需要人工介入。
//!
//! # 与 health.rs 的区别
//!
//! `health.rs` 管的是**隧道端点**（入口该拨哪个出口地址），是主备关系，切换代价高
//! （要重建隧道池）。这里管的是**转发目标**，切换代价只有一次 TCP 连接，所以阈值
//! 可以更激进、恢复可以更快。
//!
//! # 与 LoadBalance 的区别
//!
//! [`tunnel_common::model::LoadBalance`] 决定一条连接走隧道池里的哪条隧道；这里
//! 决定连接落到哪台目标机器。两者正交，互不影响。

use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tunnel_common::model::TargetStrategy;

const REL: Ordering = Ordering::Relaxed;

/// 连续失败多少次后熔断。
///
/// 3 次：一次瞬时失败很常见，两次可能是巧合，三次基本可以判定目标有问题。
const FAILURE_THRESHOLD: u32 = 3;

/// 熔断后多久放连接过去试探。
///
/// 30 秒：短到目标恢复后用户几乎无感，长到不会在目标持续不可用时反复浪费连接。
const PROBE_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Debug)]
struct TargetState {
    addr: String,
    consecutive_failures: AtomicU32,
    /// 熔断开始时间。`None` 表示电路闭合（健康）。
    tripped_at: Mutex<Option<Instant>>,
    /// 当前活跃连接数。`least_conn` 据此选目标。
    ///
    /// 由 [`TargetLease`] 维护：取得租约时 +1，租约析构（连接结束）时 -1。让计数
    /// 跟着 RAII 走，而不是在 relay 的每条返回路径上手工减 —— 那样早退、panic、
    /// `?` 传播任何一处漏掉都会让计数永久偏高，最终这个目标再也不会被选中。
    active: AtomicU64,
    total_ok: AtomicU64,
    total_failed: AtomicU64,
}

impl TargetState {
    fn new(addr: String) -> Self {
        Self {
            addr,
            consecutive_failures: AtomicU32::new(0),
            tripped_at: Mutex::new(None),
            active: AtomicU64::new(0),
            total_ok: AtomicU64::new(0),
            total_failed: AtomicU64::new(0),
        }
    }

    /// 当前是否可参与分配。熔断且冷却未到则不可。
    fn is_available(&self) -> bool {
        match self.tripped_at.lock() {
            Ok(guard) => match *guard {
                None => true,
                // 冷却已过：放它参与分配，这一次就是试探。
                Some(at) => at.elapsed() >= PROBE_INTERVAL,
            },
            // 锁中毒只是统计层面的问题，不该让转发停摆 —— 当作可用，最坏情况是
            // 多试一次。
            Err(_) => true,
        }
    }

    /// 电路是否处于打开状态（已熔断，不论冷却是否到期）。
    ///
    /// 与 [`Self::is_available`] 分开是为了让面板能区分「健康」和「熔断中正在试探」
    /// —— 后者虽然会被选中，但它上一次拨号是失败的。
    fn is_tripped(&self) -> bool {
        self.tripped_at
            .lock()
            .map(|g| g.is_some())
            .unwrap_or(false)
    }

    fn record_success(&self) {
        self.consecutive_failures.store(0, REL);
        self.total_ok.fetch_add(1, REL);
        if let Ok(mut guard) = self.tripped_at.lock() {
            *guard = None;
        }
    }

    fn record_failure(&self) {
        self.total_failed.fetch_add(1, REL);
        // 饱和加法：持续失败的目标不该在计数回绕后突然显示为健康。
        // 取 fetch_update 返回的**旧**值再加一会在饱和处溢出，所以直接算新值。
        let failures = self
            .consecutive_failures
            .fetch_update(REL, REL, |n| Some(n.saturating_add(1)))
            .map(|prev| prev.saturating_add(1))
            .unwrap_or(1);
        if failures >= FAILURE_THRESHOLD {
            if let Ok(mut guard) = self.tripped_at.lock() {
                // 重新计时：持续失败时不断推后下次试探，避免每 30 秒都白试一轮。
                *guard = Some(Instant::now());
            }
        }
    }
}

/// 一次目标占用。
///
/// 存活期间该目标的活跃连接数 +1，析构时 -1。所以它必须跟着连接一起活到 relay
/// 结束 —— 提前 drop 会让 `least_conn` 以为这个目标是空闲的。
#[derive(Debug)]
pub struct TargetLease {
    state: Arc<TargetState>,
}

impl TargetLease {
    fn new(state: Arc<TargetState>) -> Self {
        state.active.fetch_add(1, REL);
        Self { state }
    }

    pub fn addr(&self) -> &str {
        &self.state.addr
    }

    /// 拨号成功。清零连续失败计数并关闭熔断。
    pub fn record_success(&self) {
        self.state.record_success();
    }

    /// 拨号失败。连续失败达阈值后该目标被熔断，后续连接自动绕开。
    pub fn record_failure(&self) {
        self.state.record_failure();
    }
}

impl Drop for TargetLease {
    fn drop(&mut self) {
        // 饱和减法：计数不该因为任何意外路径回绕成天文数字，那会让这个目标在
        // least_conn 下永远不被选中。
        let _ = self
            .state
            .active
            .fetch_update(REL, REL, |n| Some(n.saturating_sub(1)));
    }
}

/// 一条线路的目标集合。
#[derive(Debug)]
pub struct TargetSelector {
    targets: Vec<Arc<TargetState>>,
    strategy: TargetStrategy,
    /// 轮询游标。其他策略不用它。
    cursor: AtomicUsize,
}

/// 目标的对外状态，供面板展示与遥测上报。
#[derive(Debug, Clone, serde::Serialize)]
pub struct TargetStatus {
    pub addr: String,
    /// 当前是否会被分配到新连接。
    pub available: bool,
    /// 电路是否已熔断。`available && tripped` 表示正在试探。
    pub tripped: bool,
    pub active: u64,
    pub consecutive_failures: u32,
    pub total_ok: u64,
    pub total_failed: u64,
}

impl TargetSelector {
    /// `addrs` 不应为空 —— 调用方用 `Route::effective_targets()` 保证这点。
    /// 万一为空，这里不 panic，[`Self::pick`] 会返回 `None` 让上层报错。
    pub fn new(addrs: Vec<String>, strategy: TargetStrategy) -> Self {
        Self {
            targets: addrs
                .into_iter()
                .map(|a| Arc::new(TargetState::new(a)))
                .collect(),
            strategy,
            cursor: AtomicUsize::new(0),
        }
    }

    /// 从线路直接构造，策略与目标都取自它。
    pub fn from_route(route: &tunnel_common::model::Route) -> Self {
        Self::new(route.effective_targets(), route.target_strategy)
    }

    pub fn len(&self) -> usize {
        self.targets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }

    pub fn strategy(&self) -> TargetStrategy {
        self.strategy
    }

    /// 按策略挑一个目标，返回一份租约。
    ///
    /// `client_ip` 只有 `ip_hash` 用；其他策略忽略它，`None` 时 `ip_hash` 退化为
    /// 随机（拿不到客户端地址就无从保持会话，随机至少仍然均匀）。
    ///
    /// 全部熔断时仍返回一个候选，而不是 `None` —— 拒绝服务不如试一下：目标可能刚好
    /// 恢复了，而且此时报错和拨不通对用户是同一个结果。
    pub fn pick(&self, client_ip: Option<IpAddr>) -> Option<TargetLease> {
        if self.targets.is_empty() {
            return None;
        }
        if self.targets.len() == 1 {
            // 单目标时五种策略结果相同，省掉所有计算。
            return Some(TargetLease::new(self.targets[0].clone()));
        }

        let available = self.available_count();
        let state = if available == 0 {
            // 全部熔断：按策略给一个，让它去试。
            self.fallback(client_ip)
        } else {
            match self.strategy {
                TargetStrategy::Random => self.pick_random(available),
                TargetStrategy::RoundRobin => self.pick_round_robin(),
                TargetStrategy::IpHash => match client_ip {
                    Some(ip) => self.pick_ip_hash(ip),
                    None => self.pick_random(available),
                },
                TargetStrategy::LeastConn => self.pick_least_conn(),
                TargetStrategy::Failover => self.pick_failover(),
            }
        }?;
        Some(TargetLease::new(state))
    }

    /// 全部熔断时的退路：保持各策略的形状，只是不再看可用性。
    fn fallback(&self, client_ip: Option<IpAddr>) -> Option<Arc<TargetState>> {
        match self.strategy {
            TargetStrategy::IpHash => {
                if let Some(ip) = client_ip {
                    // 仍然按哈希映射：目标恢复后同一客户端回到同一台机器。
                    let idx = (hash_ip(ip) % self.targets.len() as u64) as usize;
                    return self.targets.get(idx).cloned();
                }
            }
            TargetStrategy::Failover => {
                // 主备语义下退路就是主：备机平时不承载流量。
                return self.targets.first().cloned();
            }
            _ => {}
        }
        let idx = self.cursor.fetch_add(1, REL) % self.targets.len();
        self.targets.get(idx).cloned()
    }

    /// 均匀随机挑一个可用目标。
    ///
    /// 两趟而非一趟蓄水池抽样：目标数很少，先数再走只需一次随机数，比每个元素都
    /// 摇一次便宜。
    fn pick_random(&self, available: usize) -> Option<Arc<TargetState>> {
        use rand::Rng;
        let nth = rand::thread_rng().gen_range(0..available);
        self.targets
            .iter()
            .filter(|t| t.is_available())
            .nth(nth)
            .cloned()
    }

    /// 按配置顺序轮流，跳过不可用的。
    fn pick_round_robin(&self) -> Option<Arc<TargetState>> {
        let start = self.cursor.fetch_add(1, REL);
        let n = self.targets.len();
        (0..n)
            .map(|offset| &self.targets[(start + offset) % n])
            .find(|t| t.is_available())
            .cloned()
    }

    /// 按客户端 IP 哈希固定映射。
    ///
    /// 取模的是**全部**目标数而非可用目标数：若按可用数取模，任何一台目标熔断都会
    /// 让所有客户端重新洗牌，会话保持全部失效。按全部取模再向后找可用目标，只有
    /// 原本映射到故障机的那部分客户端会迁移。
    fn pick_ip_hash(&self, ip: IpAddr) -> Option<Arc<TargetState>> {
        let n = self.targets.len();
        let start = (hash_ip(ip) % n as u64) as usize;
        (0..n)
            .map(|offset| &self.targets[(start + offset) % n])
            .find(|t| t.is_available())
            .cloned()
    }

    /// 挑当前活跃连接最少的可用目标。
    ///
    /// 并列时随机取一个，而不是固定取最靠前的 —— 启动时所有目标都是 0 连接，固定
    /// 取首个会让开头的一批连接全压到同一台机器上。
    fn pick_least_conn(&self) -> Option<Arc<TargetState>> {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut best: Option<(u64, &Arc<TargetState>)> = None;
        let mut ties = 0u32;

        for t in self.targets.iter().filter(|t| t.is_available()) {
            let active = t.active.load(REL);
            match best {
                None => {
                    best = Some((active, t));
                    ties = 1;
                }
                Some((best_active, _)) if active < best_active => {
                    best = Some((active, t));
                    ties = 1;
                }
                Some((best_active, _)) if active == best_active => {
                    // 蓄水池抽样：第 k 个并列者以 1/k 概率胜出，结果均匀。
                    ties += 1;
                    if rng.gen_range(0..ties) == 0 {
                        best = Some((active, t));
                    }
                }
                _ => {}
            }
        }
        best.map(|(_, t)| t.clone())
    }

    /// 最靠前的可用目标。主备语义。
    fn pick_failover(&self) -> Option<Arc<TargetState>> {
        self.targets.iter().find(|t| t.is_available()).cloned()
    }

    pub fn status(&self) -> Vec<TargetStatus> {
        self.targets
            .iter()
            .map(|t| TargetStatus {
                addr: t.addr.clone(),
                available: t.is_available(),
                tripped: t.is_tripped(),
                active: t.active.load(REL),
                consecutive_failures: t.consecutive_failures.load(REL),
                total_ok: t.total_ok.load(REL),
                total_failed: t.total_failed.load(REL),
            })
            .collect()
    }

    /// 上报给控制面的健康状态。
    ///
    /// 与 [`Self::status`] 的区别只在类型：那个是数据面内部结构，这个是与控制面之间
    /// 的协议类型，不该跟着内部实现一起变。
    pub fn health(&self) -> Vec<tunnel_common::model::TargetHealth> {
        self.targets
            .iter()
            .map(|t| tunnel_common::model::TargetHealth {
                addr: t.addr.clone(),
                available: t.is_available(),
                tripped: t.is_tripped(),
                active: t.active.load(REL),
                consecutive_failures: t.consecutive_failures.load(REL),
                total_ok: t.total_ok.load(REL),
                total_failed: t.total_failed.load(REL),
            })
            .collect()
    }

    /// 当前有多少个目标会被分配到新连接。面板据此提示「2/3 个目标可用」。
    pub fn available_count(&self) -> usize {
        self.targets.iter().filter(|t| t.is_available()).count()
    }

    /// 当前有多少个目标未熔断。比 [`Self::available_count`] 严格 —— 正在试探的
    /// 目标算「可用」但不算「健康」。
    pub fn healthy_count(&self) -> usize {
        self.targets.iter().filter(|t| !t.is_tripped()).count()
    }

    /// 指定地址的目标上取一份租约，绕过策略。
    ///
    /// 只给测试用：靠反复 `pick()` 直到命中某个目标在 `least_conn`/`failover` 下会
    /// 死循环（策略会稳定地给出别的目标）。
    #[cfg(test)]
    fn lease_of(&self, addr: &str) -> TargetLease {
        let state = self
            .targets
            .iter()
            .find(|t| t.addr == addr)
            .unwrap_or_else(|| panic!("目标 `{addr}` 不在列表里"));
        TargetLease::new(state.clone())
    }

    /// 指定地址的目标的状态，绕过策略。仅测试用。
    #[cfg(test)]
    fn state_of(&self, addr: &str) -> &Arc<TargetState> {
        self.targets
            .iter()
            .find(|t| t.addr == addr)
            .unwrap_or_else(|| panic!("目标 `{addr}` 不在列表里"))
    }
}

/// FNV-1a 哈希。
///
/// 自己实现而不用 `DefaultHasher`：`ip_hash` 的意义是同一个客户端固定落到同一台
/// 目标机，而一个入口**组**里有多台机器。若哈希函数在不同进程或不同 Rust 版本间
/// 结果不同，同一个客户端换一台入口机就会被分到别的目标，会话保持随之失效。FNV-1a
/// 的定义是固定的，这里的实现永远算出同一个值。
fn hash_ip(ip: IpAddr) -> u64 {
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;

    let mut hash = OFFSET_BASIS;
    let mut feed = |bytes: &[u8]| {
        for b in bytes {
            hash ^= u64::from(*b);
            hash = hash.wrapping_mul(PRIME);
        }
    };
    match ip {
        IpAddr::V4(v4) => feed(&v4.octets()),
        IpAddr::V6(v6) => feed(&v6.octets()),
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    fn selector(n: usize, strategy: TargetStrategy) -> TargetSelector {
        TargetSelector::new(
            (0..n).map(|i| format!("10.0.0.{}:443", i + 1)).collect(),
            strategy,
        )
    }

    /// 取地址并立刻释放租约 —— 测分配行为时不关心活跃计数。
    fn pick_addr(s: &TargetSelector) -> String {
        s.pick(None).unwrap().addr().to_string()
    }

    /// 把指定目标打到熔断。
    ///
    /// 直接对该目标记失败，不通过 `pick` —— `least_conn` 和 `failover` 会稳定地给出
    /// 别的目标，靠 pick 循环命中会死循环。
    fn trip(s: &TargetSelector, addr: &str) {
        let lease = s.lease_of(addr);
        for _ in 0..FAILURE_THRESHOLD {
            lease.record_failure();
        }
    }

    #[test]
    fn a_single_target_ignores_the_strategy() {
        for strategy in TargetStrategy::ALL {
            let s = selector(1, strategy);
            for _ in 0..5 {
                assert_eq!(pick_addr(&s), "10.0.0.1:443", "{strategy}");
            }
        }
    }

    #[test]
    fn an_empty_selector_yields_nothing() {
        let s = TargetSelector::new(vec![], TargetStrategy::Random);
        assert!(s.is_empty());
        assert!(s.pick(None).is_none());
    }

    // --- 轮询 ---

    #[test]
    fn round_robin_cycles_through_all_targets() {
        let s = selector(3, TargetStrategy::RoundRobin);
        let picks: Vec<String> = (0..6).map(|_| pick_addr(&s)).collect();
        let mut counts = std::collections::HashMap::new();
        for p in &picks {
            *counts.entry(p.clone()).or_insert(0) += 1;
        }
        assert_eq!(counts.len(), 3, "轮询没有覆盖全部目标: {picks:?}");
        assert!(counts.values().all(|&c| c == 2), "{counts:?}");
    }

    #[test]
    fn round_robin_is_deterministic_in_order() {
        let s = selector(3, TargetStrategy::RoundRobin);
        assert_eq!(pick_addr(&s), "10.0.0.1:443");
        assert_eq!(pick_addr(&s), "10.0.0.2:443");
        assert_eq!(pick_addr(&s), "10.0.0.3:443");
        assert_eq!(pick_addr(&s), "10.0.0.1:443");
    }

    // --- 随机 ---

    #[test]
    fn random_covers_every_target_and_is_roughly_even() {
        let s = selector(4, TargetStrategy::Random);
        let mut counts = std::collections::HashMap::new();
        for _ in 0..4000 {
            *counts.entry(pick_addr(&s)).or_insert(0) += 1;
        }
        assert_eq!(counts.len(), 4, "随机没有覆盖全部目标: {counts:?}");
        // 期望各 1000。放宽到 ±30% 以免偶发抖动让测试变得不可靠。
        for (addr, &c) in &counts {
            assert!((700..=1300).contains(&c), "{addr} 拿到 {c} 次: {counts:?}");
        }
    }

    #[test]
    fn random_is_the_default_strategy() {
        // 无共享游标、并发下天然均匀，也不会让多台入口机产生同步的分配节奏。
        assert_eq!(TargetStrategy::default(), TargetStrategy::Random);
    }

    // --- IP 哈希 ---

    #[test]
    fn ip_hash_maps_a_client_to_a_stable_target() {
        let s = selector(3, TargetStrategy::IpHash);
        let ip: IpAddr = "198.51.100.7".parse().unwrap();
        let first = s.pick(Some(ip)).unwrap().addr().to_string();
        for _ in 0..20 {
            assert_eq!(
                s.pick(Some(ip)).unwrap().addr(),
                first,
                "同一个客户端 IP 必须始终落到同一个目标"
            );
        }
    }

    #[test]
    fn ip_hash_spreads_different_clients() {
        let s = selector(3, TargetStrategy::IpHash);
        let mut seen = std::collections::HashSet::new();
        for i in 1..=60u8 {
            let ip: IpAddr = format!("198.51.100.{i}").parse().unwrap();
            seen.insert(s.pick(Some(ip)).unwrap().addr().to_string());
        }
        assert_eq!(seen.len(), 3, "60 个客户端应该分散到 3 个目标: {seen:?}");
    }

    #[test]
    fn ip_hash_is_stable_across_selector_instances() {
        // 同一个客户端在组内任意一台入口机上都必须算出同一个目标 —— 所以哈希不能
        // 依赖进程内的随机种子。
        let addrs: Vec<String> = (1..=4).map(|i| format!("10.0.0.{i}:443")).collect();
        let a = TargetSelector::new(addrs.clone(), TargetStrategy::IpHash);
        let b = TargetSelector::new(addrs, TargetStrategy::IpHash);
        for i in 1..=30u8 {
            let ip: IpAddr = format!("203.0.113.{i}").parse().unwrap();
            assert_eq!(
                a.pick(Some(ip)).unwrap().addr(),
                b.pick(Some(ip)).unwrap().addr(),
                "{ip} 在两个实例上映射到了不同目标"
            );
        }
    }

    #[test]
    fn ip_hash_without_a_client_ip_still_picks_something() {
        // 出口侧的 client_addr 是可选字段，拿不到时不能拒绝服务。
        let s = selector(3, TargetStrategy::IpHash);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            seen.insert(pick_addr(&s));
        }
        assert_eq!(seen.len(), 3, "无客户端 IP 时应退化为随机: {seen:?}");
    }

    #[test]
    fn ip_hash_only_remaps_the_clients_of_a_failed_target() {
        // 按可用数取模会让一台故障就全体洗牌；按全部取模只迁移受影响的那部分。
        let s = selector(3, TargetStrategy::IpHash);
        let ips: Vec<IpAddr> = (1..=90u8)
            .map(|i| format!("192.0.2.{i}").parse().unwrap())
            .collect();
        let before: Vec<String> = ips
            .iter()
            .map(|ip| s.pick(Some(*ip)).unwrap().addr().to_string())
            .collect();

        let victim = "10.0.0.2:443";
        trip(&s, victim);

        let after: Vec<String> = ips
            .iter()
            .map(|ip| s.pick(Some(*ip)).unwrap().addr().to_string())
            .collect();

        let moved = before
            .iter()
            .zip(&after)
            .filter(|(b, a)| b != a)
            .count();
        let on_victim = before.iter().filter(|b| *b == victim).count();
        assert!(on_victim > 0, "测试前提不成立：没有客户端映射到故障目标");
        assert_eq!(
            moved, on_victim,
            "只有原本落在故障目标上的客户端该迁移，实际迁移了 {moved} 个"
        );
        assert!(after.iter().all(|a| a != victim), "仍有客户端被分到故障目标");
    }

    // --- 最少连接数 ---

    #[test]
    fn least_conn_prefers_the_idle_target() {
        let s = selector(2, TargetStrategy::LeastConn);
        // 持有第一个目标的租约，让它的活跃数变成 3。
        let held: Vec<TargetLease> = (0..3).map(|_| s.lease_of("10.0.0.1:443")).collect();
        assert_eq!(held.len(), 3);

        for _ in 0..5 {
            assert_eq!(
                pick_addr(&s),
                "10.0.0.2:443",
                "活跃连接更少的目标才该被选中"
            );
        }
    }

    #[test]
    fn least_conn_recovers_when_a_lease_is_released() {
        let s = selector(2, TargetStrategy::LeastConn);
        let mut held = Vec::new();
        for _ in 0..4 {
            held.push(s.pick(None).unwrap());
        }
        // 两个目标各 2 条。放掉其中一个目标的全部租约，它就该重新被优先选中。
        let freed = held[0].addr().to_string();
        held.retain(|l| l.addr() != freed);
        assert_eq!(pick_addr(&s), freed, "释放租约后活跃数没有回落");
    }

    #[test]
    fn least_conn_alternates_when_all_are_idle() {
        // 全部空闲时并列，必须分散而不是固定取第一个 —— 否则启动时一批连接会全压
        // 到同一台机器上。
        let s = selector(3, TargetStrategy::LeastConn);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            seen.insert(pick_addr(&s));
        }
        assert_eq!(seen.len(), 3, "并列时没有分散: {seen:?}");
    }

    #[test]
    fn least_conn_balances_a_burst_of_concurrent_connections() {
        // 真实形状：一批连接同时到达并都保持着。每个都该落到当时最空的目标。
        let s = selector(4, TargetStrategy::LeastConn);
        let held: Vec<TargetLease> = (0..40).map(|_| s.pick(None).unwrap()).collect();

        let mut counts = std::collections::HashMap::new();
        for l in &held {
            *counts.entry(l.addr().to_string()).or_insert(0) += 1;
        }
        assert_eq!(counts.len(), 4);
        assert!(
            counts.values().all(|&c| c == 10),
            "40 条并发连接应在 4 个目标上各 10 条: {counts:?}"
        );
    }

    #[test]
    fn a_dropped_lease_decrements_the_active_count() {
        let s = selector(1, TargetStrategy::LeastConn);
        {
            let _l = s.pick(None).unwrap();
            assert_eq!(s.status()[0].active, 1);
        }
        assert_eq!(s.status()[0].active, 0, "租约析构后活跃计数没有归还");
    }

    // --- 故障转移 ---

    #[test]
    fn failover_always_uses_the_first_healthy_target() {
        let s = selector(3, TargetStrategy::Failover);
        for _ in 0..10 {
            assert_eq!(pick_addr(&s), "10.0.0.1:443", "备用机平时不该承载流量");
        }
    }

    #[test]
    fn failover_moves_to_the_next_target_and_back() {
        let s = selector(3, TargetStrategy::Failover);
        trip(&s, "10.0.0.1:443");
        assert_eq!(pick_addr(&s), "10.0.0.2:443", "主故障后应切到第二个");

        // 主恢复：试探拨通后新连接自动切回，不需要人工介入。
        s.state_of("10.0.0.1:443").record_success();
        assert_eq!(pick_addr(&s), "10.0.0.1:443", "主恢复后应切回");
    }

    // --- 熔断（与策略无关的共同行为） ---

    #[test]
    fn a_single_failure_does_not_remove_a_target() {
        // 瞬时失败很常见，一次就踢出会让一次抖动把流量全压给别人。
        let s = selector(2, TargetStrategy::RoundRobin);
        s.targets[0].record_failure();
        assert_eq!(s.available_count(), 2);
        s.targets[0].record_failure();
        assert_eq!(s.available_count(), 2, "两次仍不应熔断");
    }

    #[test]
    fn threshold_failures_trip_the_breaker_under_every_strategy() {
        for strategy in TargetStrategy::ALL {
            let s = selector(2, strategy);
            trip(&s, "10.0.0.1:443");
            assert_eq!(s.available_count(), 1, "{strategy}: 达到阈值应熔断");
            assert_eq!(s.healthy_count(), 1, "{strategy}");

            // 此后只给出健康的那个。ip_hash 也必须绕开。
            for _ in 0..6 {
                assert_eq!(
                    s.pick("198.51.100.1".parse().ok()).unwrap().addr(),
                    "10.0.0.2:443",
                    "{strategy}: 熔断的目标仍被选中"
                );
            }
        }
    }

    #[test]
    fn a_success_clears_the_failure_streak() {
        let s = selector(2, TargetStrategy::RoundRobin);
        s.targets[0].record_failure();
        s.targets[0].record_failure();
        s.targets[0].record_success();
        // 计数已清零，再失败两次仍不该熔断。
        s.targets[0].record_failure();
        s.targets[0].record_failure();
        assert_eq!(s.available_count(), 2);
    }

    #[test]
    fn alternating_results_never_trip_the_breaker() {
        // 成败交替的目标不该被熔断 —— 只有连续失败才算。
        let s = selector(2, TargetStrategy::RoundRobin);
        for _ in 0..30 {
            s.targets[0].record_failure();
            s.targets[0].record_failure();
            s.targets[0].record_success();
        }
        assert_eq!(s.available_count(), 2);
        assert_eq!(s.healthy_count(), 2);
    }

    #[test]
    fn a_recovered_target_rejoins_after_a_success() {
        let s = selector(2, TargetStrategy::RoundRobin);
        trip(&s, "10.0.0.1:443");
        assert_eq!(s.available_count(), 1);

        s.targets[0].record_success();
        assert_eq!(s.available_count(), 2, "试探成功后应立即回到分配");
        assert_eq!(s.healthy_count(), 2);
    }

    #[test]
    fn all_targets_tripped_still_yields_a_candidate() {
        // 拒绝服务不如试一下：目标可能刚恢复，而且报错和拨不通对用户是同一结果。
        for strategy in TargetStrategy::ALL {
            let s = selector(2, strategy);
            for t in &s.targets {
                for _ in 0..FAILURE_THRESHOLD {
                    t.record_failure();
                }
            }
            assert_eq!(s.available_count(), 0, "{strategy}");
            assert!(
                s.pick("198.51.100.1".parse().ok()).is_some(),
                "{strategy}: 全部熔断时也应给出一个候选"
            );
        }
    }

    #[test]
    fn failover_falls_back_to_the_primary_when_everything_is_down() {
        // 主备语义下退路是主，而不是随便一台备机。
        let s = selector(3, TargetStrategy::Failover);
        for t in &s.targets {
            for _ in 0..FAILURE_THRESHOLD {
                t.record_failure();
            }
        }
        assert_eq!(pick_addr(&s), "10.0.0.1:443");
    }

    #[test]
    fn a_persistently_failing_target_does_not_wrap_its_counter() {
        // 计数回绕会让持续失败的目标突然显示为健康。
        let s = selector(1, TargetStrategy::Random);
        for _ in 0..10 {
            s.targets[0].consecutive_failures.store(u32::MAX, REL);
            s.targets[0].record_failure();
        }
        assert_eq!(s.status()[0].consecutive_failures, u32::MAX);
        assert!(s.status()[0].tripped);
    }

    #[test]
    fn status_reports_counters() {
        let s = selector(2, TargetStrategy::RoundRobin);
        s.targets[0].record_success();
        s.targets[0].record_success();
        s.targets[1].record_failure();

        let status = s.status();
        assert_eq!(status.len(), 2);
        assert_eq!(status[0].total_ok, 2);
        assert_eq!(status[0].consecutive_failures, 0);
        assert_eq!(status[1].total_failed, 1);
        assert_eq!(status[1].consecutive_failures, 1);
        assert!(status.iter().all(|t| t.available && !t.tripped));
    }

    #[test]
    fn status_distinguishes_tripped_from_healthy() {
        let s = selector(2, TargetStrategy::RoundRobin);
        trip(&s, "10.0.0.1:443");
        let status = s.status();
        assert!(status[0].tripped, "熔断状态没有暴露给面板");
        assert!(!status[0].available);
        assert!(!status[1].tripped);
        assert_eq!(s.healthy_count(), 1);
    }

    #[test]
    fn concurrent_picks_distribute_evenly() {
        for strategy in [
            TargetStrategy::Random,
            TargetStrategy::RoundRobin,
            TargetStrategy::LeastConn,
        ] {
            let s = Arc::new(selector(4, strategy));
            let mut handles = Vec::new();
            for _ in 0..8 {
                let s = s.clone();
                handles.push(std::thread::spawn(move || {
                    let mut local = Vec::new();
                    for _ in 0..100 {
                        local.push(s.pick(None).unwrap().addr().to_string());
                    }
                    local
                }));
            }
            let mut counts = std::collections::HashMap::new();
            for h in handles {
                for addr in h.join().unwrap() {
                    *counts.entry(addr).or_insert(0usize) += 1;
                }
            }
            // 800 次分到 4 个目标，每个约 200 次。放宽到 ±20% 以容忍调度抖动。
            assert_eq!(counts.len(), 4, "{strategy}: {counts:?}");
            for (addr, &c) in &counts {
                assert!(
                    (160..=240).contains(&c),
                    "{strategy}: {addr} 拿到 {c} 次，分布不均: {counts:?}"
                );
            }
            // 所有租约都已析构，活跃计数必须归零。
            assert!(
                s.status().iter().all(|t| t.active == 0),
                "{strategy}: 活跃计数没有全部归还: {:?}",
                s.status()
            );
        }
    }

    #[test]
    fn from_route_takes_targets_and_strategy_from_the_route() {
        let mut route = tunnel_common::model::Route {
            id: "r1".into(),
            name: "x".into(),
            mode: Default::default(),
            entry_node_id: "n1".into(),
            listen_address: "0.0.0.0".into(),
            listen_port: 443,
            exit_node_id: "n2".into(),
            target_host: "1.2.3.4".into(),
            target_port: 443,
            targets: vec!["5.6.7.8:443".into(), "9.10.11.12:443".into()],
            target_strategy: TargetStrategy::Failover,
            endpoint_ids: vec![],
            tunnel_pool_size: 1,
            load_balance: Default::default(),
            max_connections: 0,
            egress_source_ip: None,
            egress_interface: None,
            enabled: true,
        };
        let s = TargetSelector::from_route(&route);
        assert_eq!(s.len(), 2);
        assert_eq!(s.strategy(), TargetStrategy::Failover);
        assert_eq!(pick_addr(&s), "5.6.7.8:443");

        // targets 为空时回落到 target_host:target_port，仍然是非空列表。
        route.targets.clear();
        let s = TargetSelector::from_route(&route);
        assert_eq!(s.len(), 1);
        assert_eq!(pick_addr(&s), "1.2.3.4:443");
    }
}
