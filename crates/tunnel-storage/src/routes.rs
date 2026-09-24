//! Route repository, including the route↔endpoint ordering table.

use crate::db::{new_id, now_string, Database, DbError, Result};
use crate::models::{
    CreateRoute, EndpointDto, EndpointRow, RouteDto, RouteRow, UpdateRoute,
};

pub struct RouteRepo<'a> {
    db: &'a Database,
}

fn validate_load_balance(v: &str) -> Result<()> {
    match v {
        "round_robin" | "least_streams" => Ok(()),
        other => Err(DbError::Invalid(format!(
            "load_balance must be round_robin or least_streams (got `{other}`)"
        ))),
    }
}

fn validate_pool_size(size: u16) -> Result<()> {
    if size == 0 {
        return Err(DbError::Invalid("tunnel_pool_size must be >= 1".into()));
    }
    if size > 256 {
        // Beyond this the connection count stops helping and starts costing
        // memory and file descriptors for no throughput gain.
        return Err(DbError::Invalid(
            "tunnel_pool_size must be <= 256".into(),
        ));
    }
    Ok(())
}

fn validate_optional_ip(value: Option<&str>, field: &str) -> Result<()> {
    if let Some(v) = value {
        let v = v.trim();
        if !v.is_empty() && v.parse::<std::net::IpAddr>().is_err() {
            return Err(DbError::Invalid(format!("{field} `{v}` 不是合法的 IP 地址")));
        }
    }
    Ok(())
}

/// 校验并归一化策略名。
///
/// 归一化而不只是校验：导入的数据可能写 `rr`、`IPHash` 这类别名，存进库前统一成
/// 规范形式，否则 migration 0005 的 CHECK 约束会拒绝它，报出的还是 SQL 错误。
fn normalise_target_strategy(v: &str) -> Result<String> {
    v.parse::<tunnel_common::model::TargetStrategy>()
        .map(|s| s.as_str().to_string())
        .map_err(|_| {
            DbError::Invalid(format!(
                "负载均衡策略必须是 random/round_robin/ip_hash/least_conn/failover（收到 `{v}`）"
            ))
        })
}

fn validate_mode(mode: &str) -> Result<()> {
    match mode {
        "tunnel" | "direct" => Ok(()),
        other => Err(DbError::Invalid(format!(
            "线路模式必须是 tunnel 或 direct（收到 `{other}`）"
        ))),
    }
}

/// 随机端口的分配区间。
///
/// 下界 2000 避开特权端口（1-1023 需要 CAP_NET_BIND_SERVICE）以及 1024-1999 里
/// 一批常见服务端口。上界放到 65535：实际部署中用户会把转发端口散布在整个高位
/// 区间，人为限制在 30000 以下既无必要，也会在线路多时更早耗尽。
///
/// 与 Linux 默认 ephemeral 区间（32768-60999）重叠是可以接受的：那个区间用于
/// **出站连接**的本地端口，而这里分配的是**监听**端口。真正冲突的前提是某个出站
/// 连接恰好占用了同一个端口号且监听尚未建立 —— 概率低，且 bind 失败会在面板上
/// 明确报错，不会静默错乱。若要彻底避开，可以调低上界或手工指定端口。
const RANDOM_PORT_MIN: u16 = 2_000;
const RANDOM_PORT_MAX: u16 = 65_535;

fn normalise_optional(value: Option<String>) -> Option<String> {
    value.map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

/// 拆分 `host:port`，支持 IPv6 的 `[::1]:443` 形式。
///
/// 从右边找冒号，因为 IPv6 地址本身含冒号。
pub fn split_host_port(addr: &str) -> Result<(String, u16)> {
    let addr = addr.trim();
    if addr.is_empty() {
        return Err(DbError::Invalid("目标地址不能为空".into()));
    }

    // `[::1]:443` —— 方括号内是地址，之后是端口。
    if let Some(rest) = addr.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| DbError::Invalid(format!("目标地址 `{addr}` 的方括号不完整")))?;
        let port = tail
            .strip_prefix(':')
            .and_then(|p| p.parse::<u16>().ok())
            .ok_or_else(|| DbError::Invalid(format!("目标地址 `{addr}` 缺少合法端口")))?;
        if port == 0 {
            return Err(DbError::Invalid(format!("目标地址 `{addr}` 端口不能为 0")));
        }
        return Ok((host.to_string(), port));
    }

    let (host, port_text) = addr
        .rsplit_once(':')
        .ok_or_else(|| DbError::Invalid(format!("目标地址 `{addr}` 缺少端口，应为 主机:端口")))?;
    if host.trim().is_empty() {
        return Err(DbError::Invalid(format!("目标地址 `{addr}` 缺少主机")));
    }
    // 裸 IPv6 字面量（多个冒号）必须加方括号，否则无法区分地址与端口。
    if host.contains(':') {
        return Err(DbError::Invalid(format!(
            "IPv6 目标地址需写成 [地址]:端口，收到 `{addr}`"
        )));
    }
    let port: u16 = port_text
        .trim()
        .parse()
        .map_err(|_| DbError::Invalid(format!("目标地址 `{addr}` 的端口不是合法数字")))?;
    if port == 0 {
        return Err(DbError::Invalid(format!("目标地址 `{addr}` 端口不能为 0")));
    }
    Ok((host.trim().to_string(), port))
}

/// 归一化目标列表，返回至少一项。
///
/// `targets` 给出时以它为准；为空则用 `target_host:target_port` 组一项。这样
/// 数据库里存的永远是同一种形态，读取侧不必处理两种来源。
fn normalise_targets(input: &CreateRoute) -> Result<Vec<String>> {
    let explicit: Vec<String> = input
        .targets
        .iter()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect();

    if !explicit.is_empty() {
        // 逐项校验，让错误指向具体那一条而不是笼统报"目标非法"。
        for t in &explicit {
            split_host_port(t)?;
        }
        return Ok(explicit);
    }

    if input.target_host.trim().is_empty() {
        return Err(DbError::Invalid("目标主机不能为空".into()));
    }
    if input.target_port == 0 {
        return Err(DbError::Invalid("目标端口必须在 1-65535 之间".into()));
    }
    let host = input.target_host.trim();
    // 裸 IPv6 补上方括号，保证存进去的形态可被 split_host_port 解析回来。
    let addr = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{}", input.target_port)
    } else {
        format!("{host}:{}", input.target_port)
    };
    Ok(vec![addr])
}

impl<'a> RouteRepo<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Create a route and its endpoint ordering.
    ///
    /// Runs in one transaction: a route whose endpoint list failed to insert
    /// would be undialable, so partial success is not an acceptable outcome.
    pub async fn create(&self, input: CreateRoute) -> Result<RouteDto> {
        if input.name.trim().is_empty() {
            return Err(DbError::Invalid("线路名称不能为空".into()));
        }
        validate_mode(&input.mode)?;
        let is_direct = input.mode == "direct";

        // 直连模式没有对端出口组 —— 单机既是入口也是出口，省略时取入口组。
        let exit_group_id = match input.exit_group_id.clone() {
            Some(g) if !g.trim().is_empty() => g,
            _ if is_direct => input.entry_group_id.clone(),
            _ => {
                return Err(DbError::Invalid(
                    "隧道线路必须指定出口组".into(),
                ))
            }
        };

        // 隧道地址只有隧道模式才需要。直连模式下即使传了也忽略 —— 本机直接 dial
        // 目标，没有对端隧道可拨。
        if !is_direct && input.endpoint_ids.is_empty() {
            return Err(DbError::Invalid(
                "隧道线路至少需要一个隧道地址".into(),
            ));
        }
        // 目标：targets 给出时以它为准，target_host/port 取其首项。
        let targets = normalise_targets(&input)?;
        let (first_host, first_port) = split_host_port(&targets[0])?;
        let target_strategy = normalise_target_strategy(&input.target_strategy)?;
        validate_load_balance(&input.load_balance)?;
        validate_pool_size(input.tunnel_pool_size)?;
        validate_optional_ip(input.egress_source_ip.as_deref(), "出站源 IP")?;

        // 端口：显式指定则校验，留空则随机分配一个该入口组未占用的。
        let listen_port = match input.listen_port {
            Some(0) => {
                return Err(DbError::Invalid(
                    "监听端口不能为 0；留空则由系统随机分配".into(),
                ))
            }
            Some(p) => p,
            None => {
                self.allocate_free_port(&input.entry_group_id, &input.listen_address)
                    .await?
            }
        };

        if !is_direct {
            self.verify_endpoints_in_group(&input.endpoint_ids, &exit_group_id)
                .await?;
        }

        let endpoint_ids: Vec<String> = if is_direct {
            Vec::new()
        } else {
            input.endpoint_ids.clone()
        };

        let id = new_id();
        let now = now_string();
        let mut tx = self.db.pool().begin().await?;

        let targets_json = serde_json::to_string(&targets)
            .map_err(|e| DbError::Other(format!("序列化目标列表失败: {e}")))?;

        sqlx::query(
            "INSERT INTO routes
             (id, name, mode, entry_group_id, listen_address, listen_port, exit_group_id,
              target_host, target_port, targets, target_strategy, tunnel_pool_size,
              load_balance, max_connections, egress_source_ip, egress_interface, enabled,
              created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)",
        )
        .bind(&id)
        .bind(input.name.trim())
        .bind(&input.mode)
        .bind(&input.entry_group_id)
        .bind(input.listen_address.trim())
        .bind(i64::from(listen_port))
        .bind(&exit_group_id)
        .bind(&first_host)
        .bind(i64::from(first_port))
        .bind(&targets_json)
        .bind(&target_strategy)
        .bind(i64::from(input.tunnel_pool_size))
        .bind(&input.load_balance)
        .bind(i64::from(input.max_connections))
        .bind(normalise_optional(input.egress_source_ip))
        .bind(normalise_optional(input.egress_interface))
        .bind(&now)
        .bind(&now)
        .execute(&mut *tx)
        .await
        .map_err(|e| DbError::from_sqlx_with_context(e, "线路名称或监听地址"))?;

        for (position, endpoint_id) in endpoint_ids.iter().enumerate() {
            sqlx::query(
                "INSERT INTO route_endpoints (route_id, endpoint_id, position)
                 VALUES (?, ?, ?)",
            )
            .bind(&id)
            .bind(endpoint_id)
            .bind(position as i64)
            .execute(&mut *tx)
            .await
            .map_err(|e| DbError::from_sqlx_with_context(e, "线路的隧道地址"))?;
        }

        tx.commit().await?;
        self.get(&id).await
    }

    /// 在该入口组上挑一个未被占用的端口。
    ///
    /// 只查数据库里同组同监听地址的已用端口 —— 无法得知目标机器上是否有**其他
    /// 程序**占着某个端口，那要等 agent 真正 bind 时才知道。所以这里是"避开本系统
    /// 已知的冲突"，不是"保证一定能绑上"。绑不上时 agent 会报错，面板能看到。
    async fn allocate_free_port(&self, entry_group_id: &str, listen_address: &str) -> Result<u16> {
        let used: Vec<(i64,)> = sqlx::query_as(
            "SELECT listen_port FROM routes
             WHERE entry_group_id = ? AND listen_address = ?",
        )
        .bind(entry_group_id)
        .bind(listen_address.trim())
        .fetch_all(self.db.pool())
        .await?;
        let used: std::collections::HashSet<u16> = used
            .into_iter()
            .filter_map(|(p,)| u16::try_from(p).ok())
            .collect();

        let span = (RANDOM_PORT_MAX - RANDOM_PORT_MIN) as usize + 1;
        if used.len() >= span {
            return Err(DbError::Invalid(format!(
                "{RANDOM_PORT_MIN}-{RANDOM_PORT_MAX} 区间内已无空闲端口，请手工指定"
            )));
        }

        // 随机试探而非顺序扫描：顺序分配会让端口号连续可预测，也更容易和别人手工
        // 配的端口撞上。试探次数有上限，之后退化为顺序查找保证必然成功。
        use rand::Rng;
        let mut rng = rand::thread_rng();
        for _ in 0..64 {
            let candidate = rng.gen_range(RANDOM_PORT_MIN..=RANDOM_PORT_MAX);
            if !used.contains(&candidate) {
                return Ok(candidate);
            }
        }
        for candidate in RANDOM_PORT_MIN..=RANDOM_PORT_MAX {
            if !used.contains(&candidate) {
                return Ok(candidate);
            }
        }
        Err(DbError::Invalid("无法分配空闲端口".into()))
    }

    /// 校验隧道地址属于出口组内的机器。
    ///
    /// 按组而非按单机校验，是一组多机的关键：出口组里三台机器各有自己的隧道
    /// 地址，一条线路可以同时引用它们，入口在这些地址间做负载与故障转移。
    async fn verify_endpoints_in_group(
        &self,
        endpoint_ids: &[String],
        exit_group_id: &str,
    ) -> Result<()> {
        for id in endpoint_ids {
            let row: Option<(String,)> = sqlx::query_as(
                "SELECT n.group_id FROM endpoints e
                 JOIN nodes n ON n.id = e.node_id
                 WHERE e.id = ?",
            )
            .bind(id)
            .fetch_optional(self.db.pool())
            .await?;
            match row {
                None => {
                    return Err(DbError::Invalid(format!("隧道地址 `{id}` 不存在")))
                }
                Some((group_id,)) if group_id != exit_group_id => {
                    return Err(DbError::Invalid(format!(
                        "隧道地址 `{id}` 所属的机器不在该线路的出口组内"
                    )))
                }
                Some(_) => {}
            }
        }
        Ok(())
    }

    pub async fn get(&self, id: &str) -> Result<RouteDto> {
        let row: Option<RouteRow> = sqlx::query_as("SELECT * FROM routes WHERE id = ?")
            .bind(id)
            .fetch_optional(self.db.pool())
            .await?;
        let row = row.ok_or_else(|| DbError::NotFound(format!("route {id}")))?;
        self.hydrate(row).await
    }

    pub async fn get_row(&self, id: &str) -> Result<RouteRow> {
        let row: Option<RouteRow> = sqlx::query_as("SELECT * FROM routes WHERE id = ?")
            .bind(id)
            .fetch_optional(self.db.pool())
            .await?;
        row.ok_or_else(|| DbError::NotFound(format!("route {id}")))
    }

    async fn hydrate(&self, row: RouteRow) -> Result<RouteDto> {
        let endpoints = self.endpoints_for(&row.id).await?;
        let entry_name: Option<(String,)> =
            sqlx::query_as("SELECT name FROM device_groups WHERE id = ?")
                .bind(&row.entry_group_id)
                .fetch_optional(self.db.pool())
                .await?;
        let exit_name: Option<(String,)> =
            sqlx::query_as("SELECT name FROM device_groups WHERE id = ?")
                .bind(&row.exit_group_id)
                .fetch_optional(self.db.pool())
                .await?;

        let mode = row.mode();
        let strategy = row.target_strategy();
        let target_list = row.target_list();
        // targets 为 NULL 的旧数据回落到 target_host:target_port。
        let single_target = if row.target_host.contains(':') && !row.target_host.starts_with('[') {
            format!("[{}]:{}", row.target_host, row.target_port)
        } else {
            format!("{}:{}", row.target_host, row.target_port)
        };
        Ok(RouteDto {
            id: row.id,
            mode: row.mode,
            mode_label: mode.label(),
            name: row.name,
            entry_group_id: row.entry_group_id,
            entry_group_name: entry_name.map(|n| n.0),
            listen_address: row.listen_address,
            listen_port: row.listen_port,
            exit_group_id: row.exit_group_id,
            exit_group_name: exit_name.map(|n| n.0),
            target_host: row.target_host,
            target_port: row.target_port,
            targets: if target_list.is_empty() {
                vec![single_target]
            } else {
                target_list
            },
            target_strategy: row.target_strategy,
            target_strategy_label: strategy.label(),
            endpoints: endpoints
                .into_iter()
                .map(|e| EndpointDto::new(e, None))
                .collect(),
            tunnel_pool_size: row.tunnel_pool_size,
            load_balance: row.load_balance,
            max_connections: row.max_connections,
            egress_source_ip: row.egress_source_ip,
            egress_interface: row.egress_interface,
            enabled: row.enabled != 0,
            created_at: row.created_at,
        })
    }

    /// Endpoints for a route, in configured (primary-first) order.
    pub async fn endpoints_for(&self, route_id: &str) -> Result<Vec<EndpointRow>> {
        let rows: Vec<EndpointRow> = sqlx::query_as(
            "SELECT e.* FROM endpoints e
             JOIN route_endpoints re ON re.endpoint_id = e.id
             WHERE re.route_id = ?
             ORDER BY re.position",
        )
        .bind(route_id)
        .fetch_all(self.db.pool())
        .await?;
        Ok(rows)
    }

    pub async fn endpoint_ids_for(&self, route_id: &str) -> Result<Vec<String>> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT endpoint_id FROM route_endpoints WHERE route_id = ? ORDER BY position",
        )
        .bind(route_id)
        .fetch_all(self.db.pool())
        .await?;
        Ok(rows.into_iter().map(|r| r.0).collect())
    }

    pub async fn list(&self) -> Result<Vec<RouteDto>> {
        let rows: Vec<RouteRow> = sqlx::query_as("SELECT * FROM routes ORDER BY name")
            .fetch_all(self.db.pool())
            .await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            out.push(self.hydrate(row).await?);
        }
        Ok(out)
    }

    /// 该组作为入口的线路 —— 组内每台机器都要起这些监听。
    pub async fn list_for_entry_group(&self, group_id: &str) -> Result<Vec<RouteRow>> {
        let rows: Vec<RouteRow> =
            sqlx::query_as("SELECT * FROM routes WHERE entry_group_id = ? ORDER BY name")
                .bind(group_id)
                .fetch_all(self.db.pool())
                .await?;
        Ok(rows)
    }

    /// 该组作为出口的线路 —— 组内每台机器都要服务这些线路。
    pub async fn list_for_exit_group(&self, group_id: &str) -> Result<Vec<RouteRow>> {
        let rows: Vec<RouteRow> =
            sqlx::query_as("SELECT * FROM routes WHERE exit_group_id = ? ORDER BY name")
                .bind(group_id)
                .fetch_all(self.db.pool())
                .await?;
        Ok(rows)
    }

    pub async fn update(&self, id: &str, input: UpdateRoute) -> Result<RouteDto> {
        let existing = self.get_row(id).await?;

        if let Some(m) = &input.mode {
            validate_mode(m)?;
        }
        let mode = input.mode.clone().unwrap_or_else(|| existing.mode.clone());
        let is_direct = mode == "direct";

        let entry_group_id = match input
            .entry_group_id
            .as_deref()
            .map(str::trim)
            .filter(|g| !g.is_empty())
        {
            Some(g) => g.to_string(),
            None => existing.entry_group_id.clone(),
        };

        // 出口组：直连模式下没有对端出口，回落到入口组。
        let exit_group_id = match input
            .exit_group_id
            .as_deref()
            .map(str::trim)
            .filter(|g| !g.is_empty())
        {
            Some(g) => g.to_string(),
            // 直连线路的出口组始终跟随入口组 —— 从隧道切过来时原出口组已无意义，
            // 换了入口组时也要跟着走，否则会留下一个指向无关组的引用。
            None if is_direct => entry_group_id.clone(),
            None => existing.exit_group_id.clone(),
        };

        if let Some(lb) = &input.load_balance {
            validate_load_balance(lb)?;
        }
        if let Some(size) = input.tunnel_pool_size {
            validate_pool_size(size)?;
        }
        validate_optional_ip(input.egress_source_ip.as_deref(), "egress_source_ip")?;
        if let Some(0) = input.listen_port {
            return Err(DbError::Invalid("监听端口必须在 1-65535 之间".into()));
        }
        if let Some(0) = input.target_port {
            return Err(DbError::Invalid("目标端口必须在 1-65535 之间".into()));
        }

        let target_strategy = match &input.target_strategy {
            Some(s) => normalise_target_strategy(s)?,
            None => existing.target_strategy.clone(),
        };

        // 目标列表全量替换。逐项校验，让错误指向具体哪一条。
        //
        // `target_host`/`target_port` 跟着更新为首项，否则两者会不一致，而其他代码
        // 路径仍在读这两列。
        let (targets_json, first_host, first_port) = match &input.targets {
            Some(list) => {
                let cleaned: Vec<String> = list
                    .iter()
                    .map(|t| t.trim().to_string())
                    .filter(|t| !t.is_empty())
                    .collect();
                if cleaned.is_empty() {
                    return Err(DbError::Invalid("线路至少需要一个目标".into()));
                }
                for t in &cleaned {
                    split_host_port(t)?;
                }
                let (h, p) = split_host_port(&cleaned[0])?;
                let json = serde_json::to_string(&cleaned)
                    .map_err(|e| DbError::Other(format!("序列化目标列表失败: {e}")))?;
                (json, h, p)
            }
            None => {
                // 没给 targets 时，若改了 target_host/port 就同步更新列表首项，
                // 否则两者会指向不同的地方。
                let host = input
                    .target_host
                    .clone()
                    .unwrap_or_else(|| existing.target_host.clone());
                let host = host.trim().to_string();
                let port = input.target_port.unwrap_or(
                    u16::try_from(existing.target_port.clamp(1, 65_535)).unwrap_or(1),
                );
                let changed =
                    host != existing.target_host || i64::from(port) != existing.target_port;
                if changed {
                    let addr = if host.contains(':') && !host.starts_with('[') {
                        format!("[{host}]:{port}")
                    } else {
                        format!("{host}:{port}")
                    };
                    split_host_port(&addr)?;
                    let mut list = existing.target_list();
                    if list.is_empty() {
                        list = vec![addr.clone()];
                    } else {
                        list[0] = addr.clone();
                    }
                    let json = serde_json::to_string(&list)
                        .map_err(|e| DbError::Other(format!("序列化目标列表失败: {e}")))?;
                    (json, host, port)
                } else {
                    let json = existing
                        .targets
                        .clone()
                        .unwrap_or_else(|| format!("[\"{host}:{port}\"]"));
                    (json, host, port)
                }
            }
        };

        // 隧道地址。
        //
        // 直连模式下一律清空 —— 本机直接拨目标，留着隧道地址会让人误以为它还在用。
        // 隧道模式下：给了就替换，没给则沿用既有的；两种情况最终都必须非空，否则
        // 这条线路无处可拨。
        let endpoint_ids: Option<Vec<String>> = if is_direct {
            Some(Vec::new())
        } else {
            match &input.endpoint_ids {
                Some(ids) => {
                    let cleaned: Vec<String> = ids
                        .iter()
                        .map(|i| i.trim().to_string())
                        .filter(|i| !i.is_empty())
                        .collect();
                    if cleaned.is_empty() {
                        return Err(DbError::Invalid("隧道线路至少需要一个隧道地址".into()));
                    }
                    Some(cleaned)
                }
                None => {
                    // 没给隧道地址却要切到隧道模式：既有的那些可能属于别的组，
                    // 必须重新校验而不是默认沿用。
                    let current = self.endpoint_ids_for(id).await?;
                    if current.is_empty() {
                        return Err(DbError::Invalid(
                            "隧道线路至少需要一个隧道地址；请先选择隧道地址".into(),
                        ));
                    }
                    // 出口组变了就得重新校验归属，否则只是沿用不必改写。
                    if exit_group_id != existing.exit_group_id {
                        Some(current)
                    } else {
                        None
                    }
                }
            }
        };

        if let Some(ids) = endpoint_ids.as_ref().filter(|ids| !ids.is_empty()) {
            self.verify_endpoints_in_group(ids, &exit_group_id).await?;
        }

        let mut tx = self.db.pool().begin().await?;

        sqlx::query(
            "UPDATE routes
             SET name = ?, mode = ?, entry_group_id = ?, exit_group_id = ?,
                 listen_address = ?, listen_port = ?, target_host = ?, target_port = ?,
                 targets = ?, target_strategy = ?,
                 tunnel_pool_size = ?, load_balance = ?, max_connections = ?,
                 egress_source_ip = ?, egress_interface = ?, enabled = ?, updated_at = ?
             WHERE id = ?",
        )
        .bind(input.name.unwrap_or(existing.name).trim())
        .bind(&mode)
        .bind(&entry_group_id)
        .bind(&exit_group_id)
        .bind(
            input
                .listen_address
                .unwrap_or(existing.listen_address)
                .trim(),
        )
        .bind(
            input
                .listen_port
                .map(i64::from)
                .unwrap_or(existing.listen_port),
        )
        .bind(&first_host)
        .bind(i64::from(first_port))
        .bind(&targets_json)
        .bind(&target_strategy)
        .bind(
            input
                .tunnel_pool_size
                .map(i64::from)
                .unwrap_or(existing.tunnel_pool_size),
        )
        .bind(input.load_balance.unwrap_or(existing.load_balance))
        .bind(
            input
                .max_connections
                .map(i64::from)
                .unwrap_or(existing.max_connections),
        )
        .bind(normalise_optional(
            input.egress_source_ip.or(existing.egress_source_ip),
        ))
        .bind(normalise_optional(
            input.egress_interface.or(existing.egress_interface),
        ))
        .bind(input.enabled.map(i64::from).unwrap_or(existing.enabled))
        .bind(now_string())
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|e| DbError::from_sqlx_with_context(e, "线路名称或监听地址"))?;

        // Replace the endpoint list wholesale when supplied. Diffing would add
        // complexity for no benefit: the list is short and ordered.
        if let Some(ids) = endpoint_ids {
            sqlx::query("DELETE FROM route_endpoints WHERE route_id = ?")
                .bind(id)
                .execute(&mut *tx)
                .await?;
            for (position, endpoint_id) in ids.iter().enumerate() {
                sqlx::query(
                    "INSERT INTO route_endpoints (route_id, endpoint_id, position)
                     VALUES (?, ?, ?)",
                )
                .bind(id)
                .bind(endpoint_id)
                .bind(position as i64)
                .execute(&mut *tx)
                .await
                .map_err(|e| DbError::from_sqlx_with_context(e, "route endpoint"))?;
            }
        }

        tx.commit().await?;
        self.get(id).await
    }

    pub async fn set_enabled(&self, id: &str, enabled: bool) -> Result<RouteDto> {
        let result = sqlx::query("UPDATE routes SET enabled = ?, updated_at = ? WHERE id = ?")
            .bind(i64::from(enabled))
            .bind(now_string())
            .bind(id)
            .execute(self.db.pool())
            .await?;
        if result.rows_affected() == 0 {
            return Err(DbError::NotFound(format!("route {id}")));
        }
        self.get(id).await
    }

    pub async fn delete(&self, id: &str) -> Result<()> {
        // route_endpoints cascades.
        let result = sqlx::query("DELETE FROM routes WHERE id = ?")
            .bind(id)
            .execute(self.db.pool())
            .await?;
        if result.rows_affected() == 0 {
            return Err(DbError::NotFound(format!("route {id}")));
        }
        Ok(())
    }

    /// 受线路变更影响的组 id，控制面据此递增相应组的配置版本。
    ///
    /// 递增到组级别而非机器级别：组内所有 agent 共享同一个版本号，一次变更让
    /// 整组在下次轮询时同步重载。
    pub async fn affected_groups(&self, route_id: &str) -> Result<Vec<String>> {
        let row: Option<(String, String)> =
            sqlx::query_as("SELECT entry_group_id, exit_group_id FROM routes WHERE id = ?")
                .bind(route_id)
                .fetch_optional(self.db.pool())
                .await?;
        Ok(match row {
            Some((entry, exit)) if entry == exit => vec![entry],
            Some((entry, exit)) => vec![entry, exit],
            None => vec![],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{CreateEndpoint, CreateNode};
    use crate::nodes::{EndpointRepo, NodeRepo};

    struct Fixture {
        db: Database,
        /// 入口组 id。线路引用组，不再引用单机。
        entry_group: String,
        exit_group: String,
        iepl_ep: String,
        public_ep: String,
    }

    async fn fixture() -> Fixture {
        let db = Database::connect_in_memory().await.unwrap();
        let groups = crate::groups::DeviceGroupRepo::new(&db);
        let nodes = NodeRepo::new(&db);
        let endpoints = EndpointRepo::new(&db);

        let (entry_group, _) = groups
            .create(crate::models::CreateDeviceGroup {
                name: "上海入口".into(),
                region: "cn-sh".into(),
                kind: "inbound".into(),
                note: None,
            })
            .await
            .unwrap();
        let (exit_group, _) = groups
            .create(crate::models::CreateDeviceGroup {
                name: "香港出口".into(),
                region: "hk".into(),
                kind: "outbound".into(),
                note: None,
            })
            .await
            .unwrap();

        nodes
            .create(CreateNode {
                group_id: entry_group.id.clone(),
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
                group_id: exit_group.id.clone(),
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

        Fixture {
            db,
            entry_group: entry_group.id,
            exit_group: exit_group.id,
            iepl_ep: iepl.id,
            public_ep: public.id,
        }
    }

    fn new_route(f: &Fixture, name: &str, port: u16, eps: Vec<String>) -> CreateRoute {
        CreateRoute {
            name: name.into(),
            mode: "tunnel".into(),
            entry_group_id: f.entry_group.clone(),
            listen_address: "0.0.0.0".into(),
            listen_port: Some(port),
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
        }
    }

    #[tokio::test]
    async fn create_with_iepl_primary_and_public_backup() {
        // The canonical configuration this system exists to serve.
        let f = fixture().await;
        let repo = RouteRepo::new(&f.db);
        let route = repo
            .create(new_route(
                &f,
                "sh-hk",
                443,
                vec![f.iepl_ep.clone(), f.public_ep.clone()],
            ))
            .await
            .unwrap();

        assert_eq!(route.name, "sh-hk");
        assert_eq!(route.endpoints.len(), 2);
        // Order is the failover order and must be preserved exactly.
        assert_eq!(route.endpoints[0].name, "hk-iepl");
        assert_eq!(route.endpoints[1].name, "hk-public");
        assert_eq!(route.entry_group_name.as_deref(), Some("上海入口"));
        assert_eq!(route.exit_group_name.as_deref(), Some("香港出口"));
        assert_eq!(route.egress_source_ip.as_deref(), Some("203.0.113.9"));
        assert!(route.enabled);
    }

    #[tokio::test]
    async fn endpoint_order_is_preserved_as_given() {
        let f = fixture().await;
        let repo = RouteRepo::new(&f.db);
        // Deliberately public-first: the operator's order wins over the
        // endpoints' own priority labels.
        let route = repo
            .create(new_route(
                &f,
                "sh-hk",
                443,
                vec![f.public_ep.clone(), f.iepl_ep.clone()],
            ))
            .await
            .unwrap();
        assert_eq!(route.endpoints[0].name, "hk-public");
        assert_eq!(route.endpoints[1].name, "hk-iepl");

        let ids = repo.endpoint_ids_for(&route.id).await.unwrap();
        assert_eq!(ids, vec![f.public_ep.clone(), f.iepl_ep.clone()]);
    }

    #[test]
    fn host_port_splitting() {
        assert_eq!(
            split_host_port("1.2.3.4:443").unwrap(),
            ("1.2.3.4".to_string(), 443)
        );
        assert_eq!(
            split_host_port("example.com:8443").unwrap(),
            ("example.com".to_string(), 8443)
        );
        // IPv6 必须带方括号，否则无法区分地址与端口。
        assert_eq!(
            split_host_port("[fd00::2]:5000").unwrap(),
            ("fd00::2".to_string(), 5000)
        );
        assert!(split_host_port("fd00::2:5000").is_err(), "裸 IPv6 应被拒绝");

        for bad in ["", "   ", "1.2.3.4", "1.2.3.4:", ":443", "1.2.3.4:abc", "1.2.3.4:0"] {
            assert!(split_host_port(bad).is_err(), "接受了非法地址 `{bad}`");
        }
    }

    #[tokio::test]
    async fn multiple_targets_are_stored_and_read_back_in_order() {
        // 导入格式里 dest 是数组，多台等价落地机分担流量是常见需求。
        let f = fixture().await;
        let repo = RouteRepo::new(&f.db);
        let mut input = new_route(&f, "多目标", 443, vec![f.iepl_ep.clone()]);
        input.targets = vec![
            "1.2.3.4:443".into(),
            "5.6.7.8:8443".into(),
            "[fd00::9]:443".into(),
        ];

        let route = repo.create(input).await.unwrap();
        assert_eq!(route.targets.len(), 3);
        // 顺序保留 —— 轮询按这个顺序走。
        assert_eq!(route.targets[0], "1.2.3.4:443");
        assert_eq!(route.targets[2], "[fd00::9]:443");
        // target_host/port 取首项，保证旧代码路径仍然可用。
        assert_eq!(route.target_host, "1.2.3.4");
        assert_eq!(route.target_port, 443);
    }

    #[tokio::test]
    async fn a_single_target_still_produces_a_one_item_list() {
        // 存进去的永远是同一种形态，读取侧不必处理两种来源。
        let f = fixture().await;
        let repo = RouteRepo::new(&f.db);
        let route = repo
            .create(new_route(&f, "单目标", 443, vec![f.iepl_ep.clone()]))
            .await
            .unwrap();
        assert_eq!(route.targets, vec!["127.0.0.1:8443".to_string()]);
    }

    #[tokio::test]
    async fn a_malformed_target_names_the_offending_entry() {
        let f = fixture().await;
        let repo = RouteRepo::new(&f.db);
        let mut input = new_route(&f, "坏目标", 443, vec![f.iepl_ep.clone()]);
        input.targets = vec!["1.2.3.4:443".into(), "5.6.7.8".into()];

        let err = repo.create(input).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("5.6.7.8"),
            "错误应指出具体哪一条非法，实际: {msg}"
        );
    }

    #[tokio::test]
    async fn blank_target_entries_are_dropped() {
        // 导入的数据可能带空行或多余空格。
        let f = fixture().await;
        let repo = RouteRepo::new(&f.db);
        let mut input = new_route(&f, "含空项", 443, vec![f.iepl_ep.clone()]);
        input.targets = vec!["  ".into(), " 1.2.3.4:443 ".into(), "".into()];

        let route = repo.create(input).await.unwrap();
        assert_eq!(route.targets, vec!["1.2.3.4:443".to_string()]);
    }

    #[tokio::test]
    async fn the_strategy_is_stored_and_labelled_in_chinese() {
        let f = fixture().await;
        let repo = RouteRepo::new(&f.db);
        let mut input = new_route(&f, "哈希线路", 443, vec![f.iepl_ep.clone()]);
        input.targets = vec!["1.2.3.4:443".into(), "5.6.7.8:443".into()];
        input.target_strategy = "ip_hash".into();

        let route = repo.create(input).await.unwrap();
        assert_eq!(route.target_strategy, "ip_hash");
        assert_eq!(route.target_strategy_label, "IP 哈希");
    }

    #[tokio::test]
    async fn the_strategy_defaults_to_random() {
        // 单目标线路也要有值，这样面板不必区分两种情况。
        let f = fixture().await;
        let repo = RouteRepo::new(&f.db);
        let route = repo
            .create(new_route(&f, "默认策略", 443, vec![f.iepl_ep.clone()]))
            .await
            .unwrap();
        assert_eq!(route.target_strategy, "random");
        assert_eq!(route.target_strategy_label, "随机");
    }

    #[tokio::test]
    async fn strategy_aliases_are_normalised_before_storage() {
        // 导入的数据可能来自别的面板。不归一化的话 CHECK 约束会拒绝，报出的还是
        // 一条看不懂的 SQL 错误。
        let f = fixture().await;
        let repo = RouteRepo::new(&f.db);
        for (i, (alias, expected)) in [
            ("rr", "round_robin"),
            ("IPHash", "ip_hash"),
            ("least_connections", "least_conn"),
            ("  Failover ", "failover"),
        ]
        .into_iter()
        .enumerate()
        {
            let mut input = new_route(&f, &format!("别名-{i}"), 3000 + i as u16, vec![f.iepl_ep.clone()]);
            input.target_strategy = alias.into();
            let route = repo.create(input).await.unwrap();
            assert_eq!(route.target_strategy, expected, "别名 `{alias}`");
        }
    }

    #[tokio::test]
    async fn an_invalid_strategy_is_rejected_with_the_valid_options() {
        let f = fixture().await;
        let repo = RouteRepo::new(&f.db);
        let mut input = new_route(&f, "坏策略", 443, vec![f.iepl_ep.clone()]);
        input.target_strategy = "sideways".into();

        let err = repo.create(input).await.unwrap_err();
        assert!(matches!(err, DbError::Invalid(_)), "{err:?}");
        let msg = err.to_string();
        assert!(msg.contains("ip_hash") && msg.contains("failover"), "{msg}");
    }

    #[tokio::test]
    async fn update_replaces_the_target_list_and_syncs_the_first_entry() {
        // 编辑线路必须能改目标 —— 否则多目标只能在新建时配一次。
        let f = fixture().await;
        let repo = RouteRepo::new(&f.db);
        let route = repo
            .create(new_route(&f, "改目标", 443, vec![f.iepl_ep.clone()]))
            .await
            .unwrap();
        assert_eq!(route.targets, vec!["127.0.0.1:8443".to_string()]);

        let updated = repo
            .update(
                &route.id,
                UpdateRoute {
                    targets: Some(vec!["9.9.9.9:443".into(), "8.8.8.8:8443".into()]),
                    target_strategy: Some("least_conn".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(updated.targets.len(), 2);
        assert_eq!(updated.target_strategy, "least_conn");
        // target_host/port 必须跟着首项走，否则两者指向不同地方。
        assert_eq!(updated.target_host, "9.9.9.9");
        assert_eq!(updated.target_port, 443);
    }

    #[tokio::test]
    async fn update_rejects_an_empty_target_list() {
        let f = fixture().await;
        let repo = RouteRepo::new(&f.db);
        let route = repo
            .create(new_route(&f, "清空目标", 443, vec![f.iepl_ep.clone()]))
            .await
            .unwrap();

        let err = repo
            .update(
                &route.id,
                UpdateRoute {
                    targets: Some(vec!["  ".into()]),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, DbError::Invalid(_)), "{err:?}");
        // 原来的目标必须还在。
        assert_eq!(
            repo.get(&route.id).await.unwrap().targets,
            vec!["127.0.0.1:8443".to_string()]
        );
    }

    #[tokio::test]
    async fn updating_only_the_host_keeps_the_list_in_sync() {
        // 老的编辑路径只改 target_host/port。此时 targets 首项必须跟着变，否则
        // agent 读 targets 会拨到旧地址。
        let f = fixture().await;
        let repo = RouteRepo::new(&f.db);
        let route = repo
            .create(new_route(&f, "只改主机", 443, vec![f.iepl_ep.clone()]))
            .await
            .unwrap();

        let updated = repo
            .update(
                &route.id,
                UpdateRoute {
                    target_host: Some("10.1.2.3".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(updated.target_host, "10.1.2.3");
        assert_eq!(
            updated.targets,
            vec!["10.1.2.3:8443".to_string()],
            "targets 首项没有跟着 target_host 更新"
        );
    }

    #[tokio::test]
    async fn a_partial_update_preserves_targets_and_strategy() {
        let f = fixture().await;
        let repo = RouteRepo::new(&f.db);
        let mut input = new_route(&f, "保留", 443, vec![f.iepl_ep.clone()]);
        input.targets = vec!["1.1.1.1:443".into(), "2.2.2.2:443".into()];
        input.target_strategy = "failover".into();
        let route = repo.create(input).await.unwrap();

        let updated = repo
            .update(
                &route.id,
                UpdateRoute {
                    name: Some("改了名".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(updated.name, "改了名");
        assert_eq!(updated.targets.len(), 2, "目标列表被清掉了");
        assert_eq!(updated.target_strategy, "failover", "策略被重置了");
    }

    #[tokio::test]
    async fn a_tunnel_route_can_be_switched_to_direct() {
        // 面板上出口组下拉改成「不使用隧道」就走这条路径。
        let f = fixture().await;
        let repo = RouteRepo::new(&f.db);
        let route = repo
            .create(new_route(&f, "转直连", 443, vec![f.iepl_ep.clone()]))
            .await
            .unwrap();
        assert_eq!(route.endpoints.len(), 1);

        let updated = repo
            .update(
                &route.id,
                UpdateRoute {
                    mode: Some("direct".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(updated.mode, "direct");
        assert!(
            updated.endpoints.is_empty(),
            "切到直连后隧道地址该被清空，留着会让人以为还在用"
        );
        // 出口组回落到入口组，与 create 的行为一致。
        assert_eq!(updated.exit_group_id, f.entry_group);
    }

    #[tokio::test]
    async fn a_direct_route_can_be_switched_to_tunnel_with_endpoints() {
        let f = fixture().await;
        let repo = RouteRepo::new(&f.db);
        let route = repo
            .create(CreateRoute {
                name: "转隧道".into(),
                mode: "direct".into(),
                entry_group_id: f.entry_group.clone(),
                listen_address: "0.0.0.0".into(),
                listen_port: Some(443),
                exit_group_id: None,
                target_host: "233.21.21.21".into(),
                target_port: 443,
                targets: vec![],
                target_strategy: "random".into(),
                endpoint_ids: vec![],
                tunnel_pool_size: 8,
                load_balance: "round_robin".into(),
                max_connections: 0,
                egress_source_ip: None,
                egress_interface: None,
            })
            .await
            .unwrap();

        let updated = repo
            .update(
                &route.id,
                UpdateRoute {
                    mode: Some("tunnel".into()),
                    exit_group_id: Some(f.exit_group.clone()),
                    endpoint_ids: Some(vec![f.iepl_ep.clone()]),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(updated.mode, "tunnel");
        assert_eq!(updated.exit_group_id, f.exit_group);
        assert_eq!(updated.endpoints.len(), 1);
    }

    #[tokio::test]
    async fn switching_to_tunnel_without_endpoints_is_rejected() {
        // 否则会得到一条永远拨不通的隧道线路。
        let f = fixture().await;
        let repo = RouteRepo::new(&f.db);
        let route = repo
            .create(CreateRoute {
                name: "缺地址".into(),
                mode: "direct".into(),
                entry_group_id: f.entry_group.clone(),
                listen_address: "0.0.0.0".into(),
                listen_port: Some(443),
                exit_group_id: None,
                target_host: "233.21.21.21".into(),
                target_port: 443,
                targets: vec![],
                target_strategy: "random".into(),
                endpoint_ids: vec![],
                tunnel_pool_size: 8,
                load_balance: "round_robin".into(),
                max_connections: 0,
                egress_source_ip: None,
                egress_interface: None,
            })
            .await
            .unwrap();

        let err = repo
            .update(
                &route.id,
                UpdateRoute {
                    mode: Some("tunnel".into()),
                    exit_group_id: Some(f.exit_group.clone()),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, DbError::Invalid(_)), "{err:?}");
        // 模式不该被改掉。
        assert_eq!(repo.get(&route.id).await.unwrap().mode, "direct");
    }

    #[tokio::test]
    async fn the_entry_group_can_be_changed() {
        // 批量改组要用它：导入 79 条后发现挪错了组，逐条编辑要开 79 次弹窗。
        let f = fixture().await;
        let repo = RouteRepo::new(&f.db);
        let groups = crate::groups::DeviceGroupRepo::new(&f.db);
        let (other, _) = groups
            .create(crate::models::CreateDeviceGroup {
                name: "北京入口".into(),
                region: "cn-bj".into(),
                kind: "inbound".into(),
                note: None,
            })
            .await
            .unwrap();

        let route = repo
            .create(new_route(&f, "换入口", 443, vec![f.iepl_ep.clone()]))
            .await
            .unwrap();
        let updated = repo
            .update(
                &route.id,
                UpdateRoute {
                    entry_group_id: Some(other.id.clone()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(updated.entry_group_id, other.id);
        assert_eq!(updated.entry_group_name.as_deref(), Some("北京入口"));
        // 出口组与隧道地址不受影响。
        assert_eq!(updated.exit_group_id, f.exit_group);
        assert_eq!(updated.endpoints.len(), 1);
    }

    #[tokio::test]
    async fn moving_a_route_onto_an_occupied_port_is_a_conflict() {
        // 端口唯一性按 (入口组, 监听地址, 端口) 算，换组可能撞上目标组里已有的线路。
        // 必须报冲突而不是静默覆盖。
        let f = fixture().await;
        let repo = RouteRepo::new(&f.db);
        let groups = crate::groups::DeviceGroupRepo::new(&f.db);
        let (other, _) = groups
            .create(crate::models::CreateDeviceGroup {
                name: "广州入口".into(),
                region: "cn-gz".into(),
                kind: "inbound".into(),
                note: None,
            })
            .await
            .unwrap();

        // 目标组里先占住 443。
        let mut squatter = new_route(&f, "先占位", 443, vec![f.iepl_ep.clone()]);
        squatter.entry_group_id = other.id.clone();
        repo.create(squatter).await.unwrap();

        // 原组里另有一条也用 443 的线路，挪过去就会撞车。
        let route = repo
            .create(new_route(&f, "要挪的", 443, vec![f.iepl_ep.clone()]))
            .await
            .unwrap();
        let err = repo
            .update(
                &route.id,
                UpdateRoute {
                    entry_group_id: Some(other.id.clone()),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, DbError::Conflict(_)), "{err:?}");
        // 没有被挪走。
        assert_eq!(
            repo.get(&route.id).await.unwrap().entry_group_id,
            f.entry_group
        );
    }

    #[tokio::test]
    async fn a_direct_routes_exit_group_follows_its_entry_group() {
        // 直连线路没有独立的出口组概念。换入口组时若不跟着走，会留下一个指向无关
        // 组的引用 —— 面板上看起来这条线路和某个毫不相干的组有关系。
        let f = fixture().await;
        let repo = RouteRepo::new(&f.db);
        let groups = crate::groups::DeviceGroupRepo::new(&f.db);
        let (other, _) = groups
            .create(crate::models::CreateDeviceGroup {
                name: "成都入口".into(),
                region: "cn-cd".into(),
                kind: "both".into(),
                note: None,
            })
            .await
            .unwrap();

        let route = repo
            .create(CreateRoute {
                name: "直连换组".into(),
                mode: "direct".into(),
                entry_group_id: f.entry_group.clone(),
                listen_address: "0.0.0.0".into(),
                listen_port: Some(443),
                exit_group_id: None,
                target_host: "233.21.21.21".into(),
                target_port: 443,
                targets: vec![],
                target_strategy: "random".into(),
                endpoint_ids: vec![],
                tunnel_pool_size: 8,
                load_balance: "round_robin".into(),
                max_connections: 0,
                egress_source_ip: None,
                egress_interface: None,
            })
            .await
            .unwrap();

        let updated = repo
            .update(
                &route.id,
                UpdateRoute {
                    entry_group_id: Some(other.id.clone()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(updated.entry_group_id, other.id);
        assert_eq!(
            updated.exit_group_id, other.id,
            "直连线路的出口组应跟随入口组"
        );
    }

    #[tokio::test]
    async fn changing_the_exit_group_revalidates_the_endpoints() {
        // 换组后原隧道地址属于旧组，沿用会让入口拨向没有运行该线路出口的机器。
        let f = fixture().await;
        let repo = RouteRepo::new(&f.db);
        let route = repo
            .create(new_route(&f, "换组", 443, vec![f.iepl_ep.clone()]))
            .await
            .unwrap();

        // 建一个第三方出口组，里面没有任何隧道地址。
        let groups = crate::groups::DeviceGroupRepo::new(&f.db);
        let (other, _) = groups
            .create(crate::models::CreateDeviceGroup {
                name: "日本出口".into(),
                region: "jp".into(),
                kind: "outbound".into(),
                note: None,
            })
            .await
            .unwrap();

        let err = repo
            .update(
                &route.id,
                UpdateRoute {
                    exit_group_id: Some(other.id.clone()),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, DbError::Invalid(_)), "{err:?}");
        assert_eq!(
            repo.get(&route.id).await.unwrap().exit_group_id,
            f.exit_group,
            "校验失败却改掉了出口组"
        );
    }

    #[tokio::test]
    async fn an_invalid_mode_is_rejected_on_update() {
        let f = fixture().await;
        let repo = RouteRepo::new(&f.db);
        let route = repo
            .create(new_route(&f, "坏模式", 443, vec![f.iepl_ep.clone()]))
            .await
            .unwrap();
        assert!(matches!(
            repo.update(
                &route.id,
                UpdateRoute {
                    mode: Some("sideways".into()),
                    ..Default::default()
                }
            )
            .await,
            Err(DbError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn update_rejects_an_invalid_strategy_without_touching_the_row() {
        let f = fixture().await;
        let repo = RouteRepo::new(&f.db);
        let route = repo
            .create(new_route(&f, "坏更新", 443, vec![f.iepl_ep.clone()]))
            .await
            .unwrap();

        let err = repo
            .update(
                &route.id,
                UpdateRoute {
                    name: Some("不该生效".into()),
                    target_strategy: Some("nonsense".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, DbError::Invalid(_)), "{err:?}");
        assert_eq!(
            repo.get(&route.id).await.unwrap().name,
            "坏更新",
            "校验失败却写入了名称"
        );
    }

    #[tokio::test]
    async fn the_wire_model_carries_all_targets() {
        let f = fixture().await;
        let repo = RouteRepo::new(&f.db);
        let mut input = new_route(&f, "多目标下发", 443, vec![f.iepl_ep.clone()]);
        input.targets = vec!["1.2.3.4:443".into(), "5.6.7.8:443".into()];
        let route = repo.create(input).await.unwrap();

        let row = repo.get_row(&route.id).await.unwrap();
        let model = row.to_model(vec![]);
        assert_eq!(model.targets.len(), 2);
        assert_eq!(model.effective_targets().len(), 2);
    }

    #[tokio::test]
    async fn a_direct_route_needs_no_endpoints_or_exit_group() {
        // 单机转发：一台三网优化机把端口转到落地机。没有对端出口，也没有隧道地址。
        let f = fixture().await;
        let repo = RouteRepo::new(&f.db);
        let route = repo
            .create(CreateRoute {
                name: "香港直转落地".into(),
                mode: "direct".into(),
                entry_group_id: f.entry_group.clone(),
                listen_address: "0.0.0.0".into(),
                listen_port: Some(443),
                // 出口组省略 —— 直连模式下会取入口组。
                exit_group_id: None,
                target_host: "233.21.21.21".into(),
                target_port: 443,
                targets: vec![],
                target_strategy: "random".into(),
                endpoint_ids: vec![],
                tunnel_pool_size: 8,
                load_balance: "round_robin".into(),
                max_connections: 0,
                egress_source_ip: Some("203.0.113.9".into()),
                egress_interface: None,
            })
            .await
            .unwrap();

        assert_eq!(route.mode, "direct");
        assert_eq!(route.mode_label, "直连转发");
        assert!(route.endpoints.is_empty(), "直连线路不该有隧道地址");
        assert_eq!(
            route.exit_group_id, f.entry_group,
            "省略出口组时应回落到入口组"
        );
        assert_eq!(route.target_host, "233.21.21.21");
        // 出站源 IP 仍然生效 —— IEPL 单机双网卡就靠它决定从哪块网卡出。
        assert_eq!(route.egress_source_ip.as_deref(), Some("203.0.113.9"));
    }

    #[tokio::test]
    async fn a_tunnel_route_still_requires_an_exit_group() {
        let f = fixture().await;
        let repo = RouteRepo::new(&f.db);
        let mut input = new_route(&f, "sh-hk", 443, vec![f.iepl_ep.clone()]);
        input.exit_group_id = None;
        assert!(matches!(
            repo.create(input).await,
            Err(DbError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn an_omitted_port_is_allocated_randomly() {
        // 一台入口机上会有多条线路，硬编码 443 会让第二条起全部冲突。
        let f = fixture().await;
        let repo = RouteRepo::new(&f.db);

        let mut ports = std::collections::HashSet::new();
        for i in 0..8 {
            let mut input = new_route(&f, &format!("线路-{i}"), 0, vec![f.iepl_ep.clone()]);
            input.listen_port = None;
            let route = repo.create(input).await.unwrap();
            assert!(
                (2_000..=65_535).contains(&route.listen_port),
                "分配的端口 {} 不在预期区间",
                route.listen_port
            );
            assert!(
                ports.insert(route.listen_port),
                "端口 {} 被分配了两次",
                route.listen_port
            );
        }
        assert_eq!(ports.len(), 8);
    }

    #[tokio::test]
    async fn random_allocation_avoids_ports_already_taken() {
        let f = fixture().await;
        let repo = RouteRepo::new(&f.db);

        // 先手工占一个区间内的端口。DTO 里端口是 i64（SQLite 的整数类型）。
        let taken: i64 = 12345;
        repo.create(new_route(
            &f,
            "手工指定",
            taken as u16,
            vec![f.iepl_ep.clone()],
        ))
        .await
        .unwrap();

        // 再随机分配若干条，都不该撞上它。
        for i in 0..20 {
            let mut input = new_route(&f, &format!("随机-{i}"), 0, vec![f.iepl_ep.clone()]);
            input.listen_port = None;
            let route = repo.create(input).await.unwrap();
            assert_ne!(
                route.listen_port, taken,
                "随机分配撞上了已被占用的端口"
            );
        }
    }

    #[tokio::test]
    async fn an_explicit_zero_port_is_rejected() {
        // 0 是"让内核随便挑"的语义，但那样面板就不知道实际端口了。
        // 想随机应当留空（None），而不是传 0。
        let f = fixture().await;
        let repo = RouteRepo::new(&f.db);
        let mut input = new_route(&f, "x", 0, vec![f.iepl_ep.clone()]);
        input.listen_port = Some(0);
        assert!(matches!(
            repo.create(input).await,
            Err(DbError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn an_invalid_mode_is_rejected() {
        let f = fixture().await;
        let repo = RouteRepo::new(&f.db);
        let mut input = new_route(&f, "x", 443, vec![f.iepl_ep.clone()]);
        input.mode = "sideways".into();
        assert!(matches!(
            repo.create(input).await,
            Err(DbError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn a_direct_route_converts_to_the_wire_model_with_its_mode() {
        let f = fixture().await;
        let repo = RouteRepo::new(&f.db);
        let route = repo
            .create(CreateRoute {
                name: "直连".into(),
                mode: "direct".into(),
                entry_group_id: f.entry_group.clone(),
                listen_address: "0.0.0.0".into(),
                listen_port: Some(8443),
                exit_group_id: None,
                target_host: "233.21.21.21".into(),
                target_port: 443,
                targets: vec![],
                target_strategy: "random".into(),
                endpoint_ids: vec![],
                tunnel_pool_size: 8,
                load_balance: "round_robin".into(),
                max_connections: 0,
                egress_source_ip: None,
                egress_interface: None,
            })
            .await
            .unwrap();

        let row = repo.get_row(&route.id).await.unwrap();
        let model = row.to_model(vec![]);
        assert_eq!(model.mode, tunnel_common::model::RouteMode::Direct);
        assert!(!model.mode.needs_tunnel());
        assert_eq!(model.target_socket_addr(), "233.21.21.21:443");
    }

    #[tokio::test]
    async fn route_without_endpoints_is_rejected() {
        let f = fixture().await;
        let repo = RouteRepo::new(&f.db);
        assert!(matches!(
            repo.create(new_route(&f, "sh-hk", 443, vec![])).await,
            Err(DbError::Invalid(_))
        ));
        assert!(repo.list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_endpoint_outside_the_exit_group_is_rejected() {
        // 否则入口会拨向一台并没有运行该线路出口的主机。
        let f = fixture().await;
        let nodes = NodeRepo::new(&f.db);
        let endpoints = EndpointRepo::new(&f.db);

        // 在入口组的机器上建一个隧道地址 —— 它不属于出口组。
        let entry_node = nodes
            .create(CreateNode {
                group_id: f.entry_group.clone(),
                name: "sh-02".into(),
                region: "cn-sh".into(),
                role: "entry".into(),
                public_address: None,
                management_address: None,
                note: None,
            })
            .await
            .unwrap();
        let stray = endpoints
            .create(CreateEndpoint {
                node_id: entry_node.id.clone(),
                name: "entry-local".into(),
                address: "127.0.0.1".into(),
                port: 5000,
                kind: "private".into(),
                priority: "primary".into(),
                interface: None,
                source_ip: None,
                tls_server_name: None,
            })
            .await
            .unwrap();

        let repo = RouteRepo::new(&f.db);
        let err = repo
            .create(new_route(&f, "sh-hk", 443, vec![stray.id]))
            .await
            .unwrap_err();
        assert!(matches!(err, DbError::Invalid(_)), "{err:?}");
    }

    #[tokio::test]
    async fn nonexistent_endpoint_is_rejected() {
        let f = fixture().await;
        let repo = RouteRepo::new(&f.db);
        assert!(matches!(
            repo.create(new_route(&f, "sh-hk", 443, vec!["ghost".into()]))
                .await,
            Err(DbError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn failed_create_leaves_no_partial_route() {
        // The transaction must roll back the route row when an endpoint insert
        // fails, or we would have a route that can never dial anything.
        let f = fixture().await;
        let repo = RouteRepo::new(&f.db);
        let _ = repo
            .create(new_route(&f, "sh-hk", 443, vec!["ghost".into()]))
            .await;

        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM routes")
            .fetch_one(f.db.pool())
            .await
            .unwrap();
        assert_eq!(count.0, 0, "orphan route row left behind");
        let links: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM route_endpoints")
            .fetch_one(f.db.pool())
            .await
            .unwrap();
        assert_eq!(links.0, 0);
    }

    #[tokio::test]
    async fn duplicate_listen_address_on_one_entry_is_a_conflict() {
        // Two routes cannot bind the same socket; catching it here beats a
        // runtime bind failure on the agent.
        let f = fixture().await;
        let repo = RouteRepo::new(&f.db);
        repo.create(new_route(&f, "first", 443, vec![f.iepl_ep.clone()]))
            .await
            .unwrap();
        let err = repo
            .create(new_route(&f, "second", 443, vec![f.iepl_ep.clone()]))
            .await
            .unwrap_err();
        assert!(matches!(err, DbError::Conflict(_)), "{err:?}");

        // A different port is fine.
        repo.create(new_route(&f, "third", 8443, vec![f.iepl_ep.clone()]))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn duplicate_route_name_is_a_conflict() {
        let f = fixture().await;
        let repo = RouteRepo::new(&f.db);
        repo.create(new_route(&f, "sh-hk", 443, vec![f.iepl_ep.clone()]))
            .await
            .unwrap();
        assert!(matches!(
            repo.create(new_route(&f, "sh-hk", 8443, vec![f.iepl_ep.clone()]))
                .await,
            Err(DbError::Conflict(_))
        ));
    }

    #[tokio::test]
    async fn pool_size_and_load_balance_are_validated() {
        let f = fixture().await;
        let repo = RouteRepo::new(&f.db);

        let mut bad = new_route(&f, "a", 443, vec![f.iepl_ep.clone()]);
        bad.tunnel_pool_size = 0;
        assert!(matches!(repo.create(bad).await, Err(DbError::Invalid(_))));

        let mut bad = new_route(&f, "b", 444, vec![f.iepl_ep.clone()]);
        bad.tunnel_pool_size = 1000;
        assert!(matches!(repo.create(bad).await, Err(DbError::Invalid(_))));

        let mut bad = new_route(&f, "c", 445, vec![f.iepl_ep.clone()]);
        bad.load_balance = "random".into();
        assert!(matches!(repo.create(bad).await, Err(DbError::Invalid(_))));

        let mut bad = new_route(&f, "d", 446, vec![f.iepl_ep.clone()]);
        bad.egress_source_ip = Some("999.999.999.999".into());
        assert!(matches!(repo.create(bad).await, Err(DbError::Invalid(_))));
    }

    #[tokio::test]
    async fn update_replaces_the_endpoint_list() {
        let f = fixture().await;
        let repo = RouteRepo::new(&f.db);
        let route = repo
            .create(new_route(&f, "sh-hk", 443, vec![f.iepl_ep.clone()]))
            .await
            .unwrap();
        assert_eq!(route.endpoints.len(), 1);

        let updated = repo
            .update(
                &route.id,
                UpdateRoute {
                    endpoint_ids: Some(vec![f.public_ep.clone(), f.iepl_ep.clone()]),
                    tunnel_pool_size: Some(16),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(updated.endpoints.len(), 2);
        assert_eq!(updated.endpoints[0].name, "hk-public");
        assert_eq!(updated.tunnel_pool_size, 16);
        // Unspecified fields must be preserved.
        assert_eq!(updated.listen_port, 443);
        assert_eq!(updated.target_port, 8443);
    }

    #[tokio::test]
    async fn partial_update_leaves_endpoints_alone() {
        let f = fixture().await;
        let repo = RouteRepo::new(&f.db);
        let route = repo
            .create(new_route(
                &f,
                "sh-hk",
                443,
                vec![f.iepl_ep.clone(), f.public_ep.clone()],
            ))
            .await
            .unwrap();

        let updated = repo
            .update(
                &route.id,
                UpdateRoute {
                    target_port: Some(9443),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(updated.target_port, 9443);
        assert_eq!(updated.endpoints.len(), 2, "endpoints were clobbered");
    }

    #[tokio::test]
    async fn enable_and_disable() {
        let f = fixture().await;
        let repo = RouteRepo::new(&f.db);
        let route = repo
            .create(new_route(&f, "sh-hk", 443, vec![f.iepl_ep.clone()]))
            .await
            .unwrap();

        assert!(!repo.set_enabled(&route.id, false).await.unwrap().enabled);
        assert!(repo.set_enabled(&route.id, true).await.unwrap().enabled);
    }

    #[tokio::test]
    async fn delete_cascades_the_endpoint_links() {
        let f = fixture().await;
        let repo = RouteRepo::new(&f.db);
        let route = repo
            .create(new_route(
                &f,
                "sh-hk",
                443,
                vec![f.iepl_ep.clone(), f.public_ep.clone()],
            ))
            .await
            .unwrap();

        repo.delete(&route.id).await.unwrap();
        assert!(matches!(repo.get(&route.id).await, Err(DbError::NotFound(_))));
        let links: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM route_endpoints")
            .fetch_one(f.db.pool())
            .await
            .unwrap();
        assert_eq!(links.0, 0, "route_endpoints rows leaked");
    }

    #[tokio::test]
    async fn per_role_listings_are_distinct() {
        let f = fixture().await;
        let repo = RouteRepo::new(&f.db);
        repo.create(new_route(&f, "sh-hk", 443, vec![f.iepl_ep.clone()]))
            .await
            .unwrap();

        assert_eq!(
            repo.list_for_entry_group(&f.entry_group).await.unwrap().len(),
            1
        );
        assert_eq!(
            repo.list_for_exit_group(&f.exit_group).await.unwrap().len(),
            1
        );
        // 入口组不是这条线路的出口，反之亦然。
        assert!(repo
            .list_for_exit_group(&f.entry_group)
            .await
            .unwrap()
            .is_empty());
        assert!(repo
            .list_for_entry_group(&f.exit_group)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn affected_groups_covers_both_ends_without_duplicates() {
        let f = fixture().await;
        let repo = RouteRepo::new(&f.db);
        let route = repo
            .create(new_route(&f, "sh-hk", 443, vec![f.iepl_ep.clone()]))
            .await
            .unwrap();

        let groups = repo.affected_groups(&route.id).await.unwrap();
        assert_eq!(groups.len(), 2);
        assert!(groups.contains(&f.entry_group) && groups.contains(&f.exit_group));
        assert!(repo.affected_groups("missing").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn row_converts_to_the_wire_model() {
        let f = fixture().await;
        let repo = RouteRepo::new(&f.db);
        let route = repo
            .create(new_route(
                &f,
                "sh-hk",
                443,
                vec![f.iepl_ep.clone(), f.public_ep.clone()],
            ))
            .await
            .unwrap();

        let row = repo.get_row(&route.id).await.unwrap();
        let ids = repo.endpoint_ids_for(&route.id).await.unwrap();
        let model = row.to_model(ids);
        assert_eq!(model.listen_socket_addr(), "0.0.0.0:443");
        assert_eq!(model.target_socket_addr(), "127.0.0.1:8443");
        assert_eq!(model.endpoint_ids.len(), 2);
        assert_eq!(
            model.egress_source_ip.unwrap().to_string(),
            "203.0.113.9",
            "egress binding must survive the round trip"
        );
    }
}
