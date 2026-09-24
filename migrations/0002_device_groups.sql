-- 设备组：一个组可接入多台机器，token 挂在组上而非单机。
--
-- 为什么 token 属于组而不属于机器：
--   线路引用的是组，不是具体机器。换机器、加机器、下线一台，线路配置都不用动。
--   同一条安装命令可以在多台机器上执行，它们自动加入同一个组。
--   这是「一键对接」能成立的前提 —— 否则每台机器都要回面板单独签发 token。
--
-- 迁移策略：
--   0001 里已有的 nodes/routes 数据要保留。做法是为每个既有节点建一个同名的
--   单机组，把节点挂进去，再把 routes 的 entry/exit 指向对应的组。这样旧部署
--   升级后行为不变，只是多了一层可扩展的组。

PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------------------------
-- device_groups
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS device_groups (
    id              TEXT PRIMARY KEY NOT NULL,
    name            TEXT NOT NULL UNIQUE,
    region          TEXT NOT NULL DEFAULT '',
    -- inbound  = 入口组，接受用户连接并拨隧道
    -- outbound = 出口组，终结隧道并拨目标
    -- both     = 两者兼任（自环或小规模部署）
    kind            TEXT NOT NULL CHECK (kind IN ('inbound', 'outbound', 'both')),
    -- 组级注册令牌的哈希。明文只在签发时显示一次。
    enroll_token_hash TEXT NOT NULL,
    note            TEXT,
    enabled         INTEGER NOT NULL DEFAULT 1,
    -- 组内任一成员的配置变更都会递增它，组内所有 agent 据此判断是否需要重载。
    config_revision INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_groups_kind ON device_groups (kind);

-- ---------------------------------------------------------------------------
-- nodes：归属到组
-- ---------------------------------------------------------------------------
-- SQLite 的 ALTER TABLE 不支持加带外键的列，也不支持改列约束，所以整表重建。
-- 重建时顺带去掉 nodes 自己的 agent_token_hash —— 认证已上移到组级别，
-- 留着会让人误以为还能按单机签发 token。

CREATE TABLE nodes_new (
    id                  TEXT PRIMARY KEY NOT NULL,
    group_id            TEXT NOT NULL,
    -- 组内唯一即可，不再全局唯一：两个机房可以都有一台叫 relay-01 的机器。
    name                TEXT NOT NULL,
    -- agent 自注册时上报的主机名，用于在面板上区分同组机器。
    hostname            TEXT,
    region              TEXT NOT NULL DEFAULT '',
    -- 仍保留：一台机器可以在组的能力范围内被单独降级（组是 both，机器只做 exit）。
    role                TEXT NOT NULL CHECK (role IN ('entry', 'exit', 'both')),
    public_address      TEXT,
    management_address  TEXT,
    agent_version       TEXT,
    note                TEXT,
    enabled             INTEGER NOT NULL DEFAULT 1,
    config_revision     INTEGER NOT NULL DEFAULT 1,
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    FOREIGN KEY (group_id) REFERENCES device_groups (id) ON DELETE CASCADE,
    UNIQUE (group_id, name)
);

-- 为每个既有节点建一个同名单机组，保持升级前后行为一致。
INSERT INTO device_groups
    (id, name, region, kind, enroll_token_hash, note, enabled,
     config_revision, created_at, updated_at)
SELECT
    'grp-' || n.id,
    n.name,
    n.region,
    CASE n.role WHEN 'entry' THEN 'inbound' WHEN 'exit' THEN 'outbound' ELSE 'both' END,
    -- 沿用原节点 token 的哈希，这样既有 agent 升级后无需换凭据。
    n.agent_token_hash,
    n.note,
    n.enabled,
    n.config_revision,
    n.created_at,
    n.updated_at
FROM nodes n;

INSERT INTO nodes_new
    (id, group_id, name, hostname, region, role, public_address,
     management_address, agent_version, note, enabled, config_revision,
     created_at, updated_at)
SELECT
    n.id, 'grp-' || n.id, n.name, NULL, n.region, n.role, n.public_address,
    n.management_address, n.agent_version, n.note, n.enabled,
    n.config_revision, n.created_at, n.updated_at
FROM nodes n;

DROP TABLE nodes;
ALTER TABLE nodes_new RENAME TO nodes;

CREATE INDEX IF NOT EXISTS idx_nodes_group ON nodes (group_id);
CREATE INDEX IF NOT EXISTS idx_nodes_role ON nodes (role);

-- node_status 的外键随 nodes 重建而失效，重建它以恢复级联。
CREATE TABLE node_status_new (
    node_id             TEXT PRIMARY KEY NOT NULL,
    status              TEXT NOT NULL DEFAULT 'offline'
                        CHECK (status IN ('online', 'degraded', 'offline')),
    cpu_percent         REAL NOT NULL DEFAULT 0,
    memory_used_bytes   INTEGER NOT NULL DEFAULT 0,
    memory_total_bytes  INTEGER NOT NULL DEFAULT 0,
    uptime_secs         INTEGER NOT NULL DEFAULT 0,
    connections         INTEGER NOT NULL DEFAULT 0,
    rx_bytes            INTEGER NOT NULL DEFAULT 0,
    tx_bytes            INTEGER NOT NULL DEFAULT 0,
    rx_bps              INTEGER NOT NULL DEFAULT 0,
    tx_bps              INTEGER NOT NULL DEFAULT 0,
    tunnels_online      INTEGER NOT NULL DEFAULT 0,
    tunnels_total       INTEGER NOT NULL DEFAULT 0,
    agent_version       TEXT,
    config_revision     INTEGER NOT NULL DEFAULT 0,
    interfaces_json     TEXT,
    last_heartbeat_at   TEXT,
    FOREIGN KEY (node_id) REFERENCES nodes (id) ON DELETE CASCADE
);

INSERT INTO node_status_new SELECT * FROM node_status;
DROP TABLE node_status;
ALTER TABLE node_status_new RENAME TO node_status;

-- ---------------------------------------------------------------------------
-- endpoints：跟随节点，外键需重建
-- ---------------------------------------------------------------------------
CREATE TABLE endpoints_new (
    id              TEXT PRIMARY KEY NOT NULL,
    node_id         TEXT NOT NULL,
    name            TEXT NOT NULL,
    address         TEXT NOT NULL,
    port            INTEGER NOT NULL CHECK (port > 0 AND port < 65536),
    kind            TEXT NOT NULL CHECK (kind IN ('public', 'private', 'iepl')),
    priority        TEXT NOT NULL DEFAULT 'primary'
                    CHECK (priority IN ('primary', 'backup')),
    interface       TEXT,
    source_ip       TEXT,
    tls_server_name TEXT,
    enabled         INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    FOREIGN KEY (node_id) REFERENCES nodes (id) ON DELETE CASCADE,
    UNIQUE (node_id, name)
);

INSERT INTO endpoints_new SELECT * FROM endpoints;
DROP TABLE endpoints;
ALTER TABLE endpoints_new RENAME TO endpoints;

CREATE INDEX IF NOT EXISTS idx_endpoints_node ON endpoints (node_id);

-- ---------------------------------------------------------------------------
-- routes：改为引用组
-- ---------------------------------------------------------------------------
-- 线路引用组而非单机，是这次改动的核心收益：组内加减机器不影响线路。
CREATE TABLE routes_new (
    id                  TEXT PRIMARY KEY NOT NULL,
    name                TEXT NOT NULL UNIQUE,
    entry_group_id      TEXT NOT NULL,
    listen_address      TEXT NOT NULL DEFAULT '0.0.0.0',
    listen_port         INTEGER NOT NULL CHECK (listen_port > 0 AND listen_port < 65536),
    exit_group_id       TEXT NOT NULL,
    target_host         TEXT NOT NULL,
    target_port         INTEGER NOT NULL CHECK (target_port > 0 AND target_port < 65536),
    tunnel_pool_size    INTEGER NOT NULL DEFAULT 8
                        CHECK (tunnel_pool_size > 0 AND tunnel_pool_size <= 256),
    load_balance        TEXT NOT NULL DEFAULT 'round_robin'
                        CHECK (load_balance IN ('round_robin', 'least_streams')),
    max_connections     INTEGER NOT NULL DEFAULT 0,
    egress_source_ip    TEXT,
    egress_interface    TEXT,
    enabled             INTEGER NOT NULL DEFAULT 1,
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    -- RESTRICT：删组时若仍有线路引用，应当报错而不是静默丢掉转发规则。
    FOREIGN KEY (entry_group_id) REFERENCES device_groups (id) ON DELETE RESTRICT,
    FOREIGN KEY (exit_group_id) REFERENCES device_groups (id) ON DELETE RESTRICT,
    -- 一个入口组内不能有两条线路抢同一个监听地址。
    UNIQUE (entry_group_id, listen_address, listen_port)
);

INSERT INTO routes_new
    (id, name, entry_group_id, listen_address, listen_port, exit_group_id,
     target_host, target_port, tunnel_pool_size, load_balance, max_connections,
     egress_source_ip, egress_interface, enabled, created_at, updated_at)
SELECT
    r.id, r.name, 'grp-' || r.entry_node_id, r.listen_address, r.listen_port,
    'grp-' || r.exit_node_id, r.target_host, r.target_port, r.tunnel_pool_size,
    r.load_balance, r.max_connections, r.egress_source_ip, r.egress_interface,
    r.enabled, r.created_at, r.updated_at
FROM routes r;

DROP TABLE routes;
ALTER TABLE routes_new RENAME TO routes;

CREATE INDEX IF NOT EXISTS idx_routes_entry_group ON routes (entry_group_id);
CREATE INDEX IF NOT EXISTS idx_routes_exit_group ON routes (exit_group_id);

-- route_endpoints 的外键随两表重建失效，重建。
CREATE TABLE route_endpoints_new (
    route_id    TEXT NOT NULL,
    endpoint_id TEXT NOT NULL,
    position    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (route_id, endpoint_id),
    FOREIGN KEY (route_id) REFERENCES routes (id) ON DELETE CASCADE,
    FOREIGN KEY (endpoint_id) REFERENCES endpoints (id) ON DELETE CASCADE
);

INSERT INTO route_endpoints_new SELECT * FROM route_endpoints;
DROP TABLE route_endpoints;
ALTER TABLE route_endpoints_new RENAME TO route_endpoints;

CREATE INDEX IF NOT EXISTS idx_route_endpoints_route ON route_endpoints (route_id);

-- ---------------------------------------------------------------------------
-- traffic_stats：外键随 nodes/routes 重建失效，重建
-- ---------------------------------------------------------------------------
CREATE TABLE traffic_stats_new (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    bucket_at       TEXT NOT NULL,
    node_id         TEXT NOT NULL,
    route_id        TEXT,
    rx_bytes        INTEGER NOT NULL DEFAULT 0,
    tx_bytes        INTEGER NOT NULL DEFAULT 0,
    rx_bps          INTEGER NOT NULL DEFAULT 0,
    tx_bps          INTEGER NOT NULL DEFAULT 0,
    connections     INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (node_id) REFERENCES nodes (id) ON DELETE CASCADE,
    FOREIGN KEY (route_id) REFERENCES routes (id) ON DELETE CASCADE
);

INSERT INTO traffic_stats_new SELECT * FROM traffic_stats;
DROP TABLE traffic_stats;
ALTER TABLE traffic_stats_new RENAME TO traffic_stats;

CREATE INDEX IF NOT EXISTS idx_traffic_bucket ON traffic_stats (bucket_at);
CREATE INDEX IF NOT EXISTS idx_traffic_node_bucket ON traffic_stats (node_id, bucket_at);
CREATE INDEX IF NOT EXISTS idx_traffic_route_bucket ON traffic_stats (route_id, bucket_at);
