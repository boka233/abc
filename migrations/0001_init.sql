-- Initial schema.
--
-- Design notes:
--
-- * Every table uses a TEXT primary key holding a UUID. Not an INTEGER
--   autoincrement, because ids appear in agent config bundles and in URLs, and
--   a sequential id leaks how many objects exist and invites enumeration.
-- * Timestamps are TEXT in RFC3339/UTC. SQLite has no native timestamp type;
--   RFC3339 sorts lexicographically, which keeps ORDER BY correct.
-- * Foreign keys use ON DELETE CASCADE where an orphan row would be a bug
--   (an endpoint without its node is meaningless) and RESTRICT where silent
--   deletion would be dangerous (a node still referenced by a route).
-- * `traffic_stats` is written by the aggregation loop, never by the data path.
--
-- Portability: this DDL avoids SQLite-only syntax so the move to PostgreSQL is
-- a type-mapping exercise rather than a rewrite.

PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------------------------
-- users
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id              TEXT PRIMARY KEY NOT NULL,
    username        TEXT NOT NULL UNIQUE,
    -- Argon2id PHC string. Contains its own salt and parameters, so no separate
    -- salt column and no risk of the two drifting apart.
    password_hash   TEXT NOT NULL,
    role            TEXT NOT NULL DEFAULT 'admin',
    -- Forces a password change on first login for seeded accounts.
    must_change_password INTEGER NOT NULL DEFAULT 0,
    disabled        INTEGER NOT NULL DEFAULT 0,
    last_login_at   TEXT,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

-- ---------------------------------------------------------------------------
-- nodes
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS nodes (
    id                  TEXT PRIMARY KEY NOT NULL,
    name                TEXT NOT NULL UNIQUE,
    region              TEXT NOT NULL DEFAULT '',
    role                TEXT NOT NULL CHECK (role IN ('entry', 'exit', 'both')),
    -- How users reach this node. Display/diagnostics only: never used to dial a
    -- tunnel. Tunnel addresses live in `endpoints`.
    public_address      TEXT,
    -- Operator SSH/ops address. Also never used to dial a tunnel.
    management_address  TEXT,
    -- Bcrypt-style hash of the agent enrolment token, so a database dump does
    -- not hand over working agent credentials.
    agent_token_hash    TEXT NOT NULL,
    agent_version       TEXT,
    note                TEXT,
    enabled             INTEGER NOT NULL DEFAULT 1,
    -- Bumped on every config change; the agent uses it to skip re-applying an
    -- identical bundle.
    config_revision     INTEGER NOT NULL DEFAULT 1,
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_nodes_role ON nodes (role);

-- Last-known runtime state. Separate from `nodes` because it is written every
-- few seconds by heartbeats, while `nodes` is configuration that changes rarely.
-- Mixing them would make every heartbeat dirty a config row.
CREATE TABLE IF NOT EXISTS node_status (
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
    -- JSON array of interfaces reported by the agent, for the node detail page.
    interfaces_json     TEXT,
    last_heartbeat_at   TEXT,
    FOREIGN KEY (node_id) REFERENCES nodes (id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------
-- endpoints
-- ---------------------------------------------------------------------------
-- A dialable tunnel address on a node. Multiple endpoints per node is the
-- mechanism for IEPL + public failover: same exit process, two paths.
CREATE TABLE IF NOT EXISTS endpoints (
    id              TEXT PRIMARY KEY NOT NULL,
    node_id         TEXT NOT NULL,
    name            TEXT NOT NULL,
    address         TEXT NOT NULL,
    port            INTEGER NOT NULL CHECK (port > 0 AND port < 65536),
    kind            TEXT NOT NULL CHECK (kind IN ('public', 'private', 'iepl')),
    priority        TEXT NOT NULL DEFAULT 'primary'
                    CHECK (priority IN ('primary', 'backup')),
    -- Informational: which NIC this address sits on, for the panel.
    interface       TEXT,
    -- Source IP the *entry* binds before connecting, to force egress out of a
    -- specific NIC.
    source_ip       TEXT,
    -- SNI / certificate name to verify. Needed when `address` is a bare IP.
    tls_server_name TEXT,
    enabled         INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    FOREIGN KEY (node_id) REFERENCES nodes (id) ON DELETE CASCADE,
    UNIQUE (node_id, name)
);

CREATE INDEX IF NOT EXISTS idx_endpoints_node ON endpoints (node_id);

-- ---------------------------------------------------------------------------
-- routes
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS routes (
    id                  TEXT PRIMARY KEY NOT NULL,
    name                TEXT NOT NULL UNIQUE,
    entry_node_id       TEXT NOT NULL,
    listen_address      TEXT NOT NULL DEFAULT '0.0.0.0',
    listen_port         INTEGER NOT NULL CHECK (listen_port > 0 AND listen_port < 65536),
    exit_node_id        TEXT NOT NULL,
    target_host         TEXT NOT NULL,
    target_port         INTEGER NOT NULL CHECK (target_port > 0 AND target_port < 65536),
    tunnel_pool_size    INTEGER NOT NULL DEFAULT 8
                        CHECK (tunnel_pool_size > 0 AND tunnel_pool_size <= 256),
    load_balance        TEXT NOT NULL DEFAULT 'round_robin'
                        CHECK (load_balance IN ('round_robin', 'least_streams')),
    -- 0 means "inherit the agent-wide limit".
    max_connections     INTEGER NOT NULL DEFAULT 0,
    -- Source IP the *exit* binds when dialling the target. This is how traffic
    -- arriving over IEPL leaves through the public NIC.
    egress_source_ip    TEXT,
    -- SO_BINDTODEVICE name. Needs CAP_NET_RAW; prefer egress_source_ip.
    egress_interface    TEXT,
    enabled             INTEGER NOT NULL DEFAULT 1,
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    -- RESTRICT, not CASCADE: deleting a node that still carries routes should
    -- fail loudly rather than silently dropping traffic rules.
    FOREIGN KEY (entry_node_id) REFERENCES nodes (id) ON DELETE RESTRICT,
    FOREIGN KEY (exit_node_id) REFERENCES nodes (id) ON DELETE RESTRICT,
    -- One listener per address per entry node.
    UNIQUE (entry_node_id, listen_address, listen_port)
);

CREATE INDEX IF NOT EXISTS idx_routes_entry ON routes (entry_node_id);
CREATE INDEX IF NOT EXISTS idx_routes_exit ON routes (exit_node_id);

-- Which endpoints a route may dial, and in what order. `position` drives
-- primary/backup ordering within the route.
CREATE TABLE IF NOT EXISTS route_endpoints (
    route_id    TEXT NOT NULL,
    endpoint_id TEXT NOT NULL,
    position    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (route_id, endpoint_id),
    FOREIGN KEY (route_id) REFERENCES routes (id) ON DELETE CASCADE,
    FOREIGN KEY (endpoint_id) REFERENCES endpoints (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_route_endpoints_route ON route_endpoints (route_id);

-- ---------------------------------------------------------------------------
-- traffic_stats
-- ---------------------------------------------------------------------------
-- Time-bucketed counters written by the control plane's aggregation loop.
--
-- Deliberately NOT written per connection or per packet: the data plane keeps
-- atomics in memory and the aggregator persists a rolled-up row per bucket. One
-- INSERT per node per bucket, regardless of traffic volume.
CREATE TABLE IF NOT EXISTS traffic_stats (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    -- Start of the bucket, RFC3339 UTC.
    bucket_at       TEXT NOT NULL,
    node_id         TEXT NOT NULL,
    -- NULL for a node-level roll-up row.
    route_id        TEXT,
    rx_bytes        INTEGER NOT NULL DEFAULT 0,
    tx_bytes        INTEGER NOT NULL DEFAULT 0,
    rx_bps          INTEGER NOT NULL DEFAULT 0,
    tx_bps          INTEGER NOT NULL DEFAULT 0,
    connections     INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (node_id) REFERENCES nodes (id) ON DELETE CASCADE,
    FOREIGN KEY (route_id) REFERENCES routes (id) ON DELETE CASCADE
);

-- Supports the dashboard's "last N minutes" queries and the retention sweep.
CREATE INDEX IF NOT EXISTS idx_traffic_bucket ON traffic_stats (bucket_at);
CREATE INDEX IF NOT EXISTS idx_traffic_node_bucket ON traffic_stats (node_id, bucket_at);
CREATE INDEX IF NOT EXISTS idx_traffic_route_bucket ON traffic_stats (route_id, bucket_at);

-- ---------------------------------------------------------------------------
-- audit_logs
-- ---------------------------------------------------------------------------
-- Append-only record of privileged actions. No UPDATE or DELETE path exists in
-- the repository layer; retention is handled by an explicit prune call.
CREATE TABLE IF NOT EXISTS audit_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    at          TEXT NOT NULL,
    -- NULL for actions taken by an agent rather than a human.
    user_id     TEXT,
    username    TEXT,
    action      TEXT NOT NULL,
    -- What was acted on, e.g. 'route' / 'endpoint' / 'certificate'.
    target_type TEXT,
    target_id   TEXT,
    target_name TEXT,
    -- Client IP of the request. Retained for accountability.
    source_ip   TEXT,
    -- JSON detail. Must never contain secrets: the writer strips password,
    -- token, psk and key fields before serialising.
    detail_json TEXT,
    success     INTEGER NOT NULL DEFAULT 1,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_at ON audit_logs (at);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs (action);

-- ---------------------------------------------------------------------------
-- settings
-- ---------------------------------------------------------------------------
-- Single-row-per-key configuration that the panel can edit at runtime.
CREATE TABLE IF NOT EXISTS settings (
    key         TEXT PRIMARY KEY NOT NULL,
    value       TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
