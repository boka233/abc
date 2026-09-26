-- Durable traffic totals survive agent counter resets and sample retention.
CREATE TABLE node_traffic_totals (
    node_id TEXT PRIMARY KEY NOT NULL,
    total_rx_bytes INTEGER NOT NULL DEFAULT 0,
    total_tx_bytes INTEGER NOT NULL DEFAULT 0,
    last_rx_bytes INTEGER NOT NULL DEFAULT 0,
    last_tx_bytes INTEGER NOT NULL DEFAULT 0
);

-- Recover as much history as the retained samples allow during upgrade.
INSERT INTO node_traffic_totals
    (node_id, total_rx_bytes, total_tx_bytes, last_rx_bytes, last_tx_bytes)
WITH ordered AS (
    SELECT node_id, rx_bytes, tx_bytes,
           LAG(rx_bytes) OVER (PARTITION BY node_id ORDER BY bucket_at, id) AS previous_rx,
           LAG(tx_bytes) OVER (PARTITION BY node_id ORDER BY bucket_at, id) AS previous_tx
    FROM traffic_stats WHERE route_id IS NULL
), totals AS (
    SELECT node_id,
           SUM(CASE WHEN previous_rx IS NULL OR rx_bytes < previous_rx
                    THEN rx_bytes ELSE rx_bytes - previous_rx END) AS total_rx,
           SUM(CASE WHEN previous_tx IS NULL OR tx_bytes < previous_tx
                    THEN tx_bytes ELSE tx_bytes - previous_tx END) AS total_tx
    FROM ordered GROUP BY node_id
)
SELECT t.node_id, t.total_rx, t.total_tx,
       (SELECT rx_bytes FROM traffic_stats s WHERE s.node_id = t.node_id AND s.route_id IS NULL
        ORDER BY bucket_at DESC, id DESC LIMIT 1),
       (SELECT tx_bytes FROM traffic_stats s WHERE s.node_id = t.node_id AND s.route_id IS NULL
        ORDER BY bucket_at DESC, id DESC LIMIT 1)
FROM totals t;

ALTER TABLE node_status ADD COLUMN observed_ip TEXT;
ALTER TABLE node_status ADD COLUMN disk_used_bytes INTEGER NOT NULL DEFAULT 0;
ALTER TABLE node_status ADD COLUMN disk_total_bytes INTEGER NOT NULL DEFAULT 0;
ALTER TABLE node_status ADD COLUMN host_uptime_secs INTEGER NOT NULL DEFAULT 0;
