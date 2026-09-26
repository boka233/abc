-- 线路累计流量的持久化账本。
--
-- # 为什么需要
--
-- 线路列表上的「累计流量」原本直接读 agent 进程内存里的计数器。agent 一重启计数器
-- 归零，面板上的累计流量跟着归零 —— 数据库里其实存着历史样本（traffic_stats），但
-- 总量从来没从那里算过。0008 给机器级流量建了 node_traffic_totals，线路级被跳过了。
--
-- # 为什么主键是 (route_id, node_id) 而不是 route_id
--
-- 一条线路在入口组里可能同时跑在多台机器上，每台各有一个独立的计数器。回退检测
-- （新值 < 旧值 ⇒ 计数器重启过）必须逐台做：若只按 route_id 存一行，A 机器上报
-- 1000、B 机器上报 200，会被误判成「从 1000 回退到 200」，把 B 的 200 当成一次重启
-- 累加，而 A 下一次上报 1010 又被当成从 200 增长了 810 —— 总量会被严重高估。
-- 读取时再按 route_id 求和。
--
-- # 为什么不加外键
--
-- traffic_stats 对 node_id 与 route_id 都是 ON DELETE CASCADE。账本若也级联，删掉
-- 一台下线的机器就会把它贡献的历史流量一起抹掉，线路的累计流量会凭空变小。账本
-- 记录的是「这条线路一共转发过多少」，与机器是否还存在无关。删除线路时由应用层
-- 清理这条线路的账本行。

CREATE TABLE route_traffic_totals (
    route_id        TEXT NOT NULL,
    node_id         TEXT NOT NULL,
    -- 累计总量：只增不减，跨越任意次计数器重置。
    total_rx_bytes  INTEGER NOT NULL DEFAULT 0,
    total_tx_bytes  INTEGER NOT NULL DEFAULT 0,
    -- 上一次看到的计数器读数，用来算增量与检测回退。
    last_rx_bytes   INTEGER NOT NULL DEFAULT 0,
    last_tx_bytes   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (route_id, node_id)
);

-- 从保留期内的样本回溯历史。
--
-- 与 0008 相同的算法：按 (node, route) 分区、按时间排序，相邻样本求差；新值小于
-- 前值视为计数器重启，贡献新值本身。第一个样本没有前驱，按其读数计入 —— 那是自
-- 计数器上次归零以来转发的量。
--
-- 保留期之外（已被 prune 删掉）的历史无法找回。
INSERT INTO route_traffic_totals
    (route_id, node_id, total_rx_bytes, total_tx_bytes, last_rx_bytes, last_tx_bytes)
WITH ordered AS (
    SELECT node_id, route_id, rx_bytes, tx_bytes,
           LAG(rx_bytes) OVER w AS previous_rx,
           LAG(tx_bytes) OVER w AS previous_tx,
           ROW_NUMBER()  OVER (PARTITION BY node_id, route_id
                               ORDER BY bucket_at DESC, id DESC) AS newest
    FROM traffic_stats
    WHERE route_id IS NOT NULL
    WINDOW w AS (PARTITION BY node_id, route_id ORDER BY bucket_at, id)
)
SELECT route_id, node_id,
       SUM(CASE WHEN previous_rx IS NULL OR rx_bytes < previous_rx
                THEN rx_bytes ELSE rx_bytes - previous_rx END),
       SUM(CASE WHEN previous_tx IS NULL OR tx_bytes < previous_tx
                THEN tx_bytes ELSE tx_bytes - previous_tx END),
       -- 最新一条样本的读数作为下次比较的基准。
       MAX(CASE WHEN newest = 1 THEN rx_bytes END),
       MAX(CASE WHEN newest = 1 THEN tx_bytes END)
FROM ordered
GROUP BY route_id, node_id;

-- 按线路求和是唯一的读取方式。
CREATE INDEX idx_route_traffic_totals_route ON route_traffic_totals (route_id);
