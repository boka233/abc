-- 多目标的分配策略。
--
-- 为什么不复用 load_balance 列：那一列决定连接走**隧道池里的哪条隧道**，是传输层
-- 的事；这一列决定连接落到**哪台目标机器**，是业务层的事。两者正交 —— 一条线路
-- 完全可以「隧道按最少流分配、目标按 IP 哈希」。挤在一列里会让这两个含义互相绑死。
--
-- 默认 random：无共享游标，并发下天然均匀；也不会像轮询那样在入口组的多台机器上
-- 产生同步的分配节奏（几台机器同时把第 N 个连接投向同一个目标）。
--
-- 单目标线路这一列不起作用，但仍然给默认值，这样面板不必区分两种情况。

PRAGMA foreign_keys = ON;

-- random | round_robin | ip_hash | least_conn | failover
--
-- CHECK 约束而不是仅靠应用层校验：手工写库或将来新增写入路径时，非法值会在这里
-- 被拦住，而不是等到 agent 解析配置时才暴露。
ALTER TABLE routes ADD COLUMN target_strategy TEXT NOT NULL DEFAULT 'random'
    CHECK (target_strategy IN ('random', 'round_robin', 'ip_hash', 'least_conn', 'failover'));
