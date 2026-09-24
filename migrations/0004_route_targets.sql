-- 多目标支持：一条线路可以转发到多个目标，按轮询分配新连接。
--
-- 为什么需要：多台等价落地机分担流量是常见需求，而且导入格式里 `dest` 本来就是
-- 数组。只支持单目标会在导入时静默丢掉后面的地址。
--
-- 存储方式选择 JSON 数组而不是单独建 route_targets 表：
--   * 目标只是「地址:端口」字符串，没有自己的属性，不需要独立实体
--   * 顺序有意义（轮询顺序），关系表还得额外维护 position 列
--   * 读取时总是整条线路一起取，不存在只查某个目标的场景
--   * 数据量小（通常 1-3 个），JSON 解析开销可忽略
-- 如果将来目标需要独立的健康状态、权重或标签，再拆表。
--
-- 兼容策略：保留 target_host/target_port 两列作为「第一个目标」，既有代码路径
-- 不变；targets 为 NULL 时回落到这两列。这样 0001-0003 建的线路无需数据迁移。

PRAGMA foreign_keys = ON;

-- JSON 文本，形如 ["1.2.3.4:443","5.6.7.8:443"]。
-- NULL 表示单目标，用 target_host/target_port。
ALTER TABLE routes ADD COLUMN targets TEXT;

-- 把既有单目标线路写进 targets，让后续代码只需处理一种形态。
-- SQLite 的 json_array 从 3.38 起可用；这里用字符串拼接以兼容更老的版本。
UPDATE routes
SET targets = '["' || target_host || ':' || target_port || '"]'
WHERE targets IS NULL;
