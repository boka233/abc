-- 线路模式：隧道转发 vs 直连转发。
--
-- 为什么需要这个区分：
--   隧道模式是「用户 → 入口 → 加密隧道 → 出口 → 目标」，两端各一台机器。
--   直连模式是「用户 → 单机 → 目标」，只有一台机器，不建隧道、不需要证书。
--
-- 直连模式覆盖的是最常见的场景：一台三网优化机（或 IEPL 商家只给出口 root 的
-- 情形）直接把端口转发到落地机。此前只实现了隧道模式，这类部署只能用 both 组
-- 自环凑，白白在同一台机器上加密再解密一次。
--
-- 载荷安全性说明：直连模式不加密，但被转发的通常是 VLESS/Trojan 这类自带 TLS
-- 的协议流量 —— 字节本来就是密文，再包一层只是浪费 CPU。隧道模式的加密买到的
-- 是「隐藏已加密流量的形状」（防 TLS-in-TLS 指纹），而不是「给明文加密」。

PRAGMA foreign_keys = ON;

-- SQLite 可以直接加列（带默认值且非空时也允许），不必重建整表。
-- 既有线路全部视为隧道模式，升级后行为不变。
ALTER TABLE routes ADD COLUMN mode TEXT NOT NULL DEFAULT 'tunnel';

-- CHECK 约束无法通过 ALTER TABLE 补加，所以用触发器守住取值范围。
-- 比重建整表安全：0002 已经重建过五张表，再来一次只会增加出错面。
CREATE TRIGGER IF NOT EXISTS routes_mode_check_insert
BEFORE INSERT ON routes
WHEN NEW.mode NOT IN ('tunnel', 'direct')
BEGIN
    SELECT RAISE(ABORT, 'route mode must be tunnel or direct');
END;

CREATE TRIGGER IF NOT EXISTS routes_mode_check_update
BEFORE UPDATE OF mode ON routes
WHEN NEW.mode NOT IN ('tunnel', 'direct')
BEGIN
    SELECT RAISE(ABORT, 'route mode must be tunnel or direct');
END;

CREATE INDEX IF NOT EXISTS idx_routes_mode ON routes (mode);
