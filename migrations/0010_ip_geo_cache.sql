-- 公网 IP → 国家的查询缓存。
--
-- # 为什么在服务端查、并且缓存
--
-- 以前是浏览器直接请求 api.country.is。那样每个打开面板的访客都会把**全部中转机
-- 的公网 IP** 发给第三方，而且面板下发的 CSP（connect-src 'self'）本来就拦住了
-- 这个请求，所以地区一直显示「—」。
--
-- 改成控制面查询：每个 IP 一辈子只查一次，结果落库，重启不丢。
--
-- # 为什么记录失败
--
-- 查询可能因为网络不通、对方限流、IP 查不到而失败。若失败不落库，每次心跳（10 秒
-- 一次）都会重试一遍，对一个查不到的 IP 就是永远每 10 秒打一次外部 API。
-- 失败也写一行并记下时间，在退避期内不再重查。

CREATE TABLE ip_geo_cache (
    ip          TEXT PRIMARY KEY NOT NULL,
    -- ISO 3166-1 alpha-2，如 HK、JP。查询失败或查不到时为 NULL。
    country     TEXT,
    -- 最后一次查询的时间（RFC 3339）。失败时据此决定何时重试。
    looked_up_at TEXT NOT NULL,
    -- 1 表示最后一次查询失败。成功查到后清零。
    failed      INTEGER NOT NULL DEFAULT 0
);
