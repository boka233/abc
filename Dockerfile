# 控制面 + 管理面板的容器镜像。
#
# 只打包控制面，不打包 agent —— agent 要操作宿主机的网络栈（绑定源地址、监听任意
# 端口、读网卡列表），跑在容器里要 --network host 加一堆 capability，那时容器已经
# 没有隔离价值了，不如直接用 systemd 装在宿主机上。
#
# 三个阶段:
#   web     构建 Vue 面板
#   build   编译 Rust 二进制
#   runtime 只带运行所需内容的精简镜像

# ---------------------------------------------------------------------------
# 前端
# ---------------------------------------------------------------------------
FROM node:20-bookworm-slim AS web

WORKDIR /src/web
# 先只拷依赖清单：源码变动不会让 npm ci 的缓存层失效。
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund

COPY web/ ./
# 这一步同时做 vue-tsc 类型检查，类型错误会让构建失败。
RUN npm run build

# ---------------------------------------------------------------------------
# Rust
# ---------------------------------------------------------------------------
FROM rust:1.80-bookworm AS build

# ring 与 libsqlite3-sys 含 C 代码，需要 cc 与 pkg-config。
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# 先拷清单与空壳源码，把依赖编译单独缓存成一层。改业务代码时这一层不必重来 ——
# 这个 workspace 的依赖树编译要几分钟。
COPY Cargo.toml Cargo.lock ./
COPY crates/tunnel-common/Cargo.toml crates/tunnel-common/
COPY crates/tunnel-protocol/Cargo.toml crates/tunnel-protocol/
COPY crates/tunnel-core/Cargo.toml crates/tunnel-core/
COPY crates/tunnel-storage/Cargo.toml crates/tunnel-storage/
COPY crates/tunnel-control/Cargo.toml crates/tunnel-control/
COPY crates/tunnel-agent/Cargo.toml crates/tunnel-agent/
RUN set -eux; \
    for c in tunnel-common tunnel-protocol tunnel-core tunnel-storage; do \
        mkdir -p "crates/$c/src" && echo '' > "crates/$c/src/lib.rs"; \
    done; \
    for c in tunnel-control tunnel-agent; do \
        mkdir -p "crates/$c/src" && echo 'fn main() {}' > "crates/$c/src/main.rs"; \
    done; \
    # tunnel-control 既有 lib 也有 main。
    echo '' > crates/tunnel-control/src/lib.rs; \
    cargo build --release --locked 2>/dev/null || true

# 真实源码。migrations 必须在编译前就位：sqlx::migrate! 是编译期宏，会把 SQL 读进
# 二进制 —— 少了它编译直接失败，而不是运行时才报错。
COPY crates/ crates/
COPY migrations/ migrations/
COPY scripts/agent-install.sh scripts/
# 触碰源码文件，确保上面空壳留下的时间戳不会让 cargo 误判为无需重编。
RUN find crates -name '*.rs' -exec touch {} + \
    && cargo build --release --locked -p tunnel-control \
    && strip target/release/tunnel-control

# ---------------------------------------------------------------------------
# 运行时
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

# ca-certificates: 反代之外若要访问外部 HTTPS 需要它
# curl: 健康检查用
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --shell /usr/sbin/nologin --uid 10001 tunnel

COPY --from=build /src/target/release/tunnel-control /usr/local/bin/tunnel-control
COPY --from=web   /src/web/dist /usr/share/tunnel-control/web

# 数据与配置目录。数据目录必须是卷 —— 不挂载的话容器一删，数据库和已注册的机器
# 信息全部丢失。
RUN install -d -o tunnel -g tunnel -m 750 /var/lib/tunnel-control \
    && install -d -o tunnel -g tunnel -m 755 /var/lib/tunnel-control/agent-bin \
    && install -d -m 755 /etc/tunnel-control

VOLUME ["/var/lib/tunnel-control"]

USER tunnel
EXPOSE 8080

# 容器里监听 0.0.0.0 而不是回环：反代在另一个容器里，连不上回环。对外暴露由
# compose 的端口映射与反代控制，不是靠这里绑回环。
ENV TUNNEL_CONTROL_LISTEN=0.0.0.0:8080 \
    TUNNEL_CONTROL_DATABASE=/var/lib/tunnel-control/control.db \
    TUNNEL_CONTROL_WEB_ROOT=/usr/share/tunnel-control/web \
    TUNNEL_CONTROL_AGENT_BINARY_DIR=/var/lib/tunnel-control/agent-bin

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/health || exit 1

ENTRYPOINT ["/usr/local/bin/tunnel-control", "--config", "/etc/tunnel-control/config.toml"]
