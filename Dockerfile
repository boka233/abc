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
# 用 rust:1-bookworm（跟随最新稳定版）而不是固定的 1.80。
#
# 为什么：Cargo.lock 里锁定的依赖有自己的 MSRV，且会随 cargo update 往上走 ——
# 目前 base64ct 1.8.3 要 1.85、icu_collections 2.3.0 要 1.86、darling_core 0.23
# 要 1.88。固定 1.80 会在这些依赖更新后突然构建失败，而失败信息出现在依赖的
# 编译输出里，离真正原因很远（exit code 101，要翻上百行日志才看到 MSRV 提示）。
#
# workspace 的 rust-version = "1.80" 描述的是**本项目代码**的下限，不是依赖树的。
# 两者不是一回事。
FROM rust:1-bookworm AS build

# ring 与 libsqlite3-sys 含 C 代码，需要 cc 与 pkg-config。
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# 一次性拷入全部源码后编译。
#
# 这里**不用**「先拷 Cargo.toml + 空壳 src 预热依赖缓存」那个常见技巧：
# tunnel-control 里有 include_str!("../../../../scripts/agent-install.sh")，
# 空壳阶段那个文件还不存在，预热编译必然失败；而为了让构建继续就得写成
# `|| true` 并丢掉 stderr —— 结果是这一层什么也没缓存，却让真正的编译错误
# 变得难以察觉（本次 MSRV 不匹配就是被这样掩盖的一部分）。
#
# 需要加速重复构建时用 BuildKit 缓存挂载，比空壳技巧更可靠：
#   DOCKER_BUILDKIT=1 docker build ...
# 并把下面的 RUN 换成带 --mount=type=cache,target=/usr/local/cargo/registry 的形式。
#
# migrations 必须在编译前就位：sqlx::migrate! 是编译期宏，会把 SQL 读进二进制。
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY migrations/ migrations/
COPY scripts/agent-install.sh scripts/

# 同时编译 control 与 agent。
#
# agent 不进运行时镜像（它要操作宿主网络栈，容器化没有隔离价值），但必须在这一阶段
# 产出：docker-deploy.sh 会从这个 build 阶段把它拷出来，放进控制面的
# agent_binary_dir，供一键对接的机器下载。只编 control 会让那一步静默拿不到文件，
# 而症状要等到有人真去对接机器时才暴露。
#
# --locked：严格按 Cargo.lock 构建。没有它 cargo 可能拉到更新的依赖，导致镜像内容
# 与仓库状态不一致，且依赖的 MSRV 可能再次超出基础镜像。
RUN cargo build --release --locked -p tunnel-control -p tunnel-agent \
    && strip target/release/tunnel-control target/release/tunnel-agent

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
