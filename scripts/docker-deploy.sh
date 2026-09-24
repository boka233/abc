#!/usr/bin/env bash
#
# 一键部署控制面 + 面板 + 反向代理（自动 HTTPS），全部跑在 Docker 里。
#
# 用法:
#   sudo ./scripts/docker-deploy.sh                          # 交互式询问域名与邮箱
#   sudo ./scripts/docker-deploy.sh -d panel.example.com -e me@example.com
#   sudo ./scripts/docker-deploy.sh --local                   # 只听本机，不申请证书
#   sudo ./scripts/docker-deploy.sh --down                    # 停止（保留数据）
#   sudo ./scripts/docker-deploy.sh --logs                    # 跟踪日志
#
# 脚本做什么:
#   1. 检查/安装 Docker 与 compose 插件
#   2. 生成 .env（域名、邮箱）与 configs/control.docker.toml（含随机密钥）
#   3. 构建镜像并启动
#   4. 把 agent 二进制放进下载目录，让面板的一键对接立刻可用
#   5. 打印首次登录密码
#
# 不做什么:
#   * 不覆盖已有的密钥。重跑本脚本不会让已发出的会话失效、agent 握手失败。
#   * 不碰防火墙与 sysctl。80/443 需要放通时会提示，但不替你改。
#   * 不部署 agent。agent 要操作宿主网络栈，容器化没有隔离价值 —— 用面板的
#     一键对接命令装到宿主机上。

set -euo pipefail

readonly REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly ENV_FILE="$REPO_ROOT/.env"
readonly CONF_FILE="$REPO_ROOT/configs/control.docker.toml"

if [[ -t 1 ]]; then
    C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'
    C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_BLUE=$'\033[34m'
else
    C_RESET=""; C_BOLD=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""
fi
info() { printf '%s[ 信息 ]%s %s\n' "$C_BLUE" "$C_RESET" "$*"; }
ok()   { printf '%s[ 完成 ]%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
warn() { printf '%s[ 注意 ]%s %s\n' "$C_YELLOW" "$C_RESET" "$*"; }
die()  { printf '%s[ 失败 ]%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; exit 1; }
step() { printf '\n%s==> %s%s\n' "$C_BOLD" "$*" "$C_RESET"; }

usage() {
    cat <<'EOF'
用法: sudo ./scripts/docker-deploy.sh [选项]

选项:
  -d, --domain <域名>    面板域名，如 panel.example.com（会自动申请证书）
  -e, --email <邮箱>     Let's Encrypt 注册邮箱
      --local            只监听 127.0.0.1:8080，不申请证书、不启反代
      --down             停止服务（数据卷保留）
      --destroy          停止并删除数据卷（不可恢复）
      --logs             跟踪日志
      --rebuild          重新构建镜像后重启
      --build            强制本地构建，不拉取预构建镜像
      --image <镜像>     使用指定镜像，如 ghcr.io/user/repo-control:0.1.0
      --help             显示本帮助

默认行为：优先从 GHCR 拉取与仓库版本对应的预构建镜像（几十秒）；拉不到时会
打印原因并回落到本地构建（十几分钟，需约 2 GB 内存）。

首次运行不带参数时会交互式询问域名与邮箱。
EOF
}

# ---------------------------------------------------------------------------
# 参数
# ---------------------------------------------------------------------------
DOMAIN=""
EMAIL=""
MODE="up"
LOCAL_ONLY="no"
FORCE_BUILD="no"
FORCED_IMAGE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--domain) DOMAIN="${2:-}"; shift 2 ;;
        -e|--email) EMAIL="${2:-}"; shift 2 ;;
        --local) LOCAL_ONLY="yes"; shift ;;
        --down) MODE="down"; shift ;;
        --destroy) MODE="destroy"; shift ;;
        --logs) MODE="logs"; shift ;;
        --rebuild) MODE="rebuild"; shift ;;
        --build) FORCE_BUILD="yes"; shift ;;
        --image) FORCED_IMAGE="${2:-}"; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) usage; die "未知参数：$1" ;;
    esac
done

[[ "$(uname -s)" == "Linux" ]] || die "本脚本仅支持 Linux"
[[ $EUID -eq 0 ]] || die "需要 root 权限运行，请使用 sudo"

# ---------------------------------------------------------------------------
# Docker
# ---------------------------------------------------------------------------
ensure_docker() {
    if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
        info "docker $(docker --version | awk '{print $3}' | tr -d ,)，compose 插件可用"
        return
    fi

    if ! command -v docker >/dev/null 2>&1; then
        step "安装 Docker"
        # 用官方便捷脚本。它会识别发行版并配好仓库 —— 自己拼 apt 源在不同
        # Debian/Ubuntu 版本上很容易出错。
        warn "将执行 Docker 官方安装脚本 get.docker.com"
        command -v curl >/dev/null 2>&1 || die "缺少 curl，请先安装"
        curl -fsSL https://get.docker.com -o /tmp/get-docker.sh \
            || die "无法下载 Docker 安装脚本"
        sh /tmp/get-docker.sh || die "Docker 安装失败"
        rm -f /tmp/get-docker.sh
        systemctl enable --now docker
        ok "Docker 已安装"
    fi

    docker compose version >/dev/null 2>&1 \
        || die "缺少 docker compose 插件。请安装 docker-compose-plugin：
  apt install docker-compose-plugin"
}

# compose 调用。COMPOSE_FILES 由镜像决策阶段填充：用预构建镜像时只有主文件，
# 本地构建时叠加 docker-compose.build.yml。
COMPOSE_FILES=(-f docker-compose.yml)

compose() {
    ( cd "$REPO_ROOT" && docker compose "${COMPOSE_FILES[@]}" "$@" )
}

# ---------------------------------------------------------------------------
# 版本与镜像
# ---------------------------------------------------------------------------
# 从 Cargo.toml 取版本号。只有这一个来源 —— 镜像 tag、发布包名、二进制的
# --version 全都从它派生。
read_version() {
    awk -F'"' '
        /^\[workspace\.package\]/ { s = 1; next }
        /^\[/ { s = 0 }
        s && /^version[[:space:]]*=/ { print $2; exit }
    ' "$REPO_ROOT/Cargo.toml"
}

# 从 git remote 推出 GHCR 镜像名与 GitHub owner/repo。
#
# 不写死仓库地址：fork 之后镜像应当指向 fork 自己的 GHCR，而不是上游的。
detect_repo_slug() {
    local url
    url="$(cd "$REPO_ROOT" && git config --get remote.origin.url 2>/dev/null || true)"
    [[ -n "$url" ]] || return 1
    # 同时处理 https://github.com/a/b.git 与 git@github.com:a/b.git
    url="${url%.git}"
    url="${url#*github.com[:/]}"
    # 去掉可能残留的协议前缀
    url="${url#https://github.com/}"
    url="${url#git@github.com:}"
    [[ "$url" == */* ]] || return 1
    printf '%s' "$url"
}

# ---------------------------------------------------------------------------
# 非部署动作
# ---------------------------------------------------------------------------
case "$MODE" in
    down)
        ensure_docker
        step "停止服务"
        compose down
        ok "已停止。数据卷保留，再次 up 即可恢复。"
        exit 0 ;;
    destroy)
        ensure_docker
        warn "这会删除数据库、已注册的机器、审计日志与证书，且不可恢复。"
        read -r -p "确认删除？输入 yes 继续：" confirm
        [[ "$confirm" == "yes" ]] || { info "已取消"; exit 0; }
        compose down -v
        ok "已删除所有数据卷"
        exit 0 ;;
    logs)
        ensure_docker
        compose logs -f --tail=100
        exit 0 ;;
esac

ensure_docker

# ---------------------------------------------------------------------------
# 域名与邮箱
# ---------------------------------------------------------------------------
if [[ "$LOCAL_ONLY" == "no" ]]; then
    if [[ -z "$DOMAIN" && -f "$ENV_FILE" ]]; then
        # 复用上次的值，重跑脚本不必重新输入。
        DOMAIN="$(awk -F= '$1=="PANEL_DOMAIN"{print $2}' "$ENV_FILE" 2>/dev/null || true)"
        EMAIL="${EMAIL:-$(awk -F= '$1=="ACME_EMAIL"{print $2}' "$ENV_FILE" 2>/dev/null || true)}"
    fi

    if [[ -z "$DOMAIN" ]]; then
        step "面板访问方式"
        cat <<'EOF'
需要一个已解析到本机的域名，Caddy 会自动申请 Let's Encrypt 证书。

  * 域名的 A/AAAA 记录必须已经指向本机公网 IP，否则证书申请会失败
  * 80 与 443 端口必须可从公网访问（ACME 验证走 80）

没有域名？用 --local 只监听本机，之后自行处理外部访问。
EOF
        read -r -p "面板域名（如 panel.example.com）：" DOMAIN
        [[ -n "$DOMAIN" ]] || die "未提供域名。若不需要 HTTPS，请用 --local"
    fi

    if [[ -z "$EMAIL" ]]; then
        read -r -p "Let's Encrypt 注册邮箱：" EMAIL
        [[ -n "$EMAIL" ]] || die "ACME 需要一个邮箱地址"
    fi

    # 只做形状检查，不做真实性校验 —— 那要等 ACME 自己去验。
    [[ "$DOMAIN" == *.* && "$DOMAIN" != *" "* ]] || die "域名 `$DOMAIN` 看起来不合法"
    [[ "$EMAIL" == *@*.* ]] || die "邮箱 `$EMAIL` 看起来不合法"

    # 提前查一下解析，比等 Caddy 申请失败再翻日志快得多。
    if command -v getent >/dev/null 2>&1; then
        resolved="$(getent ahostsv4 "$DOMAIN" 2>/dev/null | awk 'NR==1{print $1}')"
        if [[ -n "$resolved" ]]; then
            info "$DOMAIN 解析到 $resolved"
            public_ip="$(curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null || true)"
            if [[ -n "$public_ip" && "$resolved" != "$public_ip" ]]; then
                warn "域名解析到 $resolved，而本机公网 IP 是 $public_ip"
                warn "若不一致，Let's Encrypt 的 HTTP 验证会失败"
            fi
        else
            warn "无法解析 $DOMAIN。证书申请需要它已生效，请确认 DNS 记录。"
        fi
    fi
fi

# ---------------------------------------------------------------------------
# .env
# ---------------------------------------------------------------------------
step "写入环境变量"
if [[ "$LOCAL_ONLY" == "yes" ]]; then
    # Caddy 不启用时这两个值不会被读，但仍然写出来，避免 compose 报变量未定义。
    DOMAIN="localhost"
    EMAIL="admin@localhost"
fi

umask 077
cat > "$ENV_FILE" <<EOF
# 由 scripts/docker-deploy.sh 生成。密钥在 configs/control.docker.toml 里。
PANEL_DOMAIN=$DOMAIN
ACME_EMAIL=$EMAIL
EOF
ok "已写入 .env"

# ---------------------------------------------------------------------------
# 控制面配置
# ---------------------------------------------------------------------------
generate_secret() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -base64 48 | tr -d '\n'
    else
        # 退路：openssl 不一定装了，但 /dev/urandom 一定有。
        head -c 48 /dev/urandom | base64 | tr -d '\n'
    fi
}

step "生成控制面配置"
if [[ -f "$CONF_FILE" ]]; then
    # 绝不重写已有密钥：那会让所有已发出的会话失效、所有 agent 握手失败。
    # 这是「重跑一次部署脚本」最容易引入的故障。
    ok "$CONF_FILE 已存在，保留其中的密钥不变"
    if [[ "$LOCAL_ONLY" == "no" ]]; then
        # 域名可能变了，public_url 要跟着更新 —— 它决定一键对接命令里的地址。
        sed -i "s|^public_url = .*|public_url = \"https://$DOMAIN\"|" "$CONF_FILE"
        info "已更新 public_url 为 https://$DOMAIN"
    fi
else
    JWT="$(generate_secret)"
    PSK="$(generate_secret)"

    if [[ "$LOCAL_ONLY" == "yes" ]]; then
        PUBLIC_URL="http://127.0.0.1:8080"
    else
        PUBLIC_URL="https://$DOMAIN"
    fi

    # 用 | 作 sed 分隔符的老问题在这里不存在 —— 直接用 heredoc 写全文。
    cat > "$CONF_FILE" <<EOF
# 由 scripts/docker-deploy.sh 生成于 $(date -u +%Y-%m-%dT%H:%M:%SZ)
#
# 这个文件含会话签名密钥与隧道 PSK，权限是 0600。
# 重跑部署脚本不会覆盖它 —— 重写密钥会让所有会话失效、所有 agent 握手失败。

# 容器内监听所有地址；对外暴露由 compose 端口映射与反代控制。
listen = "0.0.0.0:8080"
database_path = "/var/lib/tunnel-control/control.db"
web_root = "/usr/share/tunnel-control/web"

# agent 一键对接命令里嵌入的地址。必须是 agent 能实际连上的地址。
public_url = "$PUBLIC_URL"

# 供一键对接下载 agent 二进制。docker-deploy.sh 会把二进制放进这个目录。
agent_binary_dir = "/var/lib/tunnel-control/agent-bin"

# 反代与控制面在不同容器，对端是容器网段而非回环。不声明它可信的话，所有请求的
# 来源都会被算成反代容器地址，按 IP 的登录限流退化成全局限流。
# 网段在 docker-compose.yml 里固定为 172.20.0.0/16。
trusted_proxies = ["172.20.0.0/16"]

# 严格模式：弱密钥与 insecure_skip_verify 直接拒绝启动。
production = true

# 隧道握手 PSK，分发给所有 agent。TLS 之上的第二道 —— 证书误签时它仍能拦住
# 未授权的对端。
#
# 顶层字段必须写在任何 [表] 之前：写在 [auth] 之后会静默变成 auth.tunnel_psk，
# 真正的字段仍为空，而 agent 会退化为仅 TLS 认证且不报错。
tunnel_psk = "$PSK"

[auth]
jwt_secret = "$JWT"
token_ttl = "12h"
bootstrap_username = "admin"
login_attempt_limit = 10
login_lockout = "5m"

[agent]
stale_after_secs = 45
heartbeat_interval = "10s"

[agent_tls]
ca_path = "/etc/tunnel/ca.pem"
require_client_auth = false

[log]
level = "info"
format = "json"
EOF
    chmod 600 "$CONF_FILE"
    ok "已生成 $CONF_FILE 并写入随机密钥"
fi

# ---------------------------------------------------------------------------
# 本机模式：不启反代，把 8080 映射到回环
# ---------------------------------------------------------------------------
# 用 override 文件而不是命令行参数：compose 没法从命令行加端口映射，而正常模式下
# 刻意不暴露 8080（避免绕过 TLS 直连明文端口）。
readonly OVERRIDE_FILE="$REPO_ROOT/docker-compose.override.yml"

if [[ "$LOCAL_ONLY" == "yes" ]]; then
    warn "本机模式：只启控制面，不启反代、不申请证书"
    cat > "$OVERRIDE_FILE" <<'EOF'
# 由 scripts/docker-deploy.sh --local 生成。删掉即恢复「仅经反代访问」。
#
# 绑到 127.0.0.1 而不是 0.0.0.0：后者会让明文面板直接暴露在公网上，
# 而本机模式本来就是给「自己处理外部访问」的场景用的。
services:
  control:
    ports:
      - "127.0.0.1:8080:8080"
EOF
    ok "已生成 docker-compose.override.yml（8080 → 127.0.0.1）"
else
    # 切回正常模式时必须删掉它，否则明文端口会一直开着。
    if [[ -f "$OVERRIDE_FILE" ]]; then
        rm -f "$OVERRIDE_FILE"
        info "已移除本机模式的 override 文件"
    fi
fi

# ---------------------------------------------------------------------------
# 决定用预构建镜像还是本地构建
# ---------------------------------------------------------------------------
# 在服务器上编译整套 Rust 要十几分钟、吃 2 GB 内存、小内存机器还可能被 OOM 干掉 ——
# 而每台机器编出来的东西完全一样。能拉到预构建镜像就不该重复这件事。
#
# 回落到本地构建时必须**打印原因**。静默回落会让人莫名等十几分钟还不知道为什么，
# 那比直接失败更难排查。
step "确定控制面镜像"

VERSION="$(read_version)"
[[ -n "$VERSION" ]] || die "无法从 Cargo.toml 读出版本号"
info "仓库版本 $VERSION"

USE_PREBUILT="no"

if [[ -n "$FORCED_IMAGE" ]]; then
    TUNNEL_IMAGE="$FORCED_IMAGE"
    info "使用指定镜像 $TUNNEL_IMAGE"
    if docker pull "$TUNNEL_IMAGE" 2>&1 | tail -2; then
        USE_PREBUILT="yes"
        ok "镜像已拉取"
    else
        die "无法拉取指定的镜像 $TUNNEL_IMAGE"
    fi
elif [[ "$FORCE_BUILD" == "yes" ]]; then
    info "已指定 --build，跳过拉取，直接本地构建"
else
    SLUG="$(detect_repo_slug || true)"
    if [[ -z "$SLUG" ]]; then
        warn "无法从 git remote 推出仓库名，改为本地构建"
    else
        # GHCR 不接受大写仓库名，而 GitHub 用户名可能含大写。
        IMAGE_BASE="ghcr.io/$(printf '%s' "$SLUG" | tr 'A-Z' 'a-z')-control"
        CANDIDATE="$IMAGE_BASE:$VERSION"
        info "尝试拉取 $CANDIDATE"

        # 不丢 stderr：拉取失败的原因（包是 private、tag 不存在、网络不通）
        # 需要让用户看到，否则只会得到一句「改为本地构建」。
        if docker pull "$CANDIDATE" 2>&1 | tail -3; then
            TUNNEL_IMAGE="$CANDIDATE"
            USE_PREBUILT="yes"
            ok "已拉取预构建镜像，跳过编译"
        else
            warn "拉取 $CANDIDATE 失败，将在本地构建。常见原因："
            warn "  1. 还没有发布过这个版本 —— 需要先 git tag v$VERSION && git push --tags"
            warn "  2. GHCR 的包默认是 private（即使仓库是 public）——"
            warn "     到 GitHub 的 Packages 设置里把它改为 Public"
            warn "  3. 本机网络无法访问 ghcr.io"
            info "本地构建约需十几分钟，且需要约 2 GB 内存。"
        fi
    fi
fi

if [[ "$USE_PREBUILT" == "yes" ]]; then
    export TUNNEL_IMAGE
    ok "将使用镜像 $TUNNEL_IMAGE"
else
    # 叠加 build 文件。主 compose 刻意不含 build:，所以必须显式加上它才会本地构建。
    COMPOSE_FILES+=(-f docker-compose.build.yml)
    export TUNNEL_IMAGE="tunnel-control:local"

    step "本地构建镜像"
    if [[ "$MODE" == "rebuild" ]]; then
        compose build --no-cache control || die "镜像构建失败"
    else
        compose build control || die "镜像构建失败"
    fi
    ok "镜像构建完成"
fi

step "启动服务"
if [[ "$LOCAL_ONLY" == "yes" ]]; then
    compose up -d control || die "启动失败"
else
    compose up -d || die "启动失败"
fi

# 等健康检查通过。不等的话下一步取密码会因为数据库还在迁移而取不到。
info "等待控制面就绪…"
for _ in $(seq 1 60); do
    if compose ps control 2>/dev/null | grep -q "healthy"; then
        ok "控制面已就绪"
        break
    fi
    sleep 2
done

# ---------------------------------------------------------------------------
# 放置 agent 二进制
# ---------------------------------------------------------------------------
# 一键对接要从面板下载 agent 二进制，而控制面镜像里没有它（镜像只装控制面）。
#
# 取二进制的顺序，按代价从低到高：
#   1. GitHub Release 的预编译文件（几秒，带 sha256 校验）
#   2. 本机 target/release（开发机上已经编过）
#   3. Docker build 阶段（十几分钟，最后手段）
step "放置 agent 二进制供一键对接使用"

ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64) ASSET_ARCH="x86_64" ;;
    aarch64|arm64) ASSET_ARCH="aarch64" ;;
    *) ASSET_ARCH="" ;;
esac

readonly AGENT_DEST="/var/lib/tunnel-control/agent-bin/tunnel-agent-$ASSET_ARCH"

# 从 Release 下载并校验。成功返回 0。
download_agent_from_release() {
    local slug="$1" version="$2" arch="$3" out="$4"
    local base="https://github.com/$slug/releases/download/v$version"
    local bin_url="$base/tunnel-agent-$arch"
    local sha_url="$base/tunnel-agent-$arch.sha256"

    info "尝试从 Release 下载 tunnel-agent-$arch"
    curl -fsSL --connect-timeout 10 --max-time 300 -o "$out" "$bin_url" 2>/dev/null \
        || return 1
    [[ -s "$out" ]] || return 1

    # 校验。下载的是要以 root 权限运行的可执行文件，不校验等于接受链路上任何一跳
    # 的替换。拿不到校验值时也不放行 —— 宁可回落到本地构建。
    local expected actual
    expected="$(curl -fsSL --connect-timeout 10 "$sha_url" 2>/dev/null | tr -d '[:space:]')"
    if [[ -z "$expected" ]]; then
        warn "Release 里没有 tunnel-agent-$arch.sha256，无法校验，放弃这个来源"
        return 1
    fi
    actual="$(sha256sum "$out" | awk '{print $1}')"
    if [[ "$actual" != "$expected" ]]; then
        warn "下载的 agent 二进制校验失败，已丢弃"
        warn "  声明 $expected"
        warn "  实际 $actual"
        return 1
    fi
    ok "已下载并校验 tunnel-agent-$arch（sha256 ${actual:0:16}…）"
    return 0
}

place_agent() {
    docker cp "$1" "tunnel-control:$AGENT_DEST"
}

if [[ -z "$ASSET_ARCH" ]]; then
    warn "未知架构 $ARCH，跳过 agent 二进制放置"
else
    TMP_AGENT="$(mktemp)"
    PLACED="no"

    # --- 1. Release ---
    SLUG="${SLUG:-$(detect_repo_slug || true)}"
    if [[ -n "$SLUG" ]] \
        && download_agent_from_release "$SLUG" "$VERSION" "$ASSET_ARCH" "$TMP_AGENT"; then
        place_agent "$TMP_AGENT" && PLACED="yes"
    fi

    # --- 2. 本机已编译的 ---
    if [[ "$PLACED" == "no" && -x "$REPO_ROOT/target/release/tunnel-agent" ]]; then
        info "改用本机 target/release/tunnel-agent"
        place_agent "$REPO_ROOT/target/release/tunnel-agent" && PLACED="yes"
    fi

    # --- 3. Docker build 阶段 ---
    if [[ "$PLACED" == "no" ]]; then
        info "改从 Docker 构建阶段提取（较慢）…"
        # 不丢 stderr：构建失败的真正原因（比如依赖 MSRV 超出基础镜像）
        # 必须让用户看到，否则只会得到一句「跳过」。
        if docker build --target build -t tunnel-build:local "$REPO_ROOT"; then
            cid="$(docker create tunnel-build:local)"
            if docker cp "$cid:/src/target/release/tunnel-agent" "$TMP_AGENT"; then
                place_agent "$TMP_AGENT" && PLACED="yes"
            else
                warn "无法从构建镜像提取 agent 二进制"
            fi
            docker rm -f "$cid" >/dev/null 2>&1 || true
        else
            warn "构建阶段镜像失败，见上方输出"
        fi
    fi

    rm -f "$TMP_AGENT"
    [[ "$PLACED" == "yes" ]] && ok "已放置 $AGENT_DEST"
fi

if ! docker exec tunnel-control ls "$AGENT_DEST" >/dev/null 2>&1; then
    warn "agent 二进制未就位 —— 面板上的一键对接命令会报「面板未提供二进制」。"
    warn "最省事的补法：发一个版本，之后脚本会直接从 Release 下载。"
    warn "  git tag v$VERSION && git push --tags"
    warn "或手工放置已有的二进制："
    warn "  docker cp tunnel-agent tunnel-control:$AGENT_DEST"
fi

# ---------------------------------------------------------------------------
# 首次登录密码
# ---------------------------------------------------------------------------
step "首次登录信息"

# 密码只在首次启动时打印一次，且只进日志不落盘。
PASSWORD="$(compose logs control 2>/dev/null \
    | grep -A4 -E '初始管理员|Initial administrator' \
    | grep -oE 'password: [^ ]+' | awk '{print $2}' | head -n 1 || true)"

if [[ -n "$PASSWORD" ]]; then
    printf '\n  用户名  %sadmin%s\n' "$C_BOLD" "$C_RESET"
    printf '  密码    %s%s%s\n\n' "$C_BOLD" "$PASSWORD" "$C_RESET"
    warn "这个密码只显示一次。首次登录后必须改密 —— 改密前所有写操作都会被拒绝。"
else
    info "未能从日志中提取初始密码（可能不是首次启动）。"
    info "查看完整日志：docker compose logs control | grep -A4 管理员"
    info "或重置密码：docker exec tunnel-control tunnel-control \\"
    info "  --config /etc/tunnel-control/config.toml reset-password admin"
fi

# ---------------------------------------------------------------------------
# 收尾
# ---------------------------------------------------------------------------
printf '\n%s================ 部署完成 ================%s\n' "$C_BOLD" "$C_RESET"

if [[ "$LOCAL_ONLY" == "yes" ]]; then
    cat <<EOF

面板地址  http://127.0.0.1:8080

  本机模式下没有启动反代，也没有申请证书。要从外部访问，
  重新执行本脚本并提供域名：
    sudo ./scripts/docker-deploy.sh -d panel.example.com -e you@example.com
EOF
else
    cat <<EOF

面板地址  ${C_BOLD}https://$DOMAIN${C_RESET}

  证书由 Caddy 自动申请与续期。首次申请需要几十秒，期间访问可能报错，
  稍等后刷新即可。申请失败时看日志：
    docker compose logs proxy | tail -50

  最常见的失败原因：
    * 域名还没解析到本机
    * 80/443 被防火墙拦住（ACME 验证走 80）
    * 云厂商安全组没放通
EOF
fi

cat <<EOF

${C_BOLD}接下来${C_RESET}

  1. 登录面板，立即修改密码
  2. 新建设备组，复制它的一键对接命令
  3. 在每台中转机上执行那条命令（agent 装在宿主机，不在容器里）

${C_BOLD}常用命令${C_RESET}

  ./scripts/docker-deploy.sh --logs       跟踪日志
  ./scripts/docker-deploy.sh --down       停止（保留数据）
  ./scripts/docker-deploy.sh --rebuild    改了代码后重新构建
  docker compose ps                       查看状态

${C_BOLD}备份${C_RESET}

  docker exec tunnel-control sqlite3 /var/lib/tunnel-control/control.db \\
    ".backup '/var/lib/tunnel-control/backup.db'"
  docker cp tunnel-control:/var/lib/tunnel-control/backup.db ./

${C_BOLD}文档${C_RESET}
  docs/docker.md          Docker 部署细节
  docs/使用说明.md         中文完整使用说明

EOF
