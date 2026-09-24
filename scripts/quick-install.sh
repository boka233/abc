#!/usr/bin/env bash
#
# 一条命令部署。这是引导脚本 —— 它只负责把代码取下来，然后交给
# scripts/docker-deploy.sh 做真正的部署。
#
#   bash <(curl -fsSL https://raw.githubusercontent.com/boka233/abc/main/scripts/quick-install.sh)
#
# 带参数（非交互）:
#   bash <(curl -fsSL .../quick-install.sh) -d panel.example.com -e me@example.com
#
# 为什么用 `bash <(curl ...)` 而不是 `curl | bash`:
#   后者会占用 stdin，脚本就无法在生成密钥、申请证书之前向你确认域名。需要完全
#   非交互时把域名和邮箱作为参数传进来。
#
# 为什么不把部署逻辑直接写在这里:
#   这个脚本会被 curl 到陌生机器上执行，应当尽量短、尽量容易读完。真正的部署逻辑
#   （生成密钥、写配置、起容器、放 agent 二进制）在仓库里的 docker-deploy.sh，
#   那份代码可以被审阅、被 git 追溯，而不是一段一次性的管道输入。

set -euo pipefail

readonly REPO_URL="${TUNNEL_REPO_URL:-https://github.com/boka233/abc.git}"
readonly REPO_BRANCH="${TUNNEL_REPO_BRANCH:-main}"
# 代码放在这里。不用 /tmp —— 那里的内容可能被清理，而后续升级要复用这个副本。
readonly INSTALL_DIR="${TUNNEL_INSTALL_DIR:-/opt/tunnel}"

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
用法: bash <(curl -fsSL <脚本地址>) [选项]

选项:
  -d, --domain <域名>   面板域名，需已解析到本机（自动申请 HTTPS 证书）
  -e, --email <邮箱>    Let's Encrypt 注册邮箱
      --local           只监听 127.0.0.1:8080，不申请证书
      --update          拉取最新代码并重新部署
      --help            显示本帮助

环境变量:
  TUNNEL_REPO_URL      仓库地址，默认 https://github.com/boka233/abc.git
  TUNNEL_REPO_BRANCH   分支，默认 main
  TUNNEL_INSTALL_DIR   代码存放位置，默认 /opt/tunnel

不带参数时会交互式询问域名与邮箱。
EOF
}

# 参数原样转交给 docker-deploy.sh，这里只挑出自己要用的。
PASSTHROUGH=()
DO_UPDATE="no"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --update) DO_UPDATE="yes"; shift ;;
        --help|-h) usage; exit 0 ;;
        -d|--domain|-e|--email)
            PASSTHROUGH+=("$1" "${2:-}"); shift 2 ;;
        # 跳过空串。
        #
        # 命令行里 `\` 后面多一个空格再换行，shell 会传进来一个空参数。原先它被
        # 原样转发给 docker-deploy.sh，在那边落到「未知参数」分支上，而且参数名
        # 是空的 —— 报错看起来像脚本坏了，实际只是一个多余的空格。
        "") shift ;;
        *) PASSTHROUGH+=("$1"); shift ;;
    esac
done

# ---------------------------------------------------------------------------
# 前置检查
# ---------------------------------------------------------------------------
step "环境检查"

[[ "$(uname -s)" == "Linux" ]] \
    || die "本脚本仅支持 Linux（Ubuntu 22.04+ / Debian 11+）。
控制面与 agent 都只在 Linux 上运行。"

[[ $EUID -eq 0 ]] \
    || die "需要 root 权限。请用：
  sudo bash <(curl -fsSL $REPO_URL 的脚本地址)
或先 sudo -i 再执行。"

# 架构：镜像在本机构建，所以只要是这两种就行。
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64|aarch64|arm64) info "架构 $ARCH" ;;
    *) die "不支持的架构 $ARCH（仅 x86_64 / aarch64）" ;;
esac

if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    case "${ID:-}" in
        ubuntu|debian) info "系统 ${PRETTY_NAME:-$ID}" ;;
        *) warn "未在 ${PRETTY_NAME:-$ID} 上测试过，继续执行但请自行验证" ;;
    esac
fi

# 内存检查。Rust 编译很吃内存，1 GB 的机器上链接阶段会被 OOM killer 干掉，
# 而那个失败现象是「构建到一半突然退出且没有明确错误」，很难排查。
MEM_MB="$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 0)"
if (( MEM_MB > 0 && MEM_MB < 1800 )); then
    warn "本机内存 ${MEM_MB} MB。镜像构建时编译 Rust 需要约 2 GB，可能被 OOM 中断。"
    SWAP_MB="$(awk '/SwapTotal/ {print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 0)"
    if (( SWAP_MB < 1024 )); then
        warn "当前 swap 仅 ${SWAP_MB} MB。建议先加 2 GB swap："
        warn "  fallocate -l 2G /swapfile && chmod 600 /swapfile"
        warn "  mkswap /swapfile && swapon /swapfile"
        if [[ -t 0 ]]; then
            read -r -p "仍然继续？[y/N] " go
            [[ "$go" == "y" || "$go" == "Y" ]] || { info "已取消"; exit 0; }
        fi
    fi
fi

# 磁盘。构建缓存加镜像大约要 4 GB。
AVAIL_MB="$(df -Pm /var 2>/dev/null | awk 'NR==2 {print $4}' || echo 0)"
if (( AVAIL_MB > 0 && AVAIL_MB < 4096 )); then
    warn "/var 可用空间 ${AVAIL_MB} MB。镜像构建约需 4 GB，空间不足会在构建中途失败。"
fi

# ---------------------------------------------------------------------------
# git
# ---------------------------------------------------------------------------
if ! command -v git >/dev/null 2>&1; then
    step "安装 git"
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq && apt-get install -y -qq git || die "git 安装失败"
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y -q git || die "git 安装失败"
    elif command -v yum >/dev/null 2>&1; then
        yum install -y -q git || die "git 安装失败"
    else
        die "未找到 git，且无法自动安装。请手工安装后重试。"
    fi
    ok "git 已安装"
fi

# ---------------------------------------------------------------------------
# 取代码
# ---------------------------------------------------------------------------
step "获取代码"

if [[ -d "$INSTALL_DIR/.git" ]]; then
    info "$INSTALL_DIR 已存在，拉取最新代码"
    # 用 fetch + reset 而不是 pull：本地若有改动，pull 会因冲突停住，而这台机器上
    # 的改动通常只是上次部署生成的东西，不该阻塞升级。
    #
    # 注意 reset --hard 会丢弃本地对**仓库内文件**的改动。部署产生的配置
    # （.env、configs/control.docker.toml）在 .gitignore 里，不受影响。
    ( cd "$INSTALL_DIR" \
        && git fetch --depth 1 origin "$REPO_BRANCH" \
        && git reset --hard "origin/$REPO_BRANCH" ) \
        || die "拉取代码失败。可手工处理：cd $INSTALL_DIR && git status"
    ok "代码已更新到最新"
else
    [[ -e "$INSTALL_DIR" ]] && die "$INSTALL_DIR 已存在但不是 git 仓库。
请先移走它，或用 TUNNEL_INSTALL_DIR 指定别的位置。"

    install -d -m 755 "$(dirname "$INSTALL_DIR")"
    # --depth 1：只要最新代码，不要完整历史。这个 monorepo 的历史很大，
    # 浅克隆能省掉大部分下载时间。
    git clone --depth 1 --branch "$REPO_BRANCH" "$REPO_URL" "$INSTALL_DIR" \
        || die "克隆失败。请确认网络可达 $REPO_URL，以及分支 $REPO_BRANCH 存在。"
    ok "代码已克隆到 $INSTALL_DIR"
fi

PROJECT_DIR="$INSTALL_DIR"
DEPLOY="$PROJECT_DIR/scripts/docker-deploy.sh"

[[ -f "$DEPLOY" ]] || die "找不到 $DEPLOY。
仓库内容看起来不完整，或分支 $REPO_BRANCH 上没有这个项目。
可手工确认：ls $INSTALL_DIR"

chmod +x "$PROJECT_DIR/scripts/"*.sh 2>/dev/null || true

# ---------------------------------------------------------------------------
# 交给部署脚本
# ---------------------------------------------------------------------------
step "开始部署"
info "后续由 scripts/docker-deploy.sh 接管"

if [[ "$DO_UPDATE" == "yes" ]]; then
    # 升级路径：代码已经在上面更新过，这里重新构建镜像。
    exec "$DEPLOY" --rebuild "${PASSTHROUGH[@]+"${PASSTHROUGH[@]}"}"
else
    exec "$DEPLOY" "${PASSTHROUGH[@]+"${PASSTHROUGH[@]}"}"
fi
