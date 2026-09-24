#!/usr/bin/env bash
#
# 发布包内的安装入口（打包时会被放到包根目录，命名为 install.sh）。
#
# 用法:
#   sudo ./install.sh control        # 控制面 + 面板
#   sudo ./install.sh agent          # 仅数据面
#   sudo ./install.sh both           # 同机安装两者（测试用）
#
# 与 scripts/install.sh 的关系:
#   这是一层薄封装。真正的安装逻辑在 scripts/install.sh 里，本脚本只做三件事：
#     1. 校验包完整性（SHA256SUMS）
#     2. 把包内已编译好的二进制与前端摆到 scripts/install.sh 预期的位置，
#        这样它可以用 --skip-build 运行 —— 目标机器不需要 cargo 和 npm
#     3. 把 agent 二进制放进 agent_binary_dir，让面板的一键对接立刻可用
#
#   不把这些逻辑合并进 scripts/install.sh：那个脚本服务的是「从源码装」，本脚本
#   服务的是「从发布包装」。两者的前置条件相反（一个要工具链，一个要预编译产物），
#   合成一个会到处是分支。

set -euo pipefail

readonly PKG_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly AGENT_BIN_DIR="/var/lib/tunnel-control/agent-bin"

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

ROLE="${1:-}"
case "$ROLE" in
    control|agent|both) ;;
    ""|--help|-h)
        cat <<'EOF'
用法: sudo ./install.sh <control|agent|both>

  control   控制面与 Web 管理面板
  agent     数据面 agent
  both      同机安装两者，仅建议测试环境

本包已包含编译好的二进制，目标机器不需要 Rust 或 Node.js。
EOF
        exit 0 ;;
    *) die "未知角色：$ROLE（应为 control / agent / both）" ;;
esac
shift || true

[[ $EUID -eq 0 ]] || die "需要 root 权限，请使用 sudo"
[[ "$(uname -s)" == "Linux" ]] || die "本脚本仅支持 Linux"

# ---------------------------------------------------------------------------
# 包信息与架构匹配
# ---------------------------------------------------------------------------
step "检查发布包"

[[ -f "$PKG_ROOT/BUILD-INFO" ]] || die "缺少 BUILD-INFO，这不像是一个完整的发布包"
# shellcheck disable=SC1091
PKG_VERSION="$(awk -F= '$1=="version"{print $2}' "$PKG_ROOT/BUILD-INFO")"
PKG_ARCH="$(awk -F= '$1=="arch"{print $2}' "$PKG_ROOT/BUILD-INFO")"
PKG_TESTED="$(awk -F= '$1=="tested"{print $2}' "$PKG_ROOT/BUILD-INFO")"
PKG_SHA="$(awk -F= '$1=="git_sha"{print $2}' "$PKG_ROOT/BUILD-INFO")"

info "版本 $PKG_VERSION（$PKG_SHA），架构 $PKG_ARCH"

# 架构不匹配时立刻停 —— 装上去会得到 "cannot execute binary file"，
# 那个报错离真正的原因太远。
HOST_ARCH="$(uname -m)"
case "$HOST_ARCH" in
    x86_64|amd64) HOST_ARCH="x86_64" ;;
    aarch64|arm64) HOST_ARCH="aarch64" ;;
esac
[[ "$PKG_ARCH" == "$HOST_ARCH" ]] \
    || die "包的架构是 $PKG_ARCH，本机是 $HOST_ARCH。请下载 $HOST_ARCH 的发布包。"

if [[ "$PKG_TESTED" != "yes" ]]; then
    warn "本包构建时跳过了测试（BUILD-INFO: tested=$PKG_TESTED），不建议用于生产"
fi

# 校验完整性。传输截断会产出一个能解包但二进制损坏的目录。
if [[ -f "$PKG_ROOT/SHA256SUMS" ]] && command -v sha256sum >/dev/null 2>&1; then
    if ( cd "$PKG_ROOT" && sha256sum -c --quiet SHA256SUMS 2>/dev/null ); then
        ok "包内文件校验通过"
    else
        die "包内文件校验失败，可能下载不完整。请重新下载后重试。"
    fi
else
    warn "跳过完整性校验（缺少 SHA256SUMS 或 sha256sum）"
fi

# ---------------------------------------------------------------------------
# 把预编译产物摆到 scripts/install.sh 预期的位置
# ---------------------------------------------------------------------------
# scripts/install.sh 从 <repo>/target/release/ 取二进制、从 <repo>/web/dist 取前端。
# 这里在包内造出同样的布局，它就能以 --skip-build 运行。
step "准备安装内容"

mkdir -p "$PKG_ROOT/target/release"
for bin in tunnel-control tunnel-agent; do
    [[ -f "$PKG_ROOT/$bin" ]] || die "包内缺少 $bin"
    install -m 755 "$PKG_ROOT/$bin" "$PKG_ROOT/target/release/$bin"
done

if [[ -d "$PKG_ROOT/web" ]]; then
    mkdir -p "$PKG_ROOT/web-staging"
    # scripts/install.sh 读的是 web/dist，而包里是 web/。做一层目录而不是复制文件，
    # 省掉一次几 MB 的拷贝。
    rm -rf "$PKG_ROOT/web-staging/dist"
    ln -s "$PKG_ROOT/web" "$PKG_ROOT/web-staging/dist" 2>/dev/null \
        || cp -r "$PKG_ROOT/web" "$PKG_ROOT/web-staging/dist"
    WEB_FLAG=()
else
    warn "包内没有 Web 面板，将以 API-only 模式安装"
    WEB_FLAG=(--no-web)
fi
ok "内容就绪"

# scripts/install.sh 用 REPO_ROOT 定位文件，而它是按自身路径算的。包内布局与仓库
# 一致（scripts/、configs/、systemd/、target/release/、web/dist），所以直接可用。
if [[ -d "$PKG_ROOT/web" && ! -d "$PKG_ROOT/web/dist" ]]; then
    # 包里前端在 web/ 下，install.sh 要 web/dist：补一个指向自身的链接。
    ln -sfn . "$PKG_ROOT/web/dist" 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# 调用真正的安装脚本
# ---------------------------------------------------------------------------
step "执行安装"
"$PKG_ROOT/scripts/install.sh" "$ROLE" --skip-build "${WEB_FLAG[@]+"${WEB_FLAG[@]}"}" "$@" \
    || die "安装失败，请查看上方输出"

# ---------------------------------------------------------------------------
# 放置 agent 二进制供一键对接下载
# ---------------------------------------------------------------------------
# 这一步是「一键对接能用」的前提：控制面从 agent_binary_dir 提供下载，新机器上的
# 脚本在注册之前就要取到它。不做这一步，一键对接会报「面板未提供二进制」。
if [[ "$ROLE" == "control" || "$ROLE" == "both" ]]; then
    step "放置 agent 二进制供一键对接使用"

    install -d -o tunnel -g tunnel -m 755 "$AGENT_BIN_DIR"
    if [[ -f "$PKG_ROOT/tunnel-agent-$PKG_ARCH" ]]; then
        install -m 755 -o tunnel -g tunnel \
            "$PKG_ROOT/tunnel-agent-$PKG_ARCH" "$AGENT_BIN_DIR/tunnel-agent-$PKG_ARCH"
    else
        # 退路：用不带后缀的那份，它是同一个文件。
        install -m 755 -o tunnel -g tunnel \
            "$PKG_ROOT/tunnel-agent" "$AGENT_BIN_DIR/tunnel-agent-$PKG_ARCH"
    fi
    ok "已放置 $AGENT_BIN_DIR/tunnel-agent-$PKG_ARCH"

    OTHER_ARCH="$([[ "$PKG_ARCH" == "x86_64" ]] && echo aarch64 || echo x86_64)"
    if [[ ! -f "$AGENT_BIN_DIR/tunnel-agent-$OTHER_ARCH" ]]; then
        info "目录内没有 $OTHER_ARCH 的 agent。若有该架构的机器要对接，"
        info "请下载对应发布包并把其中的 tunnel-agent-$OTHER_ARCH 复制到："
        info "  $AGENT_BIN_DIR/"
    fi
fi

# ---------------------------------------------------------------------------
# 清理临时布局
# ---------------------------------------------------------------------------
rm -rf "$PKG_ROOT/target" "$PKG_ROOT/web-staging"
[[ -L "$PKG_ROOT/web/dist" ]] && rm -f "$PKG_ROOT/web/dist"

printf '\n%s安装完成。后续步骤见上方输出与 docs/使用说明.md。%s\n\n' "$C_BOLD" "$C_RESET"
