#!/usr/bin/env bash
#
# 卸载 tunnel-control / tunnel-agent。
#
# 默认只移除二进制与 systemd 单元，保留配置、数据库与 TLS 材料 ——
# 误删数据库意味着丢掉全部节点、路由与审计记录，不可恢复。
# 需要一并清除时显式加 --purge，且脚本会二次确认。

set -euo pipefail

readonly BIN_DIR="/usr/local/bin"
readonly SYSTEMD_DIR="/etc/systemd/system"

if [[ -t 1 ]]; then
    C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'
    C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'
else
    C_RESET=""; C_BOLD=""; C_RED=""; C_GREEN=""; C_YELLOW=""
fi
info() { printf '%s\n' "$*"; }
ok()   { printf '%s[ 完成 ]%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
warn() { printf '%s[ 注意 ]%s %s\n' "$C_YELLOW" "$C_RESET" "$*"; }
die()  { printf '%s[ 失败 ]%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; exit 1; }

usage() {
    cat <<'EOF'
用法: sudo ./scripts/uninstall.sh [--purge] [--yes]

默认: 停止服务、移除二进制与 systemd 单元，保留:
  /etc/tunnel-control/  /etc/tunnel-agent/  /etc/tunnel/
  /var/lib/tunnel-control/  /var/lib/tunnel-agent/

--purge   同时删除上述配置、数据库与证书（不可恢复，需二次确认）
--yes     跳过交互确认，用于自动化
EOF
}

PURGE="no"
ASSUME_YES="no"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --purge) PURGE="yes"; shift ;;
        --yes|-y) ASSUME_YES="yes"; shift ;;
        --help|-h) usage; exit 0 ;;
        *) usage; die "未知参数：$1" ;;
    esac
done

[[ $EUID -eq 0 ]] || die "需要 root 权限，请使用 sudo"

stop_service() {
    local name="$1"
    if systemctl list-unit-files 2>/dev/null | grep -q "^$name.service"; then
        # 先 stop 触发优雅排空，再 disable。
        systemctl stop "$name" 2>/dev/null || true
        systemctl disable "$name" 2>/dev/null || true
        rm -f "$SYSTEMD_DIR/$name.service"
        ok "已停止并移除服务 $name"
    fi
}

stop_service tunnel-agent
stop_service tunnel-control
systemctl daemon-reload

for bin in tunnel-agent tunnel-control; do
    if [[ -e "$BIN_DIR/$bin" ]]; then
        rm -f "$BIN_DIR/$bin"
        ok "已移除 $BIN_DIR/$bin"
    fi
done

rm -rf /usr/share/tunnel-control/web 2>/dev/null || true

if [[ "$PURGE" == "yes" ]]; then
    printf '\n%s即将永久删除以下内容%s\n' "$C_BOLD" "$C_RESET"
    printf '  /etc/tunnel-control  /etc/tunnel-agent  /etc/tunnel\n'
    printf '  /var/lib/tunnel-control  /var/lib/tunnel-agent\n'
    warn "包含控制面数据库（全部节点、路由、审计记录）与 CA 私钥，无法恢复。"

    if [[ "$ASSUME_YES" != "yes" ]]; then
        read -r -p "确认删除？输入 DELETE 继续：" answer
        [[ "$answer" == "DELETE" ]] || die "已取消，数据保持不变"
    fi

    rm -rf /etc/tunnel-control /etc/tunnel-agent /etc/tunnel
    rm -rf /var/lib/tunnel-control /var/lib/tunnel-agent
    rm -rf /usr/share/tunnel-control
    ok "已删除全部配置与数据"

    # 仅在确实不再有任何残留时删除用户。
    if id -u tunnel >/dev/null 2>&1; then
        userdel tunnel 2>/dev/null && ok "已删除系统用户 tunnel" || true
    fi
else
    info ""
    info "配置与数据已保留："
    info "  /etc/tunnel-control  /etc/tunnel-agent  /etc/tunnel"
    info "  /var/lib/tunnel-control  /var/lib/tunnel-agent"
    info ""
    info "需要彻底清除请执行：sudo ./scripts/uninstall.sh --purge"
fi
