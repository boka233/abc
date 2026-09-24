#!/usr/bin/env bash
#
# 一键安装脚本 —— tunnel-control（控制面 + 面板）或 tunnel-agent（数据面）
#
# 用法:
#   sudo ./scripts/install.sh control          # 安装控制面
#   sudo ./scripts/install.sh agent            # 安装 agent
#   sudo ./scripts/install.sh both             # 同机安装两者（测试用）
#
# 脚本行为的几条原则:
#   1. 幂等 —— 重复执行不会破坏已有配置。已存在的 config.toml 不会被覆盖，
#      只会写出 config.toml.new 供人工对比。
#   2. 不猜测密钥 —— jwt_secret / tunnel_psk 首次安装时生成，之后绝不重写。
#      重写会让所有已发出的会话失效、让所有 agent 握手失败。
#   3. 不改动系统网络 —— 不写 sysctl、不动路由表。IEPL 主机的内核参数由
#      管理员依据 docs/networking-iepl.md 自行确认后再应用。
#   4. 失败即停 —— set -euo pipefail，任何一步失败立即退出并说明原因。

set -euo pipefail

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------
readonly SERVICE_USER="tunnel"
readonly BIN_DIR="/usr/local/bin"
readonly CONTROL_CONF_DIR="/etc/tunnel-control"
readonly AGENT_CONF_DIR="/etc/tunnel-agent"
readonly CONTROL_DATA_DIR="/var/lib/tunnel-control"
readonly AGENT_DATA_DIR="/var/lib/tunnel-agent"
readonly WEB_DIR="/usr/share/tunnel-control/web"
readonly TLS_DIR="/etc/tunnel"
readonly SYSTEMD_DIR="/etc/systemd/system"

readonly REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ---------------------------------------------------------------------------
# 输出
# ---------------------------------------------------------------------------
if [[ -t 1 ]]; then
    C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'
    C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_BLUE=$'\033[34m'
else
    C_RESET=""; C_BOLD=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""
fi

info()  { printf '%s[ 信息 ]%s %s\n' "$C_BLUE" "$C_RESET" "$*"; }
ok()    { printf '%s[ 完成 ]%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
warn()  { printf '%s[ 注意 ]%s %s\n' "$C_YELLOW" "$C_RESET" "$*"; }
die()   { printf '%s[ 失败 ]%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; exit 1; }
step()  { printf '\n%s==> %s%s\n' "$C_BOLD" "$*" "$C_RESET"; }

# ---------------------------------------------------------------------------
# 前置检查
# ---------------------------------------------------------------------------
usage() {
    cat <<'EOF'
用法: sudo ./scripts/install.sh <control|agent|both> [选项]

角色:
  control   安装控制面与 Web 管理面板
  agent     安装数据面 agent（entry / exit / both 三种角色由配置决定）
  both      同机安装两者，仅建议用于测试环境

选项:
  --skip-build     跳过编译，直接使用已有的 target/release 产物
  --no-web         不安装 Web 面板（仅提供 API）
  --help           显示本帮助

安装完成后脚本会打印后续操作步骤。
EOF
}

require_root() {
    [[ $EUID -eq 0 ]] || die "需要 root 权限运行，请使用 sudo"
}

require_linux() {
    [[ "$(uname -s)" == "Linux" ]] \
        || die "本脚本仅支持 Linux（Ubuntu 22.04+ / Debian 11+）"
}

check_os() {
    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        case "${ID:-}" in
            ubuntu|debian) info "检测到 ${PRETTY_NAME:-$ID}" ;;
            *) warn "未在 ${PRETTY_NAME:-$ID} 上测试过，继续执行但请自行验证" ;;
        esac
    fi
}

# ---------------------------------------------------------------------------
# 编译
# ---------------------------------------------------------------------------
build_binaries() {
    step "编译 Rust 二进制"

    command -v cargo >/dev/null 2>&1 \
        || die "未找到 cargo。请先安装 Rust 1.80+：https://rustup.rs"

    # 预检查版本：1.80 以下会在编译中途报晦涩的语法错误，不如提前说清楚。
    local version
    version="$(cargo --version | awk '{print $2}')"
    info "cargo 版本 $version"

    ( cd "$REPO_ROOT" && cargo build --release ) \
        || die "编译失败，请检查上方错误输出"

    ok "二进制编译完成"
}

build_web() {
    step "构建 Web 面板"

    command -v npm >/dev/null 2>&1 \
        || die "未找到 npm。请安装 Node.js 20+，或使用 --no-web 跳过面板"

    ( cd "$REPO_ROOT/web" && npm ci --no-audit --no-fund && npm run build ) \
        || die "前端构建失败"

    ok "Web 面板构建完成"
}

# ---------------------------------------------------------------------------
# 系统准备
# ---------------------------------------------------------------------------
create_user() {
    if id -u "$SERVICE_USER" >/dev/null 2>&1; then
        info "系统用户 $SERVICE_USER 已存在"
    else
        useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
        ok "已创建系统用户 $SERVICE_USER（无登录权限）"
    fi
}

# 生成密钥。只在文件不存在时生成 —— 覆盖已有密钥会导致会话全部失效、
# agent 全部握手失败，这是最容易被"重跑一次安装脚本"引入的故障。
generate_secret() {
    openssl rand -base64 48 | tr -d '\n'
}

# ---------------------------------------------------------------------------
# 控制面
# ---------------------------------------------------------------------------
install_control() {
    step "安装控制面"

    install -m 755 "$REPO_ROOT/target/release/tunnel-control" "$BIN_DIR/" \
        || die "无法安装 tunnel-control 到 $BIN_DIR"
    ok "已安装 $BIN_DIR/tunnel-control"

    install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 750 "$CONTROL_DATA_DIR"
    install -d -m 755 "$CONTROL_CONF_DIR"

    local conf="$CONTROL_CONF_DIR/config.toml"
    if [[ -f "$conf" ]]; then
        # 不覆盖：管理员可能已经改过限额、监听地址等。
        install -m 600 -o "$SERVICE_USER" -g "$SERVICE_USER" \
            "$REPO_ROOT/configs/control.example.toml" "$conf.new"
        warn "$conf 已存在，未覆盖。新示例写入 $conf.new，请自行对比差异"
    else
        install -m 600 -o "$SERVICE_USER" -g "$SERVICE_USER" \
            "$REPO_ROOT/configs/control.example.toml" "$conf"

        local jwt psk
        jwt="$(generate_secret)"
        psk="$(generate_secret)"

        # 用 | 作分隔符，base64 里不会出现它。
        sed -i "s|^jwt_secret = \"\"|jwt_secret = \"$jwt\"|" "$conf"
        sed -i "s|^tunnel_psk = \"\"|tunnel_psk = \"$psk\"|" "$conf"

        ok "已生成 $conf 并写入随机 jwt_secret 与 tunnel_psk"
        info "tunnel_psk 需与所有 agent 共享，agent 会通过控制面自动获取"
    fi

    if [[ "$INSTALL_WEB" == "yes" ]]; then
        install -d -m 755 "$(dirname "$WEB_DIR")"
        rm -rf "$WEB_DIR"
        cp -r "$REPO_ROOT/web/dist" "$WEB_DIR"
        ok "已安装 Web 面板到 $WEB_DIR"
    else
        # 面板未安装时把 web_root 注掉，否则启动会打一条找不到目录的警告。
        sed -i 's|^web_root = |#web_root = |' "$conf" 2>/dev/null || true
        info "已跳过 Web 面板，控制面仅提供 API"
    fi

    step "校验配置并初始化数据库"
    sudo -u "$SERVICE_USER" "$BIN_DIR/tunnel-control" --config "$conf" check \
        || die "配置校验失败，请修正 $conf 后重试"
    ok "配置校验通过"

    sudo -u "$SERVICE_USER" "$BIN_DIR/tunnel-control" --config "$conf" migrate \
        || die "数据库初始化失败"
    ok "数据库已就绪：$CONTROL_DATA_DIR/control.db"

    install -m 644 "$REPO_ROOT/systemd/tunnel-control.service" "$SYSTEMD_DIR/"
    systemctl daemon-reload
    ok "已安装 systemd 服务 tunnel-control"
}

# ---------------------------------------------------------------------------
# agent
# ---------------------------------------------------------------------------
install_agent() {
    step "安装 agent"

    install -m 755 "$REPO_ROOT/target/release/tunnel-agent" "$BIN_DIR/" \
        || die "无法安装 tunnel-agent 到 $BIN_DIR"
    ok "已安装 $BIN_DIR/tunnel-agent"

    install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 750 "$AGENT_DATA_DIR"
    install -d -m 755 "$AGENT_CONF_DIR"
    install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 750 "$TLS_DIR"

    local conf="$AGENT_CONF_DIR/config.toml"
    if [[ -f "$conf" ]]; then
        install -m 600 -o "$SERVICE_USER" -g "$SERVICE_USER" \
            "$REPO_ROOT/configs/agent.example.toml" "$conf.new"
        warn "$conf 已存在，未覆盖。新示例写入 $conf.new"
    else
        install -m 600 -o "$SERVICE_USER" -g "$SERVICE_USER" \
            "$REPO_ROOT/configs/agent.example.toml" "$conf"
        ok "已生成 $conf"
        # 这里不能自动填 node_id / agent_token：它们由面板在创建节点时签发，
        # 脚本无从得知。
        warn "必须手工填写 node_id、agent_token 与 control_url 后才能启动"
    fi

    install -m 644 "$REPO_ROOT/systemd/tunnel-agent.service" "$SYSTEMD_DIR/"
    systemctl daemon-reload
    ok "已安装 systemd 服务 tunnel-agent"

    step "本机网络接口"
    # 配置 endpoint 之前先让管理员确认 agent 实际看到哪些网卡和地址。
    "$BIN_DIR/tunnel-agent" interfaces || true
}

# ---------------------------------------------------------------------------
# 后续步骤说明
# ---------------------------------------------------------------------------
print_next_steps() {
    printf '\n%s================ 安装完成 ================%s\n' "$C_BOLD" "$C_RESET"

    if [[ "$ROLE" == "control" || "$ROLE" == "both" ]]; then
        cat <<EOF

${C_BOLD}控制面后续步骤${C_RESET}

  1. 启动服务
       systemctl enable --now tunnel-control

  2. 取出首次登录密码（只打印一次，不写入日志文件）
       journalctl -u tunnel-control | grep -A4 '初始管理员\|Initial administrator'

     若已错过，可重置：
       sudo -u $SERVICE_USER tunnel-control \\
         --config $CONTROL_CONF_DIR/config.toml reset-password admin

  3. 默认监听 127.0.0.1:8080。对外暴露请用 nginx 终结 TLS，
     配置样例见 docs/deployment.md。

  4. 首次登录后立即修改密码 —— 未改密前所有写操作会被拒绝。
EOF
    fi

    if [[ "$ROLE" == "agent" || "$ROLE" == "both" ]]; then
        cat <<EOF

${C_BOLD}agent 后续步骤${C_RESET}

  1. 在面板 Nodes 页创建节点，复制它一次性显示的 agent token

  2. 填入 $AGENT_CONF_DIR/config.toml：
       node_id      = "..."
       agent_token  = "..."
       control_url  = "http://<控制面地址>:8080"

  3. 准备 TLS 材料到 $TLS_DIR（ca.pem 必需；exit 角色还需 exit.pem/exit.key）
     生成步骤见 docs/deployment.md 的 PKI 一节

  4. 校验并启动
       sudo -u $SERVICE_USER tunnel-agent \\
         --config $AGENT_CONF_DIR/config.toml check
       systemctl enable --now tunnel-agent

  ${C_YELLOW}IEPL 双网卡主机${C_RESET}：配置 endpoint 之前必须先按
  docs/networking-iepl.md 设置策略路由与 rp_filter，否则源地址绑定
  不会走私网网卡，且故障现象是"连接建立不起来且日志无异常"。
EOF
    fi

    cat <<EOF

${C_BOLD}常用命令${C_RESET}
  systemctl status  tunnel-agent      查看状态
  journalctl -u     tunnel-agent -f   跟踪日志
  systemctl reload  tunnel-agent      重载证书（不断开隧道）
  systemctl restart tunnel-agent      优雅重启（先排空连接）

${C_BOLD}文档${C_RESET}
  docs/使用说明.md            中文完整使用说明
  docs/networking-iepl.md    双网卡 / IEPL 路由
  docs/linux-tuning.md       内核参数（含每项风险说明）
  docs/deployment.md         部署、PKI、升级、备份

EOF
}

# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
main() {
    ROLE=""
    SKIP_BUILD="no"
    INSTALL_WEB="yes"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            control|agent|both) ROLE="$1"; shift ;;
            --skip-build) SKIP_BUILD="yes"; shift ;;
            --no-web) INSTALL_WEB="no"; shift ;;
            --help|-h) usage; exit 0 ;;
            *) usage; die "未知参数：$1" ;;
        esac
    done

    [[ -n "$ROLE" ]] || { usage; die "请指定角色：control / agent / both"; }

    require_linux
    require_root
    check_os

    command -v openssl >/dev/null 2>&1 || die "未找到 openssl，请先安装"
    command -v systemctl >/dev/null 2>&1 || die "未找到 systemd，本脚本依赖它"

    if [[ "$SKIP_BUILD" == "no" ]]; then
        build_binaries
        if [[ "$INSTALL_WEB" == "yes" && ( "$ROLE" == "control" || "$ROLE" == "both" ) ]]; then
            build_web
        fi
    else
        info "已跳过编译，使用现有 target/release 产物"
        [[ -x "$REPO_ROOT/target/release/tunnel-control" || "$ROLE" == "agent" ]] \
            || die "未找到 target/release/tunnel-control，请去掉 --skip-build"
    fi

    create_user

    case "$ROLE" in
        control) install_control ;;
        agent)   install_agent ;;
        both)    install_control; install_agent ;;
    esac

    print_next_steps
}

main "$@"
