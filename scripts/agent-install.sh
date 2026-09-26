#!/usr/bin/env bash
#
# tunnel-agent 一键对接脚本。
#
# 由控制面在 /api/agent/install.sh 提供，面板上「复制安装命令」得到的就是：
#
#   bash <(curl -fsSL http://面板地址:8080/api/agent/install.sh) -t <令牌> -u http://面板地址:8080
#
# 用 `bash <(curl ...)` 而不是 `curl | bash`：后者会占用 stdin，脚本就无法在修改
# 内核参数前向用户确认。需要非交互执行时加 --yes。
#
# 脚本行为：
#   1. 下载并安装 tunnel-agent 二进制
#   2. 写出 /etc/tunnel-agent/config.toml，填入令牌与面板地址
#   3. 安装并启动 systemd 服务，agent 自行向组注册
#   4. 询问是否应用网络优化（改前逐项打印，只动低风险项）
#
# 不做的事：不修改路由表、不动 rp_filter、不碰 tcp_rmem/wmem —— 见 --tune 一节。

set -euo pipefail

readonly SERVICE_USER="tunnel"
readonly BIN_DIR="/usr/local/bin"
readonly CONF_DIR="/etc/tunnel-agent"
readonly DATA_DIR="/var/lib/tunnel-agent"
readonly TLS_DIR="/etc/tunnel"
readonly SYSTEMD_DIR="/etc/systemd/system"
readonly SYSCTL_FILE="/etc/sysctl.d/90-tunnel-agent.conf"

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
用法: bash <(curl -fsSL <面板地址>/api/agent/install.sh) -t <令牌> -u <面板地址> [选项]

必填:
  -t, --token <令牌>      设备组注册令牌（面板上复制）
  -u, --url <地址>        控制面地址，如 http://10.0.0.5:8080

选项:
  -n, --name <名称>       本机在组内的名称，默认用主机名
  -r, --role <角色>       entry | exit | both，默认由组类型决定
      --tune              应用网络优化（会先打印将要修改的内容并确认）
      --no-tune           跳过网络优化询问
      --yes               非交互模式，自动确认所有提示
      --uninstall         卸载 agent
      --help              显示本帮助
EOF
}

# ---------------------------------------------------------------------------
# 参数
# ---------------------------------------------------------------------------
TOKEN=""; PANEL_URL=""; NODE_NAME=""; ROLE=""
DO_TUNE="ask"; ASSUME_YES="no"; UNINSTALL="no"

while [[ $# -gt 0 ]]; do
    case "$1" in
        -t|--token) TOKEN="${2:-}"; shift 2 ;;
        -u|--url)   PANEL_URL="${2:-}"; shift 2 ;;
        -n|--name)  NODE_NAME="${2:-}"; shift 2 ;;
        -r|--role)  ROLE="${2:-}"; shift 2 ;;
        --tune)     DO_TUNE="yes"; shift ;;
        --no-tune)  DO_TUNE="no"; shift ;;
        --yes|-y)   ASSUME_YES="yes"; shift ;;
        --uninstall) UNINSTALL="yes"; shift ;;
        --help|-h)  usage; exit 0 ;;
        *) usage; die "未知参数：$1" ;;
    esac
done

[[ $EUID -eq 0 ]] || die "需要 root 权限，请用 sudo 执行"
[[ "$(uname -s)" == "Linux" ]] || die "仅支持 Linux（Ubuntu 22.04+ / Debian 11+）"

# ---------------------------------------------------------------------------
# 卸载
# ---------------------------------------------------------------------------
if [[ "$UNINSTALL" == "yes" ]]; then
    step "卸载 tunnel-agent"
    systemctl disable --now tunnel-agent 2>/dev/null || true
    rm -f "$SYSTEMD_DIR/tunnel-agent.service" "$BIN_DIR/tunnel-agent"
    systemctl daemon-reload
    ok "已移除程序与服务"
    info "配置与缓存保留在 $CONF_DIR 和 $DATA_DIR；如需清除请手工删除"
    info "内核参数保留在 $SYSCTL_FILE；如需回退请删除该文件并重启"
    exit 0
fi

[[ -n "$TOKEN" ]] || { usage; die "缺少 --token"; }
[[ -n "$PANEL_URL" ]] || { usage; die "缺少 --url"; }

# 去掉末尾斜杠，后面拼接路径时才不会出现双斜杠。
PANEL_URL="${PANEL_URL%/}"

case "$PANEL_URL" in
    http://*|https://*) ;;
    *) die "面板地址必须以 http:// 或 https:// 开头" ;;
esac

# 回环地址只在与面板同机时才可用；agent 在别的机器上跑就连不上。
if [[ "$PANEL_URL" == *"127.0.0.1"* || "$PANEL_URL" == *"localhost"* ]]; then
    warn "面板地址是回环地址（$PANEL_URL）。只有本脚本与面板在同一台机器上时才可用。"
fi

# ---------------------------------------------------------------------------
# 前置
# ---------------------------------------------------------------------------
for cmd in curl systemctl; do
    command -v "$cmd" >/dev/null 2>&1 || die "缺少命令 $cmd，请先安装"
done

if [[ -z "$NODE_NAME" ]]; then
    # 主机名作为组内名称，通常已经能区分机器。
    NODE_NAME="$(hostname -s 2>/dev/null || hostname)"
fi

ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64) ASSET_ARCH="x86_64" ;;
    aarch64|arm64) ASSET_ARCH="aarch64" ;;
    *) die "不支持的架构：$ARCH（仅 x86_64 / aarch64）" ;;
esac

step "对接信息"
printf '  面板地址   %s\n' "$PANEL_URL"
printf '  机器名称   %s\n' "$NODE_NAME"
printf '  架构       %s\n' "$ASSET_ARCH"
printf '  角色       %s\n' "${ROLE:-由设备组类型决定}"

# ---------------------------------------------------------------------------
# 安装二进制
# ---------------------------------------------------------------------------
step "安装 tunnel-agent"

id -u "$SERVICE_USER" >/dev/null 2>&1 || {
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
    ok "已创建系统用户 $SERVICE_USER"
}

install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 750 "$DATA_DIR" "$TLS_DIR"
install -d -m 755 "$CONF_DIR"

# 优先从面板下载二进制：面板与 agent 版本必须匹配，从面板取能保证这一点。
BIN_URL="$PANEL_URL/api/agent/download/tunnel-agent-$ASSET_ARCH"
TMP_BIN="$(mktemp)"
TMP_HDR="$(mktemp)"
trap 'rm -f "$TMP_BIN" "$TMP_HDR"' EXIT

# -D 把响应头存下来：面板在 X-Binary-Sha256 里给出校验值。
#
# 为什么必须校验：多数部署的面板地址是 http://内网:8080，没有 TLS 终结。此处下载的
# 是一个将以 root 权限运行的可执行文件，不校验等于接受链路上任何一跳的替换。
if curl -fsSL --connect-timeout 10 -D "$TMP_HDR" -o "$TMP_BIN" "$BIN_URL" 2>/dev/null \
   && [[ -s "$TMP_BIN" ]]; then

    EXPECTED="$(tr -d '\r' < "$TMP_HDR" \
        | awk 'tolower($1) == "x-binary-sha256:" { print tolower($2) }' \
        | tail -n 1)"

    if [[ -n "$EXPECTED" ]]; then
        if command -v sha256sum >/dev/null 2>&1; then
            ACTUAL="$(sha256sum "$TMP_BIN" | awk '{print $1}')"
        elif command -v shasum >/dev/null 2>&1; then
            ACTUAL="$(shasum -a 256 "$TMP_BIN" | awk '{print $1}')"
        else
            ACTUAL=""
            warn "本机没有 sha256sum/shasum，无法校验二进制完整性"
        fi

        if [[ -n "$ACTUAL" && "$ACTUAL" != "$EXPECTED" ]]; then
            die "下载的二进制校验失败，已中止安装。
  面板声明  $EXPECTED
  实际内容  $ACTUAL
这通常意味着传输被截断，或链路上有人替换了文件。请改用 HTTPS 访问面板后重试。"
        fi
        [[ -n "$ACTUAL" ]] && ok "二进制校验通过（sha256 ${ACTUAL:0:16}…）"
    else
        # 老版本控制面不发这个头。不中止，但要让用户知道这一趟没有校验。
        warn "面板未提供 sha256 校验值（控制面版本较旧），本次下载未经校验"
    fi

    EXPECTED_VERSION="$(tr -d '\r' < "$TMP_HDR" \
        | awk 'tolower($1) == "x-binary-version:" { print $2 }' \
        | tail -n 1)"
    [[ -n "$EXPECTED_VERSION" ]] \
        || die "面板未提供 agent 版本信息，请先升级控制面，再重新对接节点"
    chmod 700 "$TMP_BIN"
    DOWNLOADED_VERSION="$("$TMP_BIN" --version 2>/dev/null || true)"
    [[ "$DOWNLOADED_VERSION" == "tunnel-agent $EXPECTED_VERSION" ]] \
        || die "面板提供的 agent 版本不匹配：控制面 $EXPECTED_VERSION，下载到 ${DOWNLOADED_VERSION:-无法运行}。请重跑控制面部署脚本刷新 agent 二进制"

    install -m 755 "$TMP_BIN" "$BIN_DIR/tunnel-agent"
    ok "已从面板安装 $BIN_DIR/tunnel-agent"
elif [[ -x "$BIN_DIR/tunnel-agent" ]]; then
    # 面板没提供下载时，若本机已有二进制（比如先跑过 install.sh）就沿用。
    # 打印版本号：沿用一个很旧的 agent 会在握手或配置解析处报晦涩的错，
    # 提前显示出来比事后翻日志便宜。
    EXISTING_VER="$("$BIN_DIR/tunnel-agent" --version 2>/dev/null | head -n 1 || true)"
    warn "面板未提供二进制下载，沿用已安装的 $BIN_DIR/tunnel-agent（${EXISTING_VER:-版本未知}）"
    warn "若对接后出现握手失败，请先确认它与控制面版本匹配"
else
    die "无法从 $BIN_URL 下载二进制，且本机没有现成的 tunnel-agent。

可能原因：控制面没有配置 agent_binary_dir，或该目录下缺少 tunnel-agent-$ASSET_ARCH。
请在控制面机器上确认：
  grep agent_binary_dir /etc/tunnel-control/config.toml
  ls -l /var/lib/tunnel-control/agent-bin/

或在本机用源码安装：
  git clone <仓库> && cd tunnel && sudo ./scripts/install.sh agent"
fi

# ---------------------------------------------------------------------------
# 自动领取隧道证书
# ---------------------------------------------------------------------------
step "配置隧道 TLS"

if ! command -v openssl >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update && apt-get install -y openssl || die "无法安装 openssl"
    else
        die "缺少 openssl，请先安装后重试"
    fi
fi

AUTH_HEADERS=(-H "X-Agent-Token: $TOKEN" -H "X-Agent-Name: $NODE_NAME" -H "X-Agent-Hostname: $(hostname)")
[[ -n "$ROLE" ]] && AUTH_HEADERS+=(-H "X-Agent-Role: $ROLE")
TMP_CA="$(mktemp)"
TMP_CERT="$(mktemp)"
TMP_CSR="$(mktemp)"
trap 'rm -f "$TMP_BIN" "$TMP_HDR" "$TMP_CA" "$TMP_CERT" "$TMP_CSR"' EXIT

curl -fsSL --connect-timeout 10 --max-time 30 \
    "${AUTH_HEADERS[@]}" -D "$TMP_HDR" -o "$TMP_CA" \
    "$PANEL_URL/api/agent/ca.pem" || die "无法从控制面领取隧道 CA，请确认面板已升级并配置 CA"
openssl x509 -in "$TMP_CA" -noout >/dev/null 2>&1 || die "控制面返回的 CA 证书无效"

EFFECTIVE_ROLE="$(tr -d '\r' < "$TMP_HDR" | awk 'tolower($1) == "x-agent-role:" { print $2 }' | tail -n 1)"
case "$EFFECTIVE_ROLE" in
    entry|exit|both) ok "控制面确认本机角色：$EFFECTIVE_ROLE" ;;
    *) die "控制面未返回有效的节点角色" ;;
esac

if [[ -f "$TLS_DIR/ca.pem" ]]; then
    OLD_FP="$(openssl x509 -in "$TLS_DIR/ca.pem" -fingerprint -sha256 -noout 2>/dev/null || true)"
    NEW_FP="$(openssl x509 -in "$TMP_CA" -fingerprint -sha256 -noout)"
    [[ "$OLD_FP" == "$NEW_FP" ]] || die "本机 CA 与控制面不同；为避免破坏现有隧道，已停止。请确认是否连接了正确的面板"
fi
install -m 644 -o "$SERVICE_USER" -g "$SERVICE_USER" "$TMP_CA" "$TLS_DIR/ca.pem"
ok "已安装 $TLS_DIR/ca.pem"

if [[ "$EFFECTIVE_ROLE" == "exit" || "$EFFECTIVE_ROLE" == "both" ]]; then
    if [[ ! -f "$TLS_DIR/exit.key" ]]; then
        openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
            -out "$TLS_DIR/exit.key" >/dev/null 2>&1 || die "无法生成出口私钥"
    fi
    chown "$SERVICE_USER:$SERVICE_USER" "$TLS_DIR/exit.key"
    chmod 600 "$TLS_DIR/exit.key"
    openssl req -new -key "$TLS_DIR/exit.key" -subj '/CN=tunnel-exit' \
        -out "$TMP_CSR" >/dev/null 2>&1 || die "无法创建出口证书请求"
    curl -fsSL --connect-timeout 10 --max-time 30 \
        "${AUTH_HEADERS[@]}" -H 'Content-Type: application/pkcs10' \
        --data-binary "@$TMP_CSR" -o "$TMP_CERT" \
        "$PANEL_URL/api/agent/certificate" || die "控制面签发出口证书失败，请检查 CA 私钥和控制面日志"
    openssl verify -CAfile "$TLS_DIR/ca.pem" "$TMP_CERT" >/dev/null 2>&1 \
        || die "签发的出口证书无法通过 CA 验证"
    KEY_FP="$(openssl pkey -in "$TLS_DIR/exit.key" -pubout -outform DER 2>/dev/null | openssl dgst -sha256)"
    CERT_FP="$(openssl x509 -in "$TMP_CERT" -pubkey -noout 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256)"
    [[ -n "$KEY_FP" && "$KEY_FP" == "$CERT_FP" ]] || die "出口证书与本机私钥不匹配"
    install -m 644 -o "$SERVICE_USER" -g "$SERVICE_USER" "$TMP_CERT" "$TLS_DIR/exit.pem"
    ok "出口证书已签发；私钥仅保存在本机"
fi

# ---------------------------------------------------------------------------
# 写配置
# ---------------------------------------------------------------------------
step "写入配置"

CONF="$CONF_DIR/config.toml"
if [[ -f "$CONF" ]]; then
    cp -a "$CONF" "$CONF.bak.$(date +%Y%m%d-%H%M%S)"
    warn "已备份原有配置到 $CONF.bak.*"
fi

# 令牌写在配置里，权限必须是 0600。
cat >"$CONF" <<EOF
# 由一键对接脚本生成于 $(date -Iseconds)
#
# 认证凭据是**设备组**令牌，同一个令牌可用于组内多台机器。
# node_id 不再需要手工填写 —— agent 用令牌注册，控制面按机器名登记。

enroll_token = "$TOKEN"
control_url = "$PANEL_URL"
node_name = "$NODE_NAME"
role = "$EFFECTIVE_ROLE"

cache_path = "$DATA_DIR/last-known-good.json"

heartbeat_interval = "10s"
config_poll_interval = "30s"
control_timeout = "10s"
connection_sample_limit = 200

[tls]
ca_path = "$TLS_DIR/ca.pem"
$([[ "$EFFECTIVE_ROLE" == "entry" ]] || printf 'cert_path = "%s/exit.pem"\nkey_path = "%s/exit.key"\n' "$TLS_DIR" "$TLS_DIR")
require_client_auth = false
insecure_skip_verify = false

[log]
level = "info"
format = "text"
with_target = true
with_thread_ids = false
EOF

chown "$SERVICE_USER:$SERVICE_USER" "$CONF"
chmod 600 "$CONF"
ok "已写入 $CONF（权限 0600）"

# ---------------------------------------------------------------------------
# systemd
# ---------------------------------------------------------------------------
step "安装 systemd 服务"

cat >"$SYSTEMD_DIR/tunnel-agent.service" <<EOF
[Unit]
Description=TLS Tunnel Agent (data plane)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$BIN_DIR/tunnel-agent --config $CONF
# SIGHUP 重载证书，不断开已建立的隧道
ExecReload=/bin/kill -HUP \$MAINPID
KillSignal=SIGTERM
# 必须大于排空窗口，否则 systemd 会在排空中途 SIGKILL，重置所有用户连接
TimeoutStopSec=45
Restart=always
RestartSec=3

# 每条转发连接占两个描述符（客户端 + 目标），默认 1024 会把节点卡在 500 连接
LimitNOFILE=65535

User=$SERVICE_USER
Group=$SERVICE_USER

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DATA_DIR
ProtectKernelTunables=true
ProtectKernelModules=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

StandardOutput=journal
StandardError=journal
SyslogIdentifier=tunnel-agent

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
ok "已安装服务 tunnel-agent"

# ---------------------------------------------------------------------------
# 网络优化（改前打印，只动低风险项）
# ---------------------------------------------------------------------------
confirm() {
    [[ "$ASSUME_YES" == "yes" ]] && return 0
    local answer
    read -r -p "$1 [y/N] " answer
    [[ "$answer" == "y" || "$answer" == "Y" ]]
}

current_sysctl() { sysctl -n "$1" 2>/dev/null || echo "?"; }

apply_tuning() {
    step "网络优化"

    local cc_current qdisc_current somaxconn_current
    somaxconn_current="$(current_sysctl net.core.somaxconn)"
    cc_current="$(current_sysctl net.ipv4.tcp_congestion_control)"
    qdisc_current="$(current_sysctl net.core.default_qdisc)"

    local bbr_available="no"
    if modprobe tcp_bbr 2>/dev/null || grep -q bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
        bbr_available="yes"
    fi

    printf '%s将应用以下内核参数：%s\n' "$C_BOLD" "$C_RESET"
    printf '  net.core.somaxconn               %s → 4096\n' "$somaxconn_current"
    printf '     作用：accept 队列上限。过小时连接风暴会让内核静默丢 SYN，\n'
    printf '           客户端表现为连接超时而日志里什么都没有。\n'
    if [[ "$bbr_available" == "yes" ]]; then
        printf '  net.ipv4.tcp_congestion_control  %s → bbr\n' "$cc_current"
        printf '  net.core.default_qdisc           %s → fq\n' "$qdisc_current"
        printf '     作用：BBR 在有非拥塞丢包的长肥链路上通常优于 CUBIC。\n'
        printf '           风险：与 CUBIC 流共享链路时公平性有争议；专线上无此问题。\n'
    else
        printf '  %s（本机内核不支持 BBR，跳过拥塞控制调整）%s\n' "$C_YELLOW" "$C_RESET"
    fi
    printf '  LimitNOFILE (systemd)            1024 → 65535  已写入服务单元\n'
    echo
    printf '%s以下仅提示，不自动修改：%s\n' "$C_BOLD" "$C_RESET"
    printf '  tcp_rmem / tcp_wmem —— 这是**每个 socket** 的上限，会按连接数倍增。\n'
    printf '    在 10000 连接下把 max 设成 16MB 理论可占 160GB 缓冲，足以触发 OOM。\n'
    printf '    仅在实测确认长肥链路吞吐受限时再调，详见 docs/linux-tuning.md。\n'
    printf '  rp_filter —— 双网卡 IEPL 主机需要设为 2（宽松），但改错会静默丢包。\n'
    printf '    请按 docs/networking-iepl.md 手工确认后再改。\n'
    echo

    if ! confirm "继续应用上述低风险参数？"; then
        info "已跳过网络优化。随时可以重新执行本脚本并加 --tune。"
        return 0
    fi

    {
        echo "# 由 tunnel-agent 一键对接脚本生成于 $(date -Iseconds)"
        echo "# 仅包含低风险项；tcp_rmem/wmem 与 rp_filter 需管理员按实测自行决定。"
        echo "net.core.somaxconn = 4096"
        if [[ "$bbr_available" == "yes" ]]; then
            echo "net.ipv4.tcp_congestion_control = bbr"
            echo "net.core.default_qdisc = fq"
        fi
    } >"$SYSCTL_FILE"

    if sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1; then
        ok "已应用并持久化到 $SYSCTL_FILE"
        printf '  somaxconn        → %s\n' "$(current_sysctl net.core.somaxconn)"
        [[ "$bbr_available" == "yes" ]] && \
            printf '  congestion       → %s\n' "$(current_sysctl net.ipv4.tcp_congestion_control)"
    else
        warn "部分参数应用失败（容器或受限内核常见）。配置已写入 $SYSCTL_FILE，重启后生效。"
    fi
}

case "$DO_TUNE" in
    yes) apply_tuning ;;
    no)  info "已按 --no-tune 跳过网络优化" ;;
    ask)
        if confirm "是否查看并应用网络优化（somaxconn / BBR / fq）？"; then
            apply_tuning
        else
            info "已跳过。随时可以重新执行本脚本并加 --tune。"
        fi
        ;;
esac

# ---------------------------------------------------------------------------
# 启动
# ---------------------------------------------------------------------------
step "启动 agent"

if ! sudo -u "$SERVICE_USER" "$BIN_DIR/tunnel-agent" --config "$CONF" check; then
    die "配置校验失败，请检查上方输出"
fi

systemctl enable tunnel-agent
# Re-running the one-click installer may have replaced an older binary or
# config while its process kept running. Always start the installed version.
systemctl restart tunnel-agent

sleep 3
if systemctl is-active --quiet tunnel-agent; then
    ok "tunnel-agent 已启动"
else
    warn "服务未处于 active 状态，查看日志：journalctl -u tunnel-agent -n 50"
fi

# ---------------------------------------------------------------------------
# 完成
# ---------------------------------------------------------------------------
printf '\n%s================ 对接完成 ================%s\n\n' "$C_BOLD" "$C_RESET"
cat <<EOF
agent 服务已启动。注册及心跳成功后，面板「设备组」页面会显示本机上线。
若仍显示离线，请查看：journalctl -u tunnel-agent -n 50 --no-pager

${C_BOLD}后续步骤${C_RESET}

  1. 隧道 CA 与本机角色所需证书已自动安装。

  2. 若本机是出口，在面板设备组详情页添加「隧道地址」，
     入口才知道该拨向哪个地址。

  3. IEPL 双网卡主机：配置隧道地址之前必须先按
     docs/networking-iepl.md 设置策略路由与 rp_filter。
     ${C_YELLOW}未配置时的故障表现是「连接建立不起来且日志无异常」。${C_RESET}

${C_BOLD}常用命令${C_RESET}
  systemctl status  tunnel-agent
  journalctl -u     tunnel-agent -f
  systemctl reload  tunnel-agent      重载证书，不断开隧道
  $BIN_DIR/tunnel-agent interfaces    查看本机网卡

EOF
