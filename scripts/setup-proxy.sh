#!/usr/bin/env bash
#
# 给已用 systemd 装好的控制面配置反向代理与 HTTPS（不用 Docker 的场景）。
#
# 用法:
#   sudo ./scripts/setup-proxy.sh -d panel.example.com -e me@example.com
#   sudo ./scripts/setup-proxy.sh -d panel.example.com --server nginx
#   sudo ./scripts/setup-proxy.sh -d panel.example.com --self-signed   # 内网自签
#
# 默认用 Caddy：它自动申请并续期证书。nginx 需要额外配 certbot 与续期钩子，
# 而那套东西最常见的故障就是钩子没触发导致证书静默过期。
#
# 脚本做什么:
#   1. 安装 Caddy 或 nginx
#   2. 写站点配置（含 WebSocket 转发与安全响应头）
#   3. 申请证书（Caddy 自动 / nginx 走 certbot / 或自签）
#   4. 在控制面配置里把本机回环加进 trusted_proxies 并重启它
#
# 不做什么:
#   * 不改防火墙。需要放通 80/443 时会提示，但不替你动 iptables/ufw —— 改错
#     防火墙规则可能把你自己锁在 SSH 外面。
#   * 不动 DNS。域名解析必须你先配好。

set -euo pipefail

readonly REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly CONTROL_CONF="/etc/tunnel-control/config.toml"

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
用法: sudo ./scripts/setup-proxy.sh -d <域名> [选项]

必填:
  -d, --domain <域名>    面板域名，需已解析到本机

选项:
  -e, --email <邮箱>     ACME 注册邮箱（申请公网证书时必填）
      --server <类型>    caddy（默认）或 nginx
      --self-signed      用自签证书，不申请公网证书（内网/无域名场景）
      --port <端口>      控制面监听端口，默认 8080
      --help             显示本帮助

说明: Caddy 自动续期证书；选 nginx 会用 certbot，续期由它的 timer 负责。
EOF
}

DOMAIN=""
EMAIL=""
SERVER="caddy"
SELF_SIGNED="no"
CONTROL_PORT="8080"

while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--domain) DOMAIN="${2:-}"; shift 2 ;;
        -e|--email) EMAIL="${2:-}"; shift 2 ;;
        --server) SERVER="${2:-}"; shift 2 ;;
        --self-signed) SELF_SIGNED="yes"; shift ;;
        --port) CONTROL_PORT="${2:-}"; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) usage; die "未知参数：$1" ;;
    esac
done

[[ "$(uname -s)" == "Linux" ]] || die "本脚本仅支持 Linux"
[[ $EUID -eq 0 ]] || die "需要 root 权限，请使用 sudo"
[[ -n "$DOMAIN" ]] || { usage; die "必须提供 --domain"; }
case "$SERVER" in
    caddy|nginx) ;;
    *) die "--server 只接受 caddy 或 nginx" ;;
esac
if [[ "$SELF_SIGNED" == "no" && -z "$EMAIL" ]]; then
    die "申请公网证书需要 --email。内网自签请加 --self-signed"
fi

# ---------------------------------------------------------------------------
# 前置检查
# ---------------------------------------------------------------------------
step "检查控制面"

command -v systemctl >/dev/null 2>&1 || die "未找到 systemd"
if ! systemctl is-active --quiet tunnel-control 2>/dev/null; then
    warn "tunnel-control 服务未在运行。反代配好后它必须启动，否则面板打不开。"
    warn "  systemctl enable --now tunnel-control"
fi

# 控制面必须真的在监听那个端口，否则配好反代只会得到 502。
if command -v ss >/dev/null 2>&1; then
    if ss -ltn 2>/dev/null | grep -qE "[:.]${CONTROL_PORT}\b"; then
        ok "控制面正在监听 $CONTROL_PORT"
    else
        warn "没有进程监听 $CONTROL_PORT。确认控制面已启动且 listen 端口是 $CONTROL_PORT。"
    fi
fi

if [[ "$SELF_SIGNED" == "no" ]]; then
    step "检查域名解析"
    resolved="$(getent ahostsv4 "$DOMAIN" 2>/dev/null | awk 'NR==1{print $1}' || true)"
    public_ip="$(curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null || true)"
    if [[ -n "$resolved" ]]; then
        info "$DOMAIN → $resolved"
        if [[ -n "$public_ip" && "$resolved" != "$public_ip" ]]; then
            warn "解析地址 $resolved 与本机公网 IP $public_ip 不一致"
            warn "ACME 的 HTTP-01 验证会失败。若用了 CDN，请先关掉代理或改用 DNS 验证。"
        fi
    else
        warn "无法解析 $DOMAIN。证书申请需要它已生效。"
    fi

    # 80 端口必须空着给 ACME 用。
    if command -v ss >/dev/null 2>&1 && ss -ltn 2>/dev/null | grep -qE "[:.]80\b"; then
        warn "80 端口已被占用。ACME 的 HTTP-01 验证需要它 —— 若占用者不是本次要装的"
        warn "反代，请先停掉它。"
    fi
fi

# ---------------------------------------------------------------------------
# Caddy
# ---------------------------------------------------------------------------
setup_caddy() {
    step "安装 Caddy"
    if command -v caddy >/dev/null 2>&1; then
        info "Caddy 已安装：$(caddy version 2>/dev/null | head -n1)"
    else
        command -v apt-get >/dev/null 2>&1 \
            || die "只支持 Debian/Ubuntu 的自动安装。其他发行版请手工装 Caddy 后重跑。"
        apt-get update -qq
        apt-get install -y -qq debian-keyring debian-archive-keyring apt-transport-https curl gnupg
        curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/gpg.key \
            | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
        curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt \
            | tee /etc/apt/sources.list.d/caddy-stable.list >/dev/null
        apt-get update -qq
        apt-get install -y -qq caddy || die "Caddy 安装失败"
        ok "Caddy 已安装"
    fi

    step "写入 Caddy 配置"
    local conf="/etc/caddy/Caddyfile"
    [[ -f "$conf" ]] && cp -a "$conf" "$conf.bak.$(date +%Y%m%d-%H%M%S)"

    local tls_line
    if [[ "$SELF_SIGNED" == "yes" ]]; then
        # Caddy 内置的本地 CA，浏览器会警告但加密是真的。
        tls_line="tls internal"
    else
        tls_line="tls $EMAIL"
    fi

    cat > "$conf" <<EOF
# 由 scripts/setup-proxy.sh 生成于 $(date -u +%Y-%m-%dT%H:%M:%SZ)
#
# 原有配置已备份为 Caddyfile.bak.*

$DOMAIN {
	$tls_line

	reverse_proxy 127.0.0.1:$CONTROL_PORT {
		# 遥测走 WebSocket。Caddy 默认转发 Upgrade 头，不需要额外设置。
		# 长连接超时要放宽，否则实时数据流会被周期性掐断。
		transport http {
			read_timeout 300s
		}
	}

	header {
		Strict-Transport-Security "max-age=31536000; includeSubDomains"
		X-Content-Type-Options "nosniff"
		X-Frame-Options "DENY"
		Referrer-Policy "strict-origin-when-cross-origin"
		# 面板不加载第三方资源。connect-src 必须含 wss:，否则遥测会被 CSP 拦掉。
		Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' wss: ws:; font-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
		-Server
	}

	encode zstd gzip
}
EOF

    caddy validate --config "$conf" >/dev/null 2>&1 \
        || die "Caddy 配置校验失败，请检查 $conf"
    ok "配置已写入并校验通过"

    systemctl enable --now caddy
    systemctl reload caddy 2>/dev/null || systemctl restart caddy
    ok "Caddy 已启动"
}

# ---------------------------------------------------------------------------
# nginx
# ---------------------------------------------------------------------------
setup_nginx() {
    step "安装 nginx"
    if command -v nginx >/dev/null 2>&1; then
        info "nginx 已安装：$(nginx -v 2>&1)"
    else
        command -v apt-get >/dev/null 2>&1 \
            || die "只支持 Debian/Ubuntu 的自动安装"
        apt-get update -qq && apt-get install -y -qq nginx || die "nginx 安装失败"
        ok "nginx 已安装"
    fi

    local cert_path key_path
    if [[ "$SELF_SIGNED" == "yes" ]]; then
        step "生成自签证书"
        local dir="/etc/ssl/tunnel-panel"
        install -d -m 700 "$dir"
        cert_path="$dir/fullchain.pem"
        key_path="$dir/privkey.pem"
        if [[ -f "$cert_path" ]]; then
            info "证书已存在，保留不动"
        else
            openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
                -keyout "$key_path" -out "$cert_path" \
                -subj "/CN=$DOMAIN" \
                -addext "subjectAltName=DNS:$DOMAIN" >/dev/null 2>&1 \
                || die "自签证书生成失败"
            chmod 600 "$key_path"
            ok "已生成自签证书（有效期 10 年）"
        fi
    else
        step "申请 Let's Encrypt 证书"
        command -v certbot >/dev/null 2>&1 || {
            apt-get install -y -qq certbot python3-certbot-nginx || die "certbot 安装失败"
        }
        cert_path="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
        key_path="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
        if [[ -f "$cert_path" ]]; then
            info "证书已存在，跳过申请"
        else
            # --nginx 会自己改 nginx 配置，但我们随后要整体覆盖站点配置，
            # 所以用 --webroot 只做验证，配置由本脚本统一写。
            install -d -m 755 /var/www/html
            certbot certonly --webroot -w /var/www/html \
                -d "$DOMAIN" --email "$EMAIL" \
                --agree-tos --non-interactive \
                || die "证书申请失败。常见原因：域名未解析到本机、80 端口不可达、
或短时间内重复申请撞上了 Let's Encrypt 速率限制（同域名每周 5 次）。"
            ok "证书已申请"
        fi
        # certbot 的 systemd timer 负责续期。确认它开着 —— 证书静默过期是这条
        # 路径最常见的故障。
        if systemctl list-timers 2>/dev/null | grep -q certbot; then
            ok "certbot 续期定时器已启用"
        else
            systemctl enable --now certbot.timer 2>/dev/null \
                && ok "已启用 certbot 续期定时器" \
                || warn "未能启用 certbot.timer，证书到期前需手工 certbot renew"
        fi
    fi

    step "写入 nginx 站点配置"
    local site="/etc/nginx/sites-available/tunnel-panel"
    [[ -f "$site" ]] && cp -a "$site" "$site.bak.$(date +%Y%m%d-%H%M%S)"

    cat > "$site" <<EOF
# 由 scripts/setup-proxy.sh 生成于 $(date -u +%Y-%m-%dT%H:%M:%SZ)

# HTTP → HTTPS。保留 .well-known 给 certbot 续期用 —— 直接全量跳转会让
# HTTP-01 验证失败。
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;

    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }
    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name $DOMAIN;

    ssl_certificate     $cert_path;
    ssl_certificate_key $key_path;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    # connect-src 必须含 wss:，否则遥测 WebSocket 会被 CSP 拦掉。
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' wss: ws:; font-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'" always;
    server_tokens off;

    # 面板会上传/下载 agent 二进制（十几 MB）。默认 1m 会把下载截断。
    client_max_body_size 64m;

    gzip on;
    gzip_types application/json application/javascript text/css text/plain;

    location / {
        proxy_pass http://127.0.0.1:$CONTROL_PORT;
        proxy_http_version 1.1;

        # 遥测 WebSocket 必需的两行。少了它们面板上的实时数据不会更新，
        # 而且不会有任何报错 —— 只是永远停在初始值。
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";

        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$remote_addr;
        proxy_set_header X-Forwarded-Proto \$scheme;

        # 长连接：实时流默认 60s 会被断开。
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
        # 不缓冲：遥测是流式的，缓冲会让数据延迟到达。
        proxy_buffering off;
    }
}
EOF

    ln -sfn "$site" /etc/nginx/sites-enabled/tunnel-panel
    # 默认站点会抢占 80 的 default_server，导致跳转行为不可预期。
    if [[ -e /etc/nginx/sites-enabled/default ]]; then
        rm -f /etc/nginx/sites-enabled/default
        info "已移除 nginx 默认站点"
    fi

    nginx -t >/dev/null 2>&1 || { nginx -t; die "nginx 配置校验失败"; }
    ok "配置已写入并校验通过"

    systemctl enable --now nginx
    systemctl reload nginx
    ok "nginx 已重载"
}

case "$SERVER" in
    caddy) setup_caddy ;;
    nginx) setup_nginx ;;
esac

# ---------------------------------------------------------------------------
# 更新控制面配置
# ---------------------------------------------------------------------------
step "更新控制面配置"

if [[ ! -f "$CONTROL_CONF" ]]; then
    warn "找不到 $CONTROL_CONF，跳过。请手工确认以下两项："
    warn "  public_url = \"https://$DOMAIN\"   （一键对接命令里嵌入的地址）"
    warn "  listen 绑在回环即可，外部访问走反代"
else
    cp -a "$CONTROL_CONF" "$CONTROL_CONF.bak.$(date +%Y%m%d-%H%M%S)"

    # public_url 决定面板生成的一键对接命令里写哪个地址。不改它的话，agent 会被
    # 告知去连一个内部地址。
    if grep -q "^public_url" "$CONTROL_CONF"; then
        sed -i "s|^public_url = .*|public_url = \"https://$DOMAIN\"|" "$CONTROL_CONF"
    else
        # 顶层字段必须插在第一个 [表] 之前，否则会归到那个表里且不报错。
        sed -i "0,/^\[/s|^\[|public_url = \"https://$DOMAIN\"\n\n[|" "$CONTROL_CONF"
    fi
    ok "public_url 已设为 https://$DOMAIN"

    # 反代与控制面同机时对端是回环，默认就被信任，不需要 trusted_proxies。
    # 这里只在确实需要时提示，不擅自加网段 —— 白名单写宽了等于让同网段任意机器
    # 都能伪造来源 IP 绕过登录限流。
    info "反代与控制面同机，X-Forwarded-For 默认已被采信（对端是回环）"

    systemctl restart tunnel-control 2>/dev/null \
        && ok "控制面已重启以应用新配置" \
        || warn "控制面重启失败，请手工执行 systemctl restart tunnel-control"
fi

# ---------------------------------------------------------------------------
# 验证
# ---------------------------------------------------------------------------
step "验证"

sleep 2
if [[ "$SELF_SIGNED" == "yes" ]]; then
    probe=(curl -fsS -k --max-time 10)
else
    probe=(curl -fsS --max-time 10)
fi

if "${probe[@]}" "https://$DOMAIN/health" >/dev/null 2>&1; then
    ok "https://$DOMAIN/health 可访问"
else
    warn "健康检查未通过。可能是证书还在申请中（首次需要几十秒），稍等后重试："
    warn "  curl -v https://$DOMAIN/health"
    if [[ "$SERVER" == "caddy" ]]; then
        warn "看日志：journalctl -u caddy -n 50"
    else
        warn "看日志：journalctl -u nginx -n 50; tail -50 /var/log/nginx/error.log"
    fi
fi

printf '\n%s================ 反代配置完成 ================%s\n' "$C_BOLD" "$C_RESET"
cat <<EOF

面板地址  ${C_BOLD}https://$DOMAIN${C_RESET}

$(if [[ "$SELF_SIGNED" == "yes" ]]; then
    echo "  用的是自签证书，浏览器会提示不安全 —— 加密是真的，只是没有公认 CA 背书。"
    echo "  内网使用可以接受；对公网提供服务请换成正式证书。"
else
    echo "  证书已就绪。$(if [[ "$SERVER" == "caddy" ]]; then echo "Caddy 会自动续期。"; else echo "certbot 的定时器负责续期。"; fi)"
fi)

${C_BOLD}如果 80/443 访问不通${C_RESET}
  本脚本不改防火墙。请自行确认已放通：
    ufw allow 80,443/tcp          （Debian/Ubuntu 的 ufw）
    firewall-cmd --add-service={http,https} --permanent   （firewalld）
  云服务器还需在控制台的安全组里放通这两个端口。

${C_BOLD}常用命令${C_RESET}
  systemctl status $SERVER
  journalctl -u $SERVER -f
  systemctl reload $SERVER

EOF
