#!/usr/bin/env bash
#
# 生成隧道所需的私有 CA 与证书。
#
# 为什么用私有 CA 而不是公共 CA：配置里设置 ca_path 后，系统信任库会被
# 忽略。这正是想要的效果 —— 否则任何一家公共 CA 签发的证书都能冒充你的
# exit 节点。
#
# 用法:
#   ./scripts/gen-certs.sh ca                        # 创建 CA（只做一次）
#   ./scripts/gen-certs.sh server exit.internal      # exit 节点证书
#   ./scripts/gen-certs.sh client entry.internal     # entry 客户端证书（mTLS 用）
#
# 输出目录默认 ./certs，可用 OUT_DIR 覆盖。

set -euo pipefail

OUT_DIR="${OUT_DIR:-./certs}"
CA_DAYS="${CA_DAYS:-3650}"
# 825 天是浏览器/多数 TLS 栈接受的证书有效期上限。
LEAF_DAYS="${LEAF_DAYS:-825}"
KEY_BITS="${KEY_BITS:-2048}"

if [[ -t 1 ]]; then
    C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'
    C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'
else
    C_RESET=""; C_BOLD=""; C_RED=""; C_GREEN=""; C_YELLOW=""
fi
ok()   { printf '%s[ 完成 ]%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
warn() { printf '%s[ 注意 ]%s %s\n' "$C_YELLOW" "$C_RESET" "$*"; }
die()  { printf '%s[ 失败 ]%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; exit 1; }

usage() {
    cat <<'EOF'
用法: ./scripts/gen-certs.sh <子命令> [参数]

子命令:
  ca                      创建私有 CA（ca.pem / ca.key），只需执行一次
  server <名称> [SAN...]  签发服务端证书，用于 exit 节点
  client <名称>           签发客户端证书，用于启用 mTLS 时的 entry 节点

环境变量:
  OUT_DIR     输出目录，默认 ./certs
  LEAF_DAYS   叶证书有效期，默认 825
  KEY_BITS    RSA 位数，默认 2048

示例:
  ./scripts/gen-certs.sh ca
  ./scripts/gen-certs.sh server exit.internal 10.20.0.2 203.0.113.9
  ./scripts/gen-certs.sh client entry.internal

重要: server 证书的名称必须与面板里 endpoint 的 tls_server_name 一致。
endpoint 地址通常是裸 IP，而证书带的是主机名，所以那个字段是必填的。
把 IP 一并写进 SAN 也可以，这样直接用 IP 做 tls_server_name 就能通过校验。
EOF
}

require_openssl() {
    command -v openssl >/dev/null 2>&1 || die "未找到 openssl"
}

ensure_out_dir() {
    mkdir -p "$OUT_DIR"
    # CA 私钥在这里，目录本身就不该对外可读。
    chmod 700 "$OUT_DIR"
}

# 写一个临时 openssl 配置。
#
# 刻意不用 `-subj "/CN=..."`：MSYS2/Git Bash 会把以 / 开头的参数当成路径做
# 转换，`/CN=x` 变成 `C:/Program Files/Git/CN=x`，报错信息还很难和原因对上。
# 配置文件里写 DN 到处都能用，而且把 SAN、EKU 等约束集中在一处更清楚。
write_openssl_conf() {
    local path="$1" cn="$2" san="${3:-}" eku="${4:-}"

    cat >"$path" <<EOF
[req]
distinguished_name = dn
prompt = no

[dn]
CN = $cn
EOF

    if [[ -n "$eku" ]]; then
        cat >>"$path" <<EOF

[ext]
subjectAltName = $san
extendedKeyUsage = $eku
basicConstraints = CA:FALSE
keyUsage = digitalSignature,keyEncipherment
EOF
    else
        cat >>"$path" <<EOF

[ext]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
EOF
    fi
}

make_ca() {
    ensure_out_dir
    local key="$OUT_DIR/ca.key" crt="$OUT_DIR/ca.pem"

    # 覆盖 CA 会让所有已签发的证书立刻失效，必须显式确认。
    if [[ -f "$key" || -f "$crt" ]]; then
        warn "$OUT_DIR 中已存在 CA。覆盖会使所有已签发证书失效。"
        read -r -p "确认覆盖？输入 yes 继续：" answer
        [[ "$answer" == "yes" ]] || die "已取消"
    fi

    local conf="$OUT_DIR/.ca.cnf"
    write_openssl_conf "$conf" "tunnel-ca"

    openssl genrsa -out "$key" 4096 2>/dev/null
    chmod 600 "$key"
    openssl req -x509 -new -key "$key" -sha256 -days "$CA_DAYS" \
        -out "$crt" -config "$conf" -extensions ext \
        || { rm -f "$conf"; die "CA 证书生成失败"; }
    rm -f "$conf"

    ok "CA 已生成：$crt"
    warn "请离线保管 $key。丢失它意味着无法再签发新节点证书。"
}

# 构造 SAN 字段。IP 和 DNS 前缀不同，必须分别判断，写错会导致
# 校验静默失败（证书看起来有效，但名称不匹配）。
build_san() {
    local entries=()
    for name in "$@"; do
        if [[ "$name" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
            entries+=("IP:$name")
        elif [[ "$name" == *:* ]]; then
            entries+=("IP:$name")   # IPv6
        else
            entries+=("DNS:$name")
        fi
    done
    local IFS=','
    echo "${entries[*]}"
}

issue_leaf() {
    local kind="$1"; shift
    local cn="$1"; shift
    local extra_sans=("$@")

    [[ -n "$cn" ]] || die "必须提供证书名称"
    ensure_out_dir

    local ca_key="$OUT_DIR/ca.key" ca_crt="$OUT_DIR/ca.pem"
    [[ -f "$ca_key" && -f "$ca_crt" ]] \
        || die "未找到 CA，请先执行：$0 ca"

    local base="$OUT_DIR/$cn"
    local key="$base.key" csr="$base.csr" crt="$base.pem" conf="$base.cnf"

    local eku san
    if [[ "$kind" == "server" ]]; then
        eku="serverAuth"
    else
        eku="clientAuth"
    fi
    san="$(build_san "$cn" "${extra_sans[@]+"${extra_sans[@]}"}")"

    write_openssl_conf "$conf" "$cn" "$san" "$eku"

    openssl genrsa -out "$key" "$KEY_BITS" 2>/dev/null
    chmod 600 "$key"
    openssl req -new -key "$key" -out "$csr" -config "$conf" \
        || { rm -f "$conf" "$csr"; die "CSR 生成失败"; }

    openssl x509 -req -in "$csr" -CA "$ca_crt" -CAkey "$ca_key" -CAcreateserial \
        -out "$crt" -days "$LEAF_DAYS" -sha256 \
        -extfile "$conf" -extensions ext 2>/dev/null \
        || { rm -f "$conf" "$csr"; die "证书签发失败"; }

    rm -f "$csr" "$conf"

    ok "$kind 证书已生成：$crt"
    printf '     SAN: %s\n' "$san"
    printf '     有效期: %s 天\n' "$LEAF_DAYS"

    printf '\n%s部署方式%s\n' "$C_BOLD" "$C_RESET"
    if [[ "$kind" == "server" ]]; then
        cat <<EOF
  复制到 exit 节点的 /etc/tunnel/ 并在 agent 配置中填写：
     cert_path = "/etc/tunnel/$cn.pem"
     key_path  = "/etc/tunnel/$cn.key"
     ca_path   = "/etc/tunnel/ca.pem"

  面板里该 exit 的所有 endpoint 需设置：
     tls_server_name = "$cn"
EOF
    else
        cat <<EOF
  复制到 entry 节点的 /etc/tunnel/ 并在 agent 配置中填写：
     client_cert_path = "/etc/tunnel/$cn.pem"
     client_key_path  = "/etc/tunnel/$cn.key"
     ca_path          = "/etc/tunnel/ca.pem"

  同时在 exit 侧启用 require_client_auth = true 才会真正校验。
EOF
    fi
    echo
}

case "${1:-}" in
    ca)     require_openssl; make_ca ;;
    server) require_openssl; shift; issue_leaf server "$@" ;;
    client) require_openssl; shift; issue_leaf client "$@" ;;
    --help|-h|"") usage ;;
    *) usage; die "未知子命令：$1" ;;
esac
