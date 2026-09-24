#!/usr/bin/env bash
#
# 本地开发辅助脚本。不涉及安装，不需要 root。
#
#   ./scripts/dev.sh test        跑全部测试
#   ./scripts/dev.sh e2e         只跑端到端集成测试（真实 TLS + 真实 socket）
#   ./scripts/dev.sh check       编译检查 + clippy + 格式检查
#   ./scripts/dev.sh web         启动前端开发服务器（代理到 127.0.0.1:8080）
#   ./scripts/dev.sh control     以本地配置启动控制面
#   ./scripts/dev.sh clean       清理构建产物与本地运行数据

set -euo pipefail

readonly REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly DEV_DIR="$REPO_ROOT/.dev"

if [[ -t 1 ]]; then
    C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_RED=$'\033[31m'
else
    C_RESET=""; C_BOLD=""; C_RED=""
fi
step() { printf '\n%s==> %s%s\n' "$C_BOLD" "$*" "$C_RESET"; }
die()  { printf '%s[ 失败 ]%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; exit 1; }

cd "$REPO_ROOT"

# 某些环境把 CC 指向未安装的 clang，会让 ring 的构建脚本失败。
# ring 通过 cc crate 自行探测编译器，清掉这两个变量即可。
unset CC CXX 2>/dev/null || true

cmd_test() {
    step "全 workspace 测试"
    cargo test --workspace
}

cmd_e2e() {
    step "端到端集成测试"
    # 单独跑：这些用例会生成临时 PKI 并绑定真实端口，耗时约 15 秒。
    cargo test -p tunnel-core --test end_to_end -- --nocapture
}

cmd_check() {
    step "编译检查"
    cargo check --workspace --all-targets

    step "clippy"
    if cargo clippy --version >/dev/null 2>&1; then
        cargo clippy --workspace --all-targets -- -D warnings
    else
        echo "未安装 clippy，跳过（rustup component add clippy）"
    fi

    step "格式检查"
    if cargo fmt --version >/dev/null 2>&1; then
        cargo fmt --all -- --check
    else
        echo "未安装 rustfmt，跳过（rustup component add rustfmt）"
    fi

    step "前端类型检查"
    if [[ -d web/node_modules ]]; then
        ( cd web && npm run typecheck )
    else
        echo "web/node_modules 不存在，先执行：cd web && npm install"
    fi
}

cmd_web() {
    step "启动前端开发服务器"
    [[ -d web/node_modules ]] || ( cd web && npm install )
    echo "API 请求会代理到 http://127.0.0.1:8080，请确保控制面已在运行"
    ( cd web && npm run dev )
}

cmd_control() {
    step "启动本地控制面"
    mkdir -p "$DEV_DIR"
    local conf="$DEV_DIR/control.toml"

    if [[ ! -f "$conf" ]]; then
        # 开发配置：数据库落在 .dev/ 下，production=false 放宽密钥要求。
        cat >"$conf" <<EOF
listen = "127.0.0.1:8080"
database_path = "$DEV_DIR/control.db"
production = false

[auth]
jwt_secret = "$(openssl rand -base64 48 | tr -d '\n')"
token_ttl = "12h"
bootstrap_username = "admin"

tunnel_psk = "$(openssl rand -base64 48 | tr -d '\n')"

[log]
level = "debug"
format = "text"
EOF
        echo "已生成开发配置 $conf"
    fi

    cargo run --bin tunnel-control -- --config "$conf" migrate
    echo "首次启动会在下方打印初始管理员密码"
    cargo run --bin tunnel-control -- --config "$conf"
}

cmd_clean() {
    step "清理"
    cargo clean
    rm -rf web/dist web/node_modules "$DEV_DIR" certs
    echo "已清理 target / web 产物 / .dev / certs"
}

case "${1:-}" in
    test)    cmd_test ;;
    e2e)     cmd_e2e ;;
    check)   cmd_check ;;
    web)     cmd_web ;;
    control) cmd_control ;;
    clean)   cmd_clean ;;
    *)
        cat <<'EOF'
用法: ./scripts/dev.sh <子命令>

  test      全 workspace 测试
  e2e       端到端集成测试（真实 TLS + 真实 socket）
  check     cargo check + clippy + fmt + 前端类型检查
  web       启动前端开发服务器
  control   以本地开发配置启动控制面
  clean     清理构建产物与本地数据
EOF
        [[ -z "${1:-}" ]] || die "未知子命令：$1"
        ;;
esac
