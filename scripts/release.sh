#!/usr/bin/env bash
#
# 构建发布包。
#
# 用法:
#   ./scripts/release.sh                     # 只构建本机架构
#   ./scripts/release.sh --arch aarch64      # 交叉编译到 aarch64
#   ./scripts/release.sh --arch both         # 两个架构都构建
#   ./scripts/release.sh --skip-tests        # 跳过测试（包内会留下标记）
#
# 产出 dist/tunnel-<版本>-<架构>/ 与同名 .tar.gz。
#
# 为什么必须在 Linux 上跑:
#   服务端只跑 Linux。依赖里的 ring 与 libsqlite3-sys 都含 C 代码，从别的平台交叉
#   编译需要目标平台的 C 工具链 —— 与其在脚本里猜测一堆环境变量，不如直接要求在
#   Linux 上执行（或用 CI，见 .github/workflows/release.yml）。
#
# 几条原则:
#   1. 版本号只有一个来源 —— Cargo.toml 的 workspace.package.version。
#   2. 测试不过不出包。一个没跑过测试的包流到生产比没有包更糟。
#   3. 产出的包自带校验和，且 agent 二进制的校验和单独列出，供控制面的下载接口回报。
#   4. 缺工具链就明确报错说要装什么，绝不产出一个不完整的包。

set -euo pipefail

readonly REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly DIST_DIR="$REPO_ROOT/dist"

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
用法: ./scripts/release.sh [选项]

选项:
  --arch <x86_64|aarch64|both>  目标架构，默认为本机架构
  --skip-tests                  跳过 cargo test（包内会留下 UNTESTED 标记）
  --skip-web                    不构建前端（产出的包只能 API-only 运行）
  --help                        显示本帮助

需要: cargo、npm；交叉编译 aarch64 还需要 cross 或 aarch64-linux-gnu-gcc。
EOF
}

# ---------------------------------------------------------------------------
# 参数
# ---------------------------------------------------------------------------
ARCH_ARG=""
SKIP_TESTS="no"
SKIP_WEB="no"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --arch) ARCH_ARG="${2:-}"; shift 2 ;;
        --skip-tests) SKIP_TESTS="yes"; shift ;;
        --skip-web) SKIP_WEB="yes"; shift ;;
        --help|-h) usage; exit 0 ;;
        *) usage; die "未知参数：$1" ;;
    esac
done

[[ "$(uname -s)" == "Linux" ]] \
    || die "发布包必须在 Linux 上构建（服务端只跑 Linux，且依赖 ring/libsqlite3-sys 含 C 代码）。

可以让 CI 代替：
  git tag v<版本> && git push --tags
详见 docs/release.md。"

command -v cargo >/dev/null 2>&1 || die "未找到 cargo，请安装 Rust 1.80+：https://rustup.rs"

# 本机架构 → rust target 三元组。
HOST_ARCH="$(uname -m)"
case "$HOST_ARCH" in
    x86_64|amd64) HOST_ARCH="x86_64" ;;
    aarch64|arm64) HOST_ARCH="aarch64" ;;
    *) die "不支持的本机架构 $HOST_ARCH" ;;
esac

case "${ARCH_ARG:-$HOST_ARCH}" in
    x86_64)  TARGET_ARCHES=("x86_64") ;;
    aarch64) TARGET_ARCHES=("aarch64") ;;
    both)    TARGET_ARCHES=("x86_64" "aarch64") ;;
    *) die "--arch 只接受 x86_64 / aarch64 / both" ;;
esac

triple_for() {
    case "$1" in
        x86_64)  echo "x86_64-unknown-linux-gnu" ;;
        aarch64) echo "aarch64-unknown-linux-gnu" ;;
    esac
}

# ---------------------------------------------------------------------------
# 版本号
# ---------------------------------------------------------------------------
# 只从 workspace.package.version 取。写死在第二处迟早会和这里不一致，而版本号不一致
# 的发布包是最难排查的一类问题 —— 文件名说是新版，二进制 --version 说是旧版。
VERSION="$(awk -F'"' '
    /^\[workspace\.package\]/ { in_section = 1; next }
    /^\[/ { in_section = 0 }
    in_section && /^version[[:space:]]*=/ { print $2; exit }
' "$REPO_ROOT/Cargo.toml")"

[[ -n "$VERSION" ]] || die "无法从 Cargo.toml 读出版本号"
info "版本 $VERSION"

GIT_SHA="$(cd "$REPO_ROOT" && git rev-parse --short HEAD 2>/dev/null || echo unknown)"
BUILT_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
info "提交 $GIT_SHA"

# 有未提交改动时提醒。不阻止 —— 本地试打包是正常需求 —— 但要写进包里的
# BUILD-INFO，否则将来无法确定这个包到底对应哪份代码。
DIRTY="no"
if ! (cd "$REPO_ROOT" && git diff --quiet HEAD 2>/dev/null); then
    DIRTY="yes"
    warn "工作区有未提交的改动，包内 BUILD-INFO 会标记为 dirty"
fi

# ---------------------------------------------------------------------------
# 测试
# ---------------------------------------------------------------------------
if [[ "$SKIP_TESTS" == "no" ]]; then
    step "运行测试"
    # 不加 --lib：那样会跳过没有 lib.rs 的 crate（tunnel-agent）以及所有集成测试，
    # 而恰恰是那些地方最容易积压长期没编译过的代码。
    ( cd "$REPO_ROOT" && cargo test --workspace ) \
        || die "测试未通过，不产出发布包。确实要跳过请加 --skip-tests"
    ok "测试通过"
else
    warn "已跳过测试 —— 包内会写入 UNTESTED 标记"
fi

# ---------------------------------------------------------------------------
# 前端
# ---------------------------------------------------------------------------
if [[ "$SKIP_WEB" == "no" ]]; then
    step "构建 Web 面板"
    command -v npm >/dev/null 2>&1 \
        || die "未找到 npm，请安装 Node.js 20+，或用 --skip-web 跳过"
    ( cd "$REPO_ROOT/web" && npm ci --no-audit --no-fund && npm run build ) \
        || die "前端构建失败"
    ok "前端构建完成"
fi

# ---------------------------------------------------------------------------
# 逐架构构建
# ---------------------------------------------------------------------------
build_for_arch() {
    local arch="$1"
    local triple; triple="$(triple_for "$arch")"

    step "构建 $arch（$triple）"

    local cargo_cmd=(cargo build --release --target "$triple")

    if [[ "$arch" != "$HOST_ARCH" ]]; then
        # 交叉编译：ring 与 libsqlite3-sys 需要目标平台的 C 编译器。优先用 cross
        # （容器里自带工具链），否则要求系统装了对应的 gcc。
        if command -v cross >/dev/null 2>&1; then
            info "使用 cross 交叉编译"
            cargo_cmd=(cross build --release --target "$triple")
        elif command -v "${arch}-linux-gnu-gcc" >/dev/null 2>&1; then
            info "使用系统交叉工具链 ${arch}-linux-gnu-gcc"
            # cargo 与 cc crate 各读一套环境变量，两边都要给。
            local upper; upper="$(echo "$triple" | tr 'a-z-' 'A-Z_')"
            export "CARGO_TARGET_${upper}_LINKER=${arch}-linux-gnu-gcc"
            export "CC_${triple//-/_}=${arch}-linux-gnu-gcc"
            export "AR_${triple//-/_}=${arch}-linux-gnu-ar"
        else
            die "交叉编译到 $arch 需要以下任一工具，请先安装：
  cross                     cargo install cross   （推荐，需要 docker/podman）
  ${arch}-linux-gnu-gcc     apt install gcc-${arch}-linux-gnu libc6-dev-${arch/x86_64/amd64}-cross

也可以在一台 $arch 的 Linux 机器上直接执行本脚本。"
        fi
        rustup target add "$triple" >/dev/null 2>&1 || true
    fi

    ( cd "$REPO_ROOT" && "${cargo_cmd[@]}" ) || die "$arch 构建失败"

    local bin_dir="$REPO_ROOT/target/$triple/release"
    for bin in tunnel-control tunnel-agent; do
        [[ -x "$bin_dir/$bin" ]] || die "构建完成但找不到 $bin_dir/$bin"
    done
    ok "$arch 二进制就绪"

    # --- 组装目录 ---
    local name="tunnel-$VERSION-$arch"
    local out="$DIST_DIR/$name"
    rm -rf "$out"
    mkdir -p "$out/scripts" "$out/configs" "$out/systemd" "$out/docs"

    install -m 755 "$bin_dir/tunnel-control" "$out/"
    install -m 755 "$bin_dir/tunnel-agent" "$out/"
    # agent 二进制另存一份带架构后缀的：控制面的下载接口按这个名字查找，
    # 发布包里的 install.sh 会把它放进 agent_binary_dir。
    install -m 755 "$bin_dir/tunnel-agent" "$out/tunnel-agent-$arch"

    install -m 644 "$REPO_ROOT/configs/"*.toml "$out/configs/"
    install -m 644 "$REPO_ROOT/systemd/"*.service "$out/systemd/"
    install -m 755 "$REPO_ROOT/scripts/install.sh" "$out/scripts/"
    install -m 755 "$REPO_ROOT/scripts/uninstall.sh" "$out/scripts/"
    install -m 755 "$REPO_ROOT/scripts/agent-install.sh" "$out/scripts/"
    install -m 755 "$REPO_ROOT/scripts/gen-certs.sh" "$out/scripts/"
    install -m 755 "$REPO_ROOT/scripts/offline-install.sh" "$out/install.sh"
    install -m 644 "$REPO_ROOT/docs/"*.md "$out/docs/"
    install -m 644 "$REPO_ROOT/README.md" "$out/"

    # 数据库迁移已经编进二进制（sqlx::migrate! 是编译期宏），不需要单独放。
    # 放了反而会让人以为要手工执行。

    if [[ "$SKIP_WEB" == "no" ]]; then
        cp -r "$REPO_ROOT/web/dist" "$out/web"
    fi

    # --- 构建信息 ---
    {
        echo "version=$VERSION"
        echo "arch=$arch"
        echo "target=$triple"
        echo "git_sha=$GIT_SHA"
        echo "git_dirty=$DIRTY"
        echo "built_at=$BUILT_AT"
        echo "tested=$([[ "$SKIP_TESTS" == "no" ]] && echo yes || echo NO-UNTESTED)"
        echo "web_included=$([[ "$SKIP_WEB" == "no" ]] && echo yes || echo no)"
    } > "$out/BUILD-INFO"

    if [[ "$SKIP_TESTS" == "yes" ]]; then
        # 显眼的文件名：解包的人不一定会去看 BUILD-INFO。
        echo "本包构建时跳过了测试（--skip-tests），请勿用于生产。" > "$out/UNTESTED"
    fi

    # --- 校验和 ---
    ( cd "$out" && find . -type f ! -name SHA256SUMS -print0 \
        | sort -z | xargs -0 sha256sum > SHA256SUMS )
    # agent 二进制的校验和单独列出：控制面下载接口会回报它，一键脚本据此比对。
    ( cd "$out" && sha256sum "tunnel-agent-$arch" | awk '{print $1}' > "tunnel-agent-$arch.sha256" )
    ok "已生成校验和"

    # --- 打包 ---
    ( cd "$DIST_DIR" && tar czf "$name.tar.gz" "$name" )
    ok "产出 dist/$name.tar.gz（$(du -h "$DIST_DIR/$name.tar.gz" | awk '{print $1}')）"

    # --- 裸二进制，直接放在 dist/ 顶层 ---
    #
    # 为什么除了 tar 包还要单独放：一键部署脚本只需要 agent 一个文件（十几 MB），
    # 让它下载整个包再解开是浪费；而控制面所在机器也可能只想换一个二进制而不动
    # 配置。Release 页面直接挂这些文件，curl 一条就能取。
    #
    # sha256 各自成文件而不只依赖包内的 SHA256SUMS：脚本取单个文件时没有包上下文，
    # 需要一个能独立 curl 到的校验值。下载的是要以 root 运行的可执行文件，
    # 不校验等于接受链路上任何一跳的替换。
    for bin in tunnel-control tunnel-agent; do
        install -m 755 "$bin_dir/$bin" "$DIST_DIR/$bin-$arch"
        ( cd "$DIST_DIR" && sha256sum "$bin-$arch" | awk '{print $1}' > "$bin-$arch.sha256" )
    done
    ok "产出裸二进制 tunnel-control-$arch / tunnel-agent-$arch（含 .sha256）"
}

mkdir -p "$DIST_DIR"
for arch in "${TARGET_ARCHES[@]}"; do
    build_for_arch "$arch"
done

# ---------------------------------------------------------------------------
# 收尾
# ---------------------------------------------------------------------------
printf '\n%s================ 发布包已就绪 ================%s\n' "$C_BOLD" "$C_RESET"
printf '\n版本 %s（%s）\n\n' "$VERSION" "$GIT_SHA"
for arch in "${TARGET_ARCHES[@]}"; do
    printf '  dist/tunnel-%s-%s.tar.gz\n' "$VERSION" "$arch"
    printf '  dist/tunnel-control-%s（+ .sha256）\n' "$arch"
    printf '  dist/tunnel-agent-%s（+ .sha256）\n' "$arch"
done

cat <<EOF

${C_BOLD}在目标机器上安装${C_RESET}

  tar xzf tunnel-$VERSION-<架构>.tar.gz
  cd tunnel-$VERSION-<架构>
  sudo ./install.sh control        # 控制面 + 面板
  sudo ./install.sh agent          # 仅数据面

  安装控制面时会把 tunnel-agent-<架构> 放进 agent_binary_dir，
  之后面板上的一键对接命令即可直接用。

${C_BOLD}校验${C_RESET}
  cd tunnel-$VERSION-<架构> && sha256sum -c SHA256SUMS

EOF

if [[ "$SKIP_TESTS" == "yes" ]]; then
    warn "提醒：本次构建跳过了测试，包内有 UNTESTED 标记"
fi
