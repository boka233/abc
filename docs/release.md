# 发布

## 出一个版本

版本号只有一个来源：`Cargo.toml` 里 `[workspace.package]` 的 `version`。二进制的
`--version`、发布包的文件名、包内 `BUILD-INFO` 全都从它派生，不要在别处写死。

```bash
# 1. 改版本号
vim Cargo.toml          # [workspace.package] version = "0.2.0"
cargo check             # 让 Cargo.lock 跟着更新

# 2. 提交并打 tag
git add Cargo.toml Cargo.lock
git commit -m "release: 0.2.0"
git tag v0.2.0
git push && git push --tags
```

推 tag 之后 `.github/workflows/release.yml` 会构建 x86_64 与 aarch64 两个包并创建
GitHub Release。

## 本地出包

需要一台 **Linux** 机器。不是偷懒：服务端只跑 Linux，而依赖里的 `ring` 与
`libsqlite3-sys` 都含 C 代码，从别的平台交叉编译要配目标平台的 C 工具链。与其让脚本
去猜一堆环境变量，不如直接要求在 Linux 上执行。

```bash
./scripts/release.sh                  # 本机架构
./scripts/release.sh --arch aarch64   # 交叉编译，需要 cross 或 aarch64-linux-gnu-gcc
./scripts/release.sh --arch both      # 两个都要
```

产出在 `dist/`：

```
tunnel-0.2.0-x86_64/
  tunnel-control            控制面
  tunnel-agent              数据面
  tunnel-agent-x86_64       同一个文件，带架构后缀，供面板提供下载
  web/                      前端构建产物
  configs/  systemd/  scripts/  docs/
  install.sh                解包后跑这个
  BUILD-INFO                版本、提交、是否跑过测试
  SHA256SUMS
tunnel-0.2.0-x86_64.tar.gz
```

`release.sh` 会先跑 `cargo test --workspace`，**测试不过就不出包**。确实需要跳过时用
`--skip-tests`，此时包内会多一个显眼的 `UNTESTED` 文件，`BUILD-INFO` 里也会记
`tested=NO-UNTESTED`。

数据库迁移不单独打包 —— `sqlx::migrate!` 是编译期宏，SQL 已经编进二进制里了。

## 安装

```bash
tar xzf tunnel-0.2.0-x86_64.tar.gz
cd tunnel-0.2.0-x86_64
sha256sum -c SHA256SUMS          # 先校验，传输截断会产出能解包但二进制损坏的目录

sudo ./install.sh control        # 控制面 + 面板
sudo ./install.sh agent          # 仅数据面
sudo ./install.sh both           # 同机两者，仅测试环境
```

目标机器不需要 Rust 或 Node.js。`install.sh` 会先核对包的架构与本机是否一致 ——
不一致时直接停，因为装上去只会得到一句 `cannot execute binary file`，那个报错离真正
的原因太远。

## 一键对接是怎么工作的

面板上「复制安装命令」得到的是：

```bash
bash <(curl -fsSL http://面板:8080/api/agent/install.sh) -t <令牌> -u http://面板:8080
```

执行顺序：

1. 脚本从 `/api/agent/download/tunnel-agent-<架构>` 下载二进制
2. 校验 sha256（面板在 `X-Binary-Sha256` 响应头里给出）
3. 写 `/etc/tunnel-agent/config.toml`，装 systemd 服务并启动
4. agent 凭组令牌向控制面注册，控制面按 (组, 机器名) 登记并回传 node_id

**第 1 步依赖控制面配置了 `agent_binary_dir`**，默认
`/var/lib/tunnel-control/agent-bin`。发布包的 `install.sh` 装控制面时会自动把
`tunnel-agent-<架构>` 放进去，所以正常流程下不需要手工操作。

要支持另一个架构的机器对接，把那个架构发布包里的 `tunnel-agent-<架构>` 复制进同一个
目录即可：

```bash
# 在控制面机器上
cp tunnel-agent-aarch64 /var/lib/tunnel-control/agent-bin/
chown tunnel:tunnel /var/lib/tunnel-control/agent-bin/tunnel-agent-aarch64
```

不需要重启控制面 —— 文件是每次请求时读的。

### 关于下载接口不需要认证

这个端点可匿名访问，是经过考虑的取舍：

* 下载发生在注册**之前**，那时目标机器上除了命令行里的组令牌之外没有任何凭据。
* 要求认证就得把组令牌放进 URL，那会让它出现在 shell 历史、代理日志和 `ps` 输出里 ——
  比不认证更糟。
* 暴露的内容是一个公开发布的二进制：不含密钥、不含配置、不含部署信息。

架构参数只接受 `x86_64` / `aarch64` 两个字面值，且**从不参与路径拼接**（先解析成枚举，
再由枚举给出常量文件名），所以不存在路径穿越。这一点有测试盯着，包括在目录外真实放一个
文件再尝试各种方式读它。

## 升级

**先控制面，再逐台 agent。** 两侧容忍同一协议大版本内的版本差异；真正不兼容时会在
握手处被明确拒绝，而不是猜着跑。

```bash
# 控制面
systemctl stop tunnel-control
install -m 755 tunnel-control /usr/local/bin/
rm -rf /usr/share/tunnel-control/web && cp -r web /usr/share/tunnel-control/web
systemctl start tunnel-control        # 启动时自动跑数据库迁移

# 把新的 agent 二进制放进下载目录，之后新对接的机器直接拿到新版
install -m 755 -o tunnel -g tunnel \
  tunnel-agent-x86_64 /var/lib/tunnel-control/agent-bin/

# agent，一台一台来
systemctl stop tunnel-agent           # 优雅排空
install -m 755 tunnel-agent /usr/local/bin/
systemctl start tunnel-agent          # 立刻从缓存配置恢复服务
```

agent 不会自动更新自己。让一个正在承载流量的进程替换自己的二进制风险过高，升级时机
应当由管理员决定。

## 回滚

保留上一个版本的包即可回滚：

```bash
systemctl stop tunnel-control
install -m 755 上个版本/tunnel-control /usr/local/bin/
systemctl start tunnel-control
```

**但数据库迁移是单向的。** 新版本跑过的迁移不会被旧二进制撤销，而旧二进制遇到不认识
的表结构可能启动失败。跨迁移回滚之前先恢复数据库备份：

```bash
# 升级前备份
sqlite3 /var/lib/tunnel-control/control.db ".backup '/backup/control-升级前.db'"
```

判断某个版本有没有引入迁移：看 `migrations/` 目录下的文件是否有新增。当前已有
0001-0005。

## 发布前自查

```bash
cargo test --workspace --all-targets   # 不加 --lib，见下
cargo clippy --workspace --all-targets -- -D warnings
cd web && npm run build                # 含 vue-tsc 类型检查
for f in scripts/*.sh; do bash -n "$f"; done
```

`cargo test` **不要加 `--lib`**：那样会跳过没有 `lib.rs` 的 crate（`tunnel-agent` 只有
`main.rs`）以及所有集成测试。开发过程中曾因此让 agent 的测试和 `tests/end_to_end.rs`
长期没被编译，里面积压了本该失败的断言。CI 里用的是 `--all-targets`，原因就是这个。
