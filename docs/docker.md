# Docker 部署

## 一条命令（全新机器）

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/boka233/abc/main/scripts/quick-install.sh)
```

`quick-install.sh` 是引导脚本,只做三件事:检查环境(系统、架构、内存、磁盘)、克隆
仓库到 `/opt/tunnel`、然后 `exec` 到 `scripts/docker-deploy.sh`。

## 不在服务器上编译

部署默认**拉取预编译产物**,不在目标机器上编译:

| 东西 | 来源 | 耗时 |
|---|---|---|
| 控制面镜像 | `ghcr.io/<你的仓库>-control:<版本>` | 几十秒 |
| agent 二进制 | GitHub Release 的 `tunnel-agent-<arch>` | 几秒 |

在服务器上编译要十几分钟、吃 2 GB 内存、小内存机器还可能被 OOM 干掉 —— 而每台机器
编出来的东西完全一样。CI 编一次就够。

**前提是你先发过一个版本:**

```bash
git tag v0.1.0 && git push --tags
```

这会触发两个 workflow:`release.yml` 产出发布包与裸二进制,`docker.yml` 构建
amd64/arm64 镜像推到 GHCR。

### 拉不到时会回落本地构建,并打印原因

回落是显式的,不会静默让你等十几分钟。常见原因:

1. **还没发布过这个版本** —— 打个 tag 就好
2. **GHCR 包是 private** —— 即使仓库是 public,GHCR 的包默认仍是 private。首次推送
   后要到 GitHub 的 Packages 设置里改成 Public,否则匿名拉取会 401
3. **网络不通 ghcr.io**

想强制本地构建(改了代码要验证)或指定镜像:

```bash
./scripts/docker-deploy.sh --build                    # 强制本地构建
./scripts/docker-deploy.sh --image ghcr.io/xx/yy:0.1.0  # 用指定镜像
```

### 镜像 tag 与代码版本必须对应

脚本读 `Cargo.toml` 的 version 去拉对应 tag 的镜像,**不追 `latest`**。追 latest 会
导致「同一条命令在不同时间部署出不同东西」,那类问题极难排查。

`docker.yml` 里有一步会核对 git tag 与 `Cargo.toml` 的版本是否一致,不一致直接让
CI 失败 —— 否则镜像会推成 `:0.2.0` 而脚本去找 `:0.1.0`,拉不到后静默回落编译。

部署逻辑刻意**不写在引导脚本里**。那个脚本会被 curl 到陌生机器上执行,应当短到能
读完;真正的逻辑放在仓库里,可以被审阅、被 git 追溯,而不是一段一次性的管道输入。

几个可用的环境变量:

```bash
TUNNEL_REPO_URL=https://github.com/你的账号/你的仓库.git \
TUNNEL_INSTALL_DIR=/srv/tunnel \
bash <(curl -fsSL .../quick-install.sh)
```

升级:`bash <(curl -fsSL .../quick-install.sh) --update`,会拉最新代码并重建镜像。
已有配置与密钥不会被覆盖。

## 一条命令（已有代码）

```bash
sudo ./scripts/docker-deploy.sh -d panel.example.com -e you@example.com
```

这会：准备并保留隧道 CA → 构建镜像 → 生成配置与随机密钥 → 启动控制面与反代 → 申请 HTTPS 证书 →
放好 agent 二进制 → 打印首次登录密码。隧道 CA 位于 `./certs/`，请连同控制面数据一起备份；`ca.key` 只供控制面签发新出口证书。

没有域名时：

```bash
sudo ./scripts/docker-deploy.sh --local     # 只监听 127.0.0.1:8080，不申请证书
```

## 前端不需要单独部署

面板是构建后的静态文件，由 `tunnel-control` 自己托管（`web_root` 指向构建产物）。
镜像的 web 构建阶段会产出 `web/dist` 并拷进运行阶段，所以没有独立的前端容器、也不需
要单独的 nginx 来发静态文件。

浏览器访问的路径是：

```
浏览器 → Caddy(443, 自动 HTTPS) → tunnel-control(8080) → 面板静态文件 + API + WebSocket
```

## 为什么 agent 不在容器里

agent 要绑定出站源地址、监听任意端口、读宿主机的网卡列表。容器化需要
`--network host` 加一批 capability，此时容器已经没有隔离价值，只剩下"多一层
不透明"。所以 agent 用 systemd 装在宿主机上 —— 面板上的一键对接命令做的就是这件事。

镜像里也只有 `tunnel-control`，没有 `tunnel-agent`。

## 组件

| 容器 | 镜像 | 作用 |
|---|---|---|
| `tunnel-control` | 本地构建 | 控制面 + 面板 + API |
| `tunnel-proxy` | `caddy:2-alpine` | 反代、自动 HTTPS、HTTP/3 |

数据卷：

| 卷 | 内容 | 丢失后果 |
|---|---|---|
| `control-data` | SQLite 数据库、agent 二进制 | 线路、设备组、审计日志全部丢失 |
| 宿主机 `./certs` | 隧道 CA 证书和签发私钥 | 无法再为新出口签发证书 |
| `caddy-data` | 证书与 ACME 账号 | 重新申请证书，容易撞速率限制 |
| `caddy-config` | Caddy 自动生成的配置 | 可重建，影响不大 |

## 一个容易踩的坑：X-Forwarded-For

控制面默认**只在对端是回环地址时**才采信 `X-Forwarded-For`。这覆盖了"nginx 与控制面
同机"的常见形态，同时不给远程客户端伪造来源地址的机会。

但 Docker 里反代与控制面在两个容器,对端是容器网段（`172.20.x.x`）而不是回环。如果不
声明该网段可信,每个请求的来源都会被算成反代容器的地址 —— 按 IP 的登录限流就退化成了
全局限流：**一个人连续输错密码会把所有人一起锁在门外**。

所以 compose 里做了两件事：

1. 把网络网段**固定**为 `172.20.0.0/16`（不用默认网段，那个在重建网络时可能变）
2. 给控制面设 `TUNNEL_CONTROL_TRUSTED_PROXIES=172.20.0.0/16`

改网段时这两处必须一起改，否则限流会静默退化。核对方法：

```bash
grep -E "subnet:|TRUSTED_PROXIES" docker-compose.yml
```

不默认信任 `172.16.0.0/12` 这类整个私网段，是因为在"控制面直接暴露在内网"的部署里
那等于让同网段的任何机器都能伪造来源 IP。

## 手工操作

```bash
# 校验 compose 配置（本机没 docker 时无法做，需在目标机器上执行）
docker compose config

# 启停
docker compose up -d
docker compose down                 # 保留数据
docker compose down -v              # 删除数据卷，不可恢复

# 日志
docker compose logs -f control
docker compose logs -f proxy        # 证书申请失败时看这个

# 改了代码后重建
./scripts/docker-deploy.sh --rebuild
```

## 支持另一个架构的 agent

一键对接会按目标机器的架构去下载 `tunnel-agent-x86_64` 或 `tunnel-agent-aarch64`。
部署脚本只放了控制面所在机器的那个架构。要支持另一种：

```bash
# 从对应架构的发布包里取出二进制
docker cp tunnel-agent-aarch64 \
  tunnel-control:/var/lib/tunnel-control/agent-bin/tunnel-agent-aarch64
```

不需要重启 —— 文件是每次请求时读的。

## 备份与恢复

备份与恢复都在控制面**停止**时进行，并且把整个数据目录当作一个整体拷贝：

```bash
cd /opt/tunnel

# 备份
docker compose stop control
docker cp tunnel-control:/var/lib/tunnel-control/. ./backup-$(date +%F)/
docker compose start control

# 恢复（以 2026-01-01 的备份为例）
docker compose stop control
docker cp ./backup-2026-01-01/. tunnel-control:/var/lib/tunnel-control/
docker compose run --rm --no-deps --user 0 --entrypoint chown control \
  -R tunnel:tunnel /var/lib/tunnel-control
docker compose start control
```

几条容易踩的坑，也是上面这样写的原因：

- **不能用 `sqlite3 .backup`**：运行镜像里没有装 `sqlite3`，那条命令会直接报
  `executable file not found`，什么都没备份。
- **必须先停控制面**：数据库开着 WAL，运行中直接拷贝，拿到的 `control.db` 与
  `control.db-wal` 可能不是同一时刻的状态。停下来之后，整个目录就是一致的。
- **`control.db` 与 `-wal`、`-shm` 要一起拷**：只把 `control.db` 拷回去、留着容器里
  旧的 `-wal`，SQLite 下次打开时会把旧日志套到新数据库上，可能把库弄坏。拷整个
  目录就不会有这个问题。
- **拷回去后要修正属主**：`docker cp` 写进容器的文件属于 root，而控制面以
  `tunnel` 用户运行，不修正就无法写数据库，启动会失败。控制面停着时没法
  `docker exec`，所以用 `docker compose run --rm` 临时起一个容器来 `chown`。

配置文件 `configs/control.docker.toml` **也要一起备份** —— 里面有 `jwt_secret` 与
`tunnel_psk`。丢了它们：所有会话失效（可接受，重新登录即可），所有 agent 握手失败
（要逐台重新对接）。

## 升级

```bash
git pull
./scripts/docker-deploy.sh --rebuild
```

数据库迁移在控制面启动时自动执行。升级前先备份 —— 迁移是单向的，回滚需要恢复备份，
详见 `docs/release.md`。

重跑部署脚本**不会**重写已有密钥。这是刻意的：重写会让所有会话失效、所有 agent 握手
失败，而这恰恰是"重跑一次安装脚本"最容易引入的故障。

## 不用 Docker 的反代配置

已经用 systemd 装好控制面，只想配反代：

```bash
sudo ./scripts/setup-proxy.sh -d panel.example.com -e you@example.com
sudo ./scripts/setup-proxy.sh -d panel.example.com --server nginx    # 用 nginx
sudo ./scripts/setup-proxy.sh -d panel.example.com --self-signed     # 内网自签
```

默认用 Caddy，因为它自动续期。选 nginx 会装 certbot 并依赖它的 systemd timer 续期 ——
那条路径最常见的故障是钩子没触发导致证书静默过期。

两种反代的配置里都有两处不能少：

* **WebSocket 转发**（nginx 要手工设 `Upgrade`/`Connection`，Caddy 默认就转发）。
  缺了它面板上的实时数据永远停在初始值，而且不报任何错。
* **`connect-src` 含 `wss:` 的 CSP**。写漏了同样会让遥测连不上，浏览器控制台才有线索。

## 防火墙

两个脚本都不改防火墙 —— 改错规则可能把你自己锁在 SSH 外面。需要自行放通 80 与 443：

```bash
ufw allow 80,443/tcp
# 或
firewall-cmd --add-service={http,https} --permanent && firewall-cmd --reload
```

云服务器还要在控制台的安全组里放通。ACME 的 HTTP-01 验证走 80，只开 443 会导致证书
申请失败。
