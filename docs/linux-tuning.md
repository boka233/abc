# Linux tuning

**Do not apply these wholesale.** Every parameter below states what it does, what
the default costs you, when it actually needs changing, and the risk of changing
it. A node carrying a few hundred connections needs none of this except
`LimitNOFILE`.

Measure first. `ss -s`, `ss -tn state syn-recv | wc -l`, and the agent's own
`open_fds` metric will tell you which limit you are actually hitting.

## File descriptors — the one you will hit first

**What:** each relayed connection costs two descriptors (client socket + target
socket), plus one per tunnel connection in the pool.

**Default cost:** the usual 1024 soft limit caps a node at roughly 500
connections. Past it, `accept()` returns `EMFILE`; the agent logs
"out of file descriptors" and backs off, which appears to users as refused
connections while the process looks healthy.

**When to change:** any node expected to carry more than ~400 concurrent
connections.

```ini
# systemd unit — already set in systemd/tunnel-agent.service
LimitNOFILE=65535
```

```bash
# System-wide ceiling. Only raise this if LimitNOFILE alone is not enough.
# Default on a modern host is usually already in the millions.
sysctl -w fs.file-max=2097152
```

**Risk:** minimal. Descriptors cost a little kernel memory each; 65535 is
negligible on any machine with more than 1 GB.

**Verify:** `cat /proc/$(pidof tunnel-agent)/limits | grep files`

## Listen backlog

**What:** `net.core.somaxconn` caps the queue of completed-but-not-yet-accepted
connections. The agent requests a backlog of 1024, and **the kernel silently
truncates that to `somaxconn`.**

**Default cost:** older kernels default to 128; 5.4+ defaults to 4096. On a
128-backlog host, a reconnect storm overflows the queue and the kernel drops
SYNs. Clients see a connect timeout, and nothing appears in the agent's logs —
the connections never reached userspace.

**When to change:** if `ss -s` shows growing `syn-recv`, or `nstat -az
TcpExtListenOverflows` is non-zero.

```bash
sysctl -w net.core.somaxconn=4096
```

**Risk:** low. A deeper queue means a burst waits rather than being refused; the
cost is latency for the tail of the burst instead of an error.

**Verify:** `nstat -az TcpExtListenOverflows` should stay flat under load.

## TCP keepalive

**What:** detects a peer that vanished without a FIN — a crashed host, a pulled
cable, a NAT that dropped state.

**Default cost:** `tcp_keepalive_time` is 7200s (2 hours). A relay can hold dead
connections and their descriptors for that long.

The agent already sets per-socket keepalive (30s idle, 10s interval for user
sockets; 60s/15s for tunnel sockets) **and** application-level PING/PONG on each
tunnel, which detects a dead path within `ping_interval ×
ping_max_failures` — 45 seconds at the defaults. System keepalive is a backstop
for the user-facing sockets, not the primary mechanism.

**When to change:** rarely. Only if you see stale connections accumulating on the
user side despite the per-socket settings.

```bash
sysctl -w net.ipv4.tcp_keepalive_time=600
sysctl -w net.ipv4.tcp_keepalive_intvl=30
sysctl -w net.ipv4.tcp_keepalive_probes=5
```

**Risk:** aggressive values add probe traffic per idle connection and can cut
legitimately idle connections that would have resumed.

## TCP buffers

**What:** `tcp_rmem` / `tcp_wmem` bound the kernel's autotuning range as
`min default max`.

**Default cost:** usually fine. Autotuning adapts to the
bandwidth-delay product on its own.

**When to change:** a long-fat path — high bandwidth over high latency, which is
exactly what an intercontinental IEPL link is. At 100 ms RTT, 1 Gbps needs a
~12 MB window; a 6 MB `max` caps you at roughly half the link rate no matter what
the application does.

```bash
# min default max (bytes)
sysctl -w net.ipv4.tcp_rmem="4096 131072 16777216"
sysctl -w net.ipv4.tcp_wmem="4096 65536 16777216"
```

**Risk:** real. These are *per socket*. Raising `max` to 16 MB on a node with
10,000 connections permits a theoretical 160 GB of buffer. Autotuning means you
will not reach that, but a memory-pressure event can still push you into swap or
the OOM killer. Raise only with a measured need and watch
`/proc/net/sockstat`.

**Do not** set `SO_SNDBUF`/`SO_RCVBUF` in the agent config to force a size:
setting them explicitly *disables* autotuning, so you lose adaptation in exchange
for a number you guessed.

## Congestion control

**What:** BBR is generally better than CUBIC on paths with loss that is not
caused by congestion — which describes many long-haul links.

**When to change:** measurable throughput shortfall on a lossy long-haul path.
Test both; BBR is not universally better.

```bash
modprobe tcp_bbr
sysctl -w net.ipv4.tcp_congestion_control=bbr
sysctl -w net.core.default_qdisc=fq   # BBR expects fq pacing
```

**Risk:** BBR's fairness against CUBIC flows is debated. On a shared link it can
take more than its share. On a dedicated IEPL circuit this does not matter.

## SYN handling under load

**What:** `tcp_max_syn_backlog` sizes the half-open queue; `tcp_syncookies`
survives overflow without dropping.

**When to change:** a public-facing entry node exposed to scanning or SYN floods.

```bash
sysctl -w net.ipv4.tcp_max_syn_backlog=8192
sysctl -w net.ipv4.tcp_syncookies=1   # usually already 1
```

**Risk:** low. Syncookies lose some TCP options for cookie-validated connections,
which is a fine trade during an attack.

## TIME_WAIT

**What:** the exit node opens many short-lived connections to its target, each
leaving a `TIME_WAIT` socket for 60 seconds.

**When to change:** `ss -s` shows tens of thousands of `TIME_WAIT` and connects
start failing with `EADDRNOTAVAIL` (ephemeral port exhaustion).

```bash
# Widen the ephemeral range — the correct first move.
sysctl -w net.ipv4.ip_local_port_range="10240 65535"

# Allow reuse for *outgoing* connections. Safe.
sysctl -w net.ipv4.tcp_tw_reuse=1
```

**Never** set `net.ipv4.tcp_tw_recycle`. It breaks connections from clients
behind NAT and was removed in kernel 4.12. Any guide recommending it is stale.

**Risk:** `tcp_tw_reuse` is safe for outbound. Shrinking `tcp_fin_timeout` below
~30 is not recommended; `TIME_WAIT` exists to absorb delayed duplicates.

## Persisting

```bash
cat >/etc/sysctl.d/10-tunnel.conf <<'EOF'
# Only include lines you have measured a need for.
net.core.somaxconn = 4096
fs.file-max = 2097152
EOF

sysctl --system
```

## What not to do

- **Copy a "TCP tuning" blog post wholesale.** Most mix stale advice
  (`tcp_tw_recycle`) with values tuned for a workload unlike this one.
- **Disable `rp_filter` globally to fix IEPL routing.** Set it to `2` (loose) on
  the affected interfaces only — see `docs/networking-iepl.md`.
- **Raise `tcp_rmem`/`tcp_wmem` "to be safe".** These multiply by connection
  count and are the easiest way to turn a working node into an OOM kill.
- **Set socket buffers in the agent config to force a size.** It disables
  autotuning.

## Capacity reference

Rough figures for the defaults in `configs/control.example.toml`:

| Connections | Descriptors | Agent RSS (approx) |
|---|---|---|
| 1,000 | ~2,100 | 60–120 MB |
| 5,000 | ~10,100 | 200–400 MB |
| 10,000 | ~20,100 | 400–800 MB |

Memory scales with `stream_window` (512 KiB) × concurrent streams in the worst
case, but the window is a *ceiling* on in-flight bytes, not a preallocation —
actual usage tracks real traffic. To cut the worst case, lower `stream_window`;
the cost is throughput per stream on a high-latency path.
