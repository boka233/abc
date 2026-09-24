# Rust TLS 1.3 TCP Tunnel Relay

Production-grade TCP relay: a Rust data plane that carries **opaque TCP byte
streams** over multiplexed TLS 1.3 tunnels, plus a control plane and web admin
panel.

Built for server-to-server relaying, including dual-NIC IEPL deployments where
user ingress, tunnel transport and business egress each use a different network
interface.

## Install in one command

On a fresh Ubuntu/Debian host, as root:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/boka233/abc/main/scripts/quick-install.sh)
```

It asks for a domain and an email, then installs Docker, builds the images, and
brings up the control plane behind a reverse proxy with automatic HTTPS. The
first-login password is printed at the end.

Non-interactive:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/boka233/abc/main/scripts/quick-install.sh) \
  -d panel.example.com -e you@example.com
```

No domain yet? `--local` binds `127.0.0.1:8080` and skips certificates.
Upgrading later? Re-run with `--update`.

`bash <(curl ...)` rather than `curl | bash`: the latter occupies stdin, so the
script could not ask for confirmation before generating keys. The bootstrap
script only clones the repository; the deployment logic lives in
`scripts/docker-deploy.sh`, where it can be read and audited instead of being a
one-shot pipe.

## Scope

**This layer only moves TCP.** There is no UDP listener, no UDP-over-TCP, no
QUIC. Upper layers that need UDP (Dodobird does) encapsulate it in their own TCP
stream before it reaches here.

The relay never parses the payload:

```
client ──▶ TCP ──▶ entry ──▶ TLS 1.3 tunnel ──▶ exit ──▶ TCP ──▶ target
```

Whatever rides inside — Dodobird frames, VLESS, plain HTTP — is an opaque byte
stream. The contract is: **bytes in equal bytes out, in order, with the
connection lifecycle (including half-close) preserved.**

## Layout

```
tunnel/
├── crates/
│   ├── tunnel-common/      shared model, socket/egress helpers, backoff, logging
│   ├── tunnel-protocol/    binary frame codec + handshake
│   ├── tunnel-core/        data plane: TLS, mux, relay, pool, health, metrics
│   ├── tunnel-storage/     SQLite + repository layer
│   ├── tunnel-control/     REST API, WebSocket, config distribution
│   └── tunnel-agent/       the agent binary (entry / exit / both)
├── web/                    Vue 3 + TypeScript admin panel
├── migrations/             SQL schema
├── configs/                example configuration
├── systemd/                unit files
├── scripts/                install, cert generation, dev helpers
└── docs/                   architecture, protocol, IEPL routing, tuning
```

Protocol, data plane, control plane, storage and web are separate crates with
one-directional dependencies. The data plane never links the storage crate.

## Design decisions worth knowing

**One agent binary, three roles.** `role = entry | exit | both`. Two binaries
would duplicate the TLS, mux and relay code and let them drift.

**Device groups, not individual machines.** A route references an inbound group
and an outbound group. The enrolment token lives on the group, so one install
command scales a group to any number of machines, and adding or losing a machine
does not touch any route. Every machine in a group receives the same routes but
binds only its own tunnel addresses.

**A tunnel pool, not one connection.** Multiplexing N streams over one TCP
connection means one lost segment stalls every stream behind it — head-of-line
blocking that framing cannot undo. A route runs `tunnel_pool_size` independent
TLS connections (default 8), so a stall affects ~1/N of traffic instead of all of
it.

**Credit-based flow control.** Every stream has a receive window. Credit is
returned only *after* bytes reach the downstream socket, which couples the two
TCP connections' rates and bounds memory. No unbounded channels anywhere.

**The control plane is not in the traffic path.** Agents cache the last
configuration that applied cleanly and serve from it at boot, before contacting
the control plane. A control-plane outage cannot take the data plane down.

**Atomic config apply.** A new runtime is built while the old one still serves;
only then is it swapped in. A bad push leaves the previous configuration running
and reports the error.

**Reluctant failover.** 3 consecutive failures to demote, 5 successes to promote,
plus a cooldown. Only consecutive events count. A system that switched on the
first failure would flap a lossy IEPL link every few seconds.

**Public address ≠ tunnel address.** A node's public address is display-only.
Tunnel addresses are endpoints, with their own source-IP binding. Conflating them
is the usual way this class of system breaks.

## Quick start

Needs a Linux host (Ubuntu 22.04+ / Debian 11+). With a release tarball that is
the only requirement; building from source additionally needs Rust 1.80+ and
Node 20+.

If you already have the repository checked out:

```bash
# Docker: control plane + panel + reverse proxy with automatic HTTPS
sudo ./scripts/docker-deploy.sh -d panel.example.com -e you@example.com
```

Or without Docker:

```bash
# Control plane (management host), from a release tarball
tar xzf tunnel-<version>-<arch>.tar.gz && cd tunnel-<version>-<arch>
sha256sum -c SHA256SUMS
sudo ./install.sh control

# …or from source
sudo ./scripts/install.sh control

sudo systemctl enable --now tunnel-control
# HTTPS + reverse proxy, also one command
sudo ./scripts/setup-proxy.sh -d panel.example.com -e you@example.com
# the initial admin password is printed once, to stdout:
sudo journalctl -u tunnel-control | grep -A4 'Initial administrator'

# Private CA and an exit certificate
./scripts/gen-certs.sh ca
./scripts/gen-certs.sh server exit.internal 10.20.0.2 203.0.113.9
```

Then create a **device group** in the panel, copy its one-line install command,
and run it on each relay host:

```bash
bash <(curl -fsSL http://panel:8080/api/agent/install.sh) -t <token> -u http://panel:8080
```

The enrolment token belongs to the **group**, not to a machine, so the same
command enrols any number of hosts into that group. Adding or replacing a machine
never requires touching a route — routes reference groups.

That command fetches the agent binary from the panel, so the control plane needs
`agent_binary_dir` populated. The release tarball's `install.sh` does this for
you; installing from source requires one extra step (see `docs/deployment.md`).

`install.sh` is idempotent: it will not overwrite an existing config, and it
never regenerates secrets — doing so would invalidate every session and break
every agent handshake.

| Script | Purpose |
|---|---|
| `scripts/install.sh` | install `control` / `agent` / `both`, with systemd units |
| `scripts/agent-install.sh` | served at `/api/agent/install.sh`; the one-line enrolment |
| `scripts/quick-install.sh` | the `curl`-able bootstrap: clones, then hands off to the deploy script |
| `scripts/docker-deploy.sh` | one-command Docker deployment with automatic HTTPS |
| `scripts/setup-proxy.sh` | reverse proxy + certificates for a systemd install |
| `scripts/release.sh` | build release tarballs (Linux only); see `docs/release.md` |
| `scripts/offline-install.sh` | packaged as `install.sh` inside a release tarball |
| `scripts/gen-certs.sh` | private CA, server and client (mTLS) certificates |
| `scripts/uninstall.sh` | remove binaries; `--purge` also drops data |
| `scripts/dev.sh` | test / e2e / check / web / control / clean |

The enrolment script offers to apply kernel tuning. It **prints every change
before making it** and only touches low-risk knobs (`somaxconn`, BBR, `fq`,
`LimitNOFILE`); `tcp_rmem`/`wmem` and `rp_filter` are explained but never
modified, because the first multiplies per connection and the second fails
silently when set wrong.

**For an IEPL host, read `docs/networking-iepl.md` before configuring
endpoints.** Without the policy-routing rule, source-IP binding will not use the
private NIC, and the failure looks like "connections never establish, nothing in
the logs".

## Tests

```bash
cargo test --workspace          # unit + integration
cargo test -p tunnel-core --test end_to_end   # real TLS, real sockets
```

The end-to-end suite stands up a real entry+exit pair with a generated PKI and
asserts byte-exact 2 MiB transfers, half-close propagation, stream isolation
across 32 concurrent connections, and that a wrong PSK or untrusted certificate
prevents the tunnel from forming.

## Documentation

| Document | Contents |
|---|---|
| **`docs/使用说明.md`** | **完整中文使用说明 — 部署、IEPL 配置、面板操作、排查** |
| `docs/architecture.md` | component layout, data flow, task topology |
| `docs/protocol.md` | frame format, handshake, flow control |
| `docs/networking-iepl.md` | dual-NIC routing, source binding, `rp_filter` |
| `docs/linux-tuning.md` | descriptors, backlog, buffers — with risks stated |
| `docs/deployment.md` | systemd, PKI, upgrades |

## Security posture

- TLS 1.3 only. No 1.2, no downgrade path. rustls + ring; no hand-rolled crypto.
- Optional mTLS, plus an HMAC PSK proof bound to node and route.
- The exit resolves targets from **its own** configuration, never from the wire —
  an entry cannot turn an exit into an open proxy.
- Argon2id password hashing; per-IP login throttling.
- Frame length, stream id and window validated before allocation; the decoder is
  fuzzed against panics.
- Secrets wrapped in a redacting type, so `{:?}` cannot leak them; audit details
  are scrubbed by key name before storage.
