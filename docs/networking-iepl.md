# Dual-NIC / IEPL networking

This is the document to read before deploying an IEPL entry or exit. Everything
here is host configuration the operator applies; **the agent never modifies
routing tables or sysctl settings.** The panel displays interfaces and lets you
select addresses — it does not reconfigure your network.

## The topology

```
        users                                          target / Dodobird server
          │                                                      ▲
          ▼                                                      │
 ┌──────────────────┐                              ┌──────────────────┐
 │  Shanghai entry  │                              │  Hong Kong exit  │
 │                  │                              │                  │
 │ eth0 203.0.113.1 │◀── public, user ingress      │ eth0 203.0.113.9 │── public egress
 │ eth1 10.20.0.1   │───── IEPL ──────────────────▶│ eth1 10.20.0.2   │
 └──────────────────┘      tunnel traffic          └──────────────────┘
```

Three distinct roles, three distinct addresses:

| Address | Role | Configured as |
|---|---|---|
| `203.0.113.1` (SH eth0) | user ingress | route `listen_address` |
| `10.20.0.1` → `10.20.0.2` (eth1) | tunnel transport | endpoint `source_ip` → `address` |
| `203.0.113.9` (HK eth0) | business egress | route `egress_source_ip` |

The model keeps these apart deliberately. A node's `public_address` is
display-only and is **never** used to dial a tunnel; tunnel addresses live in
`endpoints`. Conflating the two is the single most common way this class of
system breaks.

## Configuration in the panel

**Exit node endpoints** — two endpoints on the same exit node, same listener,
two paths:

| Field | IEPL (primary) | Public (backup) |
|---|---|---|
| Address | `10.20.0.2` | `203.0.113.9` |
| Port | `5000` | `5000` |
| Type | `iepl` | `public` |
| Priority | `primary` | `backup` |
| Interface | `eth1` | `eth0` |
| Source IP | `10.20.0.1` | *(empty)* |
| TLS server name | `exit.internal` | `exit.internal` |

`source_ip` is bound by the **entry** before connecting. It is what forces the
tunnel out of the IEPL NIC. Both endpoints must carry the same
`tls_server_name`, because they reach the same certificate.

**Route**:

| Field | Value |
|---|---|
| Listen | `0.0.0.0:443` |
| Target | `127.0.0.1:8443` |
| Endpoints | IEPL first, public second |
| Egress source IP | `203.0.113.9` |

`egress_source_ip` is bound by the **exit** when dialling the target. This is
what makes traffic that arrived over IEPL leave through the public NIC.

## Source IP binding vs SO_BINDTODEVICE

Two mechanisms, not interchangeable. The system supports both and defaults to
the first.

### `bind(source_ip)` — preferred

Binding a local source address before `connect()` makes the kernel select a
route whose source matches.

- No privileges required.
- Works on every Unix and on Windows.
- Shows up correctly in `ss -tnp`.
- Relies on the routing table being correct — with policy routing, the source
  address *is* the route selector.

Failure mode: if the address is not present on any local interface, `bind` fails
with `EADDRNOTAVAIL`. Loud and diagnosable, which is what you want. The agent
wraps this error with the offending address and a hint.

### `SO_BINDTODEVICE` — fallback

Pins a socket to a named device regardless of the routing table.

- **Linux only.**
- **Requires `CAP_NET_RAW`** — the unit needs
  `AmbientCapabilities=CAP_NET_RAW`, or root.
- Bypasses policy routing in ways that are easy to misdiagnose.

Genuinely useful in one case: overlapping or duplicate subnets on two NICs,
where a source IP no longer uniquely identifies the path. Otherwise prefer the
source IP.

## Host routing setup

The addresses above only work if the host's routing agrees. Apply this yourself.

### Policy routing for the IEPL path

A second default route cannot live in the main table, so give the IEPL path its
own table and a rule that selects it by source address:

```bash
# /etc/iproute2/rt_tables — name the table once
echo "100 iepl" >> /etc/iproute2/rt_tables

# Entry node (Shanghai)
ip route add 10.20.0.0/24 dev eth1 src 10.20.0.1 table iepl
ip route add default via 10.20.0.254 dev eth1 table iepl
ip rule add from 10.20.0.1 lookup iepl
```

The `ip rule` is the important line: it is what makes
`bind(10.20.0.1)` actually egress via `eth1`.

Verify:

```bash
ip route get 10.20.0.2 from 10.20.0.1     # expect: dev eth1
ip route get 8.8.8.8 from 203.0.113.1     # expect: dev eth0
```

### Asymmetric routing and `rp_filter`

Reverse-path filtering drops packets that arrive on an interface the kernel
would not have used to reply. On a dual-NIC host with policy routing this
silently discards legitimate traffic, and it is the hardest failure here to
diagnose: connections simply never establish, with nothing in the logs.

```bash
# 0 = off, 1 = strict, 2 = loose.
# Loose accepts the packet if the source is reachable via *any* interface,
# which is correct for a multi-homed host.
sysctl -w net.ipv4.conf.all.rp_filter=2
sysctl -w net.ipv4.conf.eth1.rp_filter=2
```

Prefer `2` (loose) over `0` (off): loose still drops genuinely unroutable
sources, so you keep some spoofing protection.

Persist in `/etc/sysctl.d/10-tunnel.conf`. **Do not** apply these blindly on a
single-NIC host — strict `rp_filter` is a reasonable default there, and
weakening it gains nothing.

### ARP flux

With two NICs on the same L2 segment, Linux by default answers ARP for any local
address on any interface, so a peer may learn the wrong MAC:

```bash
sysctl -w net.ipv4.conf.all.arp_announce=2   # prefer a source on the outgoing iface
sysctl -w net.ipv4.conf.all.arp_ignore=1     # only answer for the target iface's address
```

Only needed when both NICs share a broadcast domain. If eth0 and eth1 are on
genuinely separate segments, leave these alone.

## Failover behaviour

With IEPL primary and public backup, the agent fails over **reluctantly**:

- 3 consecutive connect failures before demoting the primary.
- 5 consecutive successes before promoting it back — asymmetric on purpose,
  because returning abandons a path that currently works.
- A 60-second cooldown between switches.
- Only *consecutive* events count, so a link that fails intermittently never
  reaches either threshold and the route stays put.

The first transition skips the cooldown: a node whose primary is genuinely dead
must fail over immediately rather than waiting out a dwell timer.

Why so conservative: every failover rebuilds a tunnel pool, and rebuilding a
pool drops the streams on it. A system that switched on the first failure would
flap a lossy IEPL link every few seconds and be worse than no failover at all.

## Diagnostic checklist

| Symptom | Check |
|---|---|
| `EADDRNOTAVAIL` on connect | `ip addr show eth1` — is `source_ip` actually present? |
| Tunnel connects over the public path instead of IEPL | `ip rule show`, then `ip route get <exit-ip> from <source-ip>` |
| Tunnel never establishes, no errors | `rp_filter` — try `sysctl net.ipv4.conf.eth1.rp_filter` |
| Target sees the wrong source address | route `egress_source_ip` |
| `SO_BINDTODEVICE` fails with `EPERM` | missing `CAP_NET_RAW`; use `egress_source_ip` instead |
| Peer learns the wrong MAC | `arp_announce` / `arp_ignore`, if both NICs share a segment |
