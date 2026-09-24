# Architecture

## Crate graph

```
tunnel-common ◀── tunnel-protocol ◀── tunnel-core ◀── tunnel-agent
      ▲                                    │
      │                                    └──────────┐
      └──────── tunnel-storage ◀── tunnel-control ◀────┘ (types only)
```

Dependencies run one way. **`tunnel-core` does not link `tunnel-storage`** — the
data plane cannot touch a database even by accident.

| Crate | Responsibility |
|---|---|
| `tunnel-common` | domain model, socket/egress helpers, backoff, logging, `Secret` |
| `tunnel-protocol` | frame codec, handshake, limit negotiation |
| `tunnel-core` | TLS, multiplexer, relay, tunnel pool, health, metrics, entry/exit |
| `tunnel-storage` | SQLite schema and repositories |
| `tunnel-control` | REST API, WebSocket, config distribution, background loops |
| `tunnel-agent` | the binary: config cache, control client, supervisor |

## Data path

```
 user TCP
    │ accept
    ▼
 EntryListener ──▶ TunnelPool.open_stream()
    │                    │ picks a tunnel (round-robin / least-streams)
    │                    ▼
    │              Multiplexer ──▶ OPEN ──▶ TLS 1.3 ──▶ exit
    │                                                    │
    │                                            dial target (bound egress IP)
    │                                                    │
    │                                              OPEN_OK ◀┘
    ▼
 relay: socket ↔ stream, two concurrent tasks
```

### Why two tasks per relay, not one `select!`

A single loop deadlocks on a bulk transfer: the upload arm blocks waiting for
flow-control credit, credit only arrives once the download direction drains, and
draining requires the *same* loop to reach its other arm — which it cannot. Two
tasks make the dependency acyclic. This was found by a test, not by inspection.

### Task topology per tunnel

```
                 ┌── writer task ◀── bounded mpsc ◀── stream writers + ping
  TLS connection ┤
                 └── reader task ──▶ per-stream bounded mpsc ──▶ stream readers
```

Exactly two tasks own the TLS connection, one reading and one writing, so there
is no mutex on the socket. The writer coalesces queued frames into one buffer per
flush: writing each frame separately would turn every 40-byte interactive packet
into its own TLS record and its own syscall.

Backpressure falls out of the bounded channels. If a stream's reader is behind,
the reader task's `send` awaits, which stops it pulling frames off the TLS
connection — exactly the intended effect.

## Control path

```
agent ──▶ POST /api/agent/register   ──▶ full config bundle
agent ──▶ GET  /api/agent/config     ──▶ bundle, or "unchanged" by revision
agent ──▶ POST /api/agent/heartbeat  ──▶ telemetry in, revision out
```

Agent credentials (`X-Node-Id` + `X-Agent-Token`) are a separate namespace from
panel sessions. An agent cannot call panel endpoints and a panel session cannot
impersonate a node.

### The decoupling rule

The control plane is never in the traffic path:

- The agent applies its **cached** bundle at startup, before contacting the
  control plane. A node rebooting during an outage comes back carrying traffic.
- Config changes bump a revision; agents notice on their next poll. There is no
  "push and wait", which would fail whenever an agent was briefly unreachable.
- "Restart route" is advisory — it bumps the revision. The control plane cannot
  reach into an agent's process, and the UI says so rather than implying it can.

### Atomic apply

```
validate bundle ──▶ build new runtime (old one still serving) ──▶ swap ──▶ drain old
```

If validation or construction fails, the old runtime keeps running and the error
is reported. That is the difference between "a typo disabled one route" and "a
typo took every tunnel on the node offline". Only a bundle that applied cleanly
is written to the cache, so the cache can never hold a known-broken config.

The cache is written to a temp file in the same directory and renamed over the
target. `rename` is atomic within a filesystem, so a crash mid-write leaves the
old complete file — a truncated cache would mean an agent that cannot boot
without the control plane, defeating the point.

## Metrics

Hard rule: nothing on the per-byte path touches a lock, an allocation, or a
database. A relay loop does `fetch_add` on an `AtomicU64` and nothing else,
with `Relaxed` ordering — these are statistics, and paying for `SeqCst` per 16 KiB
chunk buys nothing.

```
data plane: AtomicU64 counters
     │ sampled on an interval
     ▼
agent: heartbeat report ──▶ control plane: in-memory map
                                  │ aggregated on an interval
                                  ▼
                            traffic_stats (one row per node per bucket)
```

At a 10-second bucket and 20 nodes that is ~2 inserts/second whether the fleet is
moving 1 Mbps or 10 Gbps.

Live telemetry lives only in memory and does not survive a control-plane restart.
That is correct: agents repopulate it within seconds, and the database is for
history.

## Failover

Per-endpoint health with thresholds and a cooldown:

- 3 consecutive failures → demote
- 5 consecutive successes → promote (asymmetric: returning abandons a working path)
- 60-second cooldown between switches, skipped for the first transition
- only *consecutive* events count

Every failover rebuilds a tunnel pool, and that drops the streams on it. A system
that switched on the first failure would flap a lossy IEPL link continuously and
be worse than no failover at all.

## Web panel

Vue 3 + TypeScript + Pinia. Telemetry arrives over a WebSocket and updates
**incrementally** — a node report replaces only that node's entry. Polling the
whole fleet every second would be both wasteful and visibly janky.

The broadcast channel is bounded. A tab that stops reading is dropped from the
stream with a `lagged` notice, which the client turns into a refetch. A stalled
browser must never slow telemetry for anyone else.
