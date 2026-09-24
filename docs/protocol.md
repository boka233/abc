# Frame protocol

Version 1. Implemented in `crates/tunnel-protocol`.

## Layering

```
TCP ──▶ TLS 1.3 ──▶ [ frame | frame | frame … ] ──▶ N logical TCP streams
```

Only TCP. There is no `UDP_OPEN`, no datagram framing, no QUIC. A stream's
payload is never inspected.

## Frame format

```
 0       1       2               6               8
 ├───────┼───────┼───────────────┼───────────────┼─────────────────┐
 │  ver  │ type  │   stream id   │  payload len  │     payload     │
 │  u8   │  u8   │    u32 be     │    u16 be     │    len bytes    │
 └───────┴───────┴───────────────┴───────────────┴─────────────────┘
```

8-byte header. The length is `u16`, so a frame cannot exceed 65535 payload bytes
— an over-long length is structurally unrepresentable rather than something the
decoder has to defend against. A `u32` length field is where the OOM bugs in
hand-rolled protocols live.

Stream id 0 is reserved for tunnel-level control frames. Ids are allocated by the
entry only, so there is no odd/even split and the exit never invents one.

## Frame types

| Type | Value | Direction | Payload |
|---|---|---|---|
| `OPEN` | `0x01` | entry → exit | JSON `{route_id, client_addr?}` |
| `OPEN_OK` | `0x02` | exit → entry | empty |
| `OPEN_ERROR` | `0x03` | exit → entry | UTF-8 reason, ≤256 B |
| `DATA` | `0x04` | both | opaque bytes, never empty |
| `CLOSE` | `0x05` | both | empty — half-close (FIN) |
| `RESET` | `0x06` | both | empty — abortive close (RST) |
| `PING` | `0x07` | both | 8-byte BE timestamp |
| `PONG` | `0x08` | both | echo of the PING payload |
| `WINDOW_UPDATE` | `0x09` | both | `u32` credit, > 0 |
| `GO_AWAY` | `0x0A` | both | UTF-8 reason |

`OPEN` carries **no target**. The exit resolves the target from its own route
table. If the target came from the wire, any authenticated entry could aim any
exit anywhere — every exit would be an open proxy.

An empty `DATA` frame is rejected: it would be ambiguous with `CLOSE`, leaving
`CLOSE` as the only end-of-stream signal.

## Handshake

After the TLS handshake, before any frame:

```
entry ──▶ u16 length + JSON ClientHello
exit  ──▶ u16 length + JSON ServerHello
```

`ClientHello` carries the protocol version, node and route ids, a 32-byte random
nonce, an HMAC proof, and the payload/window sizes this side is willing to
*receive*. `ServerHello` replies with the accepted flag and the **negotiated**
limits.

Handshake messages are capped at 8 KiB, checked on the length prefix before the
body is buffered.

### Limit negotiation

Both sides take the minimum of the two proposals, so neither can be pushed past
what it is willing to buffer. The result is rejected if the payload cap falls
below 1024, exceeds the wire limit, or if the window is smaller than a single
frame — that last case would deadlock, because a full-size frame could never be
sent.

### PSK proof

```
proof = HMAC-SHA256(psk, "tunnel-v1" || node_id || route_id || nonce)
```

Verified in constant time. The PSK never crosses the wire.

TLS already authenticates the server (and the client under mTLS). This layer is
defence in depth: if a certificate is mis-issued, or `insecure_skip_verify` is
left on in a lab config, the PSK still stops an unauthorised peer. Binding the
proof to `route_id` means a captured proof cannot be replayed for a different
route.

Rejections use one uniform message — "authentication failed" — for every cause,
so the reply cannot be used as an oracle.

## Flow control

Per-stream credit, because without it a single fast sender starves every other
stream on the tunnel, and an unbounded queue would consume all memory instead.

1. The receiver grants `stream_window` bytes when the stream opens.
2. The sender decrements its credit per `DATA` payload and blocks at zero.
3. As the receiver drains bytes **into the downstream socket**, it returns credit
   with `WINDOW_UPDATE`.

Step 3's ordering is the whole mechanism. Credit is returned *after* the write
completes, never on receipt. That couples the two TCP connections' rates: if the
target stops reading, the kernel send buffer fills, our write blocks, credit stops
flowing, and the original client's sender is pushed back. End-to-end backpressure
with bounded memory.

Updates are batched until half the window is consumed — one `WINDOW_UPDATE` per
1 KiB chunk would drown the tunnel in control frames.

## Head-of-line blocking

Real and unavoidable at this layer. All streams on one tunnel share one TCP
connection, so a lost segment stalls every stream behind it until retransmission.
No application framing can fix that; it is a property of ordered transport.

The mitigation is architectural: a route runs `tunnel_pool_size` independent TLS
connections and spreads streams across them, so one stalled connection affects
roughly `1/N` of traffic. That is why the default is 8 and why a
single-connection design was rejected.

## Heartbeat

`PING` on `ping_interval` (15s), requiring `PONG` within `ping_timeout` (10s).
After `ping_max_failures` (3) consecutive misses the tunnel is torn down so the
pool replaces it.

Necessary because a TCP connection can stay "established" for minutes after the
path has died. Only an application-level heartbeat notices in time.

Reconnection uses exponential backoff with full jitter. When an exit restarts,
every entry's whole pool fails at once; without jitter they all retry in lockstep
and hammer the exit the moment it returns.

## Hostile input

Every decode path is an attack surface. The decoder:

- rejects unknown versions and frame types;
- validates the announced length against the negotiated cap **before** reserving
  any buffer;
- rejects control frames on a real stream and stream frames on stream 0;
- rejects an empty `DATA` frame;
- treats a mid-frame connection close as a protocol error, not a clean EOF, so
  truncation is never silently tolerated;
- never indexes without a bounds check, and never calls `unwrap` on the hot path.

A malformed frame kills exactly one tunnel connection. It never panics the
process. `frame::tests::garbage_input_never_panics` runs pseudo-random input
through the decoder to hold that line.
