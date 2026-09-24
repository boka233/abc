# Deployment

Targets Ubuntu 22.04+/24.04+ and Debian 11+/12+.

## Install

Three paths. Docker is the least work; the release tarball suits hosts that
already run systemd.

### With Docker (one command)

```bash
sudo ./scripts/docker-deploy.sh -d panel.example.com -e you@example.com
```

Brings up the control plane plus a reverse proxy with automatic HTTPS, generates
secrets, and prints the first-login password. See `docs/docker.md`.

Only the control plane is containerised — the agent needs the host's network
stack, so it is installed on each relay host via the panel's one-line command.

### From a release tarball (recommended)

The target machine needs neither Rust nor Node.js.

```bash
tar xzf tunnel-<version>-<arch>.tar.gz
cd tunnel-<version>-<arch>
sha256sum -c SHA256SUMS          # verify before installing

sudo ./install.sh control        # control plane + panel
sudo ./install.sh agent          # data plane only
```

Installing the control plane also places `tunnel-agent-<arch>` into
`agent_binary_dir`, which is what makes the panel's one-line enrolment command
work on fresh machines. See `docs/release.md`.

### From source

```bash
cargo build --release          # → target/release/{tunnel-control,tunnel-agent}
cd web && npm ci && npm run build && cd ..   # → web/dist
sudo ./scripts/install.sh control
```

When installing from source, put the agent binary where the panel can serve it,
or one-line enrolment will report that no binary is available:

```bash
sudo install -d -o tunnel -g tunnel /var/lib/tunnel-control/agent-bin
sudo install -m 755 -o tunnel -g tunnel \
  target/release/tunnel-agent /var/lib/tunnel-control/agent-bin/tunnel-agent-x86_64
```

## PKI

Entry and exit authenticate each other with certificates from a private CA.
Use a private CA, not a public one: when `ca_path` is set the system trust store
is ignored, so no public CA can impersonate your exit.

```bash
mkdir -p /etc/tunnel && cd /etc/tunnel

# CA (keep ca.key offline)
openssl genrsa -out ca.key 4096
openssl req -x509 -new -key ca.key -sha256 -days 3650 -out ca.pem \
  -subj "/CN=tunnel-ca"

# Exit certificate. The CN/SAN must match the endpoints' tls_server_name.
openssl genrsa -out exit.key 2048
openssl req -new -key exit.key -out exit.csr -subj "/CN=exit.internal"
printf "subjectAltName=DNS:exit.internal\nextendedKeyUsage=serverAuth\n" > exit.ext
openssl x509 -req -in exit.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out exit.pem -days 825 -sha256 -extfile exit.ext

chmod 600 *.key && chown tunnel:tunnel /etc/tunnel/*
```

For mTLS, issue an entry certificate the same way with
`extendedKeyUsage=clientAuth`, set `require_client_auth = true` on the exit, and
point the entry at `client_cert_path` / `client_key_path`.

Note that `tls_server_name` on an endpoint must match the certificate, because the
endpoint address is usually a bare IP while the certificate carries a hostname.

## Control plane

```bash
useradd --system --no-create-home --shell /usr/sbin/nologin tunnel
install -d -o tunnel -g tunnel /var/lib/tunnel-control /etc/tunnel-control
install -m 755 target/release/tunnel-control /usr/local/bin/
install -d -o tunnel -g tunnel /usr/share/tunnel-control
cp -r web/dist /usr/share/tunnel-control/web

install -m 600 -o tunnel -g tunnel configs/control.example.toml \
  /etc/tunnel-control/config.toml
```

Generate the two secrets and put them in the config:

```bash
openssl rand -base64 48    # auth.jwt_secret
openssl rand -base64 48    # tunnel_psk
```

Both are mandatory when `production = true`, along with `agent_tls.ca_path`. The
process refuses to start otherwise — a deployment running on a generated
ephemeral signing key invalidates every session on restart.

```bash
sudo -u tunnel tunnel-control --config /etc/tunnel-control/config.toml check
sudo -u tunnel tunnel-control --config /etc/tunnel-control/config.toml migrate

install -m 644 systemd/tunnel-control.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now tunnel-control
```

The initial administrator password is printed **once** to stdout on first start:

```bash
journalctl -u tunnel-control | grep -A4 'Initial administrator'
```

It is never written to the log. If you miss it:

```bash
sudo -u tunnel tunnel-control --config /etc/tunnel-control/config.toml \
  reset-password admin
```

### Reverse proxy

One command, for a host already running the control plane under systemd:

```bash
sudo ./scripts/setup-proxy.sh -d panel.example.com -e you@example.com
sudo ./scripts/setup-proxy.sh -d panel.example.com --server nginx
sudo ./scripts/setup-proxy.sh -d panel.example.com --self-signed   # intranet
```

Caddy by default, because it renews certificates on its own. With `--server
nginx` the script installs certbot and relies on its systemd timer — the usual
failure mode of that path is a renewal hook that never fires, so the certificate
expires silently.

The manual equivalent, if you would rather write it yourself:

`listen = "127.0.0.1:8080"` plus nginx is the recommended shape — the panel
serves plain HTTP.

```nginx
server {
    listen 443 ssl http2;
    server_name panel.example.com;
    ssl_certificate     /etc/letsencrypt/live/panel.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/panel.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        # Required for the telemetry WebSocket.
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_read_timeout 300s;
    }
}
```

`X-Forwarded-For` is honoured **only** when the immediate peer is loopback, so a
remote client cannot spoof its address to escape login throttling.

If the proxy is *not* on the same host — Docker, or a separate load balancer —
the peer is not loopback and the header is ignored, which collapses per-IP login
throttling into a global one: one person fat-fingering their password locks
everyone out. Declare the proxy's network explicitly:

```toml
# Top-level field: keep it above every [table] header.
trusted_proxies = ["172.20.0.0/16"]
```

Be specific. Whitelisting `172.16.0.0/12` wholesale lets any machine on that
network forge a source address.

## Agents

On each relay host:

```bash
useradd --system --no-create-home --shell /usr/sbin/nologin tunnel
install -d -o tunnel -g tunnel /var/lib/tunnel-agent /etc/tunnel-agent
install -m 755 target/release/tunnel-agent /usr/local/bin/
install -m 600 -o tunnel -g tunnel configs/agent.example.toml \
  /etc/tunnel-agent/config.toml
```

Create the node in the panel, copy the token it shows once, and put it plus the
node id in the config. Then:

```bash
sudo -u tunnel tunnel-agent --config /etc/tunnel-agent/config.toml check
# Confirm the agent sees the NICs you expect before configuring endpoints:
sudo -u tunnel tunnel-agent interfaces

install -m 644 systemd/tunnel-agent.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now tunnel-agent
```

`LimitNOFILE=65535` is already in the unit. The default 1024 caps a node at
roughly 500 connections; see `docs/linux-tuning.md`.

For an IEPL host, apply the routing from `docs/networking-iepl.md` **before**
configuring endpoints. Without the `ip rule`, source-IP binding will not use the
private NIC.

## Configuring a relay

1. **Nodes** — create the entry and the exit.
2. **Endpoints** — on the exit, add the IEPL address as `primary` and the public
   address as `backup`. Both need the same `tls_server_name`.
3. **Routes** — entry, listen address, exit, target, endpoints in failover order,
   pool size (8 is a good default), and `egress_source_ip` if the exit should
   leave via a specific NIC.

Agents pick the change up on their next poll; no restart is needed.

## Operations

```bash
systemctl status tunnel-agent
journalctl -u tunnel-agent -f
systemctl reload tunnel-agent      # SIGHUP: reload TLS certs, keep tunnels up
systemctl restart tunnel-agent     # SIGTERM: graceful drain, then exit
```

### Certificate renewal

`systemctl reload` sends SIGHUP, which reloads certificates in place. Established
tunnels keep the configuration they handshook with; new handshakes use the new
material. If the new certificate is unreadable or malformed, the reload fails and
the **previous** material stays in use — a botched renewal cannot take the node
down.

```bash
# certbot deploy hook
#!/bin/sh
cp /etc/letsencrypt/live/exit.example.com/fullchain.pem /etc/tunnel/exit.pem
cp /etc/letsencrypt/live/exit.example.com/privkey.pem   /etc/tunnel/exit.key
chown tunnel:tunnel /etc/tunnel/exit.* && chmod 600 /etc/tunnel/exit.key
systemctl reload tunnel-agent
```

### Upgrades

Upgrade the control plane first, then agents one at a time. Both directions
tolerate a version skew within a protocol major version; a mismatch is refused at
the handshake with a clear message rather than being guessed at.

```bash
systemctl stop tunnel-agent      # graceful drain
install -m 755 target/release/tunnel-agent /usr/local/bin/
systemctl start tunnel-agent     # resumes from the cached config immediately
```

### Backup

```bash
sqlite3 /var/lib/tunnel-control/control.db ".backup '/backup/control.db'"
```

Use `.backup`, not `cp`: the database runs in WAL mode, so a plain copy can
capture a torn state. Also back up `/etc/tunnel-control/config.toml` and
`/etc/tunnel/` — without the CA key, agents cannot be re-issued certificates.

### Troubleshooting

| Symptom | Where to look |
|---|---|
| Node shows offline | `journalctl -u tunnel-agent`; check `control_url` reachability |
| Tunnels stuck connecting | exit-side logs; certificate name vs `tls_server_name`; PSK match |
| `authentication failed` at handshake | PSK mismatch between control config and agents |
| Route not appearing on an agent | Nodes → node detail → config preview; check the revision |
| Connections refused under load | `LimitNOFILE`, then `net.core.somaxconn` |
| Traffic leaves the wrong NIC | route `egress_source_ip`; `docs/networking-iepl.md` |
