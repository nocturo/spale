## spale: eBPF Single Packet Authentication (SPA) with HPKE sender-auth

<img src="doc/spale.jpg" alt="spale project avatar" align="left" width="64" style="margin-right: 12px; margin-bottom: 6px;">

High-performance SPA (port knocking) implemented in eBPF (using TC or XDP for heavylifting) with an HPKE sender-authenticated UDP control channel. On a valid SPA packet, the source address is allowlisted per protected destination port.

### Features
- No firewall software required
- HPKE sender-auth (RFC 9180) using X25519 and ChaCha20-Poly1305
- eBPF enforcement at ingress using either TC (default) or optional XDP mode for more oomph
- IPv4 and IPv6 support
- Protects TCP and UDP destination ports you configure
- Idle extension and post-disconnect grace windows (per-entry overrideable)
- Global SPA UDP rate limiting (per source)
- Always-allow lists via IPv4/IPv6 exact IPs or CIDR
- Self contained statically compiled binary
- Can run without root by dropping privileges after inital startup
- Optional map pinning under bpffs during runtime

### Requirements
- Linux kernel (4.18+) with BTF and XDP/TC eBPF support (for CO-RE)
- `clang`, `libbpf` >= 0.7.0, `bpftool`, OpenSSL
- Root privileges to attach XDP/TC with optinal priviledge drop in a child process

### Build
```bash
make
sudo make install
```

Installs `/usr/local/sbin/spale` by default. Adjust with `PREFIX` and `SYSCONFDIR` as needed.

### Releases (prebuilt static binary)
- Prebuilt, statically linked Linux amd64 binaries are published on this repository's Releases page.
- Download the `spale` asset from the latest release, then:
```bash
chmod +x spale
# verify checksum

# Install system-wide
sudo install -m0755 spale /usr/local/sbin/spale
```
Notes:
- Configure via `/etc/spale/spale.conf` (see below).

### Keys (X25519)
On the host where you want to run, generate server private key and public key:
```bash
openssl genpkey -algorithm X25519 -out /etc/spale/server.key
openssl pkey -in /etc/spale/server.key -pubout -out /etc/spale/server.pem
```

Distribute the server public key to all clients (there is no built-in exchange, so it must be distributed out of bounds).

Generate a client keypair (ideally on a client's device):
```bash
openssl genpkey -algorithm X25519 -out admin.key
openssl pkey -in /etc/spale/clients/admin.key -pubout -out admin.pem
```

Now copy over the client's public key to the server and place it in /etc/spale/clients/admin.pem

### Configuration file: `/etc/spale/spale.conf`
Simple `KEY=VALUE` file. On start, the loader reads this file and exports entries to the environment (CLI flags override env). Important keys:

```bash
# Interface / mode / SPA listen port
IFACE=eth0
MODE=tc                   # tc|xdp
LISTEN_PORT=55555         # SPA UDP port

# Protected destination ports (max 16)
PROTECTED_PORTS=22,443,8443

# Defaults for all clients
IDLE_SEC=60
GRACE_SEC=300

# Global SPA UDP rate limit (per-source)
SPA_RL_RATE=3
SPA_RL_BURST=3

# HPKE credentials
SERVER_KEY=/etc/spale/server.key
CLIENTS_DIR=/etc/spale/clients     # *.pem public keys; basename is client ID

# Always-allowed sources (bypass SPA). IPv4/IPv6 IPs or CIDR.
ALWAYS_ALLOW=192.168.1.10,10.0.0.0/8,203.0.113.0/24,2001:db8::/32

# Optional: never drop (observe only)
LOG_ONLY=0
```

Per-client overrides:
```bash
# For /etc/spale/clients/ADMIN.pem
ADMIN_IDLE_SEC=120
ADMIN_GRACE_SEC=60
ADMIN_PORTS=22,8443           # subset of PROTECTED_PORTS; if omitted, all previously defined ports.
```

Notes:
- Allowlist entries are tracked per (src, dport) and extend on each matching packet.
- The SPA plaintext includes a time step (30s window, ±1 step) and a random nonce; a replay cache prevents re-use during the process lifetime.

### Running
The loader requires an interface, SPA listen port, HPKE server key, clients directory (with at least one client), and `PROTECTED_PORTS` provided via either config/env.

TC mode example:
```bash
sudo /usr/local/sbin/spale -i eth0 -S 55555 \
  --server-key /etc/spale/server.key --clients /etc/spale/clients \
  -t 60 -g 300 -c /etc/spale/spale.conf
```

XDP mode example:
```bash
sudo /usr/local/sbin/spale -m xdp -i eth0 -S 55555 \
  --server-key /etc/spale/server.key --clients /etc/spale/clients \
  -c /etc/spale/spale.conf
```

Flags of interest:
- `-i IFACE`, `-S PORT`, `-m xdp|tc`, `-t IDLE_SEC`, `-g GRACE_SEC`, `-p` (pin maps), `-n` (log-only)
- `--server-key PATH`, `--clients DIR`, `--drop-privs user[:group]`

### Sending SPA (client)
Use the provided sender script:
```bash
python3 tools/spa_send.py --host 203.0.113.10 --port 55555 \
  --server-pk server.pub \
  --client-sk admin.key
```

Requires Python `cryptography` (`pip install cryptography`). The script supports IPv4/IPv6 and optional `--source` binding.

### Systemd service
```bash
sudo make install
sudo install -Dm0644 systemd/spale.service /etc/systemd/system/spale.service
sudo systemctl daemon-reload
sudo systemctl enable --now spale
```

Configure via `/etc/spale/spale.conf` (the unit reads it via `EnvironmentFile`).

### License
- Userspace (`src/`, `tools/`, `include/`): MIT
- eBPF programs (`bpf/*.bpf.c`): GPL-2.0-only
- Third-party: OpenSSL (Apache-2.0), libbpf (BSD-2-Clause)


