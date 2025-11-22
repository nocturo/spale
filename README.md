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
- Can run without root by dropping privileges after initial startup
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

Alternatively, use the provided key generation tool. When installed via packages, use `spale-keygen`; otherwise use `python3 tools/spa_keygen.py` from the source tree:

```bash
# Generate server keys (on server)
spale-keygen server --install

# Generate client keys (on client device)
spale-keygen client --name admin --bundle --server-pub /path/to/server.key.pub

# Or install client public key directly on server
spale-keygen client --name admin --install --bundle
```

Note: If using from source tree, replace `spale-keygen` with `python3 tools/spa_keygen.py`.

### Configuration file: `/etc/spale/spale.conf`
Simple `KEY=VALUE` file. On start, the loader reads this file and exports entries to the environment (CLI flags override env). 
Example config can be found [here](doc/spale.conf.example).

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

### Sending SPA (client)
Use the provided sender script. When installed via packages, use `spale-send`; otherwise use `tools/spa_send.py` from the source tree.

Basic usage with a single key file (server public + client private in one PEM):
```bash
# Create a key file containing both PEM blocks (order doesn't matter)
cat server.pem admin.key > admin.key

spale-send --host 203.0.113.10 --port 55555 \
  --key admin.key
```

Profile-based usage:
```bash
# Create profile in user's config dir
spale-send profile create myserver \
  --host 203.0.113.10 --port 55555 \
  --key admin.key

# Send using the profile
spale-send --profile myserver

# Or use short flag
spale-send -p myserver
```

Profile management:
```bash
# List profiles
spale-send profile list

# Show profile
spale-send profile show myserver

# Update profile values
spale-send profile set myserver --host 203.0.113.11 --port 55556

# Replace key for a profile
spale-send profile set myserver --key /path/to/new.key

# Delete profile
spale-send profile delete -y myserver
```

Note: If using from source tree, replace `spale-send` with `python3 tools/spa_send.py`.

Each profile lives in `<config_root>/<name>/` and contains:
- `config` file with simple `KEY=VALUE` pairs (`HOST`, `PORT`, optional `STEP`, `SOURCE`, `COUNT`)
- `key` combined PEM containing the server public key and client private key

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
