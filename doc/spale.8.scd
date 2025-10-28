SPALE(8) "October 28, 2025" "Spale Manual"

# NAME

spale - eBPF Single Packet Authentication daemon with HPKE sender-auth

# SYNOPSIS

spale [ -c PATH ] -i IFACE -S PORT [ -t SEC ] [ -g SEC ] [ -m xdp|tc ] [ -p ] [ -n ] --server-key PATH --clients DIR [ --drop-privs USER[:GROUP] ] [ --external-xdp ] [ --pin-dir DIR ]

spale --manage <list|authorize|allowlist> ...

# DESCRIPTION

spale is a high-performance Single Packet Authentication (port knocking) daemon that enforces network access using eBPF at ingress (TC by default, optional XDP). A client sends a single UDP packet using HPKE (RFC 9180, X25519/ChaCha20-Poly1305) to authenticate and authorize its source IP for one or more protected destination ports. On success, spale writes allowlist entries into eBPF maps for the requested ports and maintains them with idle-extension and post-disconnect grace windows.

# REQUIREMENTS

Linux kernel >= 4.18 with BTF and XDP/TC eBPF support.

Root privileges are required to load and attach eBPF programs; spale can drop privileges after initial setup.

# OPTIONS

*-c* PATH
	Read configuration from PATH. The file is simple KEY=VALUE. Options from CLI override environment. Default: /etc/spale/spale.conf.

*-i* IFACE
	Network interface name to attach to (required).

*-S* PORT
	UDP port to listen on for SPA packets (required).

*-t* SEC
	Idle extension window in seconds; each authorized packet from an address extends its allowlist entry by this duration.

*-g* SEC
	Post-disconnect grace window in seconds; allows new connections shortly after a TCP FIN/RST.

*-m* xdp|tc
	Attach mode; default is tc.

*-p*
	Pin BPF maps under bpffs so they persist/reuse across runs. Default directory: /sys/fs/bpf/spale.

*-n*
	Observe-only (log-only) mode; never drop traffic.

*--server-key* PATH
	Path to server private key PEM (X25519) used for HPKE decryption (required).

*--clients* DIR
	Directory containing client public key PEMs; filenames determine client IDs (required).

*--drop-privs* USER[:GROUP]
	Drop privileges to the specified user (and optional group) after attach. Parent process retains privileges for cleanup.

*--external-xdp*
	Do not load/attach XDP; open already pinned maps (useful for externally managed XDP programs).

*--pin-dir* DIR
	Override bpffs pin directory when -p or in external mode.

*--manage* ...
	Run administrative subcommands over the management socket instead of starting the daemon.

# MANAGEMENT SUBCOMMANDS

list authorized
	List currently authorized source addresses and ports with expiry information.

list allowlist
	List entries in the permanent allowlist (LPM) for IPv4/IPv6.

list ports
	List currently configured protected destination ports.

list ratelimit | list rl
	Show configured SPA rate limit and per-source token state.

authorize add --ip ADDR [--ports CSV] [--idle-sec N|-1] [--grace-sec N|-1]
	Manually authorize an address for one or more ports. Negative values (-1) make windows effectively infinite.

authorize del --ip ADDR [--ports CSV]
	Remove authorization entries for an address (optionally limited to ports).

allowlist add CIDR|IP
	Add IPv4/IPv6 CIDR or IP to the permanent allowlist (bypass SPA).

allowlist del CIDR|IP
	Remove an entry from the permanent allowlist.

# CONFIGURATION

The configuration file is loaded first and exported to environment; CLI flags override env.

	IFACE
		Interface to protect.

	LISTEN_ADDR
		IPv4 address to bind SPA listener (default 0.0.0.0).

	LISTEN_ADDR6
		IPv6 address to bind SPA listener (default ::).

	LISTEN_PORT
		UDP port to listen for SPA on LISTEN_ADDR/LISTEN_ADDR6.

	MODE
		Choose between tc (default) and xdp modes.

	IDLE_SEC
		Idle window in seconds for authorized entries.

	GRACE_SEC
		Post-disconnect grace window in seconds.

	LOG_ONLY
		Set to 1 to enable observe-only (log-only) mode.

	SERVER_KEY
		Path to server private key (PEM) used for HPKE decryption.

	CLIENTS_DIR
		Directory containing client public key PEMs.

	LOG_LEVEL
		One of: debug, info, warn, error.

	LOG_USE_SYSLOG
		Enable syslog logging.

	PROTECTED_PORTS
		CSV of destination ports to protect (max 16).

	SPA_RL_RATE
		SPA UDP rate limit per source (tokens/sec).

	SPA_RL_BURST
		Token bucket burst size.

	ALWAYS_ALLOW
		CSV of IPv4/IPv6 exact IPs or CIDR blocks that bypass SPA.

Per-client overrides (client ID uppercased):

	<CLIENT>\_IDLE\_SEC
		Idle window override (seconds) for specific client ID.

	<CLIENT>\_GRACE\_SEC
		Grace window override (seconds) for specific client ID.

	<CLIENT>\_PORTS
		CSV of destination ports for the client; filtered against PROTECTED\_PORTS.

# FILES

/etc/spale/spale.conf
	main configuration file (KEY=VALUE).

/etc/spale/spale.conf.example
	example configuration.

/etc/spale/server.key
	server private key (X25519 PEM).

/etc/spale/clients/
	directory of client public key PEMs.

/run/spale.sock
	management socket.

/run/spale.pid
	PID file.

/sys/fs/bpf/spale
	bpffs pin directory for maps

# EXAMPLES

Start in TC mode protecting ports 22,443 on eth0, listening on 55555 for SPA:
```
spale -i eth0 -S 55555 \\\
--server-key /etc/spale/server.key --clients /etc/spale/clients \\\
-t 60 -g 300 -c /etc/spale/spale.conf
```

Start in XDP mode:
```
spale -m xdp -i eth0 -S 55555 \\\
--server-key /etc/spale/server.key --clients /etc/spale/clients
```

Start in XDP mode with pinned maps (persist maps across runs):
```
spale -m xdp -p -i eth0 -S 55555 \\\
--server-key /etc/spale/server.key --clients /etc/spale/clients
```

Use external XDP program (pre-pinned maps) with spale managing SPA only:
```
spale --external-xdp --pin-dir /sys/fs/bpf/spale -i eth0 -S 55555 \\\
--server-key /etc/spale/server.key --clients /etc/spale/clients
```

List authorized entries:

	spale --manage list authorized

Authorize an IP for SSH+HTTPS:

	spale --manage authorize add --ip 198.51.100.23 --ports 22,443

Allowlist a subnet:

	spale --manage allowlist add 192.0.2.0/24

# SYSTEMD

The provided unit uses EnvironmentFile=-/etc/spale/spale.conf and:

	ExecStart=/usr/sbin/spale -c /etc/spale/spale.conf --drop-privs 65534:65534

# EXIT STATUS

Returns 0 on success; non-zero on error (missing required options, attach/load failures, etc.).

# SEE ALSO

bpftool(8), systemd(1), project README, and doc/spa-packet-format.md.
