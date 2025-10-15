#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
import argparse, hmac, hashlib, struct, socket, time, sys
import os, platform, re, shutil
import secrets

def _os_config_root() -> str:
    sysname = platform.system()
    home = os.path.expanduser('~')
    if sysname == 'Linux':
        xdg = os.environ.get('XDG_CONFIG_HOME')
        return os.path.join(xdg, 'spale') if xdg else os.path.join(home, '.config', 'spale')
    if sysname == 'Darwin':
        return os.path.join(home, 'Library', 'Application Support', 'spale')
    if sysname == 'Windows':
        appdata = os.environ.get('APPDATA') or os.environ.get('LOCALAPPDATA') or os.path.join(home, 'AppData', 'Roaming')
        return os.path.join(appdata, 'spale')
    # Other OS: use ~/.config/spale
    return os.path.join(home, '.config', 'spale')


def _legacy_config_root() -> str:
    return os.path.join(os.path.expanduser('~'), '.spale')


def _warn_dual_config(os_root: str, legacy_root: str) -> None:
    if os.path.isdir(os_root) and os.path.isdir(legacy_root):
        print(f"warning: both config roots exist: '{os_root}' and '{legacy_root}'", file=sys.stderr)


def _config_root() -> str:
    os_root = _os_config_root()
    legacy = _legacy_config_root()
    _warn_dual_config(os_root, legacy)
    return os_root


def _config_read_roots() -> list:
    os_root = _os_config_root()
    legacy = _legacy_config_root()
    _warn_dual_config(os_root, legacy)
    return [os_root, legacy]


def _read_kv_file(path: str) -> dict:
    data = {}
    try:
        with open(path, 'r') as f:
            for line in f:
                s = line.strip()
                if not s or s.startswith('#'):
                    continue
                if '=' in s:
                    k, v = s.split('=', 1)
                    data[k.strip().upper()] = v.strip()
    except FileNotFoundError:
        pass
    return data


def _write_kv_file(path: str, data: dict) -> None:
    lines = []
    for k in sorted(data.keys()):
        lines.append(f"{k}={data[k]}\n")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        f.writelines(lines)


def _profile_dir_primary(name: str) -> str:
    return os.path.join(_config_root(), name)


def _find_profile_dir(name: str) -> str:
    for root in _config_read_roots():
        p = os.path.join(root, name)
        if os.path.isdir(p):
            return p
    return ''


def _load_profile(name: str) -> tuple:
    pdir = _find_profile_dir(name)
    cfg = _read_kv_file(os.path.join(pdir, 'config')) if pdir else {}
    return pdir, cfg


def _parse_pem_blocks(pem_bytes: bytes) -> list:
    blocks = []
    for m in re.finditer(br"-----BEGIN [^-]+-----[\s\S]*?-----END [^-]+-----", pem_bytes):
        blocks.append(m.group(0))
    return blocks


def _load_keys(key_path: str):
    try:
        from cryptography.hazmat.primitives.asymmetric import x25519
        from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
    except Exception:
        print('error: python cryptography package is required. pip install cryptography', file=sys.stderr)
        sys.exit(1)

    server_pub = None
    client_sk = None

    if key_path:
        try:
            with open(key_path, 'rb') as f:
                buf = f.read()
            for block in _parse_pem_blocks(buf):
                if client_sk is None:
                    try:
                        k = load_pem_private_key(block, password=None)
                        if isinstance(k, x25519.X25519PrivateKey):
                            client_sk = k
                            continue
                    except Exception:
                        pass
                if server_pub is None:
                    try:
                        k = load_pem_public_key(block)
                        if isinstance(k, x25519.X25519PublicKey):
                            server_pub = k
                            continue
                    except Exception:
                        pass
        except Exception as e:
            print(f'error: failed to load key file: {e}', file=sys.stderr)
            sys.exit(1)

    try:
        from cryptography.hazmat.primitives.asymmetric import x25519
    except Exception:
        pass

    if server_pub is None or client_sk is None:
        print('error: missing keys. Provide --key to a PEM containing server public and client private keys', file=sys.stderr)
        sys.exit(1)

    if not isinstance(server_pub, x25519.X25519PublicKey):
        print('error: server public key must be X25519', file=sys.stderr)
        sys.exit(1)
    if not isinstance(client_sk, x25519.X25519PrivateKey):
        print('error: client private key must be X25519', file=sys.stderr)
        sys.exit(1)
    return server_pub, client_sk


def send_cmd(args):
    prof_dir = None
    if args.profile:
        prof_dir, pcfg = _load_profile(args.profile)
        if not pcfg:
            print(f"error: profile '{args.profile}' not found or empty", file=sys.stderr)
            sys.exit(1)
        args.host = args.host or pcfg.get('HOST')
        args.port = args.port or (int(pcfg['PORT']) if 'PORT' in pcfg else None)
        args.step = args.step if 'STEP' not in pcfg else int(pcfg.get('STEP', args.step))
        args.source = args.source or pcfg.get('SOURCE')
        args.count = args.count if 'COUNT' not in pcfg else int(pcfg.get('COUNT', args.count))
        if not args.key:
            key_path = os.path.join(prof_dir, 'key')
            if os.path.isfile(key_path):
                args.key = key_path

    if not args.host or not args.port or not args.key:
        print('error: --host, --port and --key are required (or via --profile)', file=sys.stderr)
        return
    if args.key and not os.path.isfile(args.key):
        print(f"error: key file not found: {args.key}", file=sys.stderr)
        return

    try:
        from cryptography.hazmat.primitives.asymmetric import x25519
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    except Exception:
        print('error: python cryptography package is required for hpke mode. pip install cryptography', file=sys.stderr)
        sys.exit(1)

    server_pub, client_sk = _load_keys(args.key)

    # AAD: 4x00 | 0x0000 | version(1)
    aad = bytearray(7)
    aad[6] = 1

    # --- HPKE helper functions (RFC 9180 labeled HKDF)
    def suite_id():
        # "HPKE" || kem_id(2) || kdf_id(2) || aead_id(2)
        return b'HPKE' + (0x0020).to_bytes(2, 'big') + (0x0001).to_bytes(2, 'big') + (0x0003).to_bytes(2, 'big')

    def labeled_extract(label: bytes, ikm: bytes, salt: bytes = b'') -> bytes:
        # HKDF-Extract(salt, "HPKE-v1" || suite_id || label || ikm)
        prefix = b'HPKE-v1'
        data = prefix + suite_id() + label + ikm
        if not salt:
            salt = b'\x00' * 32
        return hmac.new(salt, data, hashlib.sha256).digest()

    def labeled_expand(prk: bytes, label: bytes, info: bytes, L: int) -> bytes:
        # HKDF-Expand(prk, I2OSP(L,2) || "HPKE-v1" || suite_id || label || info, L)
        prefix = b'HPKE-v1'
        li = L.to_bytes(2, 'big') + prefix + suite_id() + label + info
        hk = HKDFExpand(algorithm=hashes.SHA256(), length=L, info=li)
        return hk.derive(prk)

    client_pub = client_sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    server_pub_raw = server_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)

    addrs = []
    try:
        addrs = socket.getaddrinfo(args.host, args.port, socket.AF_UNSPEC, socket.SOCK_DGRAM)
    except Exception as e:
        print(f"error: DNS resolution failed: {e}", file=sys.stderr)
        sys.exit(1)
    addrs.sort(key=lambda x: 0 if x[0] == socket.AF_INET6 else 1)
    af, socktype, proto, canonname, sa = addrs[0]
    s = socket.socket(af, socket.SOCK_DGRAM)
    s.settimeout(1.0)
    if args.source:
        # Bind source; for IPv6 allow zone id like "fe80::1%eth0"
        try:
            if af == socket.AF_INET6 and '%' in args.source:
                host, zone = args.source.split('%', 1)
                idx = 0
                try:
                    import socket as sck
                    idx = sck.if_nametoindex(zone)
                except Exception:
                    idx = 0
                s.bind((host, 0, 0, idx))
            else:
                s.bind((args.source, 0))
            if args.verbose:
                print(f"bound to source {args.source}")
        except Exception as e:
            print(f"warn: bind source failed: {e}", file=sys.stderr)

    if args.verbose:
        if af == socket.AF_INET6:
            print(f"dst=[{sa[0]}]:{sa[1]}")
        else:
            print(f"dst={sa[0]}:{sa[1]}")

    ok = 0
    for i in range(max(1, args.count)):
        # Per-send: fresh ephemeral, fresh context, avoids nonce reuse
        eph_sk = x25519.X25519PrivateKey.generate()
        eph_pk = eph_sk.public_key()
        s1 = eph_sk.exchange(server_pub)
        s2 = client_sk.exchange(server_pub)

        enc = eph_pk.public_bytes(Encoding.Raw, PublicFormat.Raw)
        kem_context = enc + server_pub_raw + client_pub

        dh_concat = s1 + s2
        eae_prk = labeled_extract(b'eae_prk', dh_concat)
        shared_secret = labeled_expand(eae_prk, b'shared_secret', kem_context, 32)

        psk_id_hash = labeled_extract(b'psk_id_hash', b'')
        info_hash = labeled_extract(b'info_hash', bytes(aad))
        secret = labeled_extract(b'secret', shared_secret)

        context = bytes([0x02]) + psk_id_hash + info_hash  # Auth mode
        key = labeled_expand(secret, b'key', context, 32)
        base_nonce = labeled_expand(secret, b'base_nonce', context, 12)

        tstep = int(time.time()) // args.step
        nonce = secrets.token_bytes(12)
        version = b"\x01"
        plaintext = version + struct.pack('>I', tstep) + nonce

        aead = ChaCha20Poly1305(key)
        ct = aead.encrypt(base_nonce, plaintext, bytes(aad))

        payload = client_pub + enc + ct

        try:
            sent = s.sendto(payload, sa)
            ok += 1
            if args.verbose:
                src = s.getsockname()
                if af == socket.AF_INET6:
                    print(f"i={i} sent={sent} src=[{src[0]}]:{src[1]} -> dst=[{sa[0]}]:{sa[1]}")
                else:
                    print(f"i={i} sent={sent} src={src[0]}:{src[1]} -> dst={sa[0]}:{sa[1]}")
        except Exception as e:
            print(f"warn: send failed at i={i}: {e}", file=sys.stderr)
        time.sleep(0.2)
    print(f"Sent HPKE SPA packet to {args.host}:{args.port} x{ok}")


def profile_create(args):
    root = _config_root()
    os.makedirs(root, exist_ok=True)
    pdir = _profile_dir_primary(args.name)
    if os.path.isdir(pdir) and not args.overwrite:
        print(f"error: profile '{args.name}' already exists (use --overwrite)", file=sys.stderr)
        sys.exit(1)
    os.makedirs(pdir, exist_ok=True)
    key_dst = os.path.join(pdir, 'key')
    if args.key:
        if not os.path.isfile(args.key):
            print(f"error: key file not found: {args.key}", file=sys.stderr)
            sys.exit(1)
        shutil.copyfile(args.key, key_dst)
    else:
        print('error: provide --key (PEM containing server public and client private)', file=sys.stderr)
        sys.exit(1)
    try:
        os.chmod(key_dst, 0o600)
    except Exception:
        pass
    cfg = {
        'HOST': args.host,
        'PORT': str(args.port),
        'STEP': str(args.step),
        'COUNT': str(args.count)
    }
    if args.source:
        cfg['SOURCE'] = args.source
    _write_kv_file(os.path.join(pdir, 'config'), cfg)
    try:
        os.chmod(pdir, 0o700)
    except Exception:
        pass
    print(f"created profile '{args.name}' in {pdir}")


def profile_list(args):
    printed = set()
    for root in _config_read_roots():
        if not os.path.isdir(root):
            continue
        for entry in sorted(os.listdir(root)):
            if entry in printed:
                continue
            if os.path.isdir(os.path.join(root, entry)):
                print(entry)
                printed.add(entry)


def profile_delete(args):
    pdir = _find_profile_dir(args.name)
    if not os.path.isdir(pdir):
        print(f"error: profile '{args.name}' not found", file=sys.stderr)
        sys.exit(1)
    # Non-interactive default; require --yes to proceed
    if not args.yes:
        print("error: deletion requires --yes", file=sys.stderr)
        sys.exit(1)
    shutil.rmtree(pdir)
    print(f"deleted profile '{args.name}'")


def profile_show(args):
    pdir, cfg = _load_profile(args.name)
    if not cfg:
        print(f"error: profile '{args.name}' not found or empty", file=sys.stderr)
        sys.exit(1)
    print(pdir)
    for k in sorted(cfg.keys()):
        print(f"{k}={cfg[k]}")


def profile_set(args):
    pdir, cfg = _load_profile(args.name)
    if not cfg and not os.path.isdir(pdir):
        print(f"error: profile '{args.name}' not found", file=sys.stderr)
        sys.exit(1)
    cfg = _read_kv_file(os.path.join(pdir, 'config'))
    if args.host is not None:
        cfg['HOST'] = args.host
    if args.port is not None:
        cfg['PORT'] = str(args.port)
    if args.step is not None:
        cfg['STEP'] = str(args.step)
    if args.source is not None:
        if args.source:
            cfg['SOURCE'] = args.source
        elif 'SOURCE' in cfg:
            del cfg['SOURCE']
    if args.count is not None:
        cfg['COUNT'] = str(args.count)
    _write_kv_file(os.path.join(pdir, 'config'), cfg)
    if args.key:
        key_dst = os.path.join(pdir, 'key')
        if not os.path.isfile(args.key):
            print(f"error: key file not found: {args.key}", file=sys.stderr)
            sys.exit(1)
        shutil.copyfile(args.key, key_dst)
        try:
            os.chmod(key_dst, 0o600)
        except Exception:
            pass
    print(f"updated profile '{args.name}'")


def main():
    parser = argparse.ArgumentParser(description='SPALE client tool')
    subparsers = parser.add_subparsers(dest='command')

    # send subcommand
    send_p = subparsers.add_parser('send', help='Send SPA UDP packet')
    send_p.add_argument('--host')
    send_p.add_argument('--port', type=int)
    send_p.add_argument('--step', type=int, default=30)
    send_p.add_argument('--profile', '-p', help='Profile name to load (host/port/key)')
    send_p.add_argument('--key', help='Key file (PEM) containing server public and client private')
    send_p.add_argument('--source', help='Optional source to bind (IPv4 or IPv6)')
    send_p.add_argument('-v', '--verbose', action='store_true')
    send_p.add_argument('--count', type=int, default=1, help='number of sends (default 1)')
    send_p.set_defaults(func=send_cmd)

    # profile subcommands
    prof_p = subparsers.add_parser('profile', help='Manage SPALE client profiles')
    prof_sub = prof_p.add_subparsers(dest='sub')

    def _profile_root_help(args, _p=prof_p):
        _p.print_help()
    prof_p.set_defaults(func=_profile_root_help)

    pc = prof_sub.add_parser('create', help='Create a new profile')
    pc.add_argument('name')
    pc.add_argument('--host', required=True)
    pc.add_argument('--port', required=True, type=int)
    pc.add_argument('--step', type=int, default=30)
    pc.add_argument('--source')
    pc.add_argument('--count', type=int, default=1)
    pc.add_argument('--key', help='Path to key file (PEM) to place into profile')
    pc.add_argument('--overwrite', action='store_true')
    pc.set_defaults(func=profile_create)

    pl = prof_sub.add_parser('list', help='List profiles')
    pl.set_defaults(func=profile_list)

    pd = prof_sub.add_parser('delete', help='Delete a profile')
    pd.add_argument('name')
    pd.add_argument('-y', '--yes', action='store_true', help='Assume yes')
    pd.set_defaults(func=profile_delete)

    ps = prof_sub.add_parser('show', help='Show profile config path and values')
    ps.add_argument('name')
    ps.set_defaults(func=profile_show)

    pset = prof_sub.add_parser('set', help='Update profile config values')
    pset.add_argument('name')
    pset.add_argument('--host')
    pset.add_argument('--port', type=int)
    pset.add_argument('--step', type=int)
    pset.add_argument('--source')
    pset.add_argument('--count', type=int)
    pset.add_argument('--key', help='Replace profile key with provided key file (PEM)')
    pset.set_defaults(func=profile_set)

    # help subcommand (prints help for topics like: send; profile; profile create)
    # Build a map of parsers to target for contextual help
    _parsers = {
        '': parser,
        'send': send_p,
        'profile': prof_p,
        'profile create': pc,
        'profile list': pl,
        'profile delete': pd,
        'profile show': ps,
        'profile set': pset,
    }

    def help_cmd(args, parsers=_parsers):
        parts = args.topic or []
        if not parts:
            parsers[''].print_help()
            return
        key = ' '.join(parts)
        if key in parsers:
            parsers[key].print_help()
            return
        # Try first segment fallback (e.g., 'profile')
        if parts[0] in parsers:
            parsers[parts[0]].print_help()
            return
        print(f"error: unknown help topic: {' '.join(parts)}", file=sys.stderr)
        print("available topics: send, profile, profile create, profile list, profile show, profile set, profile delete")

    help_p = subparsers.add_parser('help', help='Show help for a command')
    help_p.add_argument('topic', nargs='*', help='Command path (e.g., send; profile; profile create)')
    help_p.set_defaults(func=help_cmd)

    argv = sys.argv[1:]
    if not argv:
        parser.print_help()
        return
    if argv[0].startswith('-'):
        argv = ['send'] + argv
    args = parser.parse_args(argv)
    if not hasattr(args, 'func'):
        parser.print_help()
        return
    args.func(args)


if __name__ == '__main__':
    main()


