#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

import argparse
import os
import sys
import stat
import shutil
import platform


def _default_paths():
    # Mirror defaults from include/paths.h
    server_key = "/etc/spale/server.key"
    clients_dir = "/etc/spale/clients"
    return server_key, clients_dir


def _ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)


def _chmod_600(path: str):
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except Exception:
        pass


def _write_file(path: str, data: bytes, mode: int = 0o600):
    d = os.path.dirname(path)
    if d and not os.path.isdir(d):
        os.makedirs(d, exist_ok=True)
    with open(path, 'wb') as f:
        f.write(data)
    try:
        os.chmod(path, mode)
    except Exception:
        pass


def _generate_x25519():
    try:
        from cryptography.hazmat.primitives.asymmetric import x25519
    except Exception:
        print('error: python cryptography package is required. pip install cryptography', file=sys.stderr)
        sys.exit(1)
    sk = x25519.X25519PrivateKey.generate()
    pk = sk.public_key()
    return sk, pk


def _pem_priv(sk):
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
    return sk.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


def _pem_pub(pk):
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    return pk.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)


def cmd_server(args):
    sk, pk = _generate_x25519()
    pem_priv = _pem_priv(sk)
    pem_pub = _pem_pub(pk)

    if args.install:
        server_key_path, _ = _default_paths()
        _write_file(server_key_path, pem_priv, 0o600)
        print(f"wrote server private key: {server_key_path}")
        # Also write public alongside for convenience
        pub_out = server_key_path + ".pub"
        _write_file(pub_out, pem_pub, 0o644)
        print(f"wrote server public key: {pub_out}")
    else:
        out = args.out or os.getcwd()
        _ensure_dir(out)
        key_path = os.path.join(out, 'server.key')
        _write_file(key_path, pem_priv, 0o600)
        print(f"wrote server private key: {key_path}")
        pub_path = os.path.join(out, 'server.pub')
        _write_file(pub_path, pem_pub, 0o644)
        print(f"wrote server public key: {pub_path}")


def cmd_client(args):
    if not args.name:
        print('error: --name is required for client key', file=sys.stderr)
        sys.exit(1)
    name = args.name
    sk, pk = _generate_x25519()
    pem_priv = _pem_priv(sk)
    pem_pub = _pem_pub(pk)

    # Client install target: public in clients/<NAME>.pem; private safe location or bundle
    if args.install:
        _, clients_dir = _default_paths()
        _ensure_dir(clients_dir)
        dst_pub = os.path.join(clients_dir, f"{name}.pem")
        _write_file(dst_pub, pem_pub, 0o644)
        print(f"installed client public key: {dst_pub}")
        if args.bundle:
            # Bundle for sender: server public + client private in one file
            server_pub_pem = _find_server_pub_for_bundle(args)
            bundle = _compose_bundle(server_pub_pem, pem_priv)
            # Do not write into /etc/spale; write to current dir by default
            out_dir = args.out or os.getcwd()
            _ensure_dir(out_dir)
            bundle_path = os.path.join(out_dir, f"{name}.key")
            _write_file(bundle_path, bundle, 0o600)
            print(f"wrote client bundle (server pub + client priv): {bundle_path}")
    else:
        out = args.out or os.getcwd()
        _ensure_dir(out)
        # Public file to ship to server
        pub_path = os.path.join(out, f"{name}.pem")
        _write_file(pub_path, pem_pub, 0o644)
        print(f"wrote client public key: {pub_path}")
        # Private key for client sender usage
        priv_path = os.path.join(out, f"{name}.key")
        _write_file(priv_path, pem_priv, 0o600)
        print(f"wrote client private key: {priv_path}")
        if args.bundle:
            server_pub_pem = _find_server_pub_for_bundle(args)
            bundle = _compose_bundle(server_pub_pem, pem_priv)
            bundle_path = os.path.join(out, f"{name}.bundle")
            _write_file(bundle_path, bundle, 0o600)
            print(f"wrote client bundle (server pub + client priv): {bundle_path}")


def _compose_bundle(server_pub_pem: bytes, client_priv_pem: bytes) -> bytes:
    # tools/spa_send.py expects a file containing both server public and client private PEM blocks
    # in any order. We place server public first for readability.
    return server_pub_pem + b"\n" + client_priv_pem


def _find_server_pub_for_bundle(args) -> bytes:
    # Try explicit path first
    if args.server_pub and os.path.isfile(args.server_pub):
        with open(args.server_pub, 'rb') as f:
            return f.read()
    # Try alongside installed server.key
    server_key_path, _ = _default_paths()
    default_pub = server_key_path + ".pub"
    if os.path.isfile(default_pub):
        with open(default_pub, 'rb') as f:
            return f.read()
    # If server.key exists, derive public from it
    if os.path.isfile(server_key_path):
        try:
            from cryptography.hazmat.primitives.serialization import load_pem_private_key
            with open(server_key_path, 'rb') as f:
                sk = load_pem_private_key(f.read(), password=None)
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
            pk = sk.public_key()
            return pk.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        except Exception:
            pass
    print('error: could not find server public key for bundle; pass --server-pub', file=sys.stderr)
    sys.exit(1)


def build_parser():
    p = argparse.ArgumentParser(description='Generate HPKE X25519 keys for spale server and clients')
    sub = p.add_subparsers(dest='cmd')

    ps = sub.add_parser('server', help='generate server private key (X25519)')
    ps.add_argument('--install', action='store_true', help='write to /etc/spale/server.key and server.key.pub')
    ps.add_argument('--out', help='output directory when not using --install')
    ps.set_defaults(func=cmd_server)

    pc = sub.add_parser('client', help='generate client keys (public .pem and private .key)')
    pc.add_argument('--name', required=True, help='client name (used for public key filename <name>.pem)')
    pc.add_argument('--bundle', action='store_true', help='also emit bundle file for spa_send.py (server pub + client priv)')
    pc.add_argument('--server-pub', help='path to server public key PEM for bundling')
    pc.add_argument('--install', action='store_true', help='install public key into /etc/spale/clients/<name>.pem')
    pc.add_argument('--out', help='output directory for files when not using --install')
    pc.set_defaults(func=cmd_client)

    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.cmd:
        parser.print_help()
        return 1
    return args.func(args) or 0


if __name__ == '__main__':
    sys.exit(main())


