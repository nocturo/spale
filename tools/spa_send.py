#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
import argparse, hmac, hashlib, struct, socket, time, sys
import secrets

"""HPKE sender utility for SPALE."""

def main():
    p = argparse.ArgumentParser(description='Send SPA UDP packet')
    p.add_argument('--host', required=True)
    p.add_argument('--port', type=int, required=True)
    p.add_argument('--step', type=int, default=30)
    # HPKE options
    p.add_argument('--server-pk', help='Server public key (PEM)')
    p.add_argument('--client-sk', help='Client private key (PEM)')
    # Net/options
    p.add_argument('--source', help='Optional source to bind (IPv4 or IPv6)')
    p.add_argument('-v', '--verbose', action='store_true')
    p.add_argument('--count', type=int, default=1, help='number of sends (default 1)')
    args = p.parse_args()

    payload = b""
    # RFC 9180 HPKE Auth mode (DHKEM(X25519, HKDF-SHA256), KDF=HKDF-SHA256, AEAD=ChaCha20-Poly1305)
    if not args.server_pk:
        print('error: --server-pk required', file=sys.stderr)
        sys.exit(1)
    if not args.client_sk:
        print('error: --client-sk required', file=sys.stderr)
        sys.exit(1)
    try:
        from cryptography.hazmat.primitives.asymmetric import x25519
        from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key, Encoding, PublicFormat
        from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    except Exception as e:
        print('error: python cryptography package is required for hpke mode. pip install cryptography', file=sys.stderr)
        sys.exit(1)

    # Load server public key (PEM)
    try:
        with open(args.server_pk, 'rb') as f:
            server_pem = f.read()
        server_pub = load_pem_public_key(server_pem)
        if not isinstance(server_pub, x25519.X25519PublicKey):
            raise ValueError('server public key must be X25519')
    except Exception as e:
        print(f'error: failed to load server public key: {e}', file=sys.stderr)
        sys.exit(1)

    # Load client static private key (X25519)
    try:
        with open(args.client_sk, 'rb') as f:
            client_pem = f.read()
        client_sk = load_pem_private_key(client_pem, password=None)
        if not isinstance(client_sk, x25519.X25519PrivateKey):
            raise ValueError('client private key must be X25519')
    except Exception as e:
        print(f'error: failed to load client private key: {e}', file=sys.stderr)
        sys.exit(1)

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

    # Load raw keys
    client_pub = client_sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    server_pub_raw = server_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)

    # Resolve host for IPv4 or IPv6
    addrs = []
    try:
        addrs = socket.getaddrinfo(args.host, args.port, socket.AF_UNSPEC, socket.SOCK_DGRAM)
    except Exception as e:
        print(f"error: DNS resolution failed: {e}", file=sys.stderr)
        sys.exit(1)
    # Prefer IPv6 first, then IPv4
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
    try:
        s.connect(sa)
    except Exception as e:
        print(f"error: connect failed: {e}", file=sys.stderr)
        sys.exit(1)

    src = s.getsockname()
    if args.verbose:
        if af == socket.AF_INET6:
            print(f"src=[{src[0]}]:{src[1]} -> dst=[{sa[0]}]:{sa[1]}")
        else:
            print(f"src={src[0]}:{src[1]} -> dst={sa[0]}:{sa[1]}")

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
            sent = s.send(payload)
            ok += 1
            if args.verbose:
                print(f"i={i} sent={sent}")
        except Exception as e:
            print(f"warn: send failed at i={i}: {e}", file=sys.stderr)
        time.sleep(0.2)
    print(f"Sent HPKE SPA packet to {args.host}:{args.port} x{ok}")

if __name__ == '__main__':
    main()


