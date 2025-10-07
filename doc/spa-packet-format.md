SPA Packet Format (HPKE Auth Mode)

Overview
The SPA packet is a single UDP datagram that authenticates a client and authorizes access by writing an allowlist entry into eBPF maps. The payload uses HPKE (RFC 9180) with DHKEM(X25519, HKDF-SHA256), KDF=HKDF-SHA256, AEAD=ChaCha20-Poly1305, in authenticated mode (Auth).

Wire Layout
The UDP payload bytes are laid out as follows:

- client_pub: 32 bytes (X25519 public key of the client; metadata used to identify client and select key)
- enc: 32 bytes (KEM encapsulated key; ephemeral X25519 public key)
- ct: N bytes (AEAD ciphertext || 16-byte tag)

Plaintext Structure
After decryption, the plaintext is exactly 17 bytes:

- version: 1 byte
  - currently 0x01
- time_step: 4 bytes, big-endian unsigned
  - value is floor(current_unix_time / 30)
- nonce: 12 bytes
  - random per message

Associated Data (AAD)
The implementation uses a 7-byte AAD value:

- aad[0..5] = 0x00
- aad[6] = 0x01 (version)

HPKE Suite and Derivations
- KEM: DHKEM(X25519, HKDF-SHA256) (kem_id=0x0020)
- KDF: HKDF-SHA256 (kdf_id=0x0001)
- AEAD: ChaCha20-Poly1305 (aead_id=0x0003)

Label conventions follow RFC 9180 using LabeledExtract/LabeledExpand with prefix "HPKE-v1" and suite_id = "HPKE" || kem_id || kdf_id || aead_id.

Key Schedule (Auth Mode)
Given:
- enc: ephemeral public key (sender -> receiver)
- pkR: server public key (receiver)
- pkS: client public key (sender static)
- s1 = DH(skR, pkE)
- s2 = DH(skR, pkS)
- kem_context = enc || pkR || pkS

Derive:
- eae_prk  = LabeledExtract("eae_prk", s1 || s2)
- shared   = LabeledExpand(eae_prk, "shared_secret", kem_context, 32)
- psk_id_hash = LabeledExtract("psk_id_hash", "")
- info_hash   = LabeledExtract("info_hash", AAD)
- secret      = LabeledExtract("secret", shared)
- context     = 0x02 || psk_id_hash || info_hash  (0x02 = Auth mode)
- key         = LabeledExpand(secret, "key", context, 32)
- base_nonce  = LabeledExpand(secret, "base_nonce", context, 12)

AEAD Usage
- Encrypt: ct = ChaCha20-Poly1305(key, base_nonce, plaintext, AAD)
- Decrypt verifies the tag; failure rejects the SPA packet.

Client Identification and Authorization
- The first 32 bytes (client_pub) are matched against loaded client public keys to identify the client and bind authentication to a known identity.
- On successful decrypt and validation, userspace inserts allowlist entries into eBPF maps for the sender’s IP and selected destination ports.

Replay Protection
- The userspace daemon maintains a fixed-size, in-memory replay cache keyed by (client_pub, time_step, nonce). A packet that repeats all three fields is treated as a replay and discarded.
- time_step must match current step within a ±1 window.

Versioning
- Packet version is currently 0x01. AAD also embeds this version in aad[6]. Future versions should update both places and remain distinct.

IPv4/IPv6 Considerations
- The SPA listener binds on both IPv4 and IPv6 and applies the same packet format.
- The eBPF layer maintains separate IPv4 and IPv6 allowlists keyed by source and destination port.

Security Notes
- The format fixes the HPKE suite; changing algorithms requires coordinated updates on both sender and receiver.
- The 12-byte nonce is inside the plaintext and not used as the AEAD nonce; AEAD uses the derived base_nonce and AAD. The internal nonce serves for replay uniqueness alongside time_step.

Test/Sender Interop
- The provided `tools/spa_send.py` implements the same suite and packet layout and can be used to generate SPA packets.


