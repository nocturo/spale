// SPDX-License-Identifier: MIT
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef struct HpkeContext HpkeContext;

typedef struct {
	uint8_t client_pub[32];
	uint32_t client_pub_len; /* should be 32 */
	uint32_t time_step;
	uint8_t nonce[16];
	uint32_t nonce_len;
    /* Matched client identity (basename of PEM without extension when loading from directory) */
    char client_id[64];
    uint32_t client_id_len;
} HpkePayload;

// Initialize HPKE context: load server private key and clients public keys mapping
// server_key_path: path to server private key (PEM)
// clients_path: directory of client public key PEMs ("<id>.pem")
HpkeContext* hpke_init(const char *server_key_path, const char *clients_path, char *errbuf, size_t errlen);

// Test/support constructor for fuzzing: initialize context from raw keys
// server_sk: 32-byte X25519 private key
// client_pk: 32-byte X25519 public key
// client_id: optional identifier string (may be NULL)
HpkeContext* hpke_init_from_raw(const uint8_t server_sk[32], const uint8_t client_pk[32], const char *client_id);

// Verify and decrypt a single packet using HPKE (sender-auth mode).
// aad: pointer and length for associated data
// enc_ct: pointer to incoming datagram formatted as client_pub(32) || enc(32) || ct
// On success returns true and fills out payload.
bool hpke_verify_and_decrypt(HpkeContext *ctx,
				const uint8_t *aad, size_t aad_len,
				const uint8_t *enc_ct, size_t enc_ct_len,
				HpkePayload *out);

void hpke_free(HpkeContext *ctx);


