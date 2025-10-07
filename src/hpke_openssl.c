// SPDX-License-Identifier: MIT
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <dirent.h>
#include <sys/stat.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/kdf.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>

#include "hpke.h"

typedef struct {
    char *client_id;
    char *pub_pem;
    EVP_PKEY *pub_key;
} HpkeClient;

struct HpkeContext {
    char *server_key_pem;
    EVP_PKEY *server_priv;
    HpkeClient *clients;
    size_t num_clients;
};

// --- RFC 9180 HPKE (Auth) helpers for DHKEM(X25519, HKDF-SHA256), KDF=HKDF-SHA256, AEAD=ChaCha20-Poly1305
// Implements LabeledExtract and LabeledExpand per RFC 9180 for the fixed suite only.

#define HPKE_KEM_ID_X25519         0x0020
#define HPKE_KDF_ID_HKDF_SHA256    0x0001
#define HPKE_AEAD_ID_CHACHA20P     0x0003

#define SPA_MAX_PACKET_LEN 256

static void hpke_write_u16_be(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)((v >> 8) & 0xFF);
    p[1] = (uint8_t)(v & 0xFF);
}

static size_t hpke_build_suite_id(uint8_t out[10])
{
    out[0] = 'H'; out[1] = 'P'; out[2] = 'K'; out[3] = 'E';
    hpke_write_u16_be(out + 4, HPKE_KEM_ID_X25519);
    hpke_write_u16_be(out + 6, HPKE_KDF_ID_HKDF_SHA256);
    hpke_write_u16_be(out + 8, HPKE_AEAD_ID_CHACHA20P);
    return 10;
}

// HKDF-Extract(salt, ikm) using HMAC-SHA256
static int hkdf_extract_sha256(const uint8_t *salt, size_t salt_len,
                               const uint8_t *ikm, size_t ikm_len,
                               uint8_t *out_prk, size_t out_len)
{
    if (out_len < 32) return 0;
    unsigned int mdlen = 0;
    uint8_t zero_salt[32];
    const uint8_t *salt_use = salt;
    size_t salt_use_len = salt_len;
    if (!salt || salt_len == 0) {
        memset(zero_salt, 0, sizeof(zero_salt));
        salt_use = zero_salt;
        salt_use_len = sizeof(zero_salt);
    }
    if (!HMAC(EVP_sha256(), salt_use, (int)salt_use_len, ikm, (int)ikm_len, out_prk, &mdlen)) return 0;
    if (mdlen != 32) return 0;
    return 1;
}

// RFC 9180: LabeledExtract(salt, label, ikm) = HKDF-Extract(salt, "HPKE-v1" || suite_id || label || ikm)
static int hpke_labeled_extract(const char *label,
                                const uint8_t *ikm, size_t ikm_len,
                                const uint8_t *salt, size_t salt_len,
                                uint8_t out_prk[32])
{
    uint8_t suite_id[10];
    (void)hpke_build_suite_id(suite_id);
    const char *prefix = "HPKE-v1";
    size_t prefix_len = 7;
    size_t label_len = strlen(label);
    size_t buf_len = prefix_len + sizeof(suite_id) + label_len + ikm_len;
    uint8_t *buf = (uint8_t*)OPENSSL_malloc(buf_len);
    if (!buf) return 0;
    size_t off = 0;
    memcpy(buf + off, prefix, prefix_len); off += prefix_len;
    memcpy(buf + off, suite_id, sizeof(suite_id)); off += sizeof(suite_id);
    memcpy(buf + off, label, label_len); off += label_len;
    if (ikm_len) { memcpy(buf + off, ikm, ikm_len); off += ikm_len; }
    int ok = hkdf_extract_sha256(salt, salt_len, buf, off, out_prk, 32);
    OPENSSL_free(buf);
    return ok;
}

// RFC 9180: LabeledExpand(prk, label, info, L) = HKDF-Expand(prk, I2OSP(L,2)||"HPKE-v1"||suite_id||label||info, L)
static int hpke_labeled_expand(const uint8_t prk[32], const char *label,
                               const uint8_t *info, size_t info_len,
                               uint8_t *out, size_t L)
{
    uint8_t suite_id[10];
    (void)hpke_build_suite_id(suite_id);
    const char *prefix = "HPKE-v1";
    size_t prefix_len = 7;
    size_t label_len = strlen(label);
    // Build labeled_info
    size_t li_len = 2 + prefix_len + sizeof(suite_id) + label_len + info_len;
    uint8_t *li = (uint8_t*)OPENSSL_malloc(li_len);
    if (!li) return 0;
    size_t off = 0;
    li[off++] = (uint8_t)((L >> 8) & 0xFF);
    li[off++] = (uint8_t)(L & 0xFF);
    memcpy(li + off, prefix, prefix_len); off += prefix_len;
    memcpy(li + off, suite_id, sizeof(suite_id)); off += sizeof(suite_id);
    memcpy(li + off, label, label_len); off += label_len;
    if (info_len) { memcpy(li + off, info, info_len); off += info_len; }

    int ok = 0;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) { OPENSSL_free(li); return 0; }
    if (EVP_PKEY_derive_init(pctx) > 0 &&
        EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) > 0 &&
        EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) > 0 &&
        EVP_PKEY_CTX_set1_hkdf_key(pctx, prk, 32) > 0 &&
        EVP_PKEY_CTX_add1_hkdf_info(pctx, li, (int)li_len) > 0) {
        size_t outlen = L;
        if (EVP_PKEY_derive(pctx, out, &outlen) > 0 && outlen == L) ok = 1;
    }
    EVP_PKEY_CTX_free(pctx);
    OPENSSL_free(li);
    return ok;
}

static char *read_file_all(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long n = ftell(f);
    if (n < 0) { fclose(f); return NULL; }
    rewind(f);
    char *buf = (char*)malloc((size_t)n + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t rd = fread(buf, 1, (size_t)n, f);
    fclose(f);
    buf[rd] = '\0';
    if (out_len) *out_len = rd;
    return buf;
}

static int ends_with(const char *s, const char *suf)
{
    size_t ls = strlen(s), lf = strlen(suf);
    if (lf > ls) return 0;
    return strcmp(s + (ls - lf), suf) == 0;
}

static char *basename_no_ext(const char *path)
{
    const char *slash = strrchr(path, '/');
    const char *name = slash ? slash + 1 : path;
    size_t len = strlen(name);
    const char *dot = strrchr(name, '.');
    if (dot && dot > name) len = (size_t)(dot - name);
    char *out = (char*)malloc(len + 1);
    if (!out) return NULL;
    memcpy(out, name, len);
    out[len] = '\0';
    return out;
}

static EVP_PKEY *load_priv_from_pem_string(const char *pem)
{
    BIO *bio = BIO_new_mem_buf((void*)pem, -1);
    if (!bio) return NULL;
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return pkey;
}

static EVP_PKEY *load_pub_from_pem_string(const char *pem)
{
    BIO *bio = BIO_new_mem_buf((void*)pem, -1);
    if (!bio) return NULL;
    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return pkey;
}

HpkeContext* hpke_init(const char *server_key_path, const char *clients_path, char *errbuf, size_t errlen)
{
    HpkeContext *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) { if (errbuf && errlen) snprintf(errbuf, errlen, "oom"); return NULL; }
    size_t sk_len = 0;
    ctx->server_key_pem = read_file_all(server_key_path, &sk_len);
    if (!ctx->server_key_pem || sk_len == 0) {
        if (errbuf && errlen) snprintf(errbuf, errlen, "failed to read server key");
        hpke_free(ctx); return NULL;
    }
    ctx->server_priv = load_priv_from_pem_string(ctx->server_key_pem);
    if (!ctx->server_priv) {
        if (errbuf && errlen) snprintf(errbuf, errlen, "failed to parse server private key");
        hpke_free(ctx); return NULL;
    }
    struct stat st;
    if (stat(clients_path, &st) == 0 && S_ISDIR(st.st_mode)) {
        DIR *dir = opendir(clients_path);
        if (!dir) { if (errbuf && errlen) snprintf(errbuf, errlen, "failed to open clients dir"); hpke_free(ctx); return NULL; }
        size_t cap = 8, n = 0;
        HpkeClient *arr = (HpkeClient*)calloc(cap, sizeof(HpkeClient));
        if (!arr) { closedir(dir); if (errbuf && errlen) snprintf(errbuf, errlen, "oom"); hpke_free(ctx); return NULL; }
        struct dirent *de;
        while ((de = readdir(dir)) != NULL) {
            if (de->d_name[0] == '.') continue;
            if (!ends_with(de->d_name, ".pem")) continue;
            char path[1024];
            snprintf(path, sizeof(path), "%s/%s", clients_path, de->d_name);
            size_t plen = 0;
            char *pem = read_file_all(path, &plen);
            if (!pem || plen == 0) { free(pem); continue; }
            char *cid = basename_no_ext(de->d_name);
            if (!cid) { free(pem); continue; }
            if (n == cap) { cap *= 2; HpkeClient *tmp = (HpkeClient*)realloc(arr, cap * sizeof(HpkeClient)); if (!tmp) { free(cid); free(pem); break; } arr = tmp; }
            arr[n].client_id = cid;
            arr[n].pub_pem = pem;
            n++;
        }
        closedir(dir);
        ctx->clients = arr;
        ctx->num_clients = n;
        if (!ctx->clients || ctx->num_clients == 0) {
            if (errbuf && errlen) snprintf(errbuf, errlen, "no clients in dir");
            hpke_free(ctx); return NULL;
        }
    } else {
        if (errbuf && errlen) snprintf(errbuf, errlen, "clients path must be a directory of PEMs");
        hpke_free(ctx); return NULL;
    }
    // Parse client public keys
    for (size_t i = 0; i < ctx->num_clients; i++) {
        ctx->clients[i].pub_key = load_pub_from_pem_string(ctx->clients[i].pub_pem);
        if (!ctx->clients[i].pub_key) {
            if (errbuf && errlen) snprintf(errbuf, errlen, "failed to parse client pub key for %s", ctx->clients[i].client_id);
            hpke_free(ctx); return NULL;
        }
    }
    return ctx;
}

HpkeContext* hpke_init_from_raw(const uint8_t server_sk[32], const uint8_t client_pk[32], const char *client_id)
{
    if (!server_sk || !client_pk) return NULL;
    HpkeContext *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;
    // Build server private key EVP from raw
    ctx->server_priv = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, server_sk, 32);
    if (!ctx->server_priv) { free(ctx); return NULL; }
    ctx->clients = (HpkeClient*)calloc(1, sizeof(HpkeClient));
    if (!ctx->clients) { EVP_PKEY_free(ctx->server_priv); free(ctx); return NULL; }
    ctx->clients[0].pub_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, client_pk, 32);
    if (!ctx->clients[0].pub_key) { EVP_PKEY_free(ctx->server_priv); free(ctx->clients); free(ctx); return NULL; }
    if (client_id) {
        size_t len = strlen(client_id);
        ctx->clients[0].client_id = (char*)malloc(len + 1);
        if (ctx->clients[0].client_id) { memcpy(ctx->clients[0].client_id, client_id, len + 1); }
    }
    ctx->num_clients = 1;
    return ctx;
}

bool hpke_verify_and_decrypt(HpkeContext *ctx,
                const uint8_t *aad, size_t aad_len,
                const uint8_t *enc_ct, size_t enc_ct_len,
                HpkePayload *out)
{
    if (!ctx || !out || !enc_ct || enc_ct_len < 32 + 32 + 16) return false;
    if (enc_ct_len > SPA_MAX_PACKET_LEN) return false;
    // Packet: client_pub(32) | enc(32) | ct  (client_pub is app metadata; HPKE uses enc||ct)
    const uint8_t *client_pub = enc_ct;
    const uint8_t *enc = enc_ct + 32;
    const uint8_t *ct = enc + 32;
    size_t ct_len = enc_ct_len - 64;

    // Lookup client by public key bytes
    const HpkeClient *cl = NULL;
    for (size_t i = 0; i < ctx->num_clients; i++) {
        uint8_t raw[32]; size_t rawlen = sizeof(raw);
        if (EVP_PKEY_get_raw_public_key(ctx->clients[i].pub_key, raw, &rawlen) == 1 && rawlen == 32) {
            if (memcmp(raw, client_pub, 32) == 0) { cl = &ctx->clients[i]; break; }
        }
    }
    if (!cl || !cl->pub_key) return false;

    // Derive DH values for DHKEM(Auth): DH(skR, pkE) and DH(skR, pkS)
    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, enc, 32);
    if (!peer) return false;
    EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new(ctx->server_priv, NULL);
    if (!dctx) { EVP_PKEY_free(peer); return false; }
    if (EVP_PKEY_derive_init(dctx) <= 0) { EVP_PKEY_free(peer); EVP_PKEY_CTX_free(dctx); return false; }
    if (EVP_PKEY_derive_set_peer(dctx, peer) <= 0) { EVP_PKEY_free(peer); EVP_PKEY_CTX_free(dctx); return false; }
    size_t s1_len = 32;
    uint8_t s1[32];
    if (EVP_PKEY_derive(dctx, s1, &s1_len) <= 0 || s1_len != 32) { EVP_PKEY_free(peer); EVP_PKEY_CTX_free(dctx); return false; }
    EVP_PKEY_free(peer);
    EVP_PKEY_CTX_free(dctx);

    // DH with client static public key
    EVP_PKEY_CTX *dctx2 = EVP_PKEY_CTX_new(ctx->server_priv, NULL);
    if (!dctx2) return false;
    if (EVP_PKEY_derive_init(dctx2) <= 0) { EVP_PKEY_CTX_free(dctx2); return false; }
    if (EVP_PKEY_derive_set_peer(dctx2, cl->pub_key) <= 0) { EVP_PKEY_CTX_free(dctx2); return false; }
    size_t s2_len = 32;
    uint8_t s2[32];
    if (EVP_PKEY_derive(dctx2, s2, &s2_len) <= 0 || s2_len != 32) { EVP_PKEY_CTX_free(dctx2); return false; }
    EVP_PKEY_CTX_free(dctx2);

    // Build KEM context: enc || pkR || pkS  (all raw 32-byte keys)
    uint8_t pkR_raw[32]; size_t pkR_len = sizeof(pkR_raw);
    if (EVP_PKEY_get_raw_public_key(ctx->server_priv, pkR_raw, &pkR_len) != 1 || pkR_len != 32) return false;
    uint8_t kem_context[32 + 32 + 32];
    size_t kem_ctx_len = 0;
    memcpy(kem_context + kem_ctx_len, enc, 32); kem_ctx_len += 32;
    memcpy(kem_context + kem_ctx_len, pkR_raw, 32); kem_ctx_len += 32;
    memcpy(kem_context + kem_ctx_len, client_pub, 32); kem_ctx_len += 32;

    // DH concat
    uint8_t dh_concat[64];
    memcpy(dh_concat, s1, 32);
    memcpy(dh_concat + 32, s2, 32);

    // DHKEM(Auth) shared_secret via labeled extract/expand
    uint8_t eae_prk[32];
    if (!hpke_labeled_extract("eae_prk", dh_concat, sizeof(dh_concat), NULL, 0, eae_prk)) return false;
    uint8_t shared_secret[32];
    if (!hpke_labeled_expand(eae_prk, "shared_secret", kem_context, kem_ctx_len, shared_secret, sizeof(shared_secret))) return false;

    // Key schedule (Auth mode): psk, psk_id are empty; info is application context (use provided aad)
    uint8_t zero[1] = {0}; (void)zero;
    uint8_t psk_id_hash[32];
    if (!hpke_labeled_extract("psk_id_hash", NULL, 0, NULL, 0, psk_id_hash)) return false;
    uint8_t info_hash[32];
    if (!hpke_labeled_extract("info_hash", aad, aad_len, NULL, 0, info_hash)) return false;
    uint8_t secret[32];
    if (!hpke_labeled_extract("secret", shared_secret, sizeof(shared_secret), NULL, 0, secret)) return false;

    // context = mode(1 byte) || psk_id_hash (32) || info_hash (32)
    uint8_t context[1 + 32 + 32];
    size_t context_len = 0;
    context[context_len++] = 0x02; // Auth mode
    memcpy(context + context_len, psk_id_hash, 32); context_len += 32;
    memcpy(context + context_len, info_hash, 32); context_len += 32;

    uint8_t key[32];
    if (!hpke_labeled_expand(secret, "key", context, context_len, key, sizeof(key))) return false;
    uint8_t base_nonce[12];
    if (!hpke_labeled_expand(secret, "base_nonce", context, context_len, base_nonce, sizeof(base_nonce))) return false;
    // exporter_secret not used

    if (ct_len < 16) return false;
    size_t pt_max = ct_len - 16;
    uint8_t *pt = (uint8_t*)OPENSSL_malloc(pt_max);
    if (!pt) return false;

    EVP_CIPHER_CTX *cctx = EVP_CIPHER_CTX_new();
    int ok = 0;
    if (cctx &&
        EVP_DecryptInit_ex(cctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) > 0 &&
        EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) > 0 &&
        EVP_DecryptInit_ex(cctx, NULL, NULL, key, base_nonce) > 0) {
        int len = 0, total = 0;
        if (aad && aad_len) {
            if (EVP_DecryptUpdate(cctx, NULL, &len, aad, (int)aad_len) <= 0) goto done;
        }
        if (EVP_DecryptUpdate(cctx, pt, &len, ct, (int)(ct_len - 16)) <= 0) goto done;
        total += len;
        if (EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_AEAD_SET_TAG, 16, (void *)(ct + ct_len - 16)) <= 0) goto done;
        if (EVP_DecryptFinal_ex(cctx, pt + total, &len) <= 0) goto done;
        total += len;
        // parse plaintext: version(1) | time_step(4) | nonce(12)
        if (total != 1 + 4 + 12) goto done;
        uint8_t ver = pt[0];
        if (ver != 0x01) goto done;
        memset(out, 0, sizeof(*out));
        out->client_pub_len = 32;
        memcpy(out->client_pub, client_pub, 32);
        const uint8_t *tp = pt + 1;
        out->time_step = (uint32_t)tp[0] << 24 | (uint32_t)tp[1] << 16 | (uint32_t)tp[2] << 8 | (uint32_t)tp[3];
        memcpy(out->nonce, tp + 4, 12);
        out->nonce_len = 12;
        if (cl->client_id) {
            size_t cid_len = strlen(cl->client_id);
            if (cid_len > sizeof(out->client_id) - 1) cid_len = sizeof(out->client_id) - 1;
            memcpy(out->client_id, cl->client_id, cid_len);
            out->client_id[cid_len] = '\0';
            out->client_id_len = (uint32_t)cid_len;
        }

        // client already validated by pubkey match above

        // Validate time step window ±1
        time_t now = time(NULL);
        uint32_t tstep = (uint32_t)(now / 30);
        if (!(out->time_step == tstep || out->time_step + 1 == tstep || (tstep > 0 && out->time_step == tstep - 1))) goto done;
        ok = 1;
    }
done:
    if (cctx) EVP_CIPHER_CTX_free(cctx);
    if (pt) { OPENSSL_cleanse(pt, pt_max); }
    OPENSSL_free(pt);
    return ok ? true : false;
}

void hpke_free(HpkeContext *ctx)
{
    if (!ctx) return;
    free(ctx->server_key_pem);
    if (ctx->server_priv) EVP_PKEY_free(ctx->server_priv);
    if (ctx->clients) {
        for (size_t i = 0; i < ctx->num_clients; i++) {
            free(ctx->clients[i].client_id);
            free(ctx->clients[i].pub_pem);
            if (ctx->clients[i].pub_key) EVP_PKEY_free(ctx->clients[i].pub_key);
        }
        free(ctx->clients);
    }
    free(ctx);
}


