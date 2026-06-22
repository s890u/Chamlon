#include "vpn_crypto.h"
#include <string.h>
#include <sodium.h>

void derive_two_keys(const uint8_t *shared, size_t shared_len,
                     const uint8_t *context, size_t context_len,
                     uint8_t out1[AEAD_KEY_LEN], uint8_t out2[AEAD_KEY_LEN]) {
    uint8_t tmp[64];
    crypto_generichash_state st;
    crypto_generichash_init(&st, NULL, 0, sizeof(tmp));
    crypto_generichash_update(&st, shared, shared_len);
    uint8_t c1 = 1; crypto_generichash_update(&st, &c1, 1);
    crypto_generichash_update(&st, context, context_len);
    crypto_generichash_final(&st, tmp, sizeof(tmp));
    memcpy(out1, tmp, AEAD_KEY_LEN);

    crypto_generichash_init(&st, NULL, 0, sizeof(tmp));
    crypto_generichash_update(&st, tmp, AEAD_KEY_LEN);
    uint8_t c2 = 2; crypto_generichash_update(&st, &c2, 1);
    crypto_generichash_update(&st, context, context_len);
    crypto_generichash_final(&st, tmp, sizeof(tmp));
    memcpy(out2, tmp, AEAD_KEY_LEN);

    sodium_memzero(tmp, sizeof(tmp));
}

void build_nonce(uint8_t nonce[AEAD_NONCE_LEN], const uint8_t key[AEAD_KEY_LEN], uint64_t seq) {
    memcpy(nonce, key, 4);
    for (int i = 0; i < 8; ++i) nonce[4 + i] = (seq >> (56 - 8*i)) & 0xFF;
}

int aead_encrypt(const uint8_t key[AEAD_KEY_LEN], const uint8_t session_id[SESSION_ID_LEN],
                 uint64_t seq, const uint8_t *pt, size_t ptlen,
                 uint8_t *out, size_t *outlen) {
    uint8_t nonce[AEAD_NONCE_LEN];
    build_nonce(nonce, key, seq);
    uint8_t ad[SESSION_ID_LEN + 8];
    memcpy(ad, session_id, SESSION_ID_LEN);
    for (int i = 0; i < 8; ++i) ad[SESSION_ID_LEN + i] = (seq >> (56 - 8*i)) & 0xFF;
    unsigned long long clen = 0;
    if (crypto_aead_chacha20poly1305_ietf_encrypt(out, &clen, pt, ptlen, ad, sizeof(ad), NULL, nonce, key) != 0) return -1;
    *outlen = (size_t)clen;
    return 0;
}

int aead_decrypt(const uint8_t key[AEAD_KEY_LEN], const uint8_t session_id[SESSION_ID_LEN],
                 uint64_t seq, const uint8_t *ct, size_t ctlen,
                 uint8_t *out, size_t *outlen) {
    uint8_t nonce[AEAD_NONCE_LEN];
    build_nonce(nonce, key, seq);
    uint8_t ad[SESSION_ID_LEN + 8];
    memcpy(ad, session_id, SESSION_ID_LEN);
    for (int i = 0; i < 8; ++i) ad[SESSION_ID_LEN + i] = (seq >> (56 - 8*i)) & 0xFF;
    unsigned long long mlen = 0;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(out, &mlen, NULL, ct, ctlen, ad, sizeof(ad), nonce, key) != 0) return -1;
    *outlen = (size_t)mlen;
    return 0;
}
