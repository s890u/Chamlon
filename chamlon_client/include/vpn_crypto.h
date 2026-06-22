#ifndef VPN_CRYPTO_H
#define VPN_CRYPTO_H

#include "vpn_common.h"
#include <stddef.h>

void derive_two_keys(const uint8_t *shared, size_t shared_len,
                     const uint8_t *context, size_t context_len,
                     uint8_t out1[AEAD_KEY_LEN], uint8_t out2[AEAD_KEY_LEN]);

int aead_encrypt(const uint8_t key[AEAD_KEY_LEN], const uint8_t session_id[SESSION_ID_LEN],
                 uint64_t seq, const uint8_t *pt, size_t ptlen,
                 uint8_t *out, size_t *outlen);

int aead_decrypt(const uint8_t key[AEAD_KEY_LEN], const uint8_t session_id[SESSION_ID_LEN],
                 uint64_t seq, const uint8_t *ct, size_t ctlen,
                 uint8_t *out, size_t *outlen);

void build_nonce(uint8_t nonce[AEAD_NONCE_LEN], const uint8_t key[AEAD_KEY_LEN], uint64_t seq);

#endif // VPN_CRYPTO_H
