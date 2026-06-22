#ifndef CONFIG_H
#define CONFIG_H

#include <sodium.h>

/* Buffer and packet sizes */
#define BUFFER_SIZE 1600
#define MAX_CLIENTS 250
#define PACKET_LENGTH 1024

/* Protocol magic and version */
#define PKT_MAGIC 0x77E1DAu
#define PKT_VERSION 1
#define PKT_TYPE_HANDSHAKE 222
#define PKT_TYPE_DATA 111

/* Packet control types */
#define PKT_CTRL_KEEPALIVE 0x02
#define PKT_CTRL_DISCONNECT 0x03
#define PKT_DUMMY 0xFF

/* Cryptography constants */
#define PUBKEY_LEN crypto_kx_PUBLICKEYBYTES
#define PRIVKEY_LEN crypto_kx_SECRETKEYBYTES
#define DH_LEN 32
#define SESSION_ID_LEN 16
#define AEAD_KEY_LEN crypto_aead_chacha20poly1305_ietf_KEYBYTES
#define AEAD_NONCE_LEN crypto_aead_chacha20poly1305_ietf_NPUBBYTES
#define MAC_LEN crypto_aead_chacha20poly1305_ietf_ABYTES

#define CONFIG_REHANDSHAKE_INTERVAL_SEC  900
#define CONFIG_REHANDSHAKE_BYTES_LIMIT   (1ULL << 30)
#define CONFIG_REHANDSHAKE_SEQ_LIMIT     (1ULL << 32)

/* Replay attack prevention */
#define SLIDING_WINDOW_SIZE 128

/* Session timeout (seconds) */
#define SESSION_TIMEOUT_SEC 120

#endif // CONFIG_H
