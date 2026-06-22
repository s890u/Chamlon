#ifndef HANDSHAKE_H
#define HANDSHAKE_H

#include <stdint.h>
#include <netinet/in.h>
#include "vpn_common.h"
#include "vpn_crypto.h"

/**
 * load_or_create_server_key:
 * Loads the server's static key pair from file if found else it generates and saves a new one.
 * Returns 0 on success, -1 on error.
 */
#define ED25519_PK_LEN crypto_sign_PUBLICKEYBYTES

int load_or_create_server_key(const char *path,
                               uint8_t sk[PRIVKEY_LEN],
                               uint8_t pk[PUBKEY_LEN],
                               uint8_t sign_pk[ED25519_PK_LEN]);
/**
 * handle_msg1:
 * Processes the initial MSG1 handshake message from a client.
 * Establishes a new session and sends back MSG2.
 * Returns 0 on success, -1 on error.
 */
int handle_msg1(int udp_sock, uint8_t *msg1, ssize_t len, struct sockaddr_in *src, uint8_t server_sk[PRIVKEY_LEN]);

int handle_rehandshake_msg1(int udp_sock, uint8_t *msg1, ssize_t len, struct sockaddr_in *src, uint8_t server_sk[PRIVKEY_LEN]);

#endif // HANDSHAKE_H
