#ifndef VPN_HANDSHAKE_H
#define VPN_HANDSHAKE_H

#include <stdint.h>
#include <signal.h>
#include <netinet/in.h>
#include "vpn_common.h"
#include "vpn_crypto.h"
#include "vpn_sender_thread.h"
#include "vpn_replay_window.h"
#include "../include/session.h"

/**
 * Buffer for storing DATA packets received during rehandshake.
 * These packets are encrypted with old keys and need to be
 * processed after rehandshake completes.
 */
#define REHANDSHAKE_BUFFER_SIZE 128  /* max buffered packets */

typedef struct {
    uint8_t *pkt_data;
    ssize_t pkt_len;
} buffered_pkt_t;

typedef struct {
    buffered_pkt_t pkts[REHANDSHAKE_BUFFER_SIZE];
    int count;
} rehandshake_buffer_t;

int client_handshake(int sock,
                     struct sockaddr_in *server_addr,
                     const uint8_t server_pk[PUBKEY_LEN],
                     uint8_t session_id[SESSION_ID_LEN],
                     uint8_t k_send[AEAD_KEY_LEN],
                     uint8_t k_recv[AEAD_KEY_LEN],
                     uint8_t assigned_ip[4],
                     rehandshake_buffer_t *buffer);

/**
 * Process buffered packets after rehandshake with old keys.
 * Returns number of packets successfully processed.
 */
int process_rehandshake_buffer(int tun_fd, 
                               const uint8_t old_k_recv[AEAD_KEY_LEN],
                               rehandshake_buffer_t *buffer);

/**
 * Initialize empty buffer
 */
void rehandshake_buffer_init(rehandshake_buffer_t *buffer);

/**
 * Free all buffered packets
 */
void rehandshake_buffer_free(rehandshake_buffer_t *buffer);

/**
 * rehandshake_client_with_state:
 * Performs rehandshake with state machine logic.
 * Returns: 0 = success, -1 = failure (caller should disconnect)
 * 
 * State transitions:
 * - READY -> IN_PROGRESS -> success -> READY (reset attempts)
 * - READY -> IN_PROGRESS -> failure -> BACKOFF (incr attempts)
 * - BACKOFF -> IN_PROGRESS (after backoff expires)
 * - Consecutive failures >= 5 -> caller should disconnect
 */
int rehandshake_client_with_state(int sock,
                                   struct sockaddr_in *server_addr,
                                   const uint8_t server_pk[PUBKEY_LEN],
                                   server_t *srv,
                                   sender_args_t *sender_args,
                                   replay_window_t *rw,
                                   rehandshake_buffer_t *buffer);

/**
 * Should rehandshake be attempted?
 * Returns 1 if yes, 0 if in backoff/in-progress, -1 if max failures reached (disconnect)
 */
int should_attempt_rehandshake(server_t *srv);

extern volatile sig_atomic_t g_rehandshake_in_progress;

#endif
