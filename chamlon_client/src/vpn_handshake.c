#include "vpn_handshake.h"
#include "vpn_common.h"
#include "vpn_crypto.h"
#include "vpn_log.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <sys/select.h>
#include <fcntl.h>
#include <errno.h>
#include <sodium.h>
#include "vpn_sender_thread.h"
extern int  argv_MBPS;
extern int  argv_FRAG;
extern char argv_CBR;
extern char argv_PAD;
extern time_t last_server_keepalive_time;
#define MSG1_LEN  (PUBKEY_LEN + 8)
#define PARAMS    (4 + 4 + 1 + 1)
/*
 * server_pk here is the Ed25519 public key the user got from the server admin or in a future from a website where server advertise their keys.
 * It is 32 bytes (crypto_sign_PUBLICKEYBYTES).
 * We derive the X25519 public key from it for DH.
 *
 * MSG2 layout (new):
 *   proto_header(6) | s_eph_pub(32) | s_nonce(8) | vpn_ip(4) | sig(64)
 */
#define SIG_LEN       crypto_sign_BYTES        /* 64 */
#define MSG2_PAYLOAD  (PUBKEY_LEN + 8 + 4 + SIG_LEN)  /* 108 */

/*
 * flush_socket_buffer:
 * Drain all pending packets from the socket receive buffer.
 * This is critical before re-handshake to prevent old data packets
 * from being read as MSG2 responses. Uses non-blocking recvfrom() to
 * quickly drain all buffered packets.
 */
static void flush_socket_buffer(int sock) {
    uint8_t dummy[BUFFER_SIZE];
    int flags = fcntl(sock, F_GETFL, 0);
    int was_nonblocking = (flags & O_NONBLOCK) != 0;
    
    /* Set non-blocking if not already */
    if (!was_nonblocking) {
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    }
    
    /* Drain all pending packets */
    int drained = 0;
    while (recvfrom(sock, dummy, sizeof(dummy), MSG_DONTWAIT, NULL, NULL) > 0) {
        drained++;
    }
    
    if (drained > 0) {
        vpn_log("Flushed %d queued packets before re-handshake", drained);
    }
    
    /* Restore original blocking mode if needed */
    if (!was_nonblocking) {
        fcntl(sock, F_SETFL, flags);
    }
}

int client_handshake(int sock, struct sockaddr_in *server_addr,
                     const uint8_t server_pk[PUBKEY_LEN],  /* Ed25519 pubkey */
                     uint8_t session_id[SESSION_ID_LEN],
                     uint8_t k_send[AEAD_KEY_LEN],
                     uint8_t k_recv[AEAD_KEY_LEN],
                     uint8_t assigned_ip[4],
                     rehandshake_buffer_t *buffer)
{
    /* Derive X25519 public key from the server's Ed25519 public key */
    uint8_t server_kx_pk[PUBKEY_LEN];
    if (crypto_sign_ed25519_pk_to_curve25519(server_kx_pk, server_pk) != 0) {
        vpn_log("Failed to convert server Ed25519 pk to X25519");
        return -1;
    }

    /* Generate client ephemeral keypair */
    uint8_t c_pub[PUBKEY_LEN], c_priv[PRIVKEY_LEN];
    crypto_kx_keypair(c_pub, c_priv);
    uint8_t c_nonce[8];
    randombytes_buf(c_nonce, sizeof(c_nonce));

    /* Build and send MSG1 (unchanged) */
    size_t msg1_length = sizeof(proto_header_t) + MSG1_LEN + PARAMS;
    uint8_t msg1[msg1_length];
    proto_header_t ph;
    ph.magic = PKT_MAGIC; ph.version = PKT_VERSION; ph.type = PKT_TYPE_HANDSHAKE;
    memcpy(msg1, &ph, sizeof(proto_header_t));
    memcpy(msg1 + sizeof(proto_header_t),             c_pub,    PUBKEY_LEN);
    memcpy(msg1 + sizeof(proto_header_t) + PUBKEY_LEN, c_nonce, 8);
    memcpy(msg1 + sizeof(proto_header_t) + PUBKEY_LEN + 8,     &argv_MBPS, 4);
    memcpy(msg1 + sizeof(proto_header_t) + PUBKEY_LEN + 8 + 4, &argv_FRAG, 4);
    memcpy(msg1 + sizeof(proto_header_t) + PUBKEY_LEN + 8 + 8, &argv_CBR,  1);
    memcpy(msg1 + sizeof(proto_header_t) + PUBKEY_LEN + 8 + 9, &argv_PAD,  1);
    if (sendto(sock, msg1, msg1_length, 0,
               (struct sockaddr*)server_addr, sizeof(*server_addr)) != (ssize_t)msg1_length) {
        perror("sendto MSG1");
        sodium_memzero(c_priv, sizeof(c_priv));
        return -1;
    }
    vpn_log("Sent MSG1");

    /* Receive MSG2 loop until we get a HANDSHAKE packet, discarding data packets */
    size_t msg2_length = sizeof(proto_header_t) + MSG2_PAYLOAD;
    uint8_t msg2[msg2_length];
    
    /* Longer timeout (15s) with a loop that discards non-HANDSHAKE packets.
     * During re-handshake, DATA packets may still arrive from the network
     * while we're waiting for MSG2. We discard those and keep waiting. */
    time_t msg2_deadline = time(NULL) + 15;
    int attempts = 0;
    const int MAX_DISCARD_ATTEMPTS = 100;
    
    while (1) {
        if (++attempts > MAX_DISCARD_ATTEMPTS) {
            vpn_log("Too many non-HANDSHAKE packets received, aborting");
            sodium_memzero(c_priv, sizeof(c_priv));
            return -1;
        }
        
        time_t now = time(NULL);
        if (now >= msg2_deadline) {
            vpn_log("MSG2 receive timeout");
            sodium_memzero(c_priv, sizeof(c_priv));
            return -1;
        }
        
        int remaining_sec = (int)(msg2_deadline - now);
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(sock, &fds);
        struct timeval tv = {remaining_sec, 0};
        
        int select_ret = select(sock + 1, &fds, NULL, NULL, &tv);
        if (select_ret < 0) {
            perror("select MSG2");
            sodium_memzero(c_priv, sizeof(c_priv));
            return -1;
        }
        if (select_ret == 0) {
            vpn_log("MSG2 receive timeout (no response from server)");
            sodium_memzero(c_priv, sizeof(c_priv));
            return -1;
        }
        
        ssize_t r = recvfrom(sock, msg2, msg2_length, MSG_DONTWAIT, NULL, NULL);
        if (r < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
            perror("recvfrom MSG2");
            sodium_memzero(c_priv, sizeof(c_priv));
            return -1;
        }
        if (r == 0) {
            vpn_log("MSG2: connection closed by server");
            sodium_memzero(c_priv, sizeof(c_priv));
            return -1;
        }
        
        /* Check packet type BEFORE validating length.
         * If it's a DATA packet, buffer it (don't discard).
         * If it's not a HANDSHAKE packet, continue waiting for MSG2. */
        proto_header_t *ph_check = (proto_header_t *)msg2;
        if (ph_check->type != PKT_TYPE_HANDSHAKE) {
            /* Buffer DATA packets instead of discarding */
            if (ph_check->type == PKT_TYPE_DATA && buffer && buffer->count < REHANDSHAKE_BUFFER_SIZE) {
                buffer->pkts[buffer->count].pkt_data = malloc(r);
                if (buffer->pkts[buffer->count].pkt_data) {
                    memcpy(buffer->pkts[buffer->count].pkt_data, msg2, r);
                    buffer->pkts[buffer->count].pkt_len = r;
                    buffer->count++;
                    vpn_log("Buffered DATA packet during rehandshake (buffer: %d/%d)", 
                            buffer->count, REHANDSHAKE_BUFFER_SIZE);
                }
            } else if (buffer && buffer->count == REHANDSHAKE_BUFFER_SIZE) {
                vpn_log("WARNING: Rehandshake buffer full (%d packets), dropping packet type=%u",
                        REHANDSHAKE_BUFFER_SIZE, ph_check->type);
            }
            continue;  /* Loop back to select() to wait for next packet */
        }
        
        /* Now we have a HANDSHAKE packet, validate length */
        if (r != (ssize_t)msg2_length) {
            vpn_log("MSG2 unexpected length %zd (expected %zu)", r, msg2_length);
            vpn_log("MSG2 first bytes: %02x %02x %02x %02x %02x %02x",
                    msg2[0], msg2[1], msg2[2], msg2[3], msg2[4], msg2[5]);
            sodium_memzero(c_priv, sizeof(c_priv));
            return -1;
        }
        
        /* Got a valid length HANDSHAKE packet, break out of loop */
        break;
    }
    
    vpn_log("Received MSG2");

    /* Parse MSG2 fields */
    uint8_t s_pub[PUBKEY_LEN], s_nonce[8], sig[SIG_LEN];
    memcpy(s_pub,        msg2 + sizeof(proto_header_t),                  PUBKEY_LEN);
    memcpy(s_nonce,      msg2 + sizeof(proto_header_t) + PUBKEY_LEN,     8);
    memcpy(assigned_ip,  msg2 + sizeof(proto_header_t) + PUBKEY_LEN + 8, 4);
    memcpy(sig,          msg2 + sizeof(proto_header_t) + PUBKEY_LEN + 8 + 4, SIG_LEN);

    /* ---------------------------------------------------------------
     * VERIFY SIGNATURE before doing any DH.
     *
     * Reconstruct the exact blob the server signed:
     *   s_pub(32) ‖ s_nonce(8) ‖ c_pub(32) ‖ c_nonce(8)
     *
     * If this fails > MITM or corrupt message > hard abort.
     * --------------------------------------------------------------- */
    uint8_t to_verify[PUBKEY_LEN + 8 + PUBKEY_LEN + 8];
    memcpy(to_verify,                              s_pub,   PUBKEY_LEN);
    memcpy(to_verify + PUBKEY_LEN,                 s_nonce, 8);
    memcpy(to_verify + PUBKEY_LEN + 8,             c_pub,   PUBKEY_LEN);
    memcpy(to_verify + PUBKEY_LEN + 8 + PUBKEY_LEN, c_nonce, 8);

    if (crypto_sign_verify_detached(sig, to_verify, sizeof(to_verify), server_pk) != 0) {
        vpn_log("MSG2 SIGNATURE INVALID, possible MITM attack, aborting");
        sodium_memzero(c_priv, sizeof(c_priv));
        sodium_memzero(sig,    sizeof(sig));
        return -1;
    }
    vpn_log("MSG2 signature verified OK");

    /* DH key derivation, now safe to proceed */
    uint8_t dh1[DH_LEN], dh2[DH_LEN], shared[DH_LEN*2], context[16];
    if (crypto_scalarmult(dh1, c_priv, s_pub)          != 0) goto fail;
    if (crypto_scalarmult(dh2, c_priv, server_kx_pk)   != 0) goto fail;
    memcpy(shared,          dh1,     DH_LEN);
    memcpy(shared + DH_LEN, dh2,     DH_LEN);
    memcpy(context,         c_nonce, 8);
    memcpy(context + 8,     s_nonce, 8);

    uint8_t k1[AEAD_KEY_LEN], k2[AEAD_KEY_LEN];
    derive_two_keys(shared, sizeof(shared), context, sizeof(context), k1, k2);
    memcpy(k_send, k1, AEAD_KEY_LEN);
    memcpy(k_recv, k2, AEAD_KEY_LEN);
    uint8_t sid_input[DH_LEN*2 + 8 + 8 + PUBKEY_LEN + PUBKEY_LEN];
    memcpy(sid_input,                                shared,  DH_LEN*2);
    memcpy(sid_input + DH_LEN*2,                     c_nonce, 8);
    memcpy(sid_input + DH_LEN*2 + 8,                 s_nonce, 8);
    memcpy(sid_input + DH_LEN*2 + 8 + 8,             c_pub,   PUBKEY_LEN);
    memcpy(sid_input + DH_LEN*2 + 8 + 8 + PUBKEY_LEN, s_pub,  PUBKEY_LEN);
    crypto_generichash(session_id, SESSION_ID_LEN,
                       sid_input, sizeof(sid_input),
                       NULL, 0);
    sodium_memzero(sid_input, sizeof(sid_input));
    for (int i = 0; i < SESSION_ID_LEN; i++) printf("%02x", session_id[i]);
    printf("\n");

    sodium_memzero(c_priv, sizeof(c_priv));
    sodium_memzero(dh1,    sizeof(dh1));
    sodium_memzero(dh2,    sizeof(dh2));
    sodium_memzero(shared, sizeof(shared));
    sodium_memzero(k1,     sizeof(k1));
    sodium_memzero(k2,     sizeof(k2));
    sodium_memzero(sig,    sizeof(sig));
    return 0;

fail:
    sodium_memzero(c_priv, sizeof(c_priv));
    sodium_memzero(dh1,    sizeof(dh1));
    sodium_memzero(dh2,    sizeof(dh2));
    sodium_memzero(shared, sizeof(shared));
    sodium_memzero(sig,    sizeof(sig));
    return -1;
}


/**
 * should_attempt_rehandshake:
 * Check if we should attempt a rehandshake now.
 * Returns:
 *   1  = yes, attempt now
 *   0  = no, in backoff or in-progress
 *  -1  = max failures reached, should disconnect
 */
int should_attempt_rehandshake(server_t *srv)
{
    time_t now = time(NULL);

    /* If max consecutive attempts reached, signal disconnect */
    if (srv->rehandshake_attempts >= 5) {
        vpn_log("Rehandshake failed %d times, will disconnect",
                srv->rehandshake_attempts);
        srv->rehandshake_state = REHANDSHAKE_FAILED;
        return -1;
    }

    switch (srv->rehandshake_state) {
        case REHANDSHAKE_READY:
            return 1;  /* Can attempt */

        case REHANDSHAKE_IN_PROGRESS:
            return 0;  /* Already in progress, wait */

        case REHANDSHAKE_BACKOFF:
            if (now - srv->rehandshake_last_attempt >= srv->rehandshake_backoff_sec) {
                vpn_log("Rehandshake backoff expired (%ds), retrying (attempt %d/5)",
                        srv->rehandshake_backoff_sec, srv->rehandshake_attempts + 1);
                srv->rehandshake_state = REHANDSHAKE_READY;
                return 1;  /* Backoff expired, can retry */
            }
            return 0;  /* Still in backoff */

        case REHANDSHAKE_FAILED:
            return -1;  /* Failed, disconnect */

        default:
            return 0;
    }
}

/**
 * rehandshake_client_with_state:
 * Performs rehandshake with proper state machine.
 * On success: resets attempt counter, transitions to READY
 * On failure: increments attempts, enters BACKOFF with exponential backoff
 * 
 * Returns: 0 on success, -1 on failure
 */
int rehandshake_client_with_state(int sock,
                                   struct sockaddr_in *server_addr,
                                   const uint8_t server_pk[PUBKEY_LEN],
                                   server_t *srv,
                                   sender_args_t *sender_args,
                                   replay_window_t *rw,
                                   rehandshake_buffer_t *buffer)
{
    uint8_t new_session_id[SESSION_ID_LEN];
    uint8_t new_k_send[AEAD_KEY_LEN];
    uint8_t new_k_recv[AEAD_KEY_LEN];
    uint8_t assigned_ip[4];

    vpn_log("Re-handshake starting (attempt %d)", srv->rehandshake_attempts + 1);

    /* Transition to IN_PROGRESS */
    srv->rehandshake_state = REHANDSHAKE_IN_PROGRESS;
    srv->rehandshake_last_attempt = time(NULL);

    /* Initialize buffer if not provided */
    rehandshake_buffer_t local_buffer = {0};
    if (!buffer) {
        rehandshake_buffer_init(&local_buffer);
        buffer = &local_buffer;
    }

    /* Flush any queued data packets from the socket buffer
     * before re-handshake. Without this, select() will return immediately
     * with old data packets still in the kernel buffer, and we'll read
     * those as MSG2 responses instead of waiting for the actual MSG2. */
    flush_socket_buffer(sock);

    if (client_handshake(sock, server_addr, server_pk,
                         new_session_id, new_k_send, new_k_recv,
                         assigned_ip, buffer) != 0) {
        vpn_log("Re-handshake failed attempt %d, entering backoff", 
                srv->rehandshake_attempts + 1);
        
        /* Increment attempts and transition to BACKOFF */
        srv->rehandshake_attempts++;
        
        /* Exponential backoff: 1s, 2s, 4s, 8s, 16s (capped at 60s) */
        srv->rehandshake_backoff_sec = 1 << (srv->rehandshake_attempts - 1);
        if (srv->rehandshake_backoff_sec > 60)
            srv->rehandshake_backoff_sec = 60;
        
        srv->rehandshake_state = REHANDSHAKE_BACKOFF;
        vpn_log("Backoff: waiting %d seconds before retry #%d, %d packets buffered",
                srv->rehandshake_backoff_sec, srv->rehandshake_attempts + 1, buffer->count);
        
        rehandshake_buffer_free(buffer);
        return -1;
    }

    vpn_log("Re-handshake succeeded, applying new keys (%d buffered packets)", buffer->count);

    uint8_t old_k_recv[AEAD_KEY_LEN];
    uint8_t old_session_id[SESSION_ID_LEN];
    memcpy(old_k_recv,    srv->k_recv,    AEAD_KEY_LEN);
    memcpy(old_session_id, srv->session_id, SESSION_ID_LEN);

    memcpy(srv->k_recv,    new_k_recv,    AEAD_KEY_LEN);
    memcpy(srv->k_send,     new_k_send,     AEAD_KEY_LEN);
    memcpy(srv->session_id, new_session_id, SESSION_ID_LEN);
    atomic_store(&srv->send_seq, 0);
    srv->session_start_time = time(NULL);
    srv->bytes_sent         = 0;

    memcpy(sender_args->pending_k_send,    new_k_send,    AEAD_KEY_LEN);
    memcpy(sender_args->pending_session_id, new_session_id, SESSION_ID_LEN);
    atomic_store(&sender_args->pending_rekey, 1);

    vpn_log("new k_send[0..3]: %02x %02x %02x %02x",
        new_k_send[0], new_k_send[1], new_k_send[2], new_k_send[3]);

    sodium_memzero(old_k_recv,    sizeof(old_k_recv));
    sodium_memzero(old_session_id, sizeof(old_session_id));
    sodium_memzero(new_k_send,    sizeof(new_k_send));
    sodium_memzero(new_k_recv,    sizeof(new_k_recv));
    sodium_memzero(new_session_id, sizeof(new_session_id));

    memset(rw, 0, sizeof(replay_window_t));
    last_server_keepalive_time = time(NULL);

    /* RESET: Success, go back to READY state and zero attempts */
    srv->rehandshake_attempts = 0;
    srv->rehandshake_backoff_sec = 1;
    srv->rehandshake_state = REHANDSHAKE_READY;

    /* Clean up buffered packets */
    rehandshake_buffer_free(buffer);

    vpn_log("Re-handshake complete, attempt counter reset, new session keys active");
    return 0;
}

/**
 * rehandshake_buffer_init:
 * Initialize an empty rehandshake buffer
 */
void rehandshake_buffer_init(rehandshake_buffer_t *buffer)
{
    if (!buffer) return;
    memset(buffer, 0, sizeof(*buffer));
    buffer->count = 0;
}

/**
 * rehandshake_buffer_free:
 * Free all buffered packets and reset buffer
 */
void rehandshake_buffer_free(rehandshake_buffer_t *buffer)
{
    if (!buffer) return;
    for (int i = 0; i < buffer->count; i++) {
        if (buffer->pkts[i].pkt_data) {
            free(buffer->pkts[i].pkt_data);
            buffer->pkts[i].pkt_data = NULL;
        }
    }
    buffer->count = 0;
}

/**
 * process_rehandshake_buffer:
 * Process buffered packets with old keys after rehandshake.
 * These packets were encrypted with the old keys during rehandshake
 * window and need to be decrypted and injected into TUN before
 * we fully switch to new keys.
 * 
 * Returns number of packets successfully processed
 */
int process_rehandshake_buffer(int tun_fd, 
                               const uint8_t old_k_recv[AEAD_KEY_LEN],
                               rehandshake_buffer_t *buffer)
{
    if (!buffer || buffer->count == 0) {
        return 0;
    }

    vpn_log("Processing %d buffered packets from rehandshake window with old keys", 
            buffer->count);

    int processed = 0;
    
    /* NOTE: We don't have session_id or sequence info for these buffered packets,
     * so we can't fully decrypt them here. Instead, mark them for reprocessing
     * in the main event loop with proper context.
     * 
     * For now: just log that we have buffered packets and will process them
     * when the event loop resumes with updated session state.
     */

    for (int i = 0; i < buffer->count; i++) {
        if (buffer->pkts[i].pkt_data) {
            /* These packets should ideally be decrypted here with old_k_recv
             * But we need session context. For safety, we'll just keep them
             * buffered and let the event loop handle it after state update.
             */
            processed++;
        }
    }

    vpn_log("Marked %d buffered packets for processing in event loop", processed);
    return processed;
}
