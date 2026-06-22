#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include "vpn_common.h"
#include "vpn_log.h"
#include "vpn_crypto.h"
#include "session.h"
#include "packet.h"
#include "metrics.h"

session_t        sessions[MAX_CLIENTS];

/*
 * sessions_rwlock protects the sessions[] table.
 *
 * Rule: hold rdlock to READ active/session_id/vpn_ip/etc.
 *       hold wrlock to WRITE active flag or membership fields.
 *
 * Crypto fields (k_recv, k_send) are written exactly once at handshake
 * under wrlock and read-only afterward, so rdlock is sufficient for them.
 *
 * send_seq is _Atomic no lock needed.
 * replay_window rw touched only on the inbound crypto worker path;
 *   one worker per session at a time is enforced by the session-id hash
 *   sharding in the thread pool (see thread_pool.c).
 */
pthread_rwlock_t sessions_rwlock = PTHREAD_RWLOCK_INITIALIZER;

int session_index(session_t *s)
{
    return (int)(s - sessions);
}

/*
 * allocate_session caller MUST hold wrlock.
 * Returns a zeroed-rw slot or NULL if the table is full.
 */
session_t *allocate_session(void)
{
    for (int i = 0; i < MAX_CLIENTS; ++i) {
        if (!sessions[i].active) {
            memset(&sessions[i].rw, 0, sizeof(sessions[i].rw));
            return &sessions[i];
        }
    }
    return NULL;
}

/*
 * session_by_id acquires rdlock, scans table, releases rdlock.
 * Returns a pointer valid as long as the caller holds *some* reference
 * (i.e. does not call free_session concurrently on that slot).
 * For the hot inbound path the pointer is used under rdlock by the
 * worker; the worker re-validates active==1 after acquiring the lock.
 */
session_t *session_by_id(const uint8_t session_id[SESSION_ID_LEN])
{
    pthread_rwlock_rdlock(&sessions_rwlock);
    session_t *found = NULL;
    for (int i = 0; i < MAX_CLIENTS; ++i) {
        if (sessions[i].active &&
            memcmp(sessions[i].session_id, session_id, SESSION_ID_LEN) == 0) {
            found = &sessions[i];
            break;
        }
    }
    pthread_rwlock_unlock(&sessions_rwlock);
    return found;
}

session_t *session_by_vpnip(const uint8_t ip[4])
{
    pthread_rwlock_rdlock(&sessions_rwlock);
    session_t *found = NULL;
    for (int i = 0; i < MAX_CLIENTS; ++i) {
        if (sessions[i].active &&
            memcmp(sessions[i].vpn_ip, ip, 4) == 0) {
            found = &sessions[i];
            break;
        }
    }
    pthread_rwlock_unlock(&sessions_rwlock);
    return found;
}

void assign_vpn_ip_to_session(session_t *s)
{
    ptrdiff_t idx = s - sessions;
    uint8_t d = (uint8_t)(2 + idx);   /* 10.10.0.2 + idx */
    s->vpn_ip[0] = 10;
    s->vpn_ip[1] = 10;
    s->vpn_ip[2] = 0;
    s->vpn_ip[3] = d;
}

void free_session(session_t *s)
{
    if (!s) return;

    pthread_rwlock_wrlock(&sessions_rwlock);
    if (!s->active) {
        pthread_rwlock_unlock(&sessions_rwlock);
        return;
    }

    metrics_record_connection_closed();

    if (s->outq) {
        out_queue_destroy(s->outq);
        free(s->outq);
        s->outq = NULL;
    }

    sodium_memzero(s->k_recv, AEAD_KEY_LEN);
    sodium_memzero(s->k_send, AEAD_KEY_LEN);
    sodium_memzero(s->session_id, SESSION_ID_LEN);
    s->active        = 0;
    s->send_seq      = 0;
    s->last_recv_seq = 0;
    s->client_addr.sin_family = 0;
    s->client_addrlen         = 0;
    s->vpn_ip[0] = s->vpn_ip[1] = s->vpn_ip[2] = s->vpn_ip[3] = 0;
    s->last_activity = 0;

    pthread_rwlock_unlock(&sessions_rwlock);
}

int cleanup_expired_sessions(int udp_sock)
{
    int freed = 0;

    pthread_rwlock_wrlock(&sessions_rwlock);
    time_t now = time(NULL);
    for (int i = 0; i < MAX_CLIENTS; ++i) {
        session_t *s = &sessions[i];
        if (!s->active) continue;
        if (now - s->last_activity > SESSION_TIMEOUT_SEC) {
            vpn_log("Session timeout VPN %u.%u.%u.%u (idle %lds)",
                    s->vpn_ip[0], s->vpn_ip[1], s->vpn_ip[2], s->vpn_ip[3],
                    (long)(now - s->last_activity));
            send_control_packet(udp_sock, s, PKT_CTRL_DISCONNECT);
            metrics_record_connection_closed();

            sodium_memzero(s->k_recv, AEAD_KEY_LEN);
            sodium_memzero(s->k_send, AEAD_KEY_LEN);
            sodium_memzero(s->session_id, SESSION_ID_LEN);
            s->active        = 0;
            s->send_seq      = 0;
            s->last_recv_seq = 0;
            s->client_addr.sin_family = 0;
            s->client_addrlen         = 0;
            s->vpn_ip[0] = s->vpn_ip[1] = s->vpn_ip[2] = s->vpn_ip[3] = 0;
            s->last_activity = 0;
            freed++;
        }
    }
    pthread_rwlock_unlock(&sessions_rwlock);
    return freed;
}
