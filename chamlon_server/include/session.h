#ifndef SESSION_H
#define SESSION_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdatomic.h>
#include <pthread.h>
#include "vpn_common.h"
#include "vpn_crypto.h"
#include "config.h"

#define MAX_CLIENTS CONFIG_MAX_CLIENTS

typedef struct {
    int    active;
    int    s_udp_sock;
    uint8_t session_id[SESSION_ID_LEN];
    uint8_t k_recv[AEAD_KEY_LEN];
    uint8_t k_send[AEAD_KEY_LEN];

    /*
     * send_seq: incremented atomically by the epoll thread (outbound TUN)
     * and scheduler threads (CBR/keepalive).  No lock needed.
     */
    _Atomic uint64_t send_seq;
    uint64_t         last_recv_seq;

    struct sockaddr_in client_addr;
    socklen_t          client_addrlen;
    uint8_t            vpn_ip[4];

    reassembly_entry_t g_reassembly_table[MAX_REASSEMBLY_ENTRIES];
    out_queue_t       *outq;

    pthread_mutex_t seq_lock;

    time_t last_activity;
    time_t last_activity_keepalive;

    int  argv_MBPS;
    int  argv_FRAG;
    char argv_CBR;
    char argv_PAD;

    replay_window_t rw;

    uint8_t dummy_payload[MAX_FRAG];
    uint8_t final_pkt_dummy[MAX_FRAG];
    int     static_hdr_len;
} session_t;

/* -----------------------------------------------------------------------
 * Global session table + reader-writer lock.
 *
 * Locking discipline:
 *   READ  (session_by_id, session_by_vpnip, iterate sessions[]):
 *       pthread_rwlock_rdlock(&sessions_rwlock)
 *
 *   WRITE (allocate_session, free_session, cleanup_expired_sessions,
 *          any field that changes session membership/active flag):
 *       pthread_rwlock_wrlock(&sessions_rwlock)
 *
 * Crypto fields inside a session (k_recv, k_send, rw, send_seq) are
 * protected per-session: send_seq is _Atomic, rw is touched only on
 * the inbound path (single thread per session assumed), k_recv/k_send
 * are written once at handshake time under the write-lock and read
 * thereafter under the read-lock.
 * --------------------------------------------------------------------- */
extern session_t        sessions[MAX_CLIENTS];
extern pthread_rwlock_t sessions_rwlock;

int        session_index(session_t *s);
session_t *allocate_session(void);   /* caller must hold WRITE lock */
session_t *session_by_id(const uint8_t session_id[SESSION_ID_LEN]);    /* acquires read-lock internally */
session_t *session_by_vpnip(const uint8_t ip[4]);                       /* acquires read-lock internally */
void       assign_vpn_ip_to_session(session_t *s);
void       free_session(session_t *s);              /* acquires write-lock internally */
int        cleanup_expired_sessions(int udp_sock);  /* acquires write-lock internally */

#endif /* SESSION_H */
