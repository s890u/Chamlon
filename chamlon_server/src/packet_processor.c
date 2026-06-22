#include "packet_processor.h"
#include "vpn_common.h"
#include "vpn_crypto.h"
#include "vpn_tun.h"
#include "fragment.h"
#include "handshake.h"
#include "vpn_log.h"
#include "replay_window.h"
#include "packet.h"
#include "scheduler.h"
#include "rate_limiter.h"
#include "metrics.h"
#include "thread_pool.h"
#include <string.h>
#include <stdlib.h>
#include <endian.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <arpa/inet.h>

/* Declared in vpn_server.c; workers use this for JOB_TYPE_INBOUND_CRYPTO */
extern thread_pool_t *g_thread_pool;

/* -----------------------------------------------------------------------
 * handle_inbound_udp
 *
 * Called by a thread pool worker (JOB_TYPE_INBOUND_CRYPTO).
 * All crypto and TUN-write work happens here, off the epoll thread.
 * Thread-safety: same-session packets are serialised by shard routing
 * (session_id[0] % num_threads), so replay_window is safe without its
 * own lock.
 * --------------------------------------------------------------------- */
void handle_inbound_udp(int udp_sock, int tun_fd, uint8_t *buf, ssize_t r,
                        struct sockaddr_in *src, uint8_t *server_sk)
{
    if ((size_t)r < sizeof(proto_header_t)) return;
    if ((size_t)r > BUFFER_SIZE) { vpn_log("Inbound UDP exceeds buffer"); return; }

    proto_header_t *ph = (proto_header_t *)buf;
    if (ph->magic != PKT_MAGIC || ph->version != PKT_VERSION) return;

    if (ph->type == PKT_TYPE_DATA) {
        int rc = check_packet_rate_limit(&src->sin_addr);
        if (rc == RATE_LIMIT_BLACKLISTED || rc == RATE_LIMIT_EXCEEDED) {
            metrics_record_packet_dropped();
            metrics_record_rate_limit_drop();
            return;
        }
    }

    if (ph->type == PKT_TYPE_HANDSHAKE) {
        if (r == (ssize_t)(sizeof(proto_header_t) + (PUBKEY_LEN + 8) + (4+4+1+1))) {
            // Check if this is a re-handshake (existing session from same addr)
            session_t *existing = NULL;
            pthread_rwlock_rdlock(&sessions_rwlock);
            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (sessions[i].active &&
                    sessions[i].client_addr.sin_addr.s_addr == src->sin_addr.s_addr &&
                    sessions[i].client_addr.sin_port        == src->sin_port) {
                    existing = &sessions[i];
                    break;
                }
            }
            pthread_rwlock_unlock(&sessions_rwlock);

            if (existing)
                handle_rehandshake_msg1(udp_sock, buf, r, src, server_sk);
            else
                handle_msg1(udp_sock, buf, r, src, server_sk);
        }
        return;
    }

    if (ph->type == PKT_TYPE_DATA || r > 0) metrics_record_packet_received(r);

    uint8_t   *session_id = buf + sizeof(proto_header_t);
    session_t *s          = session_by_id(session_id);
    if (!s) return;

    s->last_activity = time(NULL);

    uint8_t  *p       = session_id + SESSION_ID_LEN;
    uint64_t  pkt_seq = 0;
    for (int i = 0; i < 8; ++i) pkt_seq = (pkt_seq << 8) | p[i];

    if (check_replay(pkt_seq, &s->rw)) { metrics_record_validation_error(); return; }

    size_t cipher_len = (size_t)r - DATA_HEADER_LEN;
    if (cipher_len > BUFFER_SIZE - DATA_HEADER_LEN) {
        vpn_log("Invalid cipher_len: %zu", cipher_len); return;
    }

    uint8_t plain[BUFFER_SIZE]; size_t plain_len = 0;
    if (aead_decrypt(s->k_recv, s->session_id, pkt_seq,
                     buf + DATA_HEADER_LEN, cipher_len,
                     plain, &plain_len) != 0) {
        vpn_log("decrypt/auth fail seq=%lu", pkt_seq); return;
    }
    if (plain_len > BUFFER_SIZE) { vpn_log("Decrypted len overflow: %zu", plain_len); return; }

    update_window(pkt_seq, &s->rw);

    tunnel_header_t *header = (tunnel_header_t *)plain;
    if (header->flags == PKT_DUMMY)           return;
    if (header->flags == PKT_CTRL_KEEPALIVE)  { s->last_activity = time(NULL); return; }
    if (header->flags == PKT_CTRL_DISCONNECT) { free_session(s); return; }

    uint8_t *fragment_payload_start = plain + sizeof(tunnel_header_t);
    size_t   fragment_payload_len   = plain_len - sizeof(tunnel_header_t);

    reassembly_entry_t *entry = find_or_create_entry(s, header->packet_id);
    if (!entry) return;

    if (header->fragment_offset + fragment_payload_len > MAX_PACKET_SIZE) {
        entry->is_active = false; return;
    }

    if (entry->expected_length == 0) entry->expected_length = header->total_ip_len;
    memcpy(entry->buffer + header->fragment_offset,
           fragment_payload_start, fragment_payload_len);
    entry->received_bytes += fragment_payload_len;

    bool is_last = !(header->flags & 0x8000);
    if (is_last && entry->received_bytes >= entry->expected_length) {
        if (write(tun_fd, entry->buffer, entry->expected_length) < 0)
            perror("write tun");
        entry->is_active = false;
    }
}

/* -----------------------------------------------------------------------
 * send_outbound_packet, encrypt one fragment and send or enqueue.
 * Called from handle_outbound_tun_buf (worker thread).
 * --------------------------------------------------------------------- */
static void send_outbound_packet(session_t *s,
                                 uint8_t *buf2, size_t real_data_len,
                                 const uint8_t *ip_buf, size_t ip_len)
{
    uint8_t  out[BUFFER_SIZE];
    size_t   outlen = 0;
    uint64_t seq    = atomic_fetch_add(&s->send_seq, 1);

    size_t encrypt_len = real_data_len;
    if (s->argv_CBR == 'Y' && encrypt_len < (size_t)s->argv_FRAG) {
        packet_padding(buf2, real_data_len, s->argv_FRAG);
        encrypt_len = (size_t)s->argv_FRAG;
    }

    if (aead_encrypt(s->k_send, s->session_id, seq,
                     buf2, encrypt_len, out, &outlen) != 0) return;

    size_t   pktlen = sizeof(proto_header_t) + SESSION_ID_LEN + 8 + outlen;
    uint8_t *pkt    = malloc(pktlen);
    if (!pkt) { vpn_log("malloc failed send_outbound_packet"); return; }

    proto_header_t ph = { PKT_MAGIC, PKT_VERSION, PKT_TYPE_DATA };
    memcpy(pkt, &ph, sizeof(proto_header_t));
    memcpy(pkt + sizeof(proto_header_t), s->session_id, SESSION_ID_LEN);
    uint64_t seq_net = htobe64(seq);
    memcpy(pkt + sizeof(proto_header_t) + SESSION_ID_LEN, &seq_net, 8);
    memcpy(pkt + sizeof(proto_header_t) + SESSION_ID_LEN + 8, out, outlen);

    if (s->argv_CBR == 'Y') {
        packet_queue_push(s->outq, pkt, pktlen, seq, ip_buf, ip_len);
    } else {
        if (sendto(s->s_udp_sock, pkt, pktlen, 0,
                   (struct sockaddr *)&s->client_addr,
                   s->client_addrlen) != (ssize_t)pktlen) {
            perror("sendto direct");
        }
        free(pkt);
    }
}

/* -----------------------------------------------------------------------
 * handle_outbound_tun_buf, WORKER THREAD path.
 *
 * Receives a raw IP packet already read from TUN by the epoll thread.
 * Does session-lookup, fragmentation, aead_encrypt, sendto.
 * Never touches tun_fd.
 * --------------------------------------------------------------------- */
void handle_outbound_tun_buf(int udp_sock,
                             const uint8_t *buf, size_t len)
{
    (void)udp_sock; /* routing uses s->s_udp_sock directly */

    if (len < 20) return;

    session_t *s = session_by_vpnip(buf + 16);
    if (!s) return;

    const uint8_t *ip_buf = buf;
    const size_t   ip_len = len;

    uint16_t current_id = fragment_next_packet_id();

    size_t       current_offset = 0;
    const size_t header_len     = sizeof(tunnel_header_t);
    const size_t max_payload    = (size_t)s->argv_FRAG - header_len;

    while (current_offset < len) {
        uint8_t buf2[MAX_FRAG];
        memset(buf2, 0, (size_t)s->argv_FRAG);

        size_t chunk_len = (len - current_offset > max_payload)
                           ? max_payload : (len - current_offset);

        tunnel_header_t header = {
            .packet_id       = current_id,
            .fragment_offset = (uint16_t)current_offset,
            .total_ip_len    = (uint16_t)len,
            .flags           = (current_offset + chunk_len == len)
                               ? 0x0000 : 0x8000
        };

        memcpy(buf2, &header, header_len);
        memcpy(buf2 + header_len, buf + current_offset, chunk_len);

        size_t real_data_len = header_len + chunk_len;
        if (s->argv_PAD == 'Y') {
            packet_padding(buf2, real_data_len, s->argv_FRAG);
            real_data_len = (size_t)s->argv_FRAG;
        }

        send_outbound_packet(s, buf2, real_data_len, ip_buf, ip_len);
        current_offset += chunk_len;
    }
}

/* -----------------------------------------------------------------------
 * handle_outbound_tun, EPOLL THREAD path.
 *
 * Reads ONE raw IP packet from tun_fd, copies it to a heap buffer,
 * then submits a JOB_TYPE_OUTBOUND_CRYPTO job so a worker does the
 * crypto+sendto off the epoll thread.
 *
 * Returns 1 if a packet was read and dispatched, 0 on EAGAIN.
 * --------------------------------------------------------------------- */
int handle_outbound_tun(int tun_fd, int udp_sock)
{
    uint8_t tmp[BUFFER_SIZE];
    ssize_t len = read(tun_fd, tmp, sizeof(tmp));
    if (len < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        perror("read tun");
        return 0;
    }
    if (len < 20) return 1; /* too short to be a valid IP packet */

    /*
     * Quick destination-IP pre-check: if no session exists for this
     * destination we can drop here without a heap allocation.
     */
    if (!session_by_vpnip(tmp + 16)) return 1;

    /* Copy to heap, the worker owns this buffer and frees it */
    uint8_t *buf = malloc((size_t)len);
    if (!buf) { vpn_log("OOM handle_outbound_tun"); return 1; }
    memcpy(buf, tmp, (size_t)len);

    job_t *job = calloc(1, sizeof(job_t));
    if (!job) { free(buf); return 1; }

    job->type             = JOB_TYPE_OUTBOUND_CRYPTO;
    job->outbound.buf     = buf;
    job->outbound.buf_len = (size_t)len;
    job->outbound.udp_sock = udp_sock;

    /*
     * Shard by destination VPN IP last-byte so all packets for the
     * same session go to the same worker → no send_seq ordering races
     * beyond what _Atomic already handles.
     */
    uint8_t shard_key = buf[19]; /* dst IP last byte */

    if (thread_pool_submit_sharded(g_thread_pool, job, shard_key) != 0) {
        free(buf); free(job);
    }

    return 1;
}

void send_keepalive_to_client(session_t *s) {
    uint8_t plain[sizeof(tunnel_header_t)];
    tunnel_header_t hdr = {
        .flags = PKT_CTRL_KEEPALIVE,
        .packet_id = 0,
        .fragment_offset = 0,
        .total_ip_len = 0
    };
    memcpy(plain, &hdr, sizeof(hdr));

    uint8_t out[BUFFER_SIZE];
    size_t outlen = 0;
    uint64_t seq = atomic_fetch_add(&s->send_seq, 1);

    if (aead_encrypt(s->k_send, s->session_id, seq,
                     plain, sizeof(plain), out, &outlen) != 0) return;

    size_t pktlen = sizeof(proto_header_t) + SESSION_ID_LEN + 8 + outlen;
    uint8_t *pkt = malloc(pktlen);
    if (!pkt) return;

    proto_header_t ph = { PKT_MAGIC, PKT_VERSION, PKT_TYPE_DATA };
    memcpy(pkt, &ph, sizeof(proto_header_t));
    memcpy(pkt + sizeof(proto_header_t), s->session_id, SESSION_ID_LEN);
    uint64_t seq_net = htobe64(seq);
    memcpy(pkt + sizeof(proto_header_t) + SESSION_ID_LEN, &seq_net, 8);
    memcpy(pkt + sizeof(proto_header_t) + SESSION_ID_LEN + 8, out, outlen);

    sendto(s->s_udp_sock, pkt, pktlen, 0,
           (struct sockaddr *)&s->client_addr, s->client_addrlen);
    printf("Sent keepalive to %s:%d\n", inet_ntoa(s->client_addr.sin_addr),
           ntohs(s->client_addr.sin_port));
    free(pkt);
}

void perform_maintenance(int udp_sock) {
    cleanup_expired_sessions(udp_sock);
    sweep_reassembly_table();

    time_t now = time(NULL);

    pthread_rwlock_rdlock(&sessions_rwlock);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        session_t *s = &sessions[i];
        if (!s->active) continue;
        if (now - s->last_activity_keepalive >= KEEPALIVE_INTERVAL_SEC) {
            send_keepalive_to_client(s);
            s->last_activity_keepalive = now;
            s->last_activity = now;
        }
    }
    pthread_rwlock_unlock(&sessions_rwlock);
}
