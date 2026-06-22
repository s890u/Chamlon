#include "vpn_sender_thread.h"
#include "vpn_common.h"
#include "vpn_crypto.h"
#include "vpn_log.h"
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <sys/socket.h>
#include <endian.h>
#include <pthread.h>
#include <stdatomic.h>

/* External globals from main */
extern volatile int g_stop;
extern int data_REAL;
extern int data_DUMMY;
extern time_t last_double_dummy_real;
extern int argv_FRAG;
extern char argv_CBR;
extern server_t servers[1];
extern uint8_t g_session_id[SESSION_ID_LEN];

/* Local static buffers */
static uint8_t final_pkt_dummy[BUFFER_SIZE];
static uint8_t dummy_payload[BUFFER_SIZE];
static int static_hdr_len;

void set_interval_from_mbps(double mbps, int include_headers, struct timespec *ts) {
    double payload_len     = argv_FRAG + MAC_LEN + SESSION_ID_LEN + 8 + sizeof(proto_header_t);
    double ipv4_packet_len = payload_len + 14 + 20 + 8;
    const double bytes_per_pkt = include_headers ? ipv4_packet_len : payload_len;
    const double bits_per_pkt  = bytes_per_pkt * 8.0;
    double interval_sec = bits_per_pkt / (mbps * 1e6);
    if (interval_sec <= 0) interval_sec = 0.001;

    uint64_t ns    = (uint64_t)(interval_sec * 1e9);
    ts->tv_sec     = ns / 1000000000ULL;
    ts->tv_nsec    = ns % 1000000000ULL;
}

void prepare_dummy_static_parts(const uint8_t session_id[SESSION_ID_LEN]) {
    proto_header_t ph = { .magic = PKT_MAGIC, .version = PKT_VERSION, .type = PKT_TYPE_DATA };
    uint8_t *p = final_pkt_dummy;
    memcpy(p, &ph, sizeof(proto_header_t));
    memcpy(p + sizeof(proto_header_t), session_id, SESSION_ID_LEN);
    static_hdr_len = sizeof(proto_header_t) + SESSION_ID_LEN;

    tunnel_header_t th = { .packet_id = 1, .fragment_offset = 1,
                           .total_ip_len = 1, .flags = PKT_DUMMY };
    memcpy(dummy_payload, &th, sizeof(tunnel_header_t));
    memset(dummy_payload + sizeof(tunnel_header_t), 0x99,
           (size_t)argv_FRAG - sizeof(tunnel_header_t));
}

/* -----------------------------------------------------------------------
 * send_one_dummy > encrypt and send a single CBR dummy packet.
 * Returns 0 on success, -1 on encrypt failure.
 * --------------------------------------------------------------------- */
static int send_one_dummy(sender_args_t *arg) {
    uint8_t out[BUFFER_SIZE];
    size_t  outlen = 0;

    uint64_t seq = atomic_fetch_add(&servers[0].send_seq, 1);
    if (aead_encrypt(arg->k_send, arg->session_id, seq,
                     dummy_payload, argv_FRAG, out, &outlen) != 0) {
        vpn_log("encrypt dummy failed seq=%lu", seq);
        return -1;
    }

    uint64_t seq_net = htobe64(seq);
    memcpy(final_pkt_dummy + static_hdr_len,      &seq_net, 8);
    memcpy(final_pkt_dummy + static_hdr_len + 8,  out,      outlen);
    size_t pktlen = static_hdr_len + 8 + outlen;

    if (sendto(arg->udp_sock, final_pkt_dummy, pktlen, 0,
               (struct sockaddr *)&arg->server_addr,
               sizeof(arg->server_addr)) != (ssize_t)pktlen) {
        perror("sendto dummy");
    }
    data_DUMMY++;
    return 0;
}

/* -----------------------------------------------------------------------
 * timespec_add_ns > add nanoseconds to a timespec in-place.
 * --------------------------------------------------------------------- */
static inline void timespec_add(struct timespec *ts, const struct timespec *delta) {
    ts->tv_sec  += delta->tv_sec;
    ts->tv_nsec += delta->tv_nsec;
    if (ts->tv_nsec >= 1000000000L) {
        ts->tv_nsec -= 1000000000L;
        ts->tv_sec++;
    }
}

/* -----------------------------------------------------------------------
 * timespec_cmp > return <0 if a<b, 0 if equal, >0 if a>b
 * --------------------------------------------------------------------- */
static inline int timespec_cmp(const struct timespec *a, const struct timespec *b) {
    if (a->tv_sec != b->tv_sec) return (a->tv_sec > b->tv_sec) ? 1 : -1;
    if (a->tv_nsec != b->tv_nsec) return (a->tv_nsec > b->tv_nsec) ? 1 : -1;
    return 0;
}

void *sender_thread_fn(void *argv) {
    sender_args_t *arg = (sender_args_t *)argv;
    struct timespec now, next;
    clock_gettime(CLOCK_MONOTONIC, &next);

    printf("Sender thread started (CBR=%c, FRAG=%d)\n", argv_CBR, argv_FRAG);
    fflush(stdout);

    while (!g_stop) {

        if (atomic_load(&arg->pending_rekey)) {
            uint8_t old_k_send[AEAD_KEY_LEN];
            uint8_t old_session_id[SESSION_ID_LEN];
            memcpy(old_k_send,    arg->k_send,    AEAD_KEY_LEN);
            memcpy(old_session_id, arg->session_id, SESSION_ID_LEN);

            memcpy(arg->k_send,    arg->pending_k_send,    AEAD_KEY_LEN);
            memcpy(arg->session_id, arg->pending_session_id, SESSION_ID_LEN);
            memcpy(g_session_id,   arg->session_id, SESSION_ID_LEN);

            prepare_dummy_static_parts(arg->session_id);

            sodium_memzero(old_k_send,     sizeof(old_k_send));
            sodium_memzero(old_session_id, sizeof(old_session_id));
            sodium_memzero(arg->pending_k_send,    sizeof(arg->pending_k_send));
            sodium_memzero(arg->pending_session_id, sizeof(arg->pending_session_id));

            atomic_store(&arg->pending_rekey, 0);
            vpn_log("Sender thread swapped to new session keys and refreshed dummy header");
        }

        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec > last_double_dummy_real) {
            int real    = data_REAL;  data_REAL  = 0;
            int dummy   = data_DUMMY; data_DUMMY = 0;
            int packets = real + dummy;
            double mbps = (packets * (double)argv_FRAG * 8.0) / 1e6;
            printf("MBPS %.2f  REAL %d  DUMMY %d  TOTAL %d\n",
                   mbps, real, dummy, packets);
            fflush(stdout);
            last_double_dummy_real = now.tv_sec;
        }

        out_node_t *node;
        while ((node = out_queue_pop(arg->outq)) != NULL) {
            if (sendto(arg->udp_sock, node->pkt, node->pktlen, 0,
                       (struct sockaddr *)&arg->server_addr,
                       sizeof(arg->server_addr)) != (ssize_t)node->pktlen) {
                perror("sendto real");
            }
            data_REAL++;
            free(node->pkt);
            free(node);
            if (argv_CBR == 'Y') timespec_add(&next, &arg->interval);
        }

        if (argv_CBR == 'Y') {
            if (send_one_dummy(arg) != 0) break;
            timespec_add(&next, &arg->interval);
            clock_gettime(CLOCK_MONOTONIC, &now);
            if (timespec_cmp(&now, &next) > 0) {
                next = now;
                timespec_add(&next, &arg->interval);
            }
            clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &next, NULL);
        } else {
            struct timespec idle = { .tv_sec = 0, .tv_nsec = 100000L };
            nanosleep(&idle, NULL);
        }
    }

    vpn_log("Sender thread exiting");
    free(arg);
    return NULL;
}
