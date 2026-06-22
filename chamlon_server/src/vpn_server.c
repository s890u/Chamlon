#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <sodium.h>
#include <net/if.h>
#include <linux/if.h>
#include <fcntl.h>

#include "vpn_common.h"
#include "vpn_crypto.h"
#include "vpn_tun.h"
#include "scheduler.h"
#include "vpn_log.h"
#include "packet_processor.h"
#include "handshake.h"
#include "rate_limiter.h"
#include "metrics.h"
#include "graceful_shutdown.h"
#include "thread_pool.h"
#include "session.h"
#include "packet.h"

#define MAX_EVENTS      64
#define SOCKET_BUF_SIZE (4 * 1024 * 1024)
#define MAX_BURST       64

/*
 * g_thread_pool global thread pool used by packet_processor.c workers.
 * Sized to the number of online logical CPUs so each worker maps 1:1 to
 * a CPU.
 */
thread_pool_t *g_thread_pool = NULL;

/*
 * g_server_sk static server secret key.
 * Written once at startup (single-threaded), then read-only for the
 * lifetime of the process.  Workers receive a pointer to this; no copy
 * needed.
 */
uint8_t g_server_sk[PRIVKEY_LEN];

/*
 * g_next_packet_id outbound fragment reassembly counter.
 * _Atomic so concurrent outbound workers each get a unique ID without
 * a lock (atomic_fetch_add with wrapping is fine for reassembly IDs).
 */
/* g_next_packet_id is defined in fragment.c */

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <bind_ip> <port>\n", argv[0]);
        return 1;
    }

    struct in_addr test_addr;
    if (inet_aton(argv[1], &test_addr) == 0) {
        fprintf(stderr, "Invalid IP address: %s\n", argv[1]);
        return 1;
    }

    errno = 0;
    char *endptr = NULL;
    long port_val = strtol(argv[2], &endptr, 10);
    if (errno != 0 || *endptr != '\0' || port_val < 1 || port_val > 65535) {
        fprintf(stderr, "Invalid port: %s (must be 1-65535)\n", argv[2]);
        return 1;
    }
    uint16_t port = (uint16_t)port_val;

    if (sodium_init() < 0)          { fprintf(stderr, "sodium_init failed\n");      return 1; }
    if (rate_limiter_init() < 0)    { fprintf(stderr, "rate_limiter_init failed\n"); return 1; }
    if (metrics_init() < 0)         { fprintf(stderr, "metrics_init failed\n");      return 1; }

    graceful_shutdown_init(CONFIG_GRACEFUL_SHUTDOWN_TIMEOUT_SEC);

    memset(sessions, 0, sizeof(sessions));
    signal(SIGINT,  graceful_shutdown_signal_handler);
    signal(SIGTERM, graceful_shutdown_signal_handler);

    if (setup_ip_forward(1) < 0 || setup_nat() < 0) return -1;

    /* --- TUN interface ------------------------------------------------ */
    const char *tun_base = "tun_server";
    char tun_name[IFNAMSIZ];
    if (strlen(tun_base) >= IFNAMSIZ) { fprintf(stderr, "TUN name too long\n"); return 1; }
    strncpy(tun_name, tun_base, IFNAMSIZ - 1);
    tun_name[IFNAMSIZ - 1] = '\0';

    int tun_fd = tun_alloc(tun_name);
    if (tun_fd < 0) { vpn_log("Failed to allocate TUN interface"); return 1; }
    setup_interface(tun_name, "10.10.0.1/24");
    vpn_log("Interface %s configured", tun_name);

    int tun_flags = fcntl(tun_fd, F_GETFL, 0);
    if (tun_flags == -1 || fcntl(tun_fd, F_SETFL, tun_flags | O_NONBLOCK) == -1)
        perror("fcntl O_NONBLOCK on tun_fd (non-fatal)");

    /* --- Server key --------------------------------------------------- */
    uint8_t server_pk[PUBKEY_LEN];
    uint8_t server_sign_pk[crypto_sign_PUBLICKEYBYTES];
    
    if (load_or_create_server_key("server_static.key",
                                   g_server_sk,
                                   server_pk,
                                   server_sign_pk) != 0)
        return 1;
    
    printf("=== SERVER PUBLIC KEY (pass this to clients) ===\n");
    for (int i = 0; i < crypto_sign_PUBLICKEYBYTES; ++i)
        printf("%02x", server_sign_pk[i]);
    printf("\n================================================\n");
    fflush(stdout);

    /* --- UDP socket --------------------------------------------------- */
    int udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sock < 0) { perror("socket"); return 1; }

    int reuse = 1;
    if (setsockopt(udp_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        perror("setsockopt SO_REUSEADDR"); close(udp_sock); return 1;
    }
    int bufsize = SOCKET_BUF_SIZE;
    setsockopt(udp_sock, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    setsockopt(udp_sock, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));

    struct sockaddr_in bind_addr = {0};
    bind_addr.sin_family      = AF_INET;
    bind_addr.sin_port        = htons(port);
    bind_addr.sin_addr        = test_addr;
    if (bind(udp_sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        perror("bind"); return 1;
    }

    /* --- Thread pool -------------------------------------------------- */
    /*
     * Size the pool to the number of online CPUs.  Each worker is pinned
     * to one CPU (done inside thread_pool_create) giving WireGuard-style
     * per-CPU crypto parallelism.  Minimum 2 workers even on single-core.
     */
    int ncpus = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpus < 2) ncpus = 2;

    g_thread_pool = thread_pool_create(ncpus);
    if (!g_thread_pool) {
        fprintf(stderr, "Failed to create thread pool\n");
        return 1;
    }
    vpn_log("Thread pool: %d workers (one per CPU)", ncpus);

    /* --- epoll -------------------------------------------------------- */
    int epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) { perror("epoll_create1"); return 1; }

    struct epoll_event ev, events[MAX_EVENTS];

    ev.events  = EPOLLIN;
    ev.data.fd = udp_sock;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, udp_sock, &ev) == -1) {
        perror("epoll_ctl: udp_sock"); return 1;
    }
    ev.events  = EPOLLIN;
    ev.data.fd = tun_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, tun_fd, &ev) == -1) {
        perror("epoll_ctl: tun_fd"); return 1;
    }

    /* Scheduler shards (CBR/keepalive unchanged) */
    init_global_scheduler(1, 1024);

    time_t last_cleanup       = time(NULL);
    time_t last_metric_report = time(NULL);

    /* ================================================================
     * Main event loop epoll thread ONLY dispatches.  No crypto here.
     * ================================================================ */
    while (graceful_shutdown_get_state() == SHUTDOWN_IDLE) {

        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, 10);
        if (nfds < 0) {
            if (errno == EINTR) continue;
            perror("epoll_wait");
            break;
        }

        time_t now = time(NULL);

        if (now - last_cleanup >= 5) {
            perform_maintenance(udp_sock);
            rate_limiter_cleanup();
            int active = 0;
            for (int i = 0; i < MAX_CLIENTS; ++i)
                if (sessions[i].active) active++;
            metrics_set_active_connections(active);
            last_cleanup = now;
        }

        if (now - last_metric_report >= 30) {
            metrics_print_status();
            last_metric_report = now;
        }

        for (int i = 0; i < nfds; i++) {

            if (events[i].data.fd == udp_sock) {
                /*
                 * INBOUND path epoll thread:
                 *   recvfrom() > heap-copy > submit JOB_TYPE_INBOUND_CRYPTO
                 *
                 * Crypto (session-lookup, replay-check, aead_decrypt,
                 * tun_write) all happen on a worker thread.
                 *
                 * Shard key = session_id[0] (first byte after proto header),
                 * so all packets for the same session go to the same worker
                 * which means replay_window is safe without its own lock.
                 *
                 * Handshake packets (no session_id byte meaningful) fall back
                 * to round-robin via shard_key=0; handle_inbound_udp routes
                 * them to handle_msg1 which is stateless except for the
                 * global sessions table (protected by sessions_rwlock wrlock).
                 */
                for (int b = 0; b < MAX_BURST; b++) {
                    struct sockaddr_in src;
                    socklen_t src_len = sizeof(src);

                    /* Stack buffer for the recv we'll copy to heap only
                     * if the packet passes the minimal header check.       */
                    uint8_t tmp[BUFFER_SIZE];
                    ssize_t r = recvfrom(udp_sock, tmp, BUFFER_SIZE - 1,
                                         MSG_DONTWAIT,
                                         (struct sockaddr *)&src, &src_len);
                    if (r <= 0) break; /* EAGAIN */

                    if ((size_t)r < sizeof(proto_header_t)) continue;

                    proto_header_t *ph = (proto_header_t *)tmp;
                    if (ph->magic != PKT_MAGIC || ph->version != PKT_VERSION)
                        continue;

                    /* Determine shard key before the heap alloc */
                    uint8_t shard_key = 0;
                    if (ph->type == PKT_TYPE_DATA &&
                        (size_t)r >= sizeof(proto_header_t) + SESSION_ID_LEN)
                        shard_key = tmp[sizeof(proto_header_t)]; /* session_id[0] */

                    uint8_t *buf_copy = malloc((size_t)r);
                    if (!buf_copy) continue;
                    memcpy(buf_copy, tmp, (size_t)r);

                    job_t *job = calloc(1, sizeof(job_t));
                    if (!job) { free(buf_copy); continue; }

                    job->type                = JOB_TYPE_INBOUND_CRYPTO;
                    job->inbound.buf         = buf_copy;
                    job->inbound.buf_len     = (size_t)r;
                    job->inbound.src         = src;
                    job->inbound.udp_sock    = udp_sock;
                    job->inbound.tun_fd      = tun_fd;
                    job->inbound.server_sk   = g_server_sk; /* read-only global */

                    if (thread_pool_submit_sharded(g_thread_pool,
                                                   job, shard_key) != 0) {
                        free(buf_copy);
                        free(job);
                    }
                }

            } else if (events[i].data.fd == tun_fd) {
                /*
                 * OUTBOUND path epoll thread:
                 *   handle_outbound_tun() reads ONE packet from TUN, heap-
                 *   copies it, submits JOB_TYPE_OUTBOUND_CRYPTO.
                 *   Crypto (fragmentation, aead_encrypt, sendto) on worker.
                 *   Returns 0 when TUN has no more data (EAGAIN).
                 */
                for (int b = 0; b < MAX_BURST; b++) {
                    if (handle_outbound_tun(tun_fd, udp_sock) == 0) break;
                }
            }
        }
    }

    /* ================================================================
     * Graceful shutdown
     * ================================================================ */
    vpn_log("Shutdown initiated...");

    int active_sessions = 0;
    for (int i = 0; i < MAX_CLIENTS; ++i)
        if (sessions[i].active) active_sessions++;

    if (active_sessions > 0) {
        vpn_log("Phase 1: Notifying %d session(s) to disconnect",
                active_sessions);
        graceful_shutdown_drain_sessions(udp_sock);

        vpn_log("Phase 2: Draining (timeout %d s)",
                g_shutdown.shutdown_timeout_sec);

        time_t drain_start = time(NULL);
        int    outstanding = active_sessions;

        while (outstanding > 0 && !graceful_shutdown_timeout_exceeded()) {
            int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, 10);
            if (nfds > 0) {
                for (int i = 0; i < nfds; i++) {
                    if (events[i].data.fd == udp_sock) {
                        for (int b = 0; b < MAX_BURST; b++) {
                            struct sockaddr_in src;
                            socklen_t src_len = sizeof(src);
                            uint8_t tmp[BUFFER_SIZE];
                            ssize_t r = recvfrom(udp_sock, tmp, BUFFER_SIZE - 1,
                                                 MSG_DONTWAIT,
                                                 (struct sockaddr *)&src, &src_len);
                            if (r <= 0) break;

                            if ((size_t)r < sizeof(proto_header_t)) continue;
                            proto_header_t *ph = (proto_header_t *)tmp;
                            if (ph->magic != PKT_MAGIC || ph->version != PKT_VERSION)
                                continue;

                            uint8_t shard_key = 0;
                            if (ph->type == PKT_TYPE_DATA &&
                                (size_t)r >= sizeof(proto_header_t) + SESSION_ID_LEN)
                                shard_key = tmp[sizeof(proto_header_t)];

                            uint8_t *buf_copy = malloc((size_t)r);
                            if (!buf_copy) continue;
                            memcpy(buf_copy, tmp, (size_t)r);

                            job_t *job = calloc(1, sizeof(job_t));
                            if (!job) { free(buf_copy); continue; }

                            job->type              = JOB_TYPE_INBOUND_CRYPTO;
                            job->inbound.buf       = buf_copy;
                            job->inbound.buf_len   = (size_t)r;
                            job->inbound.src       = src;
                            job->inbound.udp_sock  = udp_sock;
                            job->inbound.tun_fd    = tun_fd;
                            job->inbound.server_sk = g_server_sk;

                            if (thread_pool_submit_sharded(g_thread_pool,
                                                           job, shard_key) != 0) {
                                free(buf_copy); free(job);
                            }
                        }
                    }
                }
            }

            outstanding = 0;
            for (int i = 0; i < MAX_CLIENTS; ++i)
                if (sessions[i].active) outstanding++;

            if (outstanding > 0) {
                time_t elapsed = time(NULL) - drain_start;
                vpn_log("Waiting (%d remaining, %lds elapsed)",
                        outstanding, elapsed);
            }
        }
    }

    vpn_log("Shutting down thread pool...");
    thread_pool_destroy(g_thread_pool);
    g_thread_pool = NULL;

    close(epoll_fd);
    metrics_print_detailed_report();
    metrics_destroy();
    rate_limiter_destroy();
    graceful_shutdown_cleanup(udp_sock, tun_fd);

    return 0;
}
