#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include "vpn_common.h"
#include "vpn_crypto.h"
#include "vpn_log.h"
#include "vpn_queue.h"
#include "vpn_replay_window.h"
#include "vpn_reassembly.h"
#include "vpn_utils.h"
#include "../include/session.h"
#include "vpn_sender_thread.h"
#include "vpn_handshake.h"
#define KEEPALIVE_INTERVAL_SEC   25
#define SERVER_KEEPALIVE_TIMEOUT 125
#define MAX_BURST                64   /* max packets to drain per epoll event */
#define REHANDSHAKE_BYTES_LIMIT   (1ULL << 30)
#define REHANDSHAKE_SEQ_LIMIT     (1ULL << 32)

extern volatile int g_stop;
extern int g_tun_fd, g_udp_sock;
extern char vpn_iface[];
extern char old_gateway[128];
extern int route_added;
extern uint8_t g_session_id[SESSION_ID_LEN];
extern int argv_MBPS, argv_FRAG;
extern int argv_REHANDSHAKE_INTERVAL;
extern volatile sig_atomic_t disconnect_requested;
extern server_t servers[1];
extern uint16_t g_next_packet_id;
extern out_queue_t *g_outq;
extern sender_args_t *g_sender_args;
extern void send_disconnect(int udp_sock);
extern void send_keepalive(int udp_sock);
extern void handle_tun_packet(int tun_fd, int udp_sock, out_queue_t *outq);
extern void handle_udp_packet(int udp_sock, int tun_fd, replay_window_t *rw);

time_t last_server_keepalive_time;
volatile sig_atomic_t g_rehandshake_in_progress = 0;

static void trigger_graceful_disconnect(const char *reason) {
    vpn_log("Triggering graceful disconnect: %s", reason);
    disconnect_requested = 1;
}

static void handle_disconnect_request(void) {
    if (disconnect_requested) {
        if (g_udp_sock >= 0) send_disconnect(g_udp_sock);
        if (route_added) {
            if (old_gateway[0]) {
                char cmd[256];
                snprintf(cmd, sizeof(cmd),
                         "ip route del default dev %s 2>/dev/null; "
                         "ip route add default via %s 2>/dev/null",
                         vpn_iface, old_gateway);
                int rc = system(cmd); (void)rc;
                vpn_log("Restored default route to %s", old_gateway);
            } else {
                char cmd[128];
                snprintf(cmd, sizeof(cmd),
                         "ip route del default dev %s 2>/dev/null", vpn_iface);
                int rc = system(cmd); (void)rc;
                vpn_log("Removed VPN default route");
            }
            route_added = 0;
        }
        if (g_tun_fd >= 0)   close(g_tun_fd);
        if (g_udp_sock >= 0) close(g_udp_sock);
        _exit(0);
    }
}

int event_loop_run(int tun_fd, int udp_sock, int frag_size) {
    (void)frag_size;
    replay_window_t rw = {0};
    rehandshake_buffer_t rehandshake_buffer = {0};
    rehandshake_buffer_init(&rehandshake_buffer);
    
    time_t last_keepalive            = time(NULL);
    last_server_keepalive_time       = time(NULL);
    time_t last_sweep                = time(NULL);
    time_t last_rehandshake          = time(NULL);
    struct epoll_event ev, events[2];
    int ret = 0;

    /*
     * Set UDP socket non-blocking so we can drain multiple packets
     * per epoll event without ever blocking.
     */
    int flags = fcntl(udp_sock, F_GETFL, 0);
    if (flags != -1) fcntl(udp_sock, F_SETFL, flags | O_NONBLOCK);

    /*
     * Set UDP socket receive buffer to 4MB so the kernel doesn't
     * drop packets during download bursts before we can read them.
     */
    int bufsize = 4 * 1024 * 1024;
    setsockopt(udp_sock, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    setsockopt(udp_sock, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));

    int epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0) { perror("epoll_create1"); return -1; }

    ev.events  = EPOLLIN;
    ev.data.fd = tun_fd;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, tun_fd, &ev) < 0) {
        perror("epoll_ctl add tun"); close(epfd); return -1;
    }

    ev.events  = EPOLLIN;
    ev.data.fd = udp_sock;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, udp_sock, &ev) < 0) {
        perror("epoll_ctl add udp"); close(epfd); return -1;
    }

    while (!g_stop) {
        handle_disconnect_request();

        int nfds = epoll_wait(epfd, events, 2, 10);
        if (nfds < 0) {
            if (errno == EINTR) continue;
            perror("epoll_wait");
            break;
        }

        time_t now = time(NULL);

        if (now - last_keepalive >= KEEPALIVE_INTERVAL_SEC) {
            send_keepalive(udp_sock);
            last_keepalive = now;
        }

        if (now - last_server_keepalive_time >= SERVER_KEEPALIVE_TIMEOUT) {
            vpn_log("Server keepalive timeout, disconnecting");
            ret = -1;
            break;
        }

        if (now - last_rehandshake >= argv_REHANDSHAKE_INTERVAL ||
            servers[0].bytes_sent  >= REHANDSHAKE_BYTES_LIMIT  ||
            atomic_load(&servers[0].send_seq) >= REHANDSHAKE_SEQ_LIMIT) {
        
            int should_rehandshake = should_attempt_rehandshake(&servers[0]);
            
            if (should_rehandshake == -1) {
                /* Max attempts reached, disconnect gracefully */
                trigger_graceful_disconnect("Rehandshake max attempts exceeded");
            } else if (should_rehandshake == 1) {
                /* Attempt rehandshake */
                if (g_sender_args != NULL) {
                    if (rehandshake_client_with_state(udp_sock,
                                                       &servers[0].server_addr,
                                                       servers[0].server_pk,
                                                       &servers[0],
                                                       g_sender_args,
                                                       &rw,
                                                       &rehandshake_buffer) == 0) {
                        last_rehandshake = now;
                        vpn_log("Rehandshake succeeded, resetting timer");
                    }
                    /* On failure, state machine handles backoff internally */
                }
            }
            /* If should_rehandshake == 0, we're in backoff, just continue */
        }

        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == tun_fd && (events[i].events & EPOLLIN)) {
                /*
                 * TUN: drain all available packets.
                 * Each call to handle_tun_packet reads one IP packet
                 * from the TUN fd and encrypts/enqueues it.
                 * We loop until EAGAIN to avoid leaving packets waiting
                 * for the next epoll cycle.
                 */
                for (int b = 0; b < MAX_BURST; b++) {
                    handle_tun_packet(tun_fd, udp_sock, g_outq);
                    /* handle_tun_packet calls read() internally;
                     * if it reads 0 or gets EAGAIN it returns early.
                     * We rely on the sender thread to pace output. */
                    break; /* TUN is blocking on client                                                                                                                                                                                                                                              single read for now */
                }

            } else if (events[i].data.fd == udp_sock && (events[i].events & EPOLLIN)) {
                /*
                 * UDP: drain ALL available packets per epoll event.
                 * UNLESS re-handshake is in progress.
                 *
                 * Previously we processed ONE packet per epoll cycle.
                 * At 5 Mbps with 1024-byte fragments, we receive ~610
                 * packets/sec. With 10ms epoll timeout that's only 6
                 * packets per cycle, but if each cycle only reads ONE,
                 * the other 5 wait up to 10ms = up to 50ms of queuing
                 * latency per packet batch, destroying throughput.
                 *
                 * With MSG_DONTWAIT drain loop, all 6+ packets are
                 * processed immediately in one cycle.
                 *
                 * Skip draining during re-handshake to avoid race conditions
                 * where the event loop and re-handshake code compete for MSG2.
                 */
                if (!g_rehandshake_in_progress) {
                    for (int b = 0; b < MAX_BURST; b++) {
                        handle_udp_packet(udp_sock, tun_fd, &rw);

                        /* Check if the last call got EAGAIN.
                         * handle_udp_packet calls recvfrom internally.
                         * If errno is EAGAIN after return, stop draining. */
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                    }
                }

                if (disconnect_requested) {
                    last_server_keepalive_time = time(NULL);
                }
            }
        }

        if (now - last_sweep >= 5) {
            sweep_reassembly_table();
            last_sweep = now;
        }
    }

    vpn_log("Client event loop shutting down");
    rehandshake_buffer_free(&rehandshake_buffer);
    close(epfd);
    restore_route_and_cleanup_client();
    return ret;
}
