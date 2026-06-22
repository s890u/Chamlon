#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>
#include <time.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <arpa/inet.h>
#include <sodium.h>
#include <pthread.h>
#include <stdatomic.h>
#include "vpn_common.h"
#include "vpn_crypto.h"
#include "vpn_tun.h"
#include "vpn_log.h"
#include "vpn_queue.h"
#include "vpn_reassembly.h"
#include "vpn_sender_thread.h"
#include "vpn_handshake.h"
#include "vpn_utils.h"
#include "vpn_event_loop.h"
#include "vpn_packet_handler.h"
#include "../include/session.h"

/* Global state */
volatile int g_stop = 0;
int g_tun_fd = -1;
int g_udp_sock = -1;
char vpn_iface[IFNAMSIZ] = "tun_client";
char argv_TUN_NAME[IFNAMSIZ] = "tun_client";
char old_gateway[128] = "";
int route_added = 0;
uint8_t g_session_id[SESSION_ID_LEN];
int argv_MBPS = 5;
int argv_FRAG = 1024;
char argv_CBR = 'N';
char argv_PAD = 'N';
int argv_REHANDSHAKE_INTERVAL = 20;
int data_MBPS = 0;
int data_REAL = 0;
int data_DUMMY = 0;
int data_KEEP_ALIVES = 0;
int temp_real = 0;
int temp_dummy = 0;
time_t last_double_dummy_real = 0;
volatile sig_atomic_t disconnect_requested = 0;
sender_args_t *g_sender_args = NULL;
server_t servers[1] = {0};
pthread_t sender_thread;
uint16_t g_next_packet_id = 1;
out_queue_t *g_outq = NULL;

static void handle_signal(int sig) {
    (void)sig;
    disconnect_requested = 1;
}

void send_disconnect(int udp_sock) {
    uint8_t buf2[1400];
    tunnel_header_t th;
    th.packet_id = 1;
    th.fragment_offset = 1;
    th.total_ip_len = 1;
    th.flags = PKT_CTRL_DISCONNECT;
    memcpy(buf2, &th, sizeof(tunnel_header_t));
    memset(buf2 + sizeof(tunnel_header_t), 0x11, 1400 - sizeof(tunnel_header_t));

    size_t outlen = 0;
    uint8_t out[BUFFER_SIZE];
    /* Use atomic operation for lock-free sequence increment */
    uint64_t seq1 = atomic_fetch_add(&servers[0].send_seq, 1);

    if (aead_encrypt(servers[0].k_send, g_session_id, seq1,
                     buf2, 1400, out, &outlen) != 0) {
        vpn_log("encrypt failed seq=%lu", seq1);
        return;
    }

    size_t pktlen = sizeof(proto_header_t) + SESSION_ID_LEN + 8 + outlen;
    uint8_t pkt[pktlen];
    proto_header_t ph;
    ph.magic = PKT_MAGIC;
    ph.version = PKT_VERSION;
    ph.type = PKT_TYPE_DATA;
    memcpy(pkt, &ph, sizeof(proto_header_t));
    memcpy(pkt + sizeof(proto_header_t), g_session_id, SESSION_ID_LEN);
    uint64_t seq_net = htobe64(seq1);
    memcpy(pkt + sizeof(proto_header_t) + SESSION_ID_LEN, &seq_net, 8);
    memcpy(pkt + sizeof(proto_header_t) + SESSION_ID_LEN + 8, out, outlen);

    for (int attempt = 0; attempt < 3; attempt++) {
        ssize_t sent = sendto(udp_sock, pkt, pktlen, 0,
                              (struct sockaddr *)&servers[0].server_addr,
                              sizeof(servers[0].server_addr));
        if (sent == (ssize_t)pktlen) {
            vpn_log("Sent disconnect to server (attempt %d)", attempt + 1);
        } else {
            vpn_log("Failed to send disconnect attempt %d: %zd", attempt + 1, sent);
        }
    }
}

static int parse_arguments(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr,
            "Usage: %s <server_ip> <port> <server_pubkey_hex> [options]\n"
            "  options:\n"
            "    MBPS:<1-15>\n"
            "    FRAG:<Y/N>:<300-1200>\n"
            "    CBR:<Y/N>\n"
            "    PAD:<Y/N>\n"
            "    REHANDSHAKE:<seconds>\n"
            "    TUN:<name>\n",
            argv[0]);
        return -1;
    }

    if (hex2bin(argv[3], servers[0].server_pk, PUBKEY_LEN) != 0) {
        fprintf(stderr, "bad server pubkey hex\n");
        return -1;
    }

    memset(&servers[0].server_addr, 0, sizeof(struct sockaddr_in));
    servers[0].server_addr.sin_family = AF_INET;
    servers[0].server_addr.sin_port = htons(atoi(argv[2]));
    if (inet_aton(argv[1], &servers[0].server_addr.sin_addr) == 0) {
        fprintf(stderr, "bad server ip\n");
        return -1;
    }

    for (int i = 4; i < argc; i++) {
        char key[32], v1[32], v2[32];
        int count = sscanf(argv[i], "%31[^:]:%31[^:]:%31s", key, v1, v2);
        if (count >= 2) {
            if (strcmp(key, "MBPS") == 0) {
                int value = atoi(v1);
                if (value < 1) value = 1;
                if (value > 15) value = 15;
                argv_MBPS = value;
            } else if (strcmp(key, "FRAG") == 0) {
                if ((v1[0] == 'Y' || v1[0] == 'N') && count == 3) {
                    int value = atoi(v2);
                    if (value < 300) value = 300;
                    if (value > 1200) value = 1200;
                    argv_FRAG = value;
                }
            } else if (strcmp(key, "CBR") == 0) {
                if (v1[0] == 'Y' || v1[0] == 'N') argv_CBR = v1[0];
            } else if (strcmp(key, "PAD") == 0) {
                if (v1[0] == 'Y' || v1[0] == 'N') argv_PAD = v1[0];
            } else if (strcmp(key, "REHANDSHAKE") == 0) {
                int value = atoi(v1);
                if (value < 1) value = 1;
                argv_REHANDSHAKE_INTERVAL = value;
            } else if (strcmp(key, "TUN") == 0) {
                strncpy(argv_TUN_NAME, v1, IFNAMSIZ - 1);
                argv_TUN_NAME[IFNAMSIZ - 1] = '\0';
            }
        }
    }
    return 0;
}

static int setup_and_handshake(int *tun_fd, int *udp_sock) {
    char tun_name[IFNAMSIZ];
    strncpy(tun_name, argv_TUN_NAME, IFNAMSIZ - 1);
    tun_name[IFNAMSIZ - 1] = '\0';
    *tun_fd = tun_alloc(tun_name);
    if (*tun_fd < 0) return -1;
    g_tun_fd = *tun_fd;
    strncpy(vpn_iface, tun_name, IFNAMSIZ - 1);
    vpn_iface[IFNAMSIZ - 1] = '\0';

    *udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (*udp_sock < 0) {
        perror("socket");
        close(*tun_fd);
        return -1;
    }
    g_udp_sock = *udp_sock;

    vpn_log("Will connect to %s:%u", inet_ntoa(servers[0].server_addr.sin_addr),
            ntohs(servers[0].server_addr.sin_port));

    FILE *fp = popen("ip route show default | awk '/default/ {print $3; exit}'", "r");
    if (fp) {
        if (fgets(old_gateway, sizeof(old_gateway), fp) != NULL) {
            old_gateway[strcspn(old_gateway, "\n")] = '\0';
            vpn_log("Saved original gateway: %s", old_gateway);
        } else {
            old_gateway[0] = '\0';
        }
        pclose(fp);
    }

    if (client_handshake(*udp_sock, &servers[0].server_addr, servers[0].server_pk,
                         servers[0].session_id, servers[0].k_send, servers[0].k_recv,
                         servers[0].assigned_ip, NULL) != 0) {
        vpn_log("handshake failed");
        restore_route_and_cleanup_client();
        return -1;
    }

    memcpy(g_session_id, servers[0].session_id, SESSION_ID_LEN);

    char ipcidr[64];
    snprintf(ipcidr, sizeof(ipcidr), "%u.%u.%u.%u/24", servers[0].assigned_ip[0],
             servers[0].assigned_ip[1], servers[0].assigned_ip[2],
             servers[0].assigned_ip[3]);
    setup_interface(tun_name, ipcidr);
    vpn_log("Assigned VPN IP %s", ipcidr);

    /* --- NEW: pin server IP to real gateway BEFORE changing default route --- */
    if (old_gateway[0] != '\0') {
        char cmd_pin[256];
        snprintf(cmd_pin, sizeof(cmd_pin),
                 "ip route add %s/32 via %s 2>/dev/null",
                 inet_ntoa(servers[0].server_addr.sin_addr),
                 old_gateway);
        #pragma GCC diagnostic push
        #pragma GCC diagnostic ignored "-Wunused-result"
        system(cmd_pin);
        #pragma GCC diagnostic pop
        vpn_log("Pinned server route: %s via %s",
                inet_ntoa(servers[0].server_addr.sin_addr), old_gateway);
    }

    /* --- Change default route through tunnel --- */
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "ip route del default 2>/dev/null; "
             "ip route add default via 10.10.0.1 dev %s 2>/dev/null",
             vpn_iface);
    int rc = system(cmd);
    (void)rc;
    if (rc == 0) {
        route_added = 1;
        vpn_log("Default route changed to 10.10.0.1 (dev %s)", vpn_iface);
    }

    return 0;
}

static int start_sender_thread(int udp_sock) {
    prepare_dummy_static_parts(servers[0].session_id);

    sender_args_t *args = malloc(sizeof(sender_args_t));
    g_sender_args = args;
    if (!args) return -1;

    args->udp_sock = udp_sock;
    args->outq = g_outq;
    args->server_addr = servers[0].server_addr;
    memcpy(args->k_send, servers[0].k_send, AEAD_KEY_LEN);
    memcpy(args->session_id, servers[0].session_id, SESSION_ID_LEN);
    set_interval_from_mbps(argv_MBPS, 0, &args->interval);

    if (pthread_create(&sender_thread, NULL, sender_thread_fn, (void *)args) != 0) {
        vpn_log("Failed to create sender thread");
        free(args);
        return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init failed\n");
        return 1;
    }

    reassembly_init();
    if (parse_arguments(argc, argv) != 0) return 1;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    int tun_fd, udp_sock;
    if (setup_and_handshake(&tun_fd, &udp_sock) != 0) return 1;

    g_outq = malloc(sizeof(out_queue_t));
    if (!g_outq) {
        vpn_log("malloc failed");
        close(tun_fd);
        close(udp_sock);
        return 1;
    }
    out_queue_init(g_outq);

    if (start_sender_thread(udp_sock) != 0) {
        out_queue_destroy(g_outq);
        free(g_outq);
        close(tun_fd);
        close(udp_sock);
        return 1;
    }

    printf("CONNECTED\n");
    fflush(stdout);

    int ret = event_loop_run(tun_fd, udp_sock, argv_FRAG);

    if (disconnect_requested && g_udp_sock >= 0) {
        send_disconnect(udp_sock);
    }

    restore_route_and_cleanup_client();
    return ret;
}
