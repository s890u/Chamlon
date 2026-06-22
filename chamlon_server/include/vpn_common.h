#ifndef VPN_COMMON_H
#define VPN_COMMON_H

#include <stdint.h>
#include <netinet/in.h>
#include <time.h>
#include <stdbool.h>
#include <pthread.h>
#include <sodium.h>
#include "config.h"

/* Import configuration constants from config.h */
#define BUFFER_SIZE                 CONFIG_BUFFER_SIZE
#define MAX_FRAG                    CONFIG_MAX_FRAG
#define WINDOW_SIZE                 CONFIG_WINDOW_SIZE
#define WORD_SIZE                   CONFIG_WORD_SIZE
#define BITMAP_WORDS                CONFIG_BITMAP_WORDS
#define SESSION_ID_LEN              CONFIG_SESSION_ID_LEN
#define PACKET_LENGTH               CONFIG_PACKET_LENGTH

#define PKT_CTRL_KEEPALIVE          0x02
#define PKT_CTRL_DISCONNECT         0x03
#define PKT_TYPE_SERVER_RELAY       0x04
#define PKT_TYPE_NODE_REQUEST       0x05
#define PKT_TYPE_NODE_RESPONSE      0x06
#define PKT_TYPE_SERVER_REQUEST     0x07
#define PKT_TYPE_SERVER_RESPONSE    0x08
#define PKT_TYPE_HANDSHAKE_RELAY    0x09
#define PKT_TYPE_RELAY              0x10
#define PKT_DUMMY                   0xFF

#define PARAMS                      4+4+1+1
#define MSG1_LEN                    (PUBKEY_LEN + 8)
#define MSG2_LEN                    (PUBKEY_LEN + 8 + 4 + crypto_sign_BYTES)
#define DATA_MIN_LEN                (SESSION_ID_LEN + 8 + MAC_LEN)
#define DATA_HEADER_LEN             (sizeof(proto_header_t) + SESSION_ID_LEN + 8)

#define NEXT_HOP_EMPTY              0x01
#define MAX_RELAYS_ALLOWED_FOR_NODE 0x02
#define NXT_TUNN                    0x03
#define PKT_RELAY0                  0x04
#define PKT_RELAY1                  0x05
#define EMPTY_KRECV                 0x06
#define NEXT_HOP_ON_HELPER_TUNNEL   0x07
#define NO_FLAGS                    0x08

#define SLIDING_WINDOW_SIZE         CONFIG_SLIDING_WINDOW_SIZE
#define SESSION_TIMEOUT_SEC         CONFIG_SESSION_TIMEOUT_SEC
#define KEEPALIVE_INTERVAL_SEC      CONFIG_KEEPALIVE_INTERVAL_SEC
#define MAX_PACKET_SIZE             CONFIG_MAX_PACKET_SIZE
#define MAX_REASSEMBLY_ENTRIES      CONFIG_MAX_REASSEMBLY_ENTRIES
#define REASSEMBLY_TIMEOUT          CONFIG_REASSEMBLY_TIMEOUT_SEC
#define PKT_MAGIC                   CONFIG_PKT_MAGIC
#define PKT_VERSION                 CONFIG_PKT_VERSION
#define PKT_TYPE_HANDSHAKE          CONFIG_PKT_TYPE_HANDSHAKE
#define PKT_TYPE_DATA               CONFIG_PKT_TYPE_DATA

/* -----------------------------------------------------------------------
 * Packet priority, two-lane queue (HIGH drains before NORMAL)
 * --------------------------------------------------------------------- */
typedef enum {
    PKT_PRIO_HIGH   = 0,   /* ICMP, DNS, ACKs, small pkts */
    PKT_PRIO_NORMAL = 1,   /* Bulk data                   */
    PKT_PRIO_LEVELS = 2
} pkt_priority_t;

#define QUEUE_CAP_HIGH   64
#define QUEUE_CAP_NORMAL 256

/* -----------------------------------------------------------------------
 * Reassembly table entry
 * --------------------------------------------------------------------- */
typedef struct {
    uint16_t packet_id;
    time_t   last_activity;
    size_t   expected_length;
    size_t   received_bytes;
    uint8_t  buffer[MAX_PACKET_SIZE];
    bool     is_active;
} reassembly_entry_t;

/* -----------------------------------------------------------------------
 * Tunnel header
 * --------------------------------------------------------------------- */
typedef struct {
    uint16_t packet_id;
    uint16_t fragment_offset;
    uint16_t total_ip_len;
    uint16_t flags;
    uint8_t  session_id[SESSION_ID_LEN];
} __attribute__((packed)) tunnel_header_t;

/* -----------------------------------------------------------------------
 * out_queue, two-lane priority FIFO
 * head[0]/tail[0]/size[0] = HIGH
 * head[1]/tail[1]/size[1] = NORMAL
 * out_queue_pop always drains HIGH first.
 * --------------------------------------------------------------------- */
typedef struct out_node {
    struct out_node *next;
    uint8_t         *pkt;
    size_t           pktlen;
    uint64_t         seq;
    pkt_priority_t   priority;
} out_node_t;

typedef struct {
    out_node_t      *head[PKT_PRIO_LEVELS];
    out_node_t      *tail[PKT_PRIO_LEVELS];
    int              size[PKT_PRIO_LEVELS];
    pthread_mutex_t  lock;
} out_queue_t;

/* -----------------------------------------------------------------------
 * Replay window
 * --------------------------------------------------------------------- */
typedef struct {
    uint64_t recv_max;
    uint64_t bitmap[BITMAP_WORDS];
} replay_window_t;

/* -----------------------------------------------------------------------
 * Protocol header
 * --------------------------------------------------------------------- */
typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint8_t  version;
    uint8_t  type;
} proto_header_t;

#endif /* VPN_COMMON_H */
