#ifndef VPN_QUEUE_H
#define VPN_QUEUE_H

#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdbool.h>

/* Priority levels */
typedef enum {
    PKT_PRIO_HIGH   = 0,   /* ICMP, DNS, ACKs, keepalives always sent first */
    PKT_PRIO_NORMAL = 1,   /* Bulk data */
    PKT_PRIO_LEVELS = 2
} pkt_priority_t;

/* Maximum packets per priority level before tail-drop */
#define QUEUE_CAP_HIGH   64
#define QUEUE_CAP_NORMAL 256

typedef struct out_node {
    struct out_node  *next;
    uint8_t          *pkt;
    size_t            pktlen;
    uint64_t          seq;
    pkt_priority_t    priority;
} out_node_t;

typedef struct out_queue {
    out_node_t      *head[PKT_PRIO_LEVELS];
    out_node_t      *tail[PKT_PRIO_LEVELS];
    size_t           size[PKT_PRIO_LEVELS];
    pthread_mutex_t  lock;
} out_queue_t;

/* Lifecycle */
void out_queue_init(out_queue_t *q);
void out_queue_destroy(out_queue_t *q);

/*
 * packet_queue_push, Enqueue a packet with automatic priority classification.
 *
 * Priority is determined by inspecting the plaintext IP payload embedded
 * in the tunnel frame BEFORE encryption.  The caller passes:
 *   @ip_buf : pointer to the raw IP packet (starts at IP version byte)
 *   @ip_len : length of the raw IP packet
 *
 * This keeps all classification logic in one place and out of the hot path.
 */
void packet_queue_push(out_queue_t *q,
                       uint8_t *pkt, size_t pktlen,
                       uint64_t seq,
                       const uint8_t *ip_buf, size_t ip_len);

/*
 * out_queue_pop, Dequeue the highest-priority packet available.
 * Returns NULL if both queues are empty.
 */
out_node_t *out_queue_pop(out_queue_t *q);

/*
 * out_queue_size, Total packets across all priority levels.
 */
size_t out_queue_size(out_queue_t *q);

#endif /* VPN_QUEUE_H */
