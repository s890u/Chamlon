#include "vpn_queue.h"
#include <string.h>

/* -----------------------------------------------------------------------
 * Internal helpers
 * --------------------------------------------------------------------- */

/*
 * classify_packet - Determine priority by inspecting the raw IP header.
 *
 * HIGH priority:
 *   - ICMP  (protocol 1), ping, traceroute, unreachables
 *   - ICMPv6 (protocol 58)
 *   - DNS   (UDP dst/src port 53)
 *   - TCP packets with ACK set and no payload (pure ACKs)
 *   - Any IP packet whose total length <= 128 bytes (interactive traffic)
 *
 * Everything else is NORMAL (bulk).
 */
static pkt_priority_t classify_packet(const uint8_t *ip, size_t len)
{
    if (!ip || len < 20) return PKT_PRIO_NORMAL;

    /* Only handle IPv4 for now; IPv6 falls to NORMAL unless tiny */
    uint8_t version = (ip[0] >> 4);

    if (version == 4) {
        uint16_t total_len = (uint16_t)((ip[2] << 8) | ip[3]);
        uint8_t  protocol  = ip[9];
        uint8_t  ihl       = (ip[0] & 0x0F) * 4;

        /* Small packets are always interactive */
        if (total_len <= 128) return PKT_PRIO_HIGH;

        /* ICMP */
        if (protocol == 1) return PKT_PRIO_HIGH;

        /* DNS over UDP (port 53 either direction) */
        if (protocol == 17 && len >= (size_t)(ihl + 4)) {
            uint16_t sport = (uint16_t)((ip[ihl]     << 8) | ip[ihl + 1]);
            uint16_t dport = (uint16_t)((ip[ihl + 2] << 8) | ip[ihl + 3]);
            if (sport == 53 || dport == 53) return PKT_PRIO_HIGH;
        }

        /* TCP pure ACK (ACK flag set, payload length == 0) */
        if (protocol == 6 && len >= (size_t)(ihl + 20)) {
            uint8_t  tcp_off   = (ip[ihl + 12] >> 4) * 4;
            uint8_t  tcp_flags = ip[ihl + 13];
            uint16_t tcp_payload = total_len - ihl - tcp_off;
            if ((tcp_flags & 0x10) && tcp_payload == 0) return PKT_PRIO_HIGH;
        }

    } else if (version == 6) {
        /* ICMPv6 */
        if (len >= 40 && ip[6] == 58) return PKT_PRIO_HIGH;
        /* Small IPv6 */
        if (len <= 128) return PKT_PRIO_HIGH;
    }

    return PKT_PRIO_NORMAL;
}

static size_t queue_cap(pkt_priority_t p)
{
    return (p == PKT_PRIO_HIGH) ? QUEUE_CAP_HIGH : QUEUE_CAP_NORMAL;
}

void out_queue_init(out_queue_t *q)
{
    memset(q, 0, sizeof(*q));
    pthread_mutex_init(&q->lock, NULL);
}

void out_queue_destroy(out_queue_t *q)
{
    pthread_mutex_lock(&q->lock);
    for (int p = 0; p < PKT_PRIO_LEVELS; p++) {
        out_node_t *n = q->head[p];
        while (n) {
            out_node_t *t = n->next;
            free(n->pkt);
            free(n);
            n = t;
        }
        q->head[p] = q->tail[p] = NULL;
        q->size[p] = 0;
    }
    pthread_mutex_unlock(&q->lock);
    pthread_mutex_destroy(&q->lock);
}

void packet_queue_push(out_queue_t *q,
                       uint8_t *pkt, size_t pktlen,
                       uint64_t seq,
                       const uint8_t *ip_buf, size_t ip_len)
{
    if (!q || !pkt) return;

    pkt_priority_t prio = classify_packet(ip_buf, ip_len);
    size_t cap = queue_cap(prio);

    out_node_t *n = malloc(sizeof(out_node_t));
    if (!n) { free(pkt); return; }

    n->next     = NULL;
    n->pkt      = pkt;
    n->pktlen   = pktlen;
    n->seq      = seq;
    n->priority = prio;

    pthread_mutex_lock(&q->lock);

    /* Tail-drop: if this priority level is full, drop the OLDEST packet
     * (head of queue) to make room this keeps latency bounded. */
    if (q->size[prio] >= cap) {
        out_node_t *old = q->head[prio];
        q->head[prio] = old->next;
        if (!q->head[prio]) q->tail[prio] = NULL;
        q->size[prio]--;
        free(old->pkt);
        free(old);
    }

    /* Enqueue at tail */
    if (!q->tail[prio]) {
        q->head[prio] = q->tail[prio] = n;
    } else {
        q->tail[prio]->next = n;
        q->tail[prio] = n;
    }
    q->size[prio]++;

    pthread_mutex_unlock(&q->lock);
}

out_node_t *out_queue_pop(out_queue_t *q)
{
    pthread_mutex_lock(&q->lock);

    /* Always drain HIGH priority first */
    out_node_t *n = NULL;
    for (int p = 0; p < PKT_PRIO_LEVELS; p++) {
        if (q->head[p]) {
            n = q->head[p];
            q->head[p] = n->next;
            if (!q->head[p]) q->tail[p] = NULL;
            q->size[p]--;
            break;
        }
    }

    pthread_mutex_unlock(&q->lock);
    return n;
}

size_t out_queue_size(out_queue_t *q)
{
    pthread_mutex_lock(&q->lock);
    size_t total = 0;
    for (int p = 0; p < PKT_PRIO_LEVELS; p++) total += q->size[p];
    pthread_mutex_unlock(&q->lock);
    return total;
}
