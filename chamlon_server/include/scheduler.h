#ifndef SCHEDULER_H
#define SCHEDULER_H

#include <time.h>
#include <stdint.h>
#include <stddef.h>
#include "vpn_common.h"
#include "session.h"

/* Scheduler task / min-heap node*/
typedef struct {
    struct timespec next_run;
    uint8_t         session_id[SESSION_ID_LEN];
} scheduler_task_t;

typedef struct {
    scheduler_task_t **nodes;
    int                size;
    int                capacity;
} priority_queue_t;


/* Control packet helper (keepalive / disconnect) */
void send_control_packet(int udp_sock, session_t *s, uint8_t ctrl_type);

/* out_queue */
void        out_queue_init(out_queue_t *q);
void        out_queue_destroy(out_queue_t *q);
/*
 * packet_queue_push - enqueue an encrypted packet.
 * @ip_buf / @ip_len : pointer to the ORIGINAL raw IP packet (before
 *                     fragmentation/encryption) used for priority
 *                     classification.  Must not be NULL.
 */
void        packet_queue_push(out_queue_t *q,
                               uint8_t *pkt, size_t pktlen,
                               uint64_t seq,
                               const uint8_t *ip_buf, size_t ip_len);
out_node_t *out_queue_pop(out_queue_t *q);
size_t      out_queue_size(out_queue_t *q);

/* Scheduler min-heap */
priority_queue_t *pq_create(int capacity);
int               pq_is_empty(priority_queue_t *pq);
scheduler_task_t *pq_peek(priority_queue_t *pq);
int               timespec_compare(struct timespec *a, struct timespec *b);
void              pq_push(priority_queue_t *pq, scheduler_task_t *task);
scheduler_task_t *pq_pop(priority_queue_t *pq);

void  add_mbps_interval_to_timespec(struct timespec *ts, int mbps, int frag);
void *scheduler_worker_fn(void *arg);
void  init_global_scheduler(int num_workers, int initial_capacity);
void  scheduler_add_session(uint8_t *session_id);

#endif /* SCHEDULER_H */
