#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <time.h>
#include <stdint.h>
#include <stdatomic.h>
#include <pthread.h>
#include <errno.h>
#include <sys/prctl.h>
#include <sched.h>
#include <string.h>
#include <endian.h>
#include "vpn_common.h"
#include "vpn_log.h"
#include "session.h"
#include "vpn_crypto.h"
#include "packet.h"
#include "rate_limiter.h"
#include "metrics.h"
#include "scheduler.h"

#define NUM_SHARDS 4

/* -----------------------------------------------------------------------
 * Packet priority classifier
 * --------------------------------------------------------------------- */
static pkt_priority_t classify_packet(const uint8_t *ip, size_t len)
{
    if (!ip || len < 20) return PKT_PRIO_NORMAL;
    uint8_t version = (ip[0] >> 4);
    if (version == 4) {
        uint16_t total_len = (uint16_t)((ip[2] << 8) | ip[3]);
        uint8_t  protocol  = ip[9];
        uint8_t  ihl       = (ip[0] & 0x0F) * 4;
        if (total_len <= 128) return PKT_PRIO_HIGH;
        if (protocol == 1)    return PKT_PRIO_HIGH;
        if (protocol == 17 && len >= (size_t)(ihl + 4)) {
            uint16_t sport = (uint16_t)((ip[ihl]     << 8) | ip[ihl + 1]);
            uint16_t dport = (uint16_t)((ip[ihl + 2] << 8) | ip[ihl + 3]);
            if (sport == 53 || dport == 53) return PKT_PRIO_HIGH;
        }
        if (protocol == 6 && len >= (size_t)(ihl + 20)) {
            uint8_t  tcp_off     = (ip[ihl + 12] >> 4) * 4;
            uint8_t  tcp_flags   = ip[ihl + 13];
            uint16_t tcp_payload = total_len - ihl - tcp_off;
            if ((tcp_flags & 0x10) && tcp_payload == 0) return PKT_PRIO_HIGH;
        }
    } else if (version == 6) {
        if (len >= 40 && ip[6] == 58) return PKT_PRIO_HIGH;
        if (len <= 128)               return PKT_PRIO_HIGH;
    }
    return PKT_PRIO_NORMAL;
}

/* -----------------------------------------------------------------------
 * Two-lane priority out_queue
 * --------------------------------------------------------------------- */
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
        while (n) { out_node_t *t = n->next; free(n->pkt); free(n); n = t; }
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
    size_t cap = (prio == PKT_PRIO_HIGH) ? QUEUE_CAP_HIGH : QUEUE_CAP_NORMAL;

    out_node_t *n = malloc(sizeof(out_node_t));
    if (!n) { free(pkt); return; }
    n->next = NULL; n->pkt = pkt; n->pktlen = pktlen;
    n->seq = seq;   n->priority = prio;

    pthread_mutex_lock(&q->lock);
    if ((size_t)q->size[prio] >= cap) {
        out_node_t *old = q->head[prio];
        q->head[prio] = old->next;
        if (!q->head[prio]) q->tail[prio] = NULL;
        q->size[prio]--;
        metrics_record_queue_drop();
        free(old->pkt); free(old);
    }
    if (!q->tail[prio]) { q->head[prio] = q->tail[prio] = n; }
    else { q->tail[prio]->next = n; q->tail[prio] = n; }
    q->size[prio]++;
    pthread_mutex_unlock(&q->lock);
}

out_node_t *out_queue_pop(out_queue_t *q)
{
    pthread_mutex_lock(&q->lock);
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
    size_t t = (size_t)(q->size[PKT_PRIO_HIGH] + q->size[PKT_PRIO_NORMAL]);
    pthread_mutex_unlock(&q->lock);
    return t;
}

/* -----------------------------------------------------------------------
 * Scheduler min-heap
 * --------------------------------------------------------------------- */
priority_queue_t *pq_create(int capacity)
{
    priority_queue_t *pq = malloc(sizeof(priority_queue_t));
    if (!pq) return NULL;
    pq->capacity = capacity; pq->size = 0;
    pq->nodes = malloc(sizeof(scheduler_task_t *) * capacity);
    if (!pq->nodes) { free(pq); return NULL; }
    return pq;
}

int pq_is_empty(priority_queue_t *pq) { return (!pq || pq->size == 0); }
scheduler_task_t *pq_peek(priority_queue_t *pq) { return pq_is_empty(pq) ? NULL : pq->nodes[0]; }

int timespec_compare(struct timespec *a, struct timespec *b)
{
    if (a->tv_sec  != b->tv_sec)  return (a->tv_sec  > b->tv_sec)  ? 1 : -1;
    if (a->tv_nsec != b->tv_nsec) return (a->tv_nsec > b->tv_nsec) ? 1 : -1;
    return 0;
}

void pq_push(priority_queue_t *pq, scheduler_task_t *task)
{
    if (pq->size == pq->capacity) {
        pq->capacity *= 2;
        void *tmp = realloc(pq->nodes, sizeof(scheduler_task_t *) * pq->capacity);
        if (!tmp) { pq->capacity /= 2; return; }
        pq->nodes = tmp;
    }
    int i = pq->size++;
    while (i > 0) {
        int p = (i - 1) / 2;
        if (timespec_compare(&task->next_run, &pq->nodes[p]->next_run) >= 0) break;
        pq->nodes[i] = pq->nodes[p]; i = p;
    }
    pq->nodes[i] = task;
}

scheduler_task_t *pq_pop(priority_queue_t *pq)
{
    if (pq->size == 0) return NULL;
    scheduler_task_t *res  = pq->nodes[0];
    scheduler_task_t *last = pq->nodes[--pq->size];
    int i = 0;
    while (i * 2 + 1 < pq->size) {
        int child = i * 2 + 1;
        if (child + 1 < pq->size &&
            timespec_compare(&pq->nodes[child+1]->next_run,
                             &pq->nodes[child]->next_run) < 0) child++;
        if (timespec_compare(&last->next_run, &pq->nodes[child]->next_run) <= 0) break;
        pq->nodes[i] = pq->nodes[child]; i = child;
    }
    pq->nodes[i] = last;
    return res;
}

/* -----------------------------------------------------------------------
 * Interval helper
 * --------------------------------------------------------------------- */
void add_mbps_interval_to_timespec(struct timespec *ts, int mbps, int frag)
{
    double payload_len     = frag + MAC_LEN + SESSION_ID_LEN + 8;
    double ipv4_packet_len = payload_len + 14 + 20 + 8;
    double interval_sec    = (ipv4_packet_len * 8.0) / ((double)mbps * 1e6);
    if (interval_sec < 0.00001) interval_sec = 0.00001;
    uint64_t ns = (uint64_t)(interval_sec * 1e9);
    ts->tv_nsec += (long)ns;
    while (ts->tv_nsec >= 1000000000L) { ts->tv_sec++; ts->tv_nsec -= 1000000000L; }
}

static int execute_send(uint8_t *session_id)
{

    pthread_rwlock_rdlock(&sessions_rwlock);

    session_t *s = NULL;
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (sessions[i].active &&
            memcmp(sessions[i].session_id, session_id, SESSION_ID_LEN) == 0) {
            s = &sessions[i];
            break;
        }
    }
    if (!s) {
        pthread_rwlock_unlock(&sessions_rwlock);
        return 0;
    }

    int sent_real = 0;

    if (s->argv_CBR == 'Y') {

        out_node_t *node = out_queue_pop(s->outq);

        if (node) {

            size_t expected_wire =
                sizeof(proto_header_t) + SESSION_ID_LEN + 8 +
                (size_t)s->argv_FRAG + MAC_LEN;

            if (node->pktlen < expected_wire) {

                vpn_log("CBR size invariant broken: got %zu expected %zu",
                        node->pktlen, expected_wire);
            }

            sendto(s->s_udp_sock, node->pkt, node->pktlen, 0,
                   (struct sockaddr *)&s->client_addr, s->client_addrlen);
            free(node->pkt);
            free(node);
            sent_real = 1;

        } else {

            uint8_t encrypted_out[BUFFER_SIZE];
            size_t  outlen = 0;
            uint64_t seq   = atomic_fetch_add(&s->send_seq, 1);

            if (aead_encrypt(s->k_send, s->session_id, seq,
                             s->dummy_payload, (size_t)s->argv_FRAG,
                             encrypted_out, &outlen) == 0) {

                uint8_t  *ptr     = s->final_pkt_dummy + s->static_hdr_len;
                uint64_t  seq_net = htobe64(seq);
                memcpy(ptr,     &seq_net,      8);
                memcpy(ptr + 8, encrypted_out, outlen);
                size_t total_len =
                    (size_t)((ptr + 8 + outlen) - s->final_pkt_dummy);

                sendto(s->s_udp_sock, s->final_pkt_dummy, total_len, 0,
                       (struct sockaddr *)&s->client_addr,
                       s->client_addrlen);
            }
        }


    } else {

        out_node_t *node;
        while ((node = out_queue_pop(s->outq)) != NULL) {
            sendto(s->s_udp_sock, node->pkt, node->pktlen, 0,
                   (struct sockaddr *)&s->client_addr, s->client_addrlen);
            free(node->pkt);
            free(node);
            sent_real = 1;
        }


        if (!sent_real) {
            time_t now = time(NULL);
            if ((now - s->last_activity          >= KEEPALIVE_INTERVAL_SEC) &&
                (now - s->last_activity_keepalive >= KEEPALIVE_INTERVAL_SEC)) {
                send_control_packet(s->s_udp_sock, s, PKT_CTRL_KEEPALIVE);
                s->last_activity_keepalive = now;
            }
        }
    }

    pthread_rwlock_unlock(&sessions_rwlock);
    return sent_real;
}

/* -----------------------------------------------------------------------
 * Scheduler worker
 * --------------------------------------------------------------------- */
typedef struct {
    priority_queue_t *pq;
    pthread_mutex_t   lock;
    pthread_cond_t    cond;
    int               running;
    int               shard_id;
} global_scheduler_t;

global_scheduler_t g_shards[NUM_SHARDS];

void *scheduler_worker_fn(void *arg)
{
    global_scheduler_t *shard = (global_scheduler_t *)arg;
    prctl(PR_SET_TIMERSLACK, 1UL, 0, 0, 0);

    while (shard->running) {
        pthread_mutex_lock(&shard->lock);

        while (shard->running && pq_is_empty(shard->pq))
            pthread_cond_wait(&shard->cond, &shard->lock);

        if (!shard->running) { pthread_mutex_unlock(&shard->lock); break; }

        scheduler_task_t *task     = pq_peek(shard->pq);
        struct timespec   deadline = task->next_run;
        pthread_mutex_unlock(&shard->lock);

        clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline, NULL);

        pthread_mutex_lock(&shard->lock);
        if (pq_is_empty(shard->pq)) { pthread_mutex_unlock(&shard->lock); continue; }
        task = pq_peek(shard->pq);

        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (timespec_compare(&now, &task->next_run) < 0) {
            pthread_mutex_unlock(&shard->lock);
            continue;
        }

        task = pq_pop(shard->pq);
        pthread_mutex_unlock(&shard->lock);

        execute_send(task->session_id);

        session_t *s = session_by_id(task->session_id);
        if (s) {
            clock_gettime(CLOCK_MONOTONIC, &now);

            if (s->argv_CBR == 'Y') {

                add_mbps_interval_to_timespec(&task->next_run,
                                              s->argv_MBPS, s->argv_FRAG);

                long behind_ns =
                    (now.tv_sec  - task->next_run.tv_sec)  * 1000000000L +
                    (now.tv_nsec - task->next_run.tv_nsec);

                if (behind_ns > 0) {
                    /*
                     * Compute how many full intervals we are behind
                     * and skip them all at once rather than one per tick.
                     * This recovers instantly without a burst.
                     */
                    double payload_len =
                        (double)s->argv_FRAG + MAC_LEN + SESSION_ID_LEN + 8;
                    double wire_len    = payload_len + 14 + 20 + 8;
                    double interval_ns =
                        (wire_len * 8.0 / ((double)s->argv_MBPS * 1e6)) * 1e9;
                    if (interval_ns < 10000.0) interval_ns = 10000.0;

                    long skipped = (long)((double)behind_ns / interval_ns);
                    if (skipped > 0) {
                        vpn_log("CBR drift: skipped %ld intervals for session",
                                skipped);
                        //metrics_record_cbr_drift(skipped);
                        /*
                         * Jump next_run forward by skipped intervals
                         * so we re-sync to the correct cadence point.
                         */
                        uint64_t skip_ns = (uint64_t)((double)skipped * interval_ns);
                        task->next_run.tv_nsec += (long)(skip_ns % 1000000000ULL);
                        task->next_run.tv_sec  += (long)(skip_ns / 1000000000ULL);
                        while (task->next_run.tv_nsec >= 1000000000L) {
                            task->next_run.tv_sec++;
                            task->next_run.tv_nsec -= 1000000000L;
                        }
                    }
                }

            } else {
                task->next_run = now;
                task->next_run.tv_sec += KEEPALIVE_INTERVAL_SEC;
            }

            pthread_mutex_lock(&shard->lock);
            pq_push(shard->pq, task);
            pthread_cond_signal(&shard->cond);
            pthread_mutex_unlock(&shard->lock);
        } else {
            free(task);
        }
    }
    return NULL;
}

/* -----------------------------------------------------------------------
 * Lifecycle
 * --------------------------------------------------------------------- */
void init_global_scheduler(int ignored_num_workers, int initial_capacity)
{
    (void)ignored_num_workers;
    if (initial_capacity < 128 || initial_capacity > 65536) initial_capacity = 1024;

    for (int i = 0; i < NUM_SHARDS; i++) {
        g_shards[i].pq = pq_create(initial_capacity);
        if (!g_shards[i].pq) {
            fprintf(stderr, "Failed to create PQ for shard %d\n", i);
            return;
        }
        pthread_mutex_init(&g_shards[i].lock, NULL);
        pthread_cond_init(&g_shards[i].cond, NULL);
        g_shards[i].running  = 1;
        g_shards[i].shard_id = i;

        pthread_t tid;
        if (pthread_create(&tid, NULL, scheduler_worker_fn, &g_shards[i]) != 0) {
            fprintf(stderr, "Failed to create scheduler thread %d\n", i);
            g_shards[i].running = 0;
            return;
        }
        pthread_detach(tid);
    }
}

void scheduler_add_session(uint8_t *session_id)
{
    scheduler_task_t *task = malloc(sizeof(scheduler_task_t));
    if (!task) { vpn_log("malloc failed for scheduler_task_t"); return; }
    memcpy(task->session_id, session_id, SESSION_ID_LEN);
    clock_gettime(CLOCK_MONOTONIC, &task->next_run);

    int shard_idx = session_id[0] % NUM_SHARDS;
    pthread_mutex_lock(&g_shards[shard_idx].lock);
    pq_push(g_shards[shard_idx].pq, task);
    pthread_cond_signal(&g_shards[shard_idx].cond);
    pthread_mutex_unlock(&g_shards[shard_idx].lock);
}
