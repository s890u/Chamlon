#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>

#ifdef __linux__
#include <sched.h>
#include <sys/prctl.h>
#endif

#include "thread_pool.h"
#include "vpn_log.h"
#include "vpn_common.h"
#include "packet_processor.h"

/* -----------------------------------------------------------------------
 * Per-shard job queue
 *
 * Each worker thread owns exactly one shard.  The epoll thread routes
 * jobs to a shard via thread_pool_submit_sharded(shard_key % num_threads).
 * Because all packets for a given session always land on the same shard:
 *   - replay_window updates are single-threaded per session → no rw lock
 *   - outbound fragment ordering per session is preserved
 * --------------------------------------------------------------------- */
typedef struct job_node {
    struct job_node *next;
    job_t           *job;
} job_node_t;

typedef struct {
    job_node_t     *head;
    job_node_t     *tail;
    int             size;
    int             max_size;
    pthread_mutex_t lock;
    pthread_cond_t  cond;
} shard_queue_t;

/* -----------------------------------------------------------------------
 * Thread pool
 * --------------------------------------------------------------------- */
struct thread_pool {
    pthread_t      *threads;
    shard_queue_t  *shards;     /* one per thread */
    int             num_threads;
    int             shutdown;
};

/* -----------------------------------------------------------------------
 * Worker executes jobs from its own shard queue
 * --------------------------------------------------------------------- */
typedef struct {
    thread_pool_t *pool;
    int            shard_id;
} worker_arg_t;

/*
 * do_inbound_crypto called by the worker for JOB_TYPE_INBOUND_CRYPTO.
 *
 * The epoll thread already did recvfrom(); we own the buffer.
 * We call handle_inbound_udp which does: session-lookup, replay-check,
 * aead_decrypt, reassembly, write(tun_fd).  All CPU-bound work happens
 * here, off the epoll thread.
 */
static void do_inbound_crypto(job_t *job)
{
    handle_inbound_udp(job->inbound.udp_sock,
                       job->inbound.tun_fd,
                       job->inbound.buf,
                       (ssize_t)job->inbound.buf_len,
                       &job->inbound.src,
                       job->inbound.server_sk);
    free(job->inbound.buf);
}

/*
 * do_outbound_crypto called by the worker for JOB_TYPE_OUTBOUND_CRYPTO.
 *
 * The epoll thread already did read(tun_fd) and stored the raw IP packet
 * in job->outbound.buf.  We call handle_outbound_tun_buf() which does:
 * session-lookup by dst-IP, fragmentation, aead_encrypt, sendto().
 * The TUN fd is NOT touched here, the read already happened.
 */
static void do_outbound_crypto(job_t *job)
{
    handle_outbound_tun_buf(job->outbound.udp_sock,
                            job->outbound.buf,
                            job->outbound.buf_len);
    free(job->outbound.buf);
}

static void *worker_thread(void *arg)
{
    worker_arg_t  *wa    = (worker_arg_t *)arg;
    thread_pool_t *pool  = wa->pool;
    int            shard = wa->shard_id;
    free(wa);

    shard_queue_t *q = &pool->shards[shard];

#ifdef __linux__
    /* Pin this worker to logical CPU shard */
    int ncpus = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpus > 0) {
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(shard % ncpus, &cpuset);
        if (pthread_setaffinity_np(pthread_self(),
                                   sizeof(cpu_set_t), &cpuset) != 0) {
            /* non-fatal just log and continue without affinity */
            vpn_log("Worker %d: sched_setaffinity failed (non-fatal)", shard);
        }
    }

    /* Reduce timer slack so nanosleep wakeups are tighter */
    prctl(PR_SET_TIMERSLACK, 1UL, 0, 0, 0);

    {
        char name[16];
        snprintf(name, sizeof(name), "vpn-crypto-%d", shard);
        prctl(PR_SET_NAME, name, 0, 0, 0);
    }
#endif

    while (1) {
        pthread_mutex_lock(&q->lock);

        while (q->size == 0 && !pool->shutdown)
            pthread_cond_wait(&q->cond, &q->lock);

        if (pool->shutdown && q->size == 0) {
            pthread_mutex_unlock(&q->lock);
            break;
        }

        if (q->size == 0) {
            pthread_mutex_unlock(&q->lock);
            continue;
        }

        job_node_t *node = q->head;
        q->head = node->next;
        if (!q->head) q->tail = NULL;
        q->size--;

        job_t *job = node->job;
        pthread_mutex_unlock(&q->lock);
        free(node);

        if (!job) continue;

        switch (job->type) {
            case JOB_TYPE_INBOUND_CRYPTO:
                do_inbound_crypto(job);
                break;
            case JOB_TYPE_OUTBOUND_CRYPTO:
                do_outbound_crypto(job);
                break;
            case JOB_TYPE_SHUTDOWN:
                free(job);
                return NULL;
            default:
                vpn_log("Worker %d: unknown job type %d", shard, job->type);
                break;
        }
        free(job);
    }

    return NULL;
}

/* -----------------------------------------------------------------------
 * Lifecycle
 * --------------------------------------------------------------------- */

thread_pool_t *thread_pool_create(int num_threads)
{
    if (num_threads <= 0) num_threads = 4;

    thread_pool_t *pool = calloc(1, sizeof(thread_pool_t));
    if (!pool) return NULL;

    pool->num_threads = num_threads;
    pool->shutdown    = 0;

    pool->threads = calloc(num_threads, sizeof(pthread_t));
    pool->shards  = calloc(num_threads, sizeof(shard_queue_t));
    if (!pool->threads || !pool->shards) {
        free(pool->threads); free(pool->shards); free(pool);
        return NULL;
    }

    /* Initialise per-shard queues */
    for (int i = 0; i < num_threads; i++) {
        shard_queue_t *q = &pool->shards[i];
        q->head     = NULL;
        q->tail     = NULL;
        q->size     = 0;
        q->max_size = 4096;   /* per-shard backpressure cap */
        pthread_mutex_init(&q->lock, NULL);
        pthread_cond_init(&q->cond, NULL);
    }

    /* Spawn workers */
    for (int i = 0; i < num_threads; i++) {
        worker_arg_t *wa = malloc(sizeof(worker_arg_t));
        if (!wa) goto fail;
        wa->pool     = pool;
        wa->shard_id = i;

        if (pthread_create(&pool->threads[i], NULL, worker_thread, wa) != 0) {
            free(wa);
            vpn_log("thread_pool_create: pthread_create failed for shard %d", i);
            goto fail;
        }
    }

    vpn_log("Thread pool created: %d sharded workers (per-CPU crypto)",
            num_threads);
    return pool;

fail:
    pool->shutdown = 1;
    for (int i = 0; i < num_threads; i++) {
        pthread_cond_broadcast(&pool->shards[i].cond);
        if (pool->threads[i]) pthread_join(pool->threads[i], NULL);
        pthread_mutex_destroy(&pool->shards[i].lock);
        pthread_cond_destroy(&pool->shards[i].cond);
    }
    free(pool->threads);
    free(pool->shards);
    free(pool);
    return NULL;
}

void thread_pool_destroy(thread_pool_t *pool)
{
    if (!pool) return;

    pool->shutdown = 1;
    for (int i = 0; i < pool->num_threads; i++)
        pthread_cond_broadcast(&pool->shards[i].cond);

    for (int i = 0; i < pool->num_threads; i++) {
        pthread_join(pool->threads[i], NULL);

        /* Drain any leftover jobs */
        shard_queue_t *q = &pool->shards[i];
        pthread_mutex_lock(&q->lock);
        job_node_t *n = q->head;
        while (n) {
            job_node_t *nx = n->next;
            if (n->job) {
                /* free owned buffers */
                if (n->job->type == JOB_TYPE_INBOUND_CRYPTO)
                    free(n->job->inbound.buf);
                else if (n->job->type == JOB_TYPE_OUTBOUND_CRYPTO)
                    free(n->job->outbound.buf);
                free(n->job);
            }
            free(n);
            n = nx;
        }
        pthread_mutex_unlock(&q->lock);
        pthread_mutex_destroy(&q->lock);
        pthread_cond_destroy(&q->cond);
    }

    free(pool->threads);
    free(pool->shards);
    free(pool);
    vpn_log("Thread pool destroyed");
}

/* -----------------------------------------------------------------------
 * Submission helpers
 * --------------------------------------------------------------------- */

static int enqueue_to_shard(thread_pool_t *pool, job_t *job, int shard)
{
    shard_queue_t *q = &pool->shards[shard];

    pthread_mutex_lock(&q->lock);
    if (q->size >= q->max_size) {
        pthread_mutex_unlock(&q->lock);
        vpn_log("Shard %d queue full (%d), dropping job", shard, q->size);
        return -1;
    }

    job_node_t *node = malloc(sizeof(job_node_t));
    if (!node) {
        pthread_mutex_unlock(&q->lock);
        return -1;
    }
    node->job  = job;
    node->next = NULL;

    if (!q->tail) { q->head = q->tail = node; }
    else          { q->tail->next = node; q->tail = node; }
    q->size++;

    pthread_cond_signal(&q->cond);
    pthread_mutex_unlock(&q->lock);
    return 0;
}

int thread_pool_submit_sharded(thread_pool_t *pool, job_t *job,
                                uint8_t shard_key)
{
    if (!pool || !job) return -1;
    int shard = shard_key % pool->num_threads;
    return enqueue_to_shard(pool, job, shard);
}

int thread_pool_submit(thread_pool_t *pool, job_t *job)
{
    if (!pool || !job) return -1;
    /* Round-robin fallback when no shard key is available */
    static _Atomic int rr = 0;
    int shard = (rr++) % pool->num_threads;
    return enqueue_to_shard(pool, job, shard);
}

int thread_pool_pending_jobs(thread_pool_t *pool)
{
    if (!pool) return 0;
    int total = 0;
    for (int i = 0; i < pool->num_threads; i++) {
        pthread_mutex_lock(&pool->shards[i].lock);
        total += pool->shards[i].size;
        pthread_mutex_unlock(&pool->shards[i].lock);
    }
    return total;
}

int thread_pool_num_threads(thread_pool_t *pool)
{
    return pool ? pool->num_threads : 0;
}
