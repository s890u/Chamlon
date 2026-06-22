#ifndef THREAD_POOL_H
#define THREAD_POOL_H

#include <stdint.h>
#include <pthread.h>
#include <netinet/in.h>

/*
 * Job types
 * ---------
 * JOB_TYPE_INBOUND_CRYPTO, inbound path:
 *     The epoll thread has already called recvfrom() and copied the raw
 *     UDP payload into buf.  The worker does session-lookup, replay-check,
 *     aead_decrypt, and tun_write entirely off the epoll thread.
 *
 * JOB_TYPE_OUTBOUND_CRYPTO, outbound path:
 *     The epoll thread has already called read(tun_fd) and copied the raw
 *     IP packet into buf.  The worker does session-lookup, fragmentation,
 *     aead_encrypt, and sendto() entirely off the epoll thread.
 *     (Previously called JOB_TYPE_PROCESS_TUN which re-read the TUN, that
 *     was a double-read bug.  Fixed here.)
 *
 * JOB_TYPE_SHUTDOWN, drain signal; workers exit after draining the queue.
 */
typedef enum {
    JOB_TYPE_INBOUND_CRYPTO,
    JOB_TYPE_OUTBOUND_CRYPTO,
    JOB_TYPE_SHUTDOWN
} job_type_t;

typedef struct {
    job_type_t type;

    /*
     * JOB_TYPE_INBOUND_CRYPTO
     * buf:         heap-allocated copy of the raw UDP payload (owned by job).
     * buf_len:     length of buf.
     * src:         sender's address (for handshake replies / error logging).
     * udp_sock:    the bound UDP socket fd (for replies).
     * tun_fd:      the TUN fd (worker writes decrypted IP packet here).
     * server_sk:   pointer to the static server secret key (read-only global,
     *               never freed while the server runs, no ownership transfer).
     */
    struct {
        uint8_t            *buf;        /* heap-allocated, worker must free */
        size_t              buf_len;
        struct sockaddr_in  src;
        int                 udp_sock;
        int                 tun_fd;
        uint8_t            *server_sk;  /* points at g_server_sk in vpn_server.c */
    } inbound;

    /*
     * JOB_TYPE_OUTBOUND_CRYPTO
     * buf:         heap-allocated copy of the raw IP packet read from TUN.
     * buf_len:     length of buf.
     * udp_sock:    the bound UDP socket fd (worker calls sendto here).
     *
     * NOTE: tun_fd is NOT stored here, the read already happened on the
     * epoll thread.  Workers never touch the TUN fd.
     */
    struct {
        uint8_t *buf;       /* heap-allocated IP packet copy, worker must free */
        size_t   buf_len;
        int      udp_sock;
    } outbound;

} job_t;

typedef struct thread_pool thread_pool_t;

/*
 * thread_pool_create: spawn num_threads workers.
 * Workers are pinned to logical CPUs 0..num_threads-1.  Falls back gracefully if sched_setaffinity is
 * unavailable.
 */
thread_pool_t *thread_pool_create(int num_threads);

void thread_pool_destroy(thread_pool_t *pool);

/*
 * thread_pool_submit: enqueue job; takes ownership of job and its buf.
 * Returns 0 on success, -1 if queue is full (caller must free job+buf).
 *
 * Sharding: inbound jobs are sharded by session-id byte[0] % num_threads
 * so that all packets for the same session go to the same worker, avoiding
 * concurrent replay-window updates without a per-session lock.
 * Outbound jobs are sharded by vpn_ip byte[3] % num_threads for the same
 * reason (same session -> same worker -> no send_seq ordering issues beyond
 * what _Atomic already guarantees).
 */
int thread_pool_submit(thread_pool_t *pool, job_t *job);

/*
 * thread_pool_submit_sharded, like submit but routes to a specific shard.
 * shard_key is typically session_id[0] or vpn_ip[3].
 */
int thread_pool_submit_sharded(thread_pool_t *pool, job_t *job,
                                uint8_t shard_key);

int thread_pool_pending_jobs(thread_pool_t *pool);
int thread_pool_num_threads(thread_pool_t *pool);

#endif /* THREAD_POOL_H */
