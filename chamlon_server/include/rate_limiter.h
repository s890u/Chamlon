#ifndef RATE_LIMITER_H
#define RATE_LIMITER_H

#include <stdint.h>
#include <time.h>
#include <netinet/in.h>
#include <pthread.h>
#include <bits/pthreadtypes.h>

/**
 * Rate Limiter for DDoS Protection
 * 
 * Implements:
 * 1. Per-IP handshake rate limiting (token bucket)
 * 2. Per-IP packet rate limiting
 * 3. Global packet queue backpressure
 * 4. IP blacklisting for excessive violations
 */

/* Rate limiting configuration */
#define HANDSHAKE_MAX_PER_SECOND 5          /* Max handshake attempts per IP per second */
#define HANDSHAKE_BURST_CAPACITY 10         /* Max burst capacity for token bucket */
#define PACKET_MAX_PER_SECOND 1000          /* Max packets per IP per second */
#define PACKET_BURST_CAPACITY 2000          /* Max packet burst */
#define BLACKLIST_DURATION_SEC 60           /* Duration to blacklist abusive IPs */
#define MAX_RATE_LIMIT_ENTRIES 10000        /* Max IPs to track simultaneously */
#define RATE_LIMITER_CLEANUP_INTERVAL 10    /* Cleanup expired entries every N seconds */

/* Return codes for rate limit checks */
#define RATE_LIMIT_OK 0
#define RATE_LIMIT_EXCEEDED 1
#define RATE_LIMIT_BLACKLISTED 2

/* Token bucket state for an IP address */
typedef struct {
    uint32_t ip_addr;                   /* IPv4 address in network byte order */
    double handshake_tokens;            /* Current tokens for handshake bucket */
    double packet_tokens;               /* Current tokens for packet bucket */
    time_t last_handshake_refill;       /* Last time buckets were refilled */
    time_t last_packet_refill;
    uint32_t handshake_violations;      /* Count of handshake violations */
    uint32_t packet_violations;         /* Count of packet violations */
    time_t blacklist_until;             /* When to unblacklist this IP (0 = not blacklisted) */
    time_t last_seen;                   /* Last activity from this IP */
} ip_rate_limit_t;

/* Global rate limiter state */
typedef struct {
    ip_rate_limit_t *entries;
    int num_entries;
    int capacity;
    pthread_rwlock_t lock;
    time_t last_cleanup;
} rate_limiter_t;

/* Global queue backpressure settings */
typedef struct {
    int max_queue_size;                 /* Max packet queue size per session */
    int max_total_queue_size;           /* Max total packets across all sessions */
    int current_total_queue_size;       /* Current total queue size */
    pthread_mutex_t queue_lock;
} queue_backpressure_t;

/* Initialize the global rate limiter */
int rate_limiter_init(void);

/* Check if an IP is allowed to perform handshake */
int check_handshake_rate_limit(struct in_addr *client_ip);

/* Check if an IP is allowed to send a packet */
int check_packet_rate_limit(struct in_addr *client_ip);

/* Manually blacklist an IP */
void blacklist_ip(struct in_addr *client_ip);

/* Get rate limit entry for an IP (or create if doesn't exist) */
ip_rate_limit_t *get_or_create_ip_entry(uint32_t ip_addr);

/* Cleanup expired/old entries periodically */
void rate_limiter_cleanup(void);

/* Destroy rate limiter and free resources */
void rate_limiter_destroy(void);

/* Queue backpressure functions */
int check_queue_backpressure(int packets_to_add);
void update_queue_backpressure(int packets_added);
void release_queue_backpressure(int packets_removed);
int get_queue_backpressure_level(void);

#endif // RATE_LIMITER_H
