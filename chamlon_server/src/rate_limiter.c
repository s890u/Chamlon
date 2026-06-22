#include "rate_limiter.h"
#include <stdlib.h>
#include <string.h>

/* Global rate limiter state */
static rate_limiter_t g_rate_limiter = {0};
static queue_backpressure_t g_queue_backpressure = {0};

/* Helper function to find or create an IP entry */
static ip_rate_limit_t *find_or_create_ip_entry(uint32_t ip_addr);

/**
 * Initialize the rate limiter
 */
int rate_limiter_init(void)
{
    g_rate_limiter.capacity = MAX_RATE_LIMIT_ENTRIES;
    g_rate_limiter.num_entries = 0;
    g_rate_limiter.entries = malloc(g_rate_limiter.capacity * sizeof(ip_rate_limit_t));
    if (!g_rate_limiter.entries) {
        return -1;
    }
    
    pthread_rwlock_init(&g_rate_limiter.lock, NULL);
    g_rate_limiter.last_cleanup = time(NULL);
    
    /* Initialize queue backpressure */
    g_queue_backpressure.max_queue_size = 10000;
    g_queue_backpressure.max_total_queue_size = 100000;
    g_queue_backpressure.current_total_queue_size = 0;
    pthread_mutex_init(&g_queue_backpressure.queue_lock, NULL);
    
    return 0;
}

/**
 * Cleanup expired entries periodically
 */
void rate_limiter_cleanup(void)
{
    time_t now = time(NULL);
    int i, j;
    
    if (now - g_rate_limiter.last_cleanup < RATE_LIMITER_CLEANUP_INTERVAL) {
        return;
    }
    
    pthread_rwlock_wrlock(&g_rate_limiter.lock);
    
    for (i = 0, j = 0; i < g_rate_limiter.num_entries; i++) {
        /* Keep entries that are recent or still blacklisted */
        if ((now - g_rate_limiter.entries[i].last_seen < 300) ||
            (g_rate_limiter.entries[i].blacklist_until > now)) {
            if (i != j) {
                g_rate_limiter.entries[j] = g_rate_limiter.entries[i];
            }
            j++;
        }
    }
    
    g_rate_limiter.num_entries = j;
    g_rate_limiter.last_cleanup = now;
    
    pthread_rwlock_unlock(&g_rate_limiter.lock);
}

/**
 * Destroy rate limiter and free resources
 */
void rate_limiter_destroy(void)
{
    if (g_rate_limiter.entries) {
        free(g_rate_limiter.entries);
        g_rate_limiter.entries = NULL;
    }
    pthread_rwlock_destroy(&g_rate_limiter.lock);
    pthread_mutex_destroy(&g_queue_backpressure.queue_lock);
}

/**
 * Find or create an IP rate limit entry
 */
static ip_rate_limit_t *find_or_create_ip_entry(uint32_t ip_addr)
{
    int i;
    time_t now = time(NULL);
    
    /* Search for existing entry */
    for (i = 0; i < g_rate_limiter.num_entries; i++) {
        if (g_rate_limiter.entries[i].ip_addr == ip_addr) {
            g_rate_limiter.entries[i].last_seen = now;
            return &g_rate_limiter.entries[i];
        }
    }
    
    /* Create new entry if space available */
    if (g_rate_limiter.num_entries < g_rate_limiter.capacity) {
        ip_rate_limit_t *entry = &g_rate_limiter.entries[g_rate_limiter.num_entries];
        memset(entry, 0, sizeof(*entry));
        
        entry->ip_addr = ip_addr;
        entry->handshake_tokens = HANDSHAKE_BURST_CAPACITY;
        entry->packet_tokens = PACKET_BURST_CAPACITY;
        entry->last_handshake_refill = now;
        entry->last_packet_refill = now;
        entry->last_seen = now;
        
        g_rate_limiter.num_entries++;
        return entry;
    }
    
    return NULL;
}

/**
 * Refill tokens for a bucket based on elapsed time
 */
static void refill_tokens(double *tokens, double max_tokens, 
                         time_t *last_refill, double tokens_per_sec)
{
    time_t now = time(NULL);
    time_t elapsed = now - *last_refill;
    
    if (elapsed > 0) {
        *tokens += (double)elapsed * tokens_per_sec;
        if (*tokens > max_tokens) {
            *tokens = max_tokens;
        }
        *last_refill = now;
    }
}

/**
 * Check if an IP is allowed to perform handshake
 */
int check_handshake_rate_limit(struct in_addr *client_ip)
{
    uint32_t ip_addr = client_ip->s_addr;
    ip_rate_limit_t *entry;
    int result = RATE_LIMIT_OK;
    
    pthread_rwlock_wrlock(&g_rate_limiter.lock);
    
    entry = find_or_create_ip_entry(ip_addr);
    if (!entry) {
        pthread_rwlock_unlock(&g_rate_limiter.lock);
        return RATE_LIMIT_EXCEEDED;
    }
    
    time_t now = time(NULL);
    
    /* Check if blacklisted */
    if (entry->blacklist_until > now) {
        pthread_rwlock_unlock(&g_rate_limiter.lock);
        return RATE_LIMIT_BLACKLISTED;
    }
    
    /* Refill tokens */
    refill_tokens(&entry->handshake_tokens, HANDSHAKE_BURST_CAPACITY,
                  &entry->last_handshake_refill,
                  (double)HANDSHAKE_MAX_PER_SECOND);
    
    /* Check tokens */
    if (entry->handshake_tokens >= 1.0) {
        entry->handshake_tokens -= 1.0;
    } else {
        entry->handshake_violations++;
        
        /* Blacklist if too many violations */
        if (entry->handshake_violations > 50) {
            entry->blacklist_until = now + BLACKLIST_DURATION_SEC;
            result = RATE_LIMIT_BLACKLISTED;
        } else {
            result = RATE_LIMIT_EXCEEDED;
        }
    }
    
    pthread_rwlock_unlock(&g_rate_limiter.lock);
    return result;
}

/**
 * Check if an IP is allowed to send a packet
 */
int check_packet_rate_limit(struct in_addr *client_ip)
{
    uint32_t ip_addr = client_ip->s_addr;
    ip_rate_limit_t *entry;
    int result = RATE_LIMIT_OK;
    
    pthread_rwlock_wrlock(&g_rate_limiter.lock);
    
    entry = find_or_create_ip_entry(ip_addr);
    if (!entry) {
        pthread_rwlock_unlock(&g_rate_limiter.lock);
        return RATE_LIMIT_EXCEEDED;
    }
    
    time_t now = time(NULL);
    
    /* Check if blacklisted */
    if (entry->blacklist_until > now) {
        pthread_rwlock_unlock(&g_rate_limiter.lock);
        return RATE_LIMIT_BLACKLISTED;
    }
    
    /* Refill tokens */
    refill_tokens(&entry->packet_tokens, PACKET_BURST_CAPACITY,
                  &entry->last_packet_refill,
                  (double)PACKET_MAX_PER_SECOND);
    
    /* Check tokens */
    if (entry->packet_tokens >= 1.0) {
        entry->packet_tokens -= 1.0;
    } else {
        entry->packet_violations++;
        
        /* Blacklist if too many violations */
        if (entry->packet_violations > 500) {
            entry->blacklist_until = now + BLACKLIST_DURATION_SEC;
            result = RATE_LIMIT_BLACKLISTED;
        } else {
            result = RATE_LIMIT_EXCEEDED;
        }
    }
    
    pthread_rwlock_unlock(&g_rate_limiter.lock);
    return result;
}

/**
 * Manually blacklist an IP
 */
void blacklist_ip(struct in_addr *client_ip)
{
    uint32_t ip_addr = client_ip->s_addr;
    ip_rate_limit_t *entry;
    time_t now = time(NULL);
    
    pthread_rwlock_wrlock(&g_rate_limiter.lock);
    
    entry = find_or_create_ip_entry(ip_addr);
    if (entry) {
        entry->blacklist_until = now + BLACKLIST_DURATION_SEC;
    }
    
    pthread_rwlock_unlock(&g_rate_limiter.lock);
}

/**
 * Check queue backpressure before adding packets
 */
int check_queue_backpressure(int packets_to_add)
{
    int result = RATE_LIMIT_OK;
    
    pthread_mutex_lock(&g_queue_backpressure.queue_lock);
    
    if (g_queue_backpressure.current_total_queue_size + packets_to_add >
        g_queue_backpressure.max_total_queue_size) {
        result = RATE_LIMIT_EXCEEDED;
    }
    
    pthread_mutex_unlock(&g_queue_backpressure.queue_lock);
    return result;
}

/**
 * Update queue backpressure after adding packets
 */
void update_queue_backpressure(int packets_added)
{
    pthread_mutex_lock(&g_queue_backpressure.queue_lock);
    g_queue_backpressure.current_total_queue_size += packets_added;
    pthread_mutex_unlock(&g_queue_backpressure.queue_lock);
}

/**
 * Release queue backpressure after removing packets
 */
void release_queue_backpressure(int packets_removed)
{
    pthread_mutex_lock(&g_queue_backpressure.queue_lock);
    g_queue_backpressure.current_total_queue_size -= packets_removed;
    if (g_queue_backpressure.current_total_queue_size < 0) {
        g_queue_backpressure.current_total_queue_size = 0;
    }
    pthread_mutex_unlock(&g_queue_backpressure.queue_lock);
}

/**
 * Get current queue backpressure level
 */
int get_queue_backpressure_level(void)
{
    int level;
    pthread_mutex_lock(&g_queue_backpressure.queue_lock);
    level = g_queue_backpressure.current_total_queue_size;
    pthread_mutex_unlock(&g_queue_backpressure.queue_lock);
    return level;
}
