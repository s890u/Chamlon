#ifndef METRICS_H
#define METRICS_H

#include <stdint.h>
#include <time.h>
#include <pthread.h>

/* Metrics Tracking Structure */
typedef struct {
    /* Packet Statistics */
    uint64_t packets_received;
    uint64_t packets_sent;
    uint64_t packets_dropped;
    uint64_t bytes_received;
    uint64_t bytes_sent;
    
    /* Handshake Statistics */
    uint64_t handshakes_initiated;
    uint64_t handshakes_completed;
    uint64_t handshakes_failed;
    
    /* Connection Tracking */
    int active_connections;
    uint64_t total_connections;
    uint64_t total_disconnections;
    
    /* Queue Statistics */
    uint64_t max_queue_depth;
    uint64_t queue_drops;
    uint64_t backpressure_events;
    
    /* Latency Tracking (milliseconds) */
    uint64_t total_latency_ms;
    uint64_t latency_samples;
    uint64_t max_latency_ms;
    uint64_t min_latency_ms;
    
    /* Error Tracking */
    uint64_t crypto_errors;
    uint64_t validation_errors;
    uint64_t rate_limit_drops;
    uint64_t black_listed_ips;
    
    /* Timestamps */
    time_t startup_time;
    time_t last_reset;
    
    /* Thread Safety */
    pthread_mutex_t lock;
} metrics_t;

/* Global metrics instance */
extern metrics_t global_metrics;

/* Initialization and Cleanup */
int metrics_init(void);
void metrics_destroy(void);

/* Packet Tracking */
void metrics_record_packet_received(size_t size);
void metrics_record_packet_sent(size_t size);
void metrics_record_packet_dropped(void);

/* Handshake Tracking */
void metrics_record_handshake_initiated(void);
void metrics_record_handshake_completed(void);
void metrics_record_handshake_failed(void);

/* Connection Tracking */
void metrics_record_connection_established(void);
void metrics_record_connection_closed(void);
void metrics_set_active_connections(int count);

/* Queue Statistics */
void metrics_record_queue_depth(uint64_t depth);
void metrics_record_queue_drop(void);
void metrics_record_backpressure(void);

/* Latency Tracking */
void metrics_record_latency_ms(uint64_t latency_ms);

/* Error Tracking */
void metrics_record_crypto_error(void);
void metrics_record_validation_error(void);
void metrics_record_rate_limit_drop(void);
void metrics_record_blacklist_event(void);

/* Health Check and Status */
typedef struct {
    int is_healthy;
    int packet_drop_rate;
    int queue_fill_ratio;
    int avg_latency_ms;
    int active_clients;
    long uptime_seconds;
    uint64_t packets_per_sec;
    uint64_t bytes_per_sec;
} health_status_t;

health_status_t metrics_get_health_status(void);
void metrics_print_status(void);
void metrics_print_detailed_report(void);
void metrics_reset(void);

/* Per-Session Metrics (optional for tracking individual sessions) */
typedef struct {
    uint64_t packets_sent;
    uint64_t packets_received;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t total_latency_ms;
    uint64_t latency_samples;
    time_t session_start;
    time_t last_update;
} session_metrics_t;

#endif // METRICS_H
