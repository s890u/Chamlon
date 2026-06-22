#include "metrics.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <math.h>

metrics_t global_metrics;

int metrics_init(void) {
    memset(&global_metrics, 0, sizeof(metrics_t));
    global_metrics.startup_time = time(NULL);
    global_metrics.last_reset = global_metrics.startup_time;
    global_metrics.min_latency_ms = UINT64_MAX;
    
    if (pthread_mutex_init(&global_metrics.lock, NULL) != 0) {
        fprintf(stderr, "Failed to initialize metrics mutex\n");
        return -1;
    }
    
    return 0;
}

void metrics_destroy(void) {
    pthread_mutex_destroy(&global_metrics.lock);
}

void metrics_record_packet_received(size_t size) {
    pthread_mutex_lock(&global_metrics.lock);
    global_metrics.packets_received++;
    global_metrics.bytes_received += size;
    pthread_mutex_unlock(&global_metrics.lock);
}

void metrics_record_packet_sent(size_t size) {
    pthread_mutex_lock(&global_metrics.lock);
    global_metrics.packets_sent++;
    global_metrics.bytes_sent += size;
    pthread_mutex_unlock(&global_metrics.lock);
}

void metrics_record_packet_dropped(void) {
    pthread_mutex_lock(&global_metrics.lock);
    global_metrics.packets_dropped++;
    pthread_mutex_unlock(&global_metrics.lock);
}



void metrics_record_handshake_initiated(void) {
    pthread_mutex_lock(&global_metrics.lock);
    global_metrics.handshakes_initiated++;
    pthread_mutex_unlock(&global_metrics.lock);
}

void metrics_record_handshake_completed(void) {
    pthread_mutex_lock(&global_metrics.lock);
    global_metrics.handshakes_completed++;
    pthread_mutex_unlock(&global_metrics.lock);
}

void metrics_record_handshake_failed(void) {
    pthread_mutex_lock(&global_metrics.lock);
    global_metrics.handshakes_failed++;
    pthread_mutex_unlock(&global_metrics.lock);
}

/* Connection Tracking */
void metrics_record_connection_established(void) {
    pthread_mutex_lock(&global_metrics.lock);
    global_metrics.total_connections++;
    global_metrics.active_connections++;
    pthread_mutex_unlock(&global_metrics.lock);
}

void metrics_record_connection_closed(void) {
    pthread_mutex_lock(&global_metrics.lock);
    if (global_metrics.active_connections > 0) {
        global_metrics.active_connections--;
    }
    global_metrics.total_disconnections++;
    pthread_mutex_unlock(&global_metrics.lock);
}

void metrics_set_active_connections(int count) {
    pthread_mutex_lock(&global_metrics.lock);
    global_metrics.active_connections = count;
    pthread_mutex_unlock(&global_metrics.lock);
}

/* Queue Statistics */
void metrics_record_queue_depth(uint64_t depth) {
    pthread_mutex_lock(&global_metrics.lock);
    if (depth > global_metrics.max_queue_depth) {
        global_metrics.max_queue_depth = depth;
    }
    pthread_mutex_unlock(&global_metrics.lock);
}

void metrics_record_queue_drop(void) {
    pthread_mutex_lock(&global_metrics.lock);
    global_metrics.queue_drops++;
    pthread_mutex_unlock(&global_metrics.lock);
}

void metrics_record_backpressure(void) {
    pthread_mutex_lock(&global_metrics.lock);
    global_metrics.backpressure_events++;
    pthread_mutex_unlock(&global_metrics.lock);
}

void metrics_record_latency_ms(uint64_t latency_ms) {
    pthread_mutex_lock(&global_metrics.lock);
    global_metrics.total_latency_ms += latency_ms;
    global_metrics.latency_samples++;
    
    if (latency_ms > global_metrics.max_latency_ms) {
        global_metrics.max_latency_ms = latency_ms;
    }
    if (latency_ms < global_metrics.min_latency_ms) {
        global_metrics.min_latency_ms = latency_ms;
    }
    pthread_mutex_unlock(&global_metrics.lock);
}

void metrics_record_crypto_error(void) {
    pthread_mutex_lock(&global_metrics.lock);
    global_metrics.crypto_errors++;
    pthread_mutex_unlock(&global_metrics.lock);
}

void metrics_record_validation_error(void) {
    pthread_mutex_lock(&global_metrics.lock);
    global_metrics.validation_errors++;
    pthread_mutex_unlock(&global_metrics.lock);
}

void metrics_record_rate_limit_drop(void) {
    pthread_mutex_lock(&global_metrics.lock);
    global_metrics.rate_limit_drops++;
    pthread_mutex_unlock(&global_metrics.lock);
}

void metrics_record_blacklist_event(void) {
    pthread_mutex_lock(&global_metrics.lock);
    global_metrics.black_listed_ips++;
    pthread_mutex_unlock(&global_metrics.lock);
}

health_status_t metrics_get_health_status(void) {
    health_status_t status = {0};
    
    pthread_mutex_lock(&global_metrics.lock);
    
    time_t now = time(NULL);
    time_t uptime = now - global_metrics.startup_time;
    status.uptime_seconds = uptime;
    status.active_clients = global_metrics.active_connections;
    
    if (uptime > 0) {
        status.packets_per_sec = global_metrics.packets_received / uptime;
        status.bytes_per_sec = global_metrics.bytes_received / uptime;
    }
    
    uint64_t total_packets = global_metrics.packets_received + global_metrics.packets_dropped;
    if (total_packets > 0) {
        status.packet_drop_rate = (int)((global_metrics.packets_dropped * 100) / total_packets);
    }
    
    if (global_metrics.latency_samples > 0) {
        status.avg_latency_ms = (int)(global_metrics.total_latency_ms / global_metrics.latency_samples);
    }
    
    status.is_healthy = 1;
    if (status.packet_drop_rate > 5) status.is_healthy = 0;  /* >5% drops = unhealthy */
    if (global_metrics.handshakes_failed > global_metrics.handshakes_completed / 2) status.is_healthy = 0;  /* >50% handshake failure rate */
    if (global_metrics.black_listed_ips > 100) status.is_healthy = 0;  /* Too many blacklisted IPs */
    
    pthread_mutex_unlock(&global_metrics.lock);
    
    return status;
}

void metrics_print_status(void) {
    health_status_t status = metrics_get_health_status();
    
    printf("\n[HEALTH] Status: %s | Active: %d | Uptime: %ld sec | "
           "Packets/sec: %lu | Drop Rate: %d%% | Avg Latency: %d ms\n",
           status.is_healthy ? "HEALTHY" : "UNHEALTHY",
           status.active_clients,
           status.uptime_seconds,
           status.packets_per_sec,
           status.packet_drop_rate,
           status.avg_latency_ms);
}

void metrics_print_detailed_report(void) {
    pthread_mutex_lock(&global_metrics.lock);
    
    time_t now = time(NULL);
    long uptime = now - global_metrics.startup_time;
    
    printf("\n");
    printf("========================================\n");
    printf("     VPN SERVER METRICS REPORT\n");
    printf("========================================\n");
    printf("Uptime: %ld seconds (%.2f hours)\n", uptime, uptime / 3600.0);
    printf("\n--- PACKET STATISTICS ---\n");
    printf("Packets Received:   %lu\n", global_metrics.packets_received);
    printf("Packets Sent:       %lu\n", global_metrics.packets_sent);
    printf("Packets Dropped:    %lu\n", global_metrics.packets_dropped);
    printf("Bytes Received:     %lu\n", global_metrics.bytes_received);
    printf("Bytes Sent:         %lu\n", global_metrics.bytes_sent);
    
    if (uptime > 0) {
        printf("Throughput RX:      %.2f Mbps\n", (global_metrics.bytes_received * 8.0) / (uptime * 1000000.0));
        printf("Throughput TX:      %.2f Mbps\n", (global_metrics.bytes_sent * 8.0) / (uptime * 1000000.0));
        printf("Packet Rate RX:     %lu pps\n", global_metrics.packets_received / uptime);
        printf("Packet Rate TX:     %lu pps\n", global_metrics.packets_sent / uptime);
    }
    
    printf("\n--- CONNECTION STATISTICS ---\n");
    printf("Active Connections: %d\n", global_metrics.active_connections);
    printf("Total Connections:  %lu\n", global_metrics.total_connections);
    printf("Total Disconnections: %lu\n", global_metrics.total_disconnections);
    
    printf("\n--- HANDSHAKE STATISTICS ---\n");
    printf("Handshakes Initiated: %lu\n", global_metrics.handshakes_initiated);
    printf("Handshakes Completed: %lu\n", global_metrics.handshakes_completed);
    printf("Handshakes Failed:    %lu\n", global_metrics.handshakes_failed);
    if (global_metrics.handshakes_initiated > 0) {
        printf("Success Rate:         %.2f%%\n", 
               (global_metrics.handshakes_completed * 100.0) / global_metrics.handshakes_initiated);
    }
    
    printf("\n--- QUEUE STATISTICS ---\n");
    printf("Max Queue Depth:    %lu packets\n", global_metrics.max_queue_depth);
    printf("Queue Drops:        %lu\n", global_metrics.queue_drops);
    printf("Backpressure Events: %lu\n", global_metrics.backpressure_events);
    
    printf("\n--- LATENCY STATISTICS ---\n");
    if (global_metrics.latency_samples > 0) {
        uint64_t avg_latency = global_metrics.total_latency_ms / global_metrics.latency_samples;
        printf("Samples:            %lu\n", global_metrics.latency_samples);
        printf("Average Latency:    %lu ms\n", avg_latency);
        printf("Max Latency:        %lu ms\n", global_metrics.max_latency_ms);
        printf("Min Latency:        %lu ms\n", global_metrics.min_latency_ms);
    } else {
        printf("No latency data collected\n");
    }
    
    printf("\n--- ERROR STATISTICS ---\n");
    printf("Crypto Errors:      %lu\n", global_metrics.crypto_errors);
    printf("Validation Errors:  %lu\n", global_metrics.validation_errors);
    printf("Rate Limit Drops:   %lu\n", global_metrics.rate_limit_drops);
    printf("Blacklisted IPs:    %lu\n", global_metrics.black_listed_ips);
    
    uint64_t total_packets = global_metrics.packets_received + global_metrics.packets_dropped;
    if (total_packets > 0) {
        double drop_rate = (global_metrics.packets_dropped * 100.0) / total_packets;
        printf("Overall Drop Rate:  %.2f%%\n", drop_rate);
    }
    
    printf("\n--- HEALTH STATUS ---\n");
    
    int is_healthy = 1;
    int packet_drop_rate = 0;
    if (total_packets > 0) {
        packet_drop_rate = (int)((global_metrics.packets_dropped * 100) / total_packets);
    }
    if (packet_drop_rate > 5) is_healthy = 0;
    if (global_metrics.handshakes_failed > global_metrics.handshakes_completed / 2) is_healthy = 0;
    if (global_metrics.black_listed_ips > 100) is_healthy = 0;
    
    printf("Server Status:      %s\n", is_healthy ? "HEALTHY" : "UNHEALTHY");
    
    char time_buf[32];
    struct tm tm;
    localtime_r(&global_metrics.last_reset, &tm);
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm);
    printf("Last Reset:         %s\n", time_buf);
    printf("========================================\n\n");
    
    pthread_mutex_unlock(&global_metrics.lock);
}

void metrics_reset(void) {
    pthread_mutex_lock(&global_metrics.lock);
    
    time_t now = time(NULL);
    uint64_t saved_total_connections = global_metrics.total_connections;
    uint64_t saved_total_disconnections = global_metrics.total_disconnections;
    int saved_active = global_metrics.active_connections;
    
    memset(&global_metrics, 0, sizeof(metrics_t));
    
    global_metrics.startup_time = now;
    global_metrics.last_reset = now;
    global_metrics.min_latency_ms = UINT64_MAX;
    global_metrics.total_connections = saved_total_connections;
    global_metrics.total_disconnections = saved_total_disconnections;
    global_metrics.active_connections = saved_active;
    
    pthread_mutex_unlock(&global_metrics.lock);
    printf("[METRICS] Reset all counters\n");
}
