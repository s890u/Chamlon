#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include "graceful_shutdown.h"
#include "session.h"
#include "packet.h"
#include "vpn_log.h"

/* Global shutdown manager instance */
graceful_shutdown_t g_shutdown = {
    .state = SHUTDOWN_IDLE,
    .shutdown_started = 0,
    .shutdown_timeout_sec = CONFIG_GRACEFUL_SHUTDOWN_TIMEOUT_SEC,
    .session_disconnect_count = 0,
    .session_closed_count = 0
};

/* Initialize graceful shutdown manager */
void graceful_shutdown_init(int timeout_sec) {
    g_shutdown.state = SHUTDOWN_IDLE;
    g_shutdown.shutdown_started = 0;
    g_shutdown.shutdown_timeout_sec = (timeout_sec > 0) ? timeout_sec : CONFIG_GRACEFUL_SHUTDOWN_TIMEOUT_SEC;
    g_shutdown.session_disconnect_count = 0;
    g_shutdown.session_closed_count = 0;
    vpn_log("Graceful shutdown initialized with %d second timeout", g_shutdown.shutdown_timeout_sec);
}

/* Signal handler for SIGINT/SIGTERM */
void graceful_shutdown_signal_handler(int sig) {
    (void)sig; /* Suppress unused parameter warning */
    vpn_log("Shutdown signal received. Exiting immediately...");
    exit(0);  /* Fast kill - exit immediately without graceful shutdown */
}

/* Get current shutdown state */
shutdown_state_t graceful_shutdown_get_state(void) {
    return (shutdown_state_t)g_shutdown.state;
}

/* Initiate graceful shutdown from main loop */
void graceful_shutdown_initiate(void) {
    if (g_shutdown.state == SHUTDOWN_IDLE) {
        g_shutdown.state = SHUTDOWN_INITIATED;
        g_shutdown.shutdown_started = time(NULL);
        vpn_log("Graceful shutdown initiated. Starting client notification phase...");
    }
}

/* Execute shutdown draining phase - send disconnect to all active sessions */
int graceful_shutdown_drain_sessions(int udp_sock) {
    int new_disconnects = 0;
    
    if (g_shutdown.state != SHUTDOWN_DRAINING && g_shutdown.state != SHUTDOWN_INITIATED) {
        g_shutdown.state = SHUTDOWN_DRAINING;
        vpn_log("Entering shutdown draining phase - notifying all active sessions");
    }

    for (int i = 0; i < MAX_CLIENTS; ++i) {
        if (sessions[i].active) {
            vpn_log("Sending graceful disconnect to session %d (VPN %u.%u.%u.%u)",
                    i, sessions[i].vpn_ip[0], sessions[i].vpn_ip[1],
                    sessions[i].vpn_ip[2], sessions[i].vpn_ip[3]);
            
            send_control_packet(udp_sock, &sessions[i], PKT_CTRL_DISCONNECT);
            new_disconnects++;
        }
    }
    
    g_shutdown.session_disconnect_count = new_disconnects;
    
    if (new_disconnects > 0) {
        vpn_log("Sent DISCONNECT notification to %d active session(s). Waiting for graceful close...",
                new_disconnects);
    }
    
    return new_disconnects;
}

/* Check if shutdown timeout has been exceeded */
int graceful_shutdown_timeout_exceeded(void) {
    if (g_shutdown.shutdown_started == 0) {
        return 0;
    }
    
    time_t elapsed = time(NULL) - g_shutdown.shutdown_started;
    
    if (elapsed > g_shutdown.shutdown_timeout_sec) {
        if (g_shutdown.state != SHUTDOWN_FORCE_TIMEOUT) {
            vpn_log("Graceful shutdown timeout exceeded (%ld seconds). Force-closing remaining sessions...",
                    elapsed);
            g_shutdown.state = SHUTDOWN_FORCE_TIMEOUT;
        }
        return 1;
    }
    
    return 0;
}

/* Perform final cleanup and resource deallocation */
void graceful_shutdown_cleanup(int udp_sock, int tun_fd) {
    int still_active = 0;
    
    vpn_log("Graceful shutdown cleanup phase starting...");
    
    /* Count remaining active sessions */
    for (int i = 0; i < MAX_CLIENTS; ++i) {
        if (sessions[i].active) {
            still_active++;
        }
    }
    
    if (still_active > 0) {
        vpn_log("Force-closing %d remaining active session(s)", still_active);
        for (int i = 0; i < MAX_CLIENTS; ++i) {
            if (sessions[i].active) {
                vpn_log("Force-closing session %d (VPN %u.%u.%u.%u)",
                        i, sessions[i].vpn_ip[0], sessions[i].vpn_ip[1],
                        sessions[i].vpn_ip[2], sessions[i].vpn_ip[3]);
                free_session(&sessions[i]);
            }
        }
    }
    
    /* Close sockets */
    if (tun_fd >= 0) {
        vpn_log("Closing TUN interface...");
        close(tun_fd);
    }
    
    if (udp_sock >= 0) {
        vpn_log("Closing UDP socket...");
        close(udp_sock);
    }
    
    g_shutdown.state = SHUTDOWN_COMPLETE;
    vpn_log("Graceful shutdown cleanup complete. Server stopped.");
}
