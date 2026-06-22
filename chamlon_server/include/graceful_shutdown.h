#ifndef GRACEFUL_SHUTDOWN_H
#define GRACEFUL_SHUTDOWN_H

#include <stdint.h>
#include <time.h>
#include <signal.h>
#include "config.h"

/* Graceful shutdown states */
typedef enum {
    SHUTDOWN_IDLE = 0,              /* Server running normally */
    SHUTDOWN_INITIATED = 1,         /* Signal received, shutdown starting */
    SHUTDOWN_DRAINING = 2,          /* Notifying clients of shutdown */
    SHUTDOWN_FORCE_TIMEOUT = 3,     /* Force close remaining sessions */
    SHUTDOWN_COMPLETE = 4           /* All cleaned up, ready to exit */
} shutdown_state_t;

/* Graceful shutdown manager structure */
typedef struct {
    volatile sig_atomic_t state;    /* Current shutdown state */
    time_t shutdown_started;        /* Timestamp when shutdown began */
    int shutdown_timeout_sec;       /* Max seconds to wait for graceful close */
    int session_disconnect_count;   /* Sessions sent disconnect to */
    int session_closed_count;       /* Sessions confirmed closed */
} graceful_shutdown_t;

/* Global shutdown manager */
extern graceful_shutdown_t g_shutdown;

/* Initialize graceful shutdown manager */
void graceful_shutdown_init(int timeout_sec);

/* Signal handler for SIGINT/SIGTERM */
void graceful_shutdown_signal_handler(int sig);

/* Get current shutdown state */
shutdown_state_t graceful_shutdown_get_state(void);

/* Initiate graceful shutdown from main loop */
void graceful_shutdown_initiate(void);

/* Execute shutdown draining phase - send disconnect to all active sessions */
int graceful_shutdown_drain_sessions(int udp_sock);

/* Check if shutdown timeout has been exceeded */
int graceful_shutdown_timeout_exceeded(void);

/* Perform final cleanup and resource deallocation */
void graceful_shutdown_cleanup(int udp_sock, int tun_fd);

/* Check if server should continue running */
static inline int graceful_shutdown_should_continue(void) {
    return (g_shutdown.state == SHUTDOWN_IDLE);
}

#endif /* GRACEFUL_SHUTDOWN_H */
