#ifndef SESSION_H
#define SESSION_H

#include <stdint.h>
#include <netinet/in.h>
#include <time.h>
#include <pthread.h>
#include <stdatomic.h>
#include "config.h"

/* Forward declarations */
typedef struct out_queue out_queue_t;

/**
 * Rehandshake state machine
 */
typedef enum {
    REHANDSHAKE_READY       = 0,  /* Ready to initiate rehandshake */
    REHANDSHAKE_IN_PROGRESS = 1,  /* Rehandshake in progress */
    REHANDSHAKE_BACKOFF     = 2,  /* Waiting in exponential backoff */
    REHANDSHAKE_FAILED      = 3   /* Failed, will disconnect */
} rehandshake_state_t;

/**
 * Server Connection Session
 * Represents connection to a single VPN server
 */
typedef struct {
    int server_id;                          /* Server identifier */
    uint8_t session_id[SESSION_ID_LEN];    /* Session ID from server */
    uint8_t server_pk[PUBKEY_LEN];         /* Server's public key */
    char status;                            /* 'M' = Main Server, 'R' = Relay */
    uint8_t k_recv[AEAD_KEY_LEN];          /* Decryption key */
    uint8_t k_send[AEAD_KEY_LEN];          /* Encryption key */
    int udp_sock;                           /* UDP socket for communication */
    _Atomic(uint64_t) send_seq;             /* Send sequence number - FASTER than mutex */
    struct sockaddr_in server_addr;         /* Server address */
    char location[5];                       /* Server location identifier */
    uint8_t number_active_client;          /* Active client count */
    uint8_t assigned_ip[4];                 /* IP assigned by server */
    time_t  session_start_time;
    uint64_t bytes_sent;
    _Atomic(uint64_t) rehandshake_seq_snapshot;
    
    /* Rehandshake state machine */
    rehandshake_state_t rehandshake_state;  /* Current rehandshake state */
    int rehandshake_attempts;               /* Consecutive attempt counter */
    time_t rehandshake_last_attempt;        /* Timestamp of last attempt */
    int rehandshake_backoff_sec;            /* Current backoff window in seconds */
} server_t;

/**
 * Client Session
 * Represents a client connection session
 */
typedef struct {
    int active;                             /* Is session active */
    uint8_t session_id[SESSION_ID_LEN];    /* Session ID */
    uint8_t k_recv[AEAD_KEY_LEN];          /* Decryption key */
    uint8_t k_send[AEAD_KEY_LEN];          /* Encryption key */
    volatile uint64_t send_seq;             /* Send sequence number */
    uint64_t last_recv_seq;                 /* Last received sequence */
    struct sockaddr_in client_addr;         /* Client address */
    socklen_t client_addrlen;               /* Client address length */
    uint8_t vpn_ip[4];                      /* Assigned VPN IP */
    uint8_t slide_window[SLIDING_WINDOW_SIZE]; /* Replay attack prevention */
    out_queue_t *outq;                      /* Outgoing packet queue */
    pthread_mutex_t seq_lock;               /* Protect send_seq */
    time_t last_activity;                   /* Last activity timestamp */
} session_t;

#endif // SESSION_H
