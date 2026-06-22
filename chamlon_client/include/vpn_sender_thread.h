#ifndef VPN_SENDER_THREAD_H
#define VPN_SENDER_THREAD_H

#include <stdint.h>
#include <time.h>
#include <arpa/inet.h>
#include "vpn_common.h"
#include "vpn_queue.h"

typedef struct {
    int udp_sock;
    struct sockaddr_in server_addr;
    uint8_t session_id[SESSION_ID_LEN];
    uint8_t k_send[AEAD_KEY_LEN];
    out_queue_t *outq;
    struct timespec interval;
    uint8_t             pending_k_send[AEAD_KEY_LEN];
    uint8_t             pending_session_id[SESSION_ID_LEN];
    _Atomic int         pending_rekey;
} sender_args_t;


void set_interval_from_mbps(double mbps, int include_headers, struct timespec *ts);
void prepare_dummy_static_parts(const uint8_t session_id[SESSION_ID_LEN]);
void *sender_thread_fn(void *argv);

#endif // VPN_SENDER_THREAD_H
