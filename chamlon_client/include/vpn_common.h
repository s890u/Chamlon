#ifndef VPN_COMMON_H
#define VPN_COMMON_H

#include <stdint.h>
#include <stdbool.h>

/* Include organized headers for protocols, configs, and structures */
#include <sodium.h>
#include "config.h"
#include "packet.h"
#include "session.h"

/* Forward declarations for queue types */
typedef struct out_node out_node_t;
typedef struct out_queue out_queue_t;

#endif // VPN_COMMON_H
