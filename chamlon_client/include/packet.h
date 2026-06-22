#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>
#include "config.h"

/**
 * Protocol Header
 * Sent at the beginning of every VPN packet
 */
typedef struct __attribute__((packed)){
    uint32_t magic;      /* PKT_MAGIC */
    uint8_t version;     /* PKT_VERSION */
    uint8_t type;        /* PKT_TYPE_HANDSHAKE or PKT_TYPE_DATA */
}proto_header_t;

/**
 * Tunnel Header
 * Used inside encrypted packets for tunnel-level information
 */
typedef struct __attribute__((packed)){
    uint16_t packet_id;           /* Packet identifier */
    uint16_t fragment_offset;     /* Offset for fragmented packets */
    uint16_t total_ip_len;        /* Total IP packet length */
    uint16_t flags;               /* Control flags (KEEPALIVE, DISCONNECT, etc) */
    uint8_t session_id[SESSION_ID_LEN];      /* Session/Circuit ID */
} __attribute__((packed)) tunnel_header_t;

#endif // PACKET_H
