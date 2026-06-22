#ifndef VPN_UTILS_H
#define VPN_UTILS_H

#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "session.h"

/**
 * hex2bin: Convert hex string to binary bytes
 * hex: Hex string (must have exactly len*2 characters)
 * out: Output buffer for binary data
 * outlen: Expected length of output data
 * 
 * Returns: 0 on success, -1 on failure (invalid format or wrong length)
 */
int hex2bin(const char *hex, uint8_t *out, size_t outlen);

/**
 * packet_padding: Pad packet to fixed size
 * buf2: Packet buffer to pad
 * len_real_data_plus_header: Current length including header
 * 
 * Pads remaining bytes to argv_FRAG size if PAD mode enabled.
 * Returns: 0 on success, -1 if padding disabled
 */
int packet_padding(uint8_t *buf2, size_t len_real_data_plus_header);

/**
 * restore_route_and_cleanup_client: Restore system routes and cleanup resources
 * Restores original default gateway and closes sockets/tunnel interface
 */
void restore_route_and_cleanup_client(void);

#endif // VPN_UTILS_H
