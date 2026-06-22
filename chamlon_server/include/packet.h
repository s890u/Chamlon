#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>
#include <stddef.h>
#include "session.h"
#include "vpn_common.h"

/*
 * g_next_packet_id is declared in fragment.h and defined in vpn_server.c.
 */

void send_control_packet(int udp_sock, session_t *s, uint8_t ctrl_type);
void prepare_dummy_static_parts(session_t *s);
void packet_padding(uint8_t *buf2, size_t len_real_data_plus_header, int frag);

#endif /* PACKET_H */
