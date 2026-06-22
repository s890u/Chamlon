#ifndef PACKET_PROCESSOR_H
#define PACKET_PROCESSOR_H

#include "vpn_queue.h"
#include "vpn_replay_window.h"

/**
 * Packet processing functions
 * Handles both incoming TUN and UDP packets
 */

/* Process incoming IP packet from TUN interface */
void handle_tun_packet(int tun_fd, int udp_sock, out_queue_t *outq);

/* Process incoming UDP packet from VPN server */
void handle_udp_packet(int udp_sock, int tun_fd, replay_window_t *rw);

/* Send keepalive control packet to server */
void send_keepalive(int udp_sock);

#endif // PACKET_PROCESSOR_H
