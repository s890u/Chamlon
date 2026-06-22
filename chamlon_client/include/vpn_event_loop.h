#ifndef VPN_EVENT_LOOP_H
#define VPN_EVENT_LOOP_H

/* Main event loop for client */
int event_loop_run(int tun_fd, int udp_sock, int frag_size);

#endif // VPN_EVENT_LOOP_H
