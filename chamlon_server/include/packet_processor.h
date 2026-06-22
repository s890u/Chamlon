#ifndef PACKET_PROCESSOR_H
#define PACKET_PROCESSOR_H

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include "session.h"
#include "vpn_common.h"

#define DATA_HEADER_LEN (sizeof(proto_header_t) + SESSION_ID_LEN + 8)

/*
 * handle_inbound_udp:
 *
 * Called by thread pool workers (JOB_TYPE_INBOUND_CRYPTO).
 * The epoll thread has already done recvfrom(); this function owns buf
 * for the duration of the call (does NOT free it the worker does).
 *
 * Thread-safety: multiple workers may call this concurrently for
 * DIFFERENT sessions.  Same-session packets are serialised by the
 * shard routing in thread_pool_submit_sharded().
 */
void handle_inbound_udp(int udp_sock, int tun_fd,
                        uint8_t *buf, ssize_t r,
                        struct sockaddr_in *src,
                        uint8_t *server_sk);

/*
 * handle_outbound_tun, called by the epoll thread ONLY.
 *
 * Reads ONE raw IP packet from tun_fd, then either:
 *   - CBR=N: builds a JOB_TYPE_OUTBOUND_CRYPTO job and submits to the
 *     thread pool (crypto + sendto happen on a worker).
 *   - CBR=Y: same submission path (scheduler still paces the send).
 *
 * Returns 1 if a packet was read and dispatched, 0 on EAGAIN.
 * Must be called in a drain loop, do NOT call just once per epoll event.
 *
 * The tun_fd read happens HERE (epoll thread).  Workers never touch tun_fd.
 */
int handle_outbound_tun(int tun_fd, int udp_sock);

/*
 * handle_outbound_tun_buf, called by thread pool workers ONLY.
 *
 * Receives a pre-read raw IP packet (buf/len).  Performs session-lookup,
 * fragmentation, aead_encrypt, and sendto().  Does NOT read from tun_fd.
 * buf is owned by the caller (worker frees it after this returns).
 */
void handle_outbound_tun_buf(int udp_sock,
                             const uint8_t *buf, size_t len);

void perform_maintenance(int udp_sock);

#endif /* PACKET_PROCESSOR_H */
