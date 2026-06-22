#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <arpa/inet.h>
#include "vpn_common.h"
#include "vpn_crypto.h"
#include "vpn_log.h"
#include "vpn_queue.h"
#include "vpn_replay_window.h"
#include "vpn_reassembly.h"
#include "vpn_utils.h"
#include "../include/session.h"

extern int argv_FRAG;
extern uint8_t g_session_id[SESSION_ID_LEN];
extern server_t servers[1];
extern uint16_t g_next_packet_id;
extern out_queue_t *g_outq;
extern time_t last_server_keepalive_time;

void send_keepalive(int udp_sock) {
    uint8_t buf2[argv_FRAG];
    tunnel_header_t th;
    th.packet_id        = 1;
    th.fragment_offset  = 1;
    th.total_ip_len     = 1;
    th.flags            = PKT_CTRL_KEEPALIVE;
    memcpy(buf2, &th, sizeof(tunnel_header_t));
    memset(buf2 + sizeof(tunnel_header_t), 0x88, argv_FRAG - sizeof(tunnel_header_t));

    size_t   outlen = 0;
    uint8_t  out[BUFFER_SIZE];
    uint64_t seq1 = atomic_fetch_add(&servers[0].send_seq, 1);

    if (aead_encrypt(servers[0].k_send, servers[0].session_id, seq1,
                     buf2, argv_FRAG, out, &outlen) != 0) {
        vpn_log("encrypt keepalive failed seq=%lu", seq1);
        return;
    }

    uint8_t pkt[outlen + SESSION_ID_LEN + 8 + sizeof(proto_header_t)];
    proto_header_t ph = { .magic = PKT_MAGIC, .version = PKT_VERSION,
                          .type  = PKT_TYPE_DATA };
    memcpy(pkt, &ph, sizeof(proto_header_t));
    memcpy(pkt + sizeof(proto_header_t), servers[0].session_id, SESSION_ID_LEN);
    uint64_t seq_net = htobe64(seq1);
    memcpy(pkt + sizeof(proto_header_t) + SESSION_ID_LEN, &seq_net, 8);
    memcpy(pkt + sizeof(proto_header_t) + SESSION_ID_LEN + 8, out, outlen);
    size_t pktlen = sizeof(proto_header_t) + SESSION_ID_LEN + 8 + outlen;

    sendto(udp_sock, pkt, pktlen, 0,
           (struct sockaddr *)&servers[0].server_addr,
           sizeof(servers[0].server_addr));
    vpn_log("Sent keepalive to server");
}

void handle_tun_packet(int tun_fd, int udp_sock, out_queue_t *outq) {
    uint8_t buf[BUFFER_SIZE];
    ssize_t len = read(tun_fd, buf, sizeof(buf));
    if (len <= 0) {
        if (len < 0 && errno != EAGAIN) perror("read tun");
        return;
    }
    if (len < 20) return;

    const uint8_t *ip_buf = buf;
    const size_t   ip_len = (size_t)len;

    uint16_t current_id = g_next_packet_id++;
    if (g_next_packet_id == 0) g_next_packet_id = 1;

    size_t       current_offset = 0;
    const size_t header_len     = sizeof(tunnel_header_t);
    const size_t max_payload    = argv_FRAG - header_len;

    while (current_offset < (size_t)len) {
        uint8_t buf2[argv_FRAG];
        memset(buf2, 0, argv_FRAG);
        uint8_t out[BUFFER_SIZE];
        size_t  outlen = 0;

        size_t chunk_len = (size_t)len - current_offset;
        if (chunk_len > max_payload) chunk_len = max_payload;

        tunnel_header_t header;
        header.packet_id       = current_id;
        header.fragment_offset = (uint16_t)current_offset;
        header.total_ip_len    = (uint16_t)len;
        bool is_last_chunk     = (current_offset + chunk_len == (size_t)len);
        header.flags           = is_last_chunk ? 0x0000 : 0x8000;

        memcpy(buf2, &header, header_len);
        memcpy(buf2 + header_len, buf + current_offset, chunk_len);
        current_offset += chunk_len;

        size_t real_data_len = header_len + chunk_len;
        if (packet_padding(buf2, real_data_len) == 0)
            real_data_len = argv_FRAG;

        uint64_t seq = atomic_fetch_add(&servers[0].send_seq, 1);

        if (aead_encrypt(servers[0].k_send, servers[0].session_id, seq,
                         buf2, real_data_len, out, &outlen) != 0) {
            vpn_log("encrypt failed seq=%lu", seq);
            break;
        }

        size_t   pktlen = sizeof(proto_header_t) + SESSION_ID_LEN + 8 + outlen;
        uint8_t *pkt    = malloc(pktlen);
        if (!pkt) { vpn_log("malloc failed"); continue; }

        proto_header_t ph = { .magic = PKT_MAGIC, .version = PKT_VERSION,
                               .type  = PKT_TYPE_DATA };
        memcpy(pkt, &ph, sizeof(proto_header_t));
        memcpy(pkt + sizeof(proto_header_t), servers[0].session_id, SESSION_ID_LEN);
        uint64_t seq_net = htobe64(seq);
        memcpy(pkt + sizeof(proto_header_t) + SESSION_ID_LEN, &seq_net, 8);
        memcpy(pkt + sizeof(proto_header_t) + SESSION_ID_LEN + 8, out, outlen);

        packet_queue_push(g_outq, pkt, pktlen, seq, ip_buf, ip_len);
    }
}

void handle_udp_packet(int udp_sock, int tun_fd, replay_window_t *rw) {
    uint8_t            buf[BUFFER_SIZE];
    struct sockaddr_in src;
    socklen_t          slen = sizeof(src);

    /*
     * MSG_DONTWAIT: if no packet is available, return immediately with
     * errno=EAGAIN. This allows the caller to drain all queued packets
     * in a loop without blocking, then stop when the queue is empty.
     * Critical for download throughput without this the drain loop
     * in vpn_event_loop.c would block on the second iteration.
     */
    ssize_t r = recvfrom(udp_sock, buf, sizeof(buf), MSG_DONTWAIT,
                         (struct sockaddr *)&src, &slen);
    if (r <= 0) return;  /* errno=EAGAIN set by kernel, caller checks it */

    proto_header_t *proto_buf = (proto_header_t *)buf;
    if (proto_buf->version != PKT_VERSION) return;
    if (proto_buf->type    != PKT_TYPE_DATA) return;

    if (r <= (ssize_t)(sizeof(proto_header_t) + SESSION_ID_LEN + 8)) return;
    if (memcmp(buf + sizeof(proto_header_t), servers[0].session_id,
               SESSION_ID_LEN) != 0) return;

    uint64_t pkt_seq = 0;
    for (int j = 0; j < 8; ++j)
        pkt_seq = (pkt_seq << 8) | buf[sizeof(proto_header_t) + SESSION_ID_LEN + j];

    if (check_replay(pkt_seq, rw)) return;

    size_t  cipher_len = r - (sizeof(proto_header_t) + SESSION_ID_LEN + 8);
    uint8_t plain[BUFFER_SIZE];
    size_t  plain_len = 0;

    if (aead_decrypt(servers[0].k_recv, servers[0].session_id, pkt_seq,
                     buf + sizeof(proto_header_t) + SESSION_ID_LEN + 8,
                     cipher_len, plain, &plain_len) != 0) {
        vpn_log("decrypt/auth fail (seq=%lu)", pkt_seq);
        return;
    }
    update_window(pkt_seq, rw);

    const size_t hdr_len = sizeof(tunnel_header_t);
    if (plain_len < hdr_len) { vpn_log("Decrypted packet too small"); return; }

    tunnel_header_t *header = (tunnel_header_t *)plain;
    if (header->flags == PKT_DUMMY)           return;
    if (header->flags == PKT_CTRL_KEEPALIVE)  { last_server_keepalive_time = time(NULL);vpn_log("Received keepalive from server"); return; }
    if (header->flags == PKT_CTRL_DISCONNECT) { vpn_log("Received DISCONNECT from server"); exit(0); }

    uint8_t *fragment_payload_start = plain + hdr_len;
    size_t   fragment_payload_len   = plain_len - hdr_len;

    reassembly_entry_t *entry = find_or_create_entry(header->packet_id);
    if (!entry) return;

    if (header->fragment_offset + fragment_payload_len > MAX_PACKET_SIZE) {
        vpn_log("Fragment ID %hu exceeds MAX_PACKET_SIZE", header->packet_id);
        entry->is_active = false;
        return;
    }

    if (entry->expected_length == 0)
        entry->expected_length = header->total_ip_len;

    memcpy(entry->buffer + header->fragment_offset,
           fragment_payload_start, fragment_payload_len);
    entry->received_bytes += fragment_payload_len;

    bool is_last_fragment = !(header->flags & 0x8000);
    if (is_last_fragment && entry->received_bytes >= entry->expected_length) {
        if (write(tun_fd, entry->buffer, entry->expected_length) < 0)
            perror("write tun");
        entry->is_active = false;
    }
}
