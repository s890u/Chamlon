#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <time.h>
#include <stdint.h>
#include "vpn_common.h"
#include "vpn_log.h"
#include "session.h"
#include "vpn_crypto.h"
#include "packet.h"
#include <pthread.h>

/* funcio basica per enviar control packets als clients: [proto_header_t | session_id(16) | ctrl_type(1)] */
void send_control_packet(int udp_sock, session_t *s, uint8_t ctrl_type) {
    if (!s || !s->active) return;
    
    /* Validate fragment size is within bounds */
    size_t frag_len = (size_t)s->argv_FRAG;
    if (frag_len > MAX_FRAG || frag_len < 64) {
        vpn_log("Invalid fragment size: %zu", frag_len);
        return;
    }
    
    uint8_t buf2[MAX_FRAG];
    memset(buf2, 0, frag_len);
    
    uint8_t out[BUFFER_SIZE];
    size_t outlen = 0;
    
    pthread_mutex_lock(&s->seq_lock);
    uint64_t seq = s->send_seq++;
    pthread_mutex_unlock(&s->seq_lock);
    
    tunnel_header_t header;
    header.packet_id = 1;
    header.fragment_offset = 1;
    header.total_ip_len = 1;
    header.flags = ctrl_type;
    
    if (sizeof(tunnel_header_t) > frag_len) {
        vpn_log("Fragment size too small for header");
        return;
    }
    
    memcpy(buf2, &header, sizeof(tunnel_header_t)); 
    memset(buf2 + sizeof(tunnel_header_t), 0x77, frag_len - sizeof(tunnel_header_t));
    
    if (aead_encrypt(s->k_send, s->session_id, seq,
                     buf2, frag_len,
                     out, &outlen) != 0) {
        vpn_log("encrypt failed seq=%lu", seq);
        return;
    }
    
    /* Validate final packet size won't exceed buffer */
    size_t pktlen = sizeof(proto_header_t) + SESSION_ID_LEN + 8 + outlen;
    if (pktlen > BUFFER_SIZE) {
        vpn_log("Packet size exceeds buffer limit: %zu", pktlen);
        return;
    }
    
    uint8_t pkt[BUFFER_SIZE];
    proto_header_t ph;
    ph.magic = PKT_MAGIC;
    ph.version = PKT_VERSION;
    ph.type = PKT_TYPE_DATA;
    
    memcpy(pkt, &ph, sizeof(proto_header_t));
    memcpy(pkt + sizeof(proto_header_t), s->session_id, SESSION_ID_LEN);
    
    uint64_t seq_net = htobe64(seq);
    memcpy(pkt + sizeof(proto_header_t) + SESSION_ID_LEN, &seq_net, 8);
    memcpy(pkt + sizeof(proto_header_t) + SESSION_ID_LEN + 8, out, outlen);
    
    sendto(udp_sock, pkt, pktlen, 0, (struct sockaddr*)&s->client_addr, s->client_addrlen);
}


void prepare_dummy_static_parts(session_t *s) {
    proto_header_t ph = { .magic = PKT_MAGIC, .version = PKT_VERSION, .type = PKT_TYPE_DATA };
    uint8_t *p = s->final_pkt_dummy;
    
    /* Validate buffer space */
    if (sizeof(proto_header_t) + SESSION_ID_LEN > MAX_FRAG) {
        vpn_log("Buffer too small for static header");
        return;
    }
    
    memcpy(p, &ph, sizeof(proto_header_t));
    memcpy(p + sizeof(proto_header_t), s->session_id, SESSION_ID_LEN);
    
    s->static_hdr_len = sizeof(proto_header_t) + SESSION_ID_LEN;

    size_t frag_len = (size_t)s->argv_FRAG;
    if (frag_len > MAX_FRAG || frag_len < 64) {
        vpn_log("Invalid fragment size in prepare_dummy_static_parts: %zu", frag_len);
        frag_len = 1024;  // Reset to safe default
    }
    
    tunnel_header_t th = { .packet_id = 1, .fragment_offset = 1, .total_ip_len = 1, .flags = PKT_DUMMY };
    
    if (sizeof(tunnel_header_t) > MAX_FRAG) {
        vpn_log("Tunnel header too large");
        return;
    }
    
    memcpy(s->dummy_payload, &th, sizeof(tunnel_header_t));
    if (frag_len > sizeof(tunnel_header_t)) {
        memset(s->dummy_payload + sizeof(tunnel_header_t), 0x99, frag_len - sizeof(tunnel_header_t));
    }
}

// ASUMIM:
// buf2 te: [tunnel_header_t (8 bytes)] + [Dadess del fragment IP]
// len_real_data_plus_header es: 8 bytes + longitud_del_fragment
void packet_padding(uint8_t *buf2, size_t len_real_data_plus_header, int frag) {
    if (!buf2) return;
    
    const size_t max_len = (size_t)frag;
    
    /* Validate frag size is reasonable */
    if (frag <= 0 || frag > (int)MAX_FRAG) {
        return;
    }
    
    /* Validate that actual data doesn't exceed fragment size */
    if (len_real_data_plus_header > max_len) {
        return;
    }
    
    // Calcular cuantos bytes deben rellenarse
    size_t len_to_fill = max_len - len_real_data_plus_header;
    
    // Rellenar el area restante con un byte de relleno
    if (len_to_fill > 0 && len_to_fill <= max_len) {
        memset(buf2 + len_real_data_plus_header, 0x00, len_to_fill);
    }
    
    // No se necesita almacenar la longitud del padding porque el cliente
    // la deduce del tamaño fijo (PACKET_LENGTH) y de la longitud real
    // declarada implicitamente en el tunnel_header_t.
}
