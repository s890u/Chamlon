#include "vpn_utils.h"
#include "vpn_log.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

// External globals from main
extern server_t servers[];
extern char argv_PAD;
extern int argv_FRAG;
extern char old_gateway[128];
extern int route_added;
extern char vpn_iface[];
extern int g_tun_fd;
extern int g_udp_sock;

int hex2bin(const char *hex, uint8_t *out, size_t outlen) {
    if (strlen(hex) != outlen * 2) return -1;
    for (size_t i = 0; i < outlen; ++i) {
        unsigned int v;
        if (sscanf(hex + 2*i, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

int packet_padding(uint8_t *buf2, size_t len_real_data_plus_header) {
    if(argv_PAD=='N'){return -1;}
    const size_t max_len = (size_t)argv_FRAG;
    
    // Calcular cuantos bytes deben rellenarse
    size_t len_to_fill = max_len - len_real_data_plus_header;
    
    // Rellenar el area restante con un byte de relleno
    if (len_to_fill > 0) {
        memset(buf2 + len_real_data_plus_header, 0x00, len_to_fill);
    }
    return 0;
    // No se necesita almacenar la longitud del padding porque el cliente
    // la deduce del tamaño fijo (PACKET_LENGTH) y de la longitud real
    // declarada implicitamente en el tunnel_header_t.
}

void restore_route_and_cleanup_client(void) {
    if (old_gateway[0] != '\0') {
        char cmd_del[256];
        snprintf(cmd_del, sizeof(cmd_del),
                 "ip route del %s/32 2>/dev/null",
                 inet_ntoa(servers[0].server_addr.sin_addr));
        #pragma GCC diagnostic push
        #pragma GCC diagnostic ignored "-Wunused-result"
        system(cmd_del);
        #pragma GCC diagnostic pop
        vpn_log("Removed pinned server route for %s",
                inet_ntoa(servers[0].server_addr.sin_addr));
    }

    if (route_added) {
        if (old_gateway[0]) {
            char cmd[256];
            snprintf(cmd, sizeof(cmd),
                     "ip route del default dev %s 2>/dev/null; "
                     "ip route add default via %s 2>/dev/null",
                     vpn_iface, old_gateway);
            int rc = system(cmd);
            (void)rc;
            vpn_log("Restored default route to %s", old_gateway);
        } else {
            char cmd[128];
            snprintf(cmd, sizeof(cmd),
                     "ip route del default dev %s 2>/dev/null", vpn_iface);
            int rc = system(cmd);
            (void)rc;
            vpn_log("Removed VPN default route");
        }
        route_added = 0;
    }

    printf("DISCONNECTED\n");
    fflush(stdout);
    if (g_tun_fd >= 0) close(g_tun_fd);
    if (g_udp_sock >= 0) close(g_udp_sock);
}
