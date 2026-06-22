#define _GNU_SOURCE
#include "vpn_tun.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>

int tun_alloc(char *dev) {
    struct ifreq ifr;
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) { perror("open /dev/net/tun"); exit(1); }
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (dev && *dev) {snprintf(ifr.ifr_name, IFNAMSIZ, "%s", dev);}

    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) { 
        perror("ioctl TUNSETIFF"); 
        close(fd); 
        exit(1); 
    }
    snprintf(dev, IFNAMSIZ, "%s", ifr.ifr_name);
    return fd;
}

void setup_interface(const char *ifname, const char *ip_cidr) {
    /* Validate input parameters */
    if (!ifname || !ip_cidr) {
        fprintf(stderr, "Error: Invalid interface name or IP address\n");
        return;
    }
    
    if (strlen(ifname) >= IFNAMSIZ) {
        fprintf(stderr, "Error: Interface name too long (max %d characters)\n", IFNAMSIZ - 1);
        return;
    }
    
    #define MAX_CIDR_LEN 64
    if (strlen(ip_cidr) >= MAX_CIDR_LEN) {
        fprintf(stderr, "Error: IP/CIDR too long (max %d characters)\n", MAX_CIDR_LEN - 1);
        return;
    }
    
    char cmd[256];
    int ret;
    
    /* Validate snprintf output to ensure no truncation */
    int written = snprintf(cmd, sizeof(cmd), "ip addr add %s dev %s", ip_cidr, ifname);
    if (written < 0 || written >= (int)sizeof(cmd)) {
        fprintf(stderr, "Error: Buffer overflow prevented in interface setup\n");
        return;
    }
    ret = system(cmd);
    if (ret != 0) {fprintf(stderr, "Warning: Failed to set IP %s on %s (exit code %d)\n", ip_cidr, ifname, ret);}
    
    written = snprintf(cmd, sizeof(cmd), "ip link set %s up", ifname);
    if (written < 0 || written >= (int)sizeof(cmd)) {
        fprintf(stderr, "Error: Buffer overflow prevented in interface setup\n");
        return;
    }
    ret = system(cmd);
    if (ret != 0) {fprintf(stderr, "Error: Failed to bring up interface %s\n", ifname);}
}


int setup_ip_forward(int sw){
    if(sw==1){
        if (system("sysctl -w net.ipv4.ip_forward=1") != 0) {fprintf(stderr, "Warning: Failed to enable IP forwarding.\n"); return -1;}return 0;
    }else if(sw==0){
        if (system("sysctl -w net.ipv4.ip_forward=0") != 0) {fprintf(stderr, "Warning: Failed to disable IP forwarding.\n"); return -1;}return 0;
    }
    return -2;
}

int setup_nat() {
    char iface[64] = {0};
    FILE *fp = popen("ip route show default | awk '{print $5}' | head -1", "r");
    if (!fp || !fgets(iface, sizeof(iface), fp)) {
        fprintf(stderr, "Warning: could not detect default interface\n");
        if (fp) pclose(fp);
        return -1;
    }
    pclose(fp);
    
    iface[strcspn(iface, "\n")] = 0;

    char cmd[256];
    snprintf(cmd, sizeof(cmd),
        "iptables -t nat -A POSTROUTING -s 10.10.0.0/24 -o %s -j MASQUERADE", iface);

    if (system(cmd) != 0) {
        fprintf(stderr, "Warning: iptables NAT rule failed on interface %s\n", iface);
        return -1;
    }

    printf("[NAT] Masquerade rule set on interface: %s\n", iface);
    return 0;
}
