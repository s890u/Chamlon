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
    if (*dev) strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) { perror("ioctl TUNSETIFF"); close(fd); exit(1); }
    strncpy(dev, ifr.ifr_name, IFNAMSIZ - 1);
    dev[IFNAMSIZ - 1] = '\0';
    return fd;
}

void setup_interface(const char *ifname, const char *ip_cidr) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ip addr add %s dev %s 2>/dev/null", ip_cidr, ifname);
    if (system(cmd) == -1) {
        perror("system");
    }
    snprintf(cmd, sizeof(cmd), "ip link set %s up", ifname);
    if (system(cmd) == -1) {
        perror("system");
    }
}
