#ifndef VPN_TUN_H
#define VPN_TUN_H

int tun_alloc(char *dev);
void setup_interface(const char *ifname, const char *ip_cidr);
int setup_ip_forward(int sw);
int setup_nat();
#endif // VPN_TUN_H

