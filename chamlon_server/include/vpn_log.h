#ifndef VPN_LOG_H
#define VPN_LOG_H

#include <stdio.h>
#include <stdarg.h>
#include <time.h>

static inline void vpn_log(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    time_t now = time(NULL);
    char ts[32];
    struct tm tm;
    localtime_r(&now, &tm);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm);
    printf("[%s] ", ts);
    vprintf(fmt, ap);
    printf("\n");
    va_end(ap);
}
void log_connection(const char *ipaddr,const char *country);

#endif // VPN_LOG_H
