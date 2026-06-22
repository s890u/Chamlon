#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <string.h>
#include <errno.h>
#include "epoll_handler.h"
#include "vpn_log.h"

typedef struct epoll_handler {
    int epfd;
    struct epoll_event *events;
    int max_events;
    int num_events;
} epoll_handler_t;

epoll_handler_t *epoll_handler_create(int max_events) {
    if (max_events <= 0) max_events = 100;
    
    epoll_handler_t *handler = malloc(sizeof(epoll_handler_t));
    if (!handler) {
        vpn_log("Failed to allocate epoll_handler_t");
        return NULL;
    }
    
    handler->epfd = epoll_create1(EPOLL_CLOEXEC);
    if (handler->epfd < 0) {
        vpn_log("Failed to create epoll instance");
        free(handler);
        return NULL;
    }
    
    handler->max_events = max_events;
    handler->events = malloc(sizeof(struct epoll_event) * max_events);
    if (!handler->events) {
        vpn_log("Failed to allocate epoll events buffer");
        close(handler->epfd);
        free(handler);
        return NULL;
    }
    
    handler->num_events = 0;
    
    vpn_log("Epoll handler created with max_events=%d", max_events);
    return handler;
}

void epoll_handler_destroy(epoll_handler_t *handler) {
    if (!handler) return;
    
    if (handler->epfd >= 0) close(handler->epfd);
    if (handler->events) free(handler->events);
    free(handler);
    
    vpn_log("Epoll handler destroyed");
}

int epoll_handler_add(epoll_handler_t *handler, int fd, int events, void *data) {
    if (!handler || fd < 0) return -1;
    
    struct epoll_event ev;
    ev.events = events;
    ev.data.ptr = data;
    
    if (epoll_ctl(handler->epfd, EPOLL_CTL_ADD, fd, &ev) < 0) {
        vpn_log("Failed to add fd %d to epoll", fd);
        return -1;
    }
    
    return 0;
}

int epoll_handler_mod(epoll_handler_t *handler, int fd, int events, void *data) {
    if (!handler || fd < 0) return -1;
    
    struct epoll_event ev;
    ev.events = events;
    ev.data.ptr = data;
    
    if (epoll_ctl(handler->epfd, EPOLL_CTL_MOD, fd, &ev) < 0) {
        vpn_log("Failed to modify fd %d in epoll", fd);
        return -1;
    }
    
    return 0;
}

int epoll_handler_del(epoll_handler_t *handler, int fd) {
    if (!handler || fd < 0) return -1;
    
    if (epoll_ctl(handler->epfd, EPOLL_CTL_DEL, fd, NULL) < 0) {
        vpn_log("Failed to remove fd %d from epoll", fd);
        return -1;
    }
    
    return 0;
}

int epoll_handler_wait(epoll_handler_t *handler, int timeout_ms, 
                       struct epoll_event **events_out) {
    if (!handler || !events_out) return -1;
    
    int nfds = epoll_wait(handler->epfd, handler->events, handler->max_events, timeout_ms);
    
    if (nfds < 0) {
        if (errno == EINTR) {
            handler->num_events = 0;
            *events_out = handler->events;
            return 0;
        }
        vpn_log("epoll_wait failed");
        return -1;
    }
    
    handler->num_events = nfds;
    *events_out = handler->events;
    
    return nfds;
}

int epoll_handler_event_count(epoll_handler_t *handler) {
    if (!handler) return 0;
    return handler->num_events;
}
