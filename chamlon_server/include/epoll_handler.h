#ifndef EPOLL_HANDLER_H
#define EPOLL_HANDLER_H

#include <sys/epoll.h>

/* Event loop wrapper for epoll-based server */
typedef struct epoll_handler epoll_handler_t;

/* Create epoll instance for managing file descriptors */
epoll_handler_t *epoll_handler_create(int max_events);

/* Destroy epoll instance */
void epoll_handler_destroy(epoll_handler_t *handler);

/* Add file descriptor to epoll watch list */
int epoll_handler_add(epoll_handler_t *handler, int fd, int events, void *data);

/* Modify file descriptor events */
int epoll_handler_mod(epoll_handler_t *handler, int fd, int events, void *data);

/* Remove file descriptor from epoll watch list */
int epoll_handler_del(epoll_handler_t *handler, int fd);

/* Wait for events (blocks until timeout or event occurs) */
int epoll_handler_wait(epoll_handler_t *handler, int timeout_ms, 
                       struct epoll_event **events_out);

/* Get number of ready events from last wait call */
int epoll_handler_event_count(epoll_handler_t *handler);

#endif // EPOLL_HANDLER_H
