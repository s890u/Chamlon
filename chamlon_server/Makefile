CC = gcc
CFLAGS = -O3 -march=native -flto -Wall -Iinclude -fno-strict-aliasing -ffast-math -fomit-frame-pointer
LDFLAGS = -flto
LIBS = -lsodium -lpthread -lm

SRC_COMMON = src/vpn_crypto.c src/vpn_tun.c src/vpn_log.c src/scheduler.c src/packet.c src/session.c src/replay_window.c src/fragment.c src/handshake.c src/packet_processor.c src/rate_limiter.c src/metrics.c src/graceful_shutdown.c src/thread_pool.c src/epoll_handler.c
SERVER_OBJ = $(SRC_COMMON) src/vpn_server.c

all: vpn_server

vpn_server: $(SERVER_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

clean:
	rm -f vpn_server
