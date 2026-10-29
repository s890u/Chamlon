CC = gcc

# setup.sh probes the compiler and passes `ARCHFLAGS=` or `LTOFLAGS=` when
# it cannot use one of these, so the build is not limited to x86 desktops.
ARCHFLAGS ?= -march=native
LTOFLAGS ?= -flto
CFLAGS = -Iinclude -O3 $(ARCHFLAGS) $(LTOFLAGS) -Wall -fno-strict-aliasing -ffast-math -fomit-frame-pointer
LDFLAGS = $(LTOFLAGS)
LIBS = -lsodium -lpthread -lm

SRC_COMMON = src/vpn_crypto.c src/vpn_tun.c src/vpn_log.c src/vpn_queue.c src/vpn_replay_window.c src/vpn_reassembly.c src/vpn_sender_thread.c src/vpn_handshake.c src/vpn_utils.c src/vpn_event_loop.c src/vpn_packet_handler.c
CLIENT_SRC = src/vpn_client.c

all: vpn_client
vpn_client: $(SRC_COMMON) $(CLIENT_SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

clean:
	rm -f vpn_client

.PHONY: all clean
