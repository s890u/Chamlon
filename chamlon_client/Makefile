CC = gcc
CFLAGS = -Iinclude -O3 -march=native -flto -Wall -fno-strict-aliasing -ffast-math -fomit-frame-pointer
LDFLAGS = -flto
LIBS = -lsodium -lpthread -lm

SRC_COMMON = src/vpn_crypto.c src/vpn_tun.c src/vpn_log.c src/vpn_queue.c src/vpn_replay_window.c src/vpn_reassembly.c src/vpn_sender_thread.c src/vpn_handshake.c src/vpn_utils.c src/vpn_event_loop.c src/vpn_packet_handler.c
CLIENT_SRC = src/vpn_client.c

all: vpn_client
vpn_client: $(SRC_COMMON) $(CLIENT_SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

clean:
	rm -f vpn_client
