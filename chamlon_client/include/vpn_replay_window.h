#ifndef VPN_REPLAY_WINDOW_H
#define VPN_REPLAY_WINDOW_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#define WINDOW_SIZE   64                // RFC 4303: minimum 64
#define WORD_SIZE     64
#define BITMAP_WORDS  (WINDOW_SIZE / WORD_SIZE)

typedef struct {
    uint64_t recv_max;                  // highest sequence number seen
    uint64_t bitmap[BITMAP_WORDS];      // sliding window bits
} replay_window_t;

/**
 * check_replay - Check if a sequence number is a replay or invalid
 * seq: Sequence number to check
 * w: Replay window state
 * 
 * Returns: true if packet is a replay/invalid, false if packet is valid
 */
bool check_replay(uint64_t seq, replay_window_t *w);

/**
 * update_window - Update the replay window after accepting a valid packet
 * seq: Sequence number that was accepted
 * w: Replay window state
 */
void update_window(uint64_t seq, replay_window_t *w);

#endif // VPN_REPLAY_WINDOW_H
