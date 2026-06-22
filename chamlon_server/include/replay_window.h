#ifndef REPLAY_WINDOW_H
#define REPLAY_WINDOW_H

#include <stdint.h>
#include <stdbool.h>
#include "vpn_common.h"

/**
 * check_replay:
 * Returns true if the packet is a replay or too old.
 */
bool check_replay(uint64_t seq, replay_window_t *w);

/**
 * update_window:
 * Marks a sequence number as received. 
 * Only call this after the packet is authenticated.
 */
void update_window(uint64_t seq, replay_window_t *w);

#endif // REPLAY_WINDOW_H
