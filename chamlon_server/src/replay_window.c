#include "replay_window.h"
#include <string.h>

/**
 * check_replay:
 * Returns true if the packet is a replay or too old.
 */
bool check_replay(uint64_t seq, replay_window_t *w)
{
    // Reject seq == 0 if your protocol disallows it
    if (seq == 0) {
        return true; // treat as replay/invalid
    }

    // 1) New sequence beyond the right edge of the window then accept
    if (seq > w->recv_max) {
        return false;
    }

    // 2) Too old (left of the window) then replay
    if (seq + WINDOW_SIZE <= w->recv_max) {
        return true;
    }

    // 3) Inside window: check bitmap
    uint64_t diff = w->recv_max - seq;   // 0 <= diff < WINDOW_SIZE
    uint64_t bit_index = diff;           // 0 = newest, WINDOW_SIZE-1 = oldest

    uint64_t word = bit_index / WORD_SIZE;
    uint64_t bit  = bit_index % WORD_SIZE;

    return (w->bitmap[word] & (1ULL << bit)) != 0;
}


/**
 * update_window:
 * Marks a sequence number as received. 
 * Only call this after the packet is authenticated.
 */
void update_window(uint64_t seq, replay_window_t *w)
{
    if (seq == 0) {
        return; // ignore or handle as error
    }

    // Case 1: seq is newer than anything we've seen
    if (seq > w->recv_max) {
        uint64_t diff = seq - w->recv_max;

        if (diff >= WINDOW_SIZE) {
            // The new seq is so far ahead we drop all history
            memset(w->bitmap, 0, sizeof(w->bitmap));
        } else {
            // Shift the window left by 'diff' bits
            // Newest bit is at position 0 (LSB of bitmap[0])
            uint64_t shift = diff;

            if (shift >= WORD_SIZE) {
                uint64_t word_shift = shift / WORD_SIZE;
                uint64_t bit_shift  = shift % WORD_SIZE;

                // Shift whole words first
                for (int i = BITMAP_WORDS - 1; i >= 0; i--) {
                    uint64_t val = 0;
                    if (i >= (int)word_shift) {
                        val = w->bitmap[i - word_shift];
                    }
                    w->bitmap[i] = val;
                }

                // Then shift bits inside each word if needed
                if (bit_shift != 0) {
                    for (int i = BITMAP_WORDS - 1; i >= 0; i--) {
                        uint64_t high = w->bitmap[i] << bit_shift;
                        uint64_t carry = 0;
                        if (i > 0) {
                            carry = w->bitmap[i - 1] >> (WORD_SIZE - bit_shift);
                        }
                        w->bitmap[i] = high | carry;
                    }
                }
            } else {
                // Only bit shift
                uint64_t bit_shift = shift;
                for (int i = BITMAP_WORDS - 1; i >= 0; i--) {
                    uint64_t high = w->bitmap[i] << bit_shift;
                    uint64_t carry = 0;
                    if (i > 0) {
                        carry = w->bitmap[i - 1] >> (WORD_SIZE - bit_shift);
                    }
                    w->bitmap[i] = high | carry;
                }
            }

            // Clear bits that just slid into the window (lowest 'diff' bits)
            // Since we shift left, the newest bits are at the least significant positions.
            uint64_t mask = (diff >= 64) ? 0 : ((1ULL << diff) - 1);
            w->bitmap[0] &= ~mask;
        }

        w->recv_max = seq;
    }

    // Case 2: seq is inside the current window
    uint64_t diff = w->recv_max - seq;   // 0 <= diff < WINDOW_SIZE
    uint64_t bit_index = diff;

    uint64_t word = bit_index / WORD_SIZE;
    uint64_t bit  = bit_index % WORD_SIZE;

    w->bitmap[word] |= (1ULL << bit);
}
