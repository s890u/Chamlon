#include "fragment.h"
#include "vpn_log.h"
#include "session.h"
#include <string.h>
#include <time.h>
#include <stdatomic.h>

static _Atomic uint16_t g_next_packet_id_atomic = 1;

uint16_t fragment_next_packet_id(void)
{
    uint16_t id = atomic_fetch_add(&g_next_packet_id_atomic, 1);
    /* Skip 0, reserved as "no ID" sentinel in some reassembly logic */
    if (id == 0) id = atomic_fetch_add(&g_next_packet_id_atomic, 1);
    return id;
}

/* Keep g_next_packet_id for ABI compat with anything that extern's it */
uint16_t g_next_packet_id = 1;

void sweep_reassembly_table(void)
{
    time_t now = time(NULL);
    for (int c = 0; c < MAX_CLIENTS; c++) {
        for (int i = 0; i < MAX_REASSEMBLY_ENTRIES; i++) {
            if (sessions[c].g_reassembly_table[i].is_active &&
                (now - sessions[c].g_reassembly_table[i].last_activity
                 > REASSEMBLY_TIMEOUT)) {
                vpn_log("Expiring packet ID %hu",
                        sessions[c].g_reassembly_table[i].packet_id);
                memset(&sessions[c].g_reassembly_table[i], 0,
                       sizeof(reassembly_entry_t));
            }
        }
    }
}

reassembly_entry_t *find_or_create_entry(session_t *s, uint16_t id)
{
    time_t now = time(NULL);
    for (int i = 0; i < MAX_REASSEMBLY_ENTRIES; i++) {
        if (s->g_reassembly_table[i].is_active &&
            s->g_reassembly_table[i].packet_id == id) {
            s->g_reassembly_table[i].last_activity = now;
            return &s->g_reassembly_table[i];
        }
    }
    for (int i = 0; i < MAX_REASSEMBLY_ENTRIES; i++) {
        if (!s->g_reassembly_table[i].is_active) {
            memset(&s->g_reassembly_table[i], 0, sizeof(reassembly_entry_t));
            s->g_reassembly_table[i].is_active     = true;
            s->g_reassembly_table[i].packet_id     = id;
            s->g_reassembly_table[i].last_activity = now;
            return &s->g_reassembly_table[i];
        }
    }
    vpn_log("Reassembly table full, dropping fragment ID %hu", id);
    return NULL;
}
