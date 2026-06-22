#include "vpn_reassembly.h"
#include "vpn_log.h"
#include <string.h>
#include <time.h>

// --- TABLA GLOBAL DE REENSAMBLAJE CLIENTE---
static reassembly_entry_t g_reassembly_table[MAX_REASSEMBLY_ENTRIES];

void reassembly_init(void) {
    memset(g_reassembly_table, 0, sizeof(g_reassembly_table));
}

// Funcio periodica que neteja la taula de paquets fragmentats
void sweep_reassembly_table(void) {
    time_t now = time(NULL);
    for (int i = 0; i < MAX_REASSEMBLY_ENTRIES; i++) {
        if (g_reassembly_table[i].is_active &&
            (now - g_reassembly_table[i].last_activity > REASSEMBLY_TIMEOUT)) {
            vpn_log("INFO: Expiring packet ID %hu", g_reassembly_table[i].packet_id);
            memset(&g_reassembly_table[i], 0, sizeof(reassembly_entry_t));
        }
    }
}

// Funcio per buscar o crear en la taula el id de un paquet fragmentat
reassembly_entry_t* find_or_create_entry(uint16_t id) {
    time_t now = time(NULL);

    // Cas 1: El paquet fragmentat existeix
    for (int i = 0; i < MAX_REASSEMBLY_ENTRIES; i++) {
        if (g_reassembly_table[i].is_active &&
            g_reassembly_table[i].packet_id == id) {
            g_reassembly_table[i].last_activity = now;
            return &g_reassembly_table[i];
        }
    }

    // Cass 2: El paquet no existeix per tant creem un de nou
    for (int i = 0; i < MAX_REASSEMBLY_ENTRIES; i++) {
        if (!g_reassembly_table[i].is_active) {
            memset(&g_reassembly_table[i], 0, sizeof(reassembly_entry_t));
            g_reassembly_table[i].is_active = true;
            g_reassembly_table[i].packet_id = id;
            g_reassembly_table[i].last_activity = now;
            return &g_reassembly_table[i];
        }
    }

    // Table full
    vpn_log("ERROR: Reassembly table full, dropping fragment ID %hu.", id);
    return NULL;
}
