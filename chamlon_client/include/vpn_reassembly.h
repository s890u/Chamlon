#ifndef VPN_REASSEMBLY_H
#define VPN_REASSEMBLY_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <stdbool.h>

#define MAX_PACKET_SIZE 2500          //REVISAR MTU
#define MAX_REASSEMBLY_ENTRIES 256     
#define REASSEMBLY_TIMEOUT 20

typedef struct {
    uint16_t packet_id;           // ID del paquete que se esta reensamblando.
    time_t last_activity;         // Marca de tiempo para el timeout.
    size_t expected_length;       // Longitud total esperada.
    size_t received_bytes;        // Contador de bytes recibidos.
    
    uint8_t buffer[MAX_PACKET_SIZE]; // El buffer real de reensamblaje.
    bool is_active;               // Bandera de estado.
} reassembly_entry_t;

/**
 * reassembly_init, Initialize the reassembly table
 */
void reassembly_init(void);

/**
 * sweep_reassembly_table, Periodically clean up timed-out fragmented packets
 */
void sweep_reassembly_table(void);

/**
 * find_or_create_entry, Find existing or create new reassembly entry for packet ID
 * id: Packet ID to find or create
 * 
 * Returns: Pointer to reassembly_entry_t or NULL if table is full
 */
reassembly_entry_t* find_or_create_entry(uint16_t id);

#endif // VPN_REASSEMBLY_H
