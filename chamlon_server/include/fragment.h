#ifndef FRAGMENT_H
#define FRAGMENT_H

#include <stdint.h>
#include <time.h>
#include "vpn_common.h"
#include "session.h"

/* Packet ID generator for outbound fragmentation.*/
extern uint16_t g_next_packet_id;
uint16_t fragment_next_packet_id(void);
void               sweep_reassembly_table(void);
reassembly_entry_t *find_or_create_entry(session_t *s, uint16_t id);

#endif /* FRAGMENT_H */
