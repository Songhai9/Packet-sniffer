#ifndef SCTP_H
#define SCTP_H

#include <stdint.h>

// Définition des structures pour les en-têtes SCTP

typedef struct sctp_header {
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t verification_tag;
    uint32_t checksum;
} sctp_header_t;

typedef struct sctp_chunk_header {
    uint8_t type;
    uint8_t flags;
    uint16_t length;
} sctp_chunk_header_t;

// Prototypes de fonctions
void analyze_sctp(const unsigned char *packet, long unsigned int length);

#endif // SCTP_H
