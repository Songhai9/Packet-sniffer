#include "../include/sctp.h"
#include <stdio.h>
#include <arpa/inet.h>

extern int verbose_level;

// Fonction pour analyser un en-tête SCTP
void analyze_sctp(const unsigned char *packet, long unsigned int length)
{
    if (length < sizeof(sctp_header_t))
    {
        printf("Paquet SCTP trop court pour l'en-tête\n");
        return;
    }

    const sctp_header_t *sctp_header = (const sctp_header_t *)packet;
    if (verbose_level == 1)
    {
        printf("| SCTP ");
    }
    else if (verbose_level > 1)
    {
        printf("SCTP | Source Port: %d | Destination Port: %d\n",
               ntohs(sctp_header->src_port), ntohs(sctp_header->dest_port));

        long unsigned int offset = sizeof(sctp_header_t);
        while (offset < length)
        {
            const sctp_chunk_header_t *chunk_header = (const sctp_chunk_header_t *)(packet + offset);

            if (ntohs(chunk_header->length) < sizeof(sctp_chunk_header_t))
            {
                printf("Chunk SCTP invalide ou trop court");
                printf("\n");
                break;
            }

            printf("Chunk Type: %u | Chunk Flags: %u | Chunk Length: %u\n",
                   chunk_header->type, chunk_header->flags, ntohs(chunk_header->length));

            offset += ntohs(chunk_header->length);
        }
    }
}
