#include "../../include/applications/dns.h"
#include <stdio.h>
#include <arpa/inet.h> // Pour ntohs et ntohl

extern int verbose_level;

void analyze_dns(const unsigned char *packet, unsigned int length)
{
    if (length < sizeof(dns_header_t))
    {
        printf("Truncated DNS packet\n");
        return;
    }

    const dns_header_t *dns_hdr = (const dns_header_t *)packet;

    if (verbose_level == 1)
        printf("| DNS ");
    else if (verbose_level == 2)
    {
        printf("DNS Header : ID : %d | Questions : %d | Answer RRs : %d \n", ntohs(dns_hdr->id),
               ntohs(dns_hdr->qdcount), ntohs(dns_hdr->ancount));
    }
    else
    {
        printf("****************** DNS Header ******************\n");
        printf("    |- ID: %u\n", ntohs(dns_hdr->id));
        printf("    |- Flags: %u\n", ntohs(dns_hdr->flags));
        printf("    |- Questions: %u\n", ntohs(dns_hdr->qdcount));
        printf("    |- Answer RRs: %u\n", ntohs(dns_hdr->ancount));
        printf("    |- Authority RRs: %u\n", ntohs(dns_hdr->nscount));
        printf("    |- Additional RRs: %u\n", ntohs(dns_hdr->arcount));
    }
}
