#include "../include/udp.h"
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/udp.h>

extern int verbose_level;

void analyze_udp(const unsigned char *packet) {

    const struct udphdr *udp_header = (const struct udphdr *) packet;
    
    if (verbose_level == 1)
        printf("UDP | ");
    else if (verbose_level == 2)
        printf("UDP Header : Source Port : %d | Destination Port : %d | Length: %d\n", ntohs(udp_header->source), ntohs(udp_header->dest), ntohs(udp_header->len));
    else {
        printf("UDP Segment:\n");
        printf("    |- Source Port: %d\n", ntohs(udp_header->source));
        printf("    |- Destination Port: %d\n", ntohs(udp_header->dest));
        printf("    |- Length: %d\n", ntohs(udp_header->len));
        printf("    |- Checksum: 0x%x\n", ntohs(udp_header->check));
    }
}