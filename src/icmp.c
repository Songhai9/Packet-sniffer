// icmp.c

#include "../include/icmp.h"
#include <stdio.h>

extern int verbose_level;

void analyze_icmp(const unsigned char *packet, unsigned int length) {
    const struct icmphdr *icmp_header = (struct icmphdr *)packet;

    if (length < sizeof(struct icmphdr)) {
        printf("Truncated ICMP packet\n");
        return;
    }

    if (verbose_level == 1) {
        printf("ICMP | ");
    } else if (verbose_level == 2) {
        printf("ICMP: Type %d | Code %d | ", icmp_header->type, icmp_header->code);
    } else {
        printf("ICMP Packet:\n");
        printf("    |- Type: %d\n", icmp_header->type);
        printf("    |- Code: %d\n", icmp_header->code);
        printf("    |- Checksum: 0x%04x\n", ntohs(icmp_header->checksum));
    }
}
