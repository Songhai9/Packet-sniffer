#include "../include/udp.h"
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/udp.h>

void analyze_udp(const unsigned char *packet) {

    const struct udphdr *udp_header = (const struct udphdr *) packet;

    printf("UDP Segment:\n");
    printf("   Source Port: %d\n", ntohs(udp_header->source));
    printf("   Destination Port: %d\n", ntohs(udp_header->dest));
    printf("   Length: %d\n", ntohs(udp_header->len));
    printf("   Checksum: 0x%x\n", ntohs(udp_header->check));
}