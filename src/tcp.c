#include "../include/tcp.h"
#include "../include/applications/dns.h"
#include <netinet/ip.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

extern int verbose_level;

void analyze_tcp(const unsigned char *packet, int length) {
    const struct tcphdr *tcp_header = (const struct tcphdr *)packet;
    (void)length;

    uint16_t src_port = ntohs(tcp_header->source);
    uint16_t dest_port = ntohs(tcp_header->dest);

    if (verbose_level == 1)
        printf("TCP | ");
    else if (verbose_level == 2)
        printf("TCP Header : Source Port : %d | Destination Port : %d\n", ntohs(tcp_header->source), ntohs(tcp_header->dest));
    else {
        printf("TCP Segment:\n");
        printf("    |- Source Port: %d\n", src_port);
        printf("    |- Destination Port: %d\n", dest_port);
        printf("    |- Sequence Number: %u\n", ntohl(tcp_header->seq));
        printf("    |- Acknowledgment Number: %u\n", ntohl(tcp_header->ack_seq));
        printf("    |- Header Length: %d bytes\n", tcp_header->doff * 4);
        printf("    |- Flags: %c%c%c%c%c%c\n",
            (tcp_header->urg ? 'U' : '.'),
            (tcp_header->ack ? 'A' : '.'),
            (tcp_header->psh ? 'P' : '.'),
            (tcp_header->rst ? 'R' : '.'),
            (tcp_header->syn ? 'S' : '.'),
            (tcp_header->fin ? 'F' : '.'));
        printf("    |- Window Size: %d\n", ntohs(tcp_header->window));
        printf("    |- Checksum: 0x%04x\n", ntohs(tcp_header->check));
        printf("    |- Urgent Pointer: %d\n", tcp_header->urg_ptr);
    }

    if (src_port == 53 || dest_port == 53) {
        analyze_dns(packet + tcp_header->doff * 4, length - tcp_header->doff * 4);
    }

}