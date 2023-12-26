#include "../include/tcp.h"
#include <netinet/ip.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

void analyze_tcp(const unsigned char *packet, int length) {
    const struct tcphdr *tcp_header = (const struct tcphdr *)packet;
    (void)length;
    printf("TCP Segment:\n");
    printf("   Source Port: %d\n", ntohs(tcp_header->source));
    printf("   Destination Port: %d\n", ntohs(tcp_header->dest));
    printf("   Sequence Number: %u\n", ntohl(tcp_header->seq));
    printf("   Acknowledgment Number: %u\n", ntohl(tcp_header->ack_seq));
    printf("   Header Length: %d bytes\n", tcp_header->doff * 4);
    printf("   Flags: %c%c%c%c%c%c\n",
           (tcp_header->urg ? 'U' : '.'),
           (tcp_header->ack ? 'A' : '.'),
           (tcp_header->psh ? 'P' : '.'),
           (tcp_header->rst ? 'R' : '.'),
           (tcp_header->syn ? 'S' : '.'),
           (tcp_header->fin ? 'F' : '.'));
    printf("   Window Size: %d\n", ntohs(tcp_header->window));
    printf("   Checksum: 0x%04x\n", ntohs(tcp_header->check));
    printf("   Urgent Pointer: %d\n", tcp_header->urg_ptr);

    // Gestion de la longueur des données TCP (si nécessaire)
    // int tcp_data_length = length - (tcp_header->doff * 4);

}