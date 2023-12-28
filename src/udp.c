#include "../include/udp.h"
#include "../include/applications/dns.h"
#include "../include/applications/http.h"
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/udp.h>

extern int verbose_level;

void analyze_udp(const unsigned char *packet) {

    const struct udphdr *udp_header = (const struct udphdr *) packet;
    uint16_t src_port = ntohs(udp_header->source);
    uint16_t dest_port = ntohs(udp_header->dest);
    
    if (verbose_level == 1)
        printf("UDP | ");
    else if (verbose_level == 2)
        printf("UDP Header : Source Port : %d | Destination Port : %d | Length: %d\n", ntohs(udp_header->source), ntohs(udp_header->dest), ntohs(udp_header->len));
    else {
        printf("UDP Segment:\n");
        printf("    |- Source Port: %d\n", src_port);
        printf("    |- Destination Port: %d\n", dest_port);
        printf("    |- Length: %d\n", ntohs(udp_header->len));
        printf("    |- Checksum: 0x%x\n", ntohs(udp_header->check));
    }

    if (src_port == 53 || dest_port == 53) {
        analyze_dns(packet + sizeof(struct udphdr), ntohs(udp_header->len) - sizeof(struct udphdr));
    }

    // Supposons que src_port et dest_port ont été extraits de l'en-tête UDP
    if (src_port == 80 || dest_port == 80) {
        // La charge utile commence après l'en-tête UDP
        const unsigned char *http_payload = packet + sizeof(struct udphdr);
        unsigned int http_payload_length = ntohs(udp_header->len) - sizeof(struct udphdr);
        
        analyze_http(http_payload, http_payload_length);
    }
}