// dns.c

#include "../include/applications/dns.h"
#include <stdio.h>
#include <arpa/inet.h>

extern int verbose_level;

void analyze_dns(const unsigned char *packet, unsigned int length) {
    const struct dns_header *dns = (struct dns_header *)packet;

    if (length < sizeof(struct dns_header)) {
        printf("Truncated DNS packet\n");
        return;
    }

    if (verbose_level == 1) {
        printf("DNS | ");
    } 
    else if (verbose_level == 2) {
        printf("DNS: ID : %d | Number questions : %d | Number answers %d", ntohs(dns->id),
         ntohs(dns->qdcount), ntohs(dns->ancount));
    } 
    else {
        printf("DNS Packet:\n");
        printf("    |- ID: %d\n", ntohs(dns->id));
        printf("    |- Flags: 0x%04x\n", ntohs(dns->flags));
        printf("    |- Number questions: %d\n", ntohs(dns->qdcount));
        printf("    |- Number answers: %d\n", ntohs(dns->ancount));
        printf("    |- Authority RRs: %d\n", ntohs(dns->nscount));
        printf("    |- Additional RRs: %d\n", ntohs(dns->arcount));
    }
        
}
