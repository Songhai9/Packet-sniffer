#include "../include/arp.h"
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

void analyze_arp(const unsigned char *packet, long unsigned int length) {
    struct arphdr *arp_header = (struct arphdr *) packet;

    if (length < sizeof(struct arphdr)) {
        printf("Truncated ARP packet\n");
        return;
    }

    printf("ARP Packet:\n");
    printf("  Hardware Type: %s (%d)\n", 
        (ntohs(arp_header->ar_hrd) == ARPHRD_ETHER) ? "Ethernet" : "Unknown", ntohs(arp_header->ar_hrd));
    printf("  Protocol Type: %04x\n", ntohs(arp_header->ar_pro));
    printf("  Hardware Size: %d\n", arp_header->ar_hln);
    printf("  Protocol Size: %d\n", arp_header->ar_pln);
    printf("  Opcode: %s (%d)\n", 
        (ntohs(arp_header->ar_op) == ARPOP_REQUEST) ? "Request" : "Reply", ntohs(arp_header->ar_op));

    // Pointers to addresses
    unsigned char *sender_mac = (unsigned char *)(packet + sizeof(struct arphdr));
    unsigned char *sender_ip = (unsigned char *)(packet + sizeof(struct arphdr) + arp_header->ar_hln);
    unsigned char *target_mac = (unsigned char *)(packet + sizeof(struct arphdr) + arp_header->ar_hln + arp_header->ar_pln);
    unsigned char *target_ip = (unsigned char *)(packet + sizeof(struct arphdr) + 2 * arp_header->ar_hln + arp_header->ar_pln);

    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, sender_ip, ip_str, INET_ADDRSTRLEN);
    printf("  Sender MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
        sender_mac[0], sender_mac[1], sender_mac[2], sender_mac[3], sender_mac[4], sender_mac[5]);
    printf("  Sender IP: %s\n", ip_str);

    inet_ntop(AF_INET, target_ip, ip_str, INET_ADDRSTRLEN);
    printf("  Target MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
        target_mac[0], target_mac[1], target_mac[2], target_mac[3], target_mac[4], target_mac[5]);
    printf("  Target IP: %s\n", ip_str);
}
