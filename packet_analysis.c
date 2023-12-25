#include "packet_analysis.h"
#include <stdio.h>
#include <arpa/inet.h>  // Ajoutez cette ligne
#include <netinet/tcp.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

// Fonction pour convertir un nombre hexidécimal en décimal
int hex_to_decimal(const char *hex) {
    int len = strlen(hex);
    int base = 1;
    int dec_val = 0;
    for (int i=len-1; i>=0; i--) {
        if (hex[i] >= '0' && hex[i] <= '9') {
            dec_val += (hex[i] - 48) * base;
            base = base * 16;
        }
        else if (hex[i] >= 'A' && hex[i] <= 'F') {
            dec_val += (hex[i] - 55) * base;
            base = base*16;
        }
    }
    return dec_val;
}

char* get_ethertype_name(uint16_t type) {
    switch (type) {
        case ETHERTYPE_IP: return "IPv4";
        case ETHERTYPE_ARP: return "ARP";
        // Ajoutez d'autres types Ethernet si nécessaire
        default: return "Unknown";
    }
}

char* get_ip_protocol_name(uint8_t protocol) {
    switch (protocol) {
        case IPPROTO_TCP: return "TCP";
        case IPPROTO_UDP: return "UDP";
        case IPPROTO_ICMP: return "ICMP";
        // Ajoutez d'autres protocoles IP si nécessaire
        default: return "Unknown";
    }
}

// Fonction pour obtenir une description lisible du type de protocole Ethernet
const char* get_ethertype_description(uint16_t ethertype) {
    switch (ethertype) {
        case ETHERTYPE_IP: return "IPv4 (0x0800)";
        case ETHERTYPE_IPV6: return "IPv6 (0x86DD)";
        case ETHERTYPE_ARP: return "ARP (0x0806)";
        // Ajouter d'autres cas si nécessaire
        default: return "Unknown";
    }
}


void analyze_ethernet(const unsigned char *packet, long unsigned int length) {
    struct ether_header *eth_header = (struct ether_header *) packet;

    // Conversion des adresses MAC en chaînes de caractères pour un affichage lisible
    char src_mac[18], dest_mac[18];
    snprintf(src_mac, sizeof(src_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             eth_header->ether_shost[0], eth_header->ether_shost[1], eth_header->ether_shost[2],
             eth_header->ether_shost[3], eth_header->ether_shost[4], eth_header->ether_shost[5]);
    snprintf(dest_mac, sizeof(dest_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             eth_header->ether_dhost[0], eth_header->ether_dhost[1], eth_header->ether_dhost[2],
             eth_header->ether_dhost[3], eth_header->ether_dhost[4], eth_header->ether_dhost[5]);

    printf("Ethernet Frame:\n");
    printf("   Destination MAC: %s\n", dest_mac);
    printf("   Source MAC: %s\n", src_mac);
    int type = hex_to_decimal(get_ethertype_description(ntohs(eth_header->ether_type)));
    printf("   Type: %d\n", type);

    // Continuer l'analyse en fonction du type de protocole Ethernet
    switch (ntohs(eth_header->ether_type)) {
        case ETHERTYPE_IP:
            analyze_ip(packet + sizeof(struct ether_header), ntohs(eth_header->ether_type));
            break;
        case ETHERTYPE_ARP:
            analyze_arp(packet + sizeof(struct ether_header), length - sizeof(struct ether_header));
            break;
        // Ajouter d'autres cas pour d'autres types de protocoles Ethernet si nécessaire
    }
}


void analyze_ip(const unsigned char *packet, unsigned int length) {
    const struct iphdr *ip_header = (struct iphdr *)packet;
    printf("IP Header:\n");
    printf("    IP Version: %d\n", ip_header->version);
    printf("    IP Header Length: %d bytes\n", ip_header->ihl * 4);
    printf("    Type of Service: %d\n", ip_header->tos);
    printf("    Total Length: %d\n", ntohs(ip_header->tot_len));
    printf("    Identification: %d\n", ntohs(ip_header->id));

    printf("    Flags: %d\n", ntohs(ip_header->frag_off) >> 13);
    printf("    Fragment Offset: %d\n", ntohs(ip_header->frag_off) & 0x1FFF);

    printf("    TTL: %d\n", ip_header->ttl);
    printf("    Protocol: %s\n", get_ip_protocol_name(ip_header->protocol));
    printf("    Header Checksum: %04x\n", ntohs(ip_header->check));

    char source[INET_ADDRSTRLEN];
    char dest[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->saddr), source, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->daddr), dest, INET_ADDRSTRLEN);

    printf("    Source IP: %s\n", source);
    printf("    Destination IP: %s\n", dest);

    // Gérer les options IP si elles sont présentes
    if (ip_header->ihl > 5) {
        printf("IP Options: Present\n");
        // Traiter les options ici si nécessaire
    }

    if (ip_header->protocol == IPPROTO_TCP) {
        analyze_tcp(packet + ip_header->ihl * 4, length - ip_header->ihl * 4);
    }
    if (ip_header->protocol == IPPROTO_UDP) {
        analyze_udp(packet + ip_header->ihl * 4);
    }
}


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

void analyze_udp(const unsigned char *packet) {
    const struct udphdr *udp_header = (const struct udphdr *) packet;

    printf("UDP Segment:\n");
    printf("   Source Port: %d\n", ntohs(udp_header->source));
    printf("   Destination Port: %d\n", ntohs(udp_header->dest));
    printf("   Length: %d\n", ntohs(udp_header->len));
    printf("   Checksum: 0x%x\n", ntohs(udp_header->check));
}