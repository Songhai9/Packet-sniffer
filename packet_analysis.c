#include "packet_analysis.h"
#include <stdio.h>
#include <arpa/inet.h>  // Ajoutez cette ligne

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




void analyze_ethernet(const unsigned char *packet) {
    struct ether_header *eth_header = (struct ether_header *) packet;

    // Imprimer l'adresse MAC source et destination
    printf("MAC Source: %02x:%02x:%02x:%02x:%02x:%02x\n", 
        eth_header->ether_shost[0], eth_header->ether_shost[1], 
        eth_header->ether_shost[2], eth_header->ether_shost[3], 
        eth_header->ether_shost[4], eth_header->ether_shost[5]);

    printf("MAC Destination: %02x:%02x:%02x:%02x:%02x:%02x\n", 
        eth_header->ether_dhost[0], eth_header->ether_dhost[1], 
        eth_header->ether_dhost[2], eth_header->ether_dhost[3], 
        eth_header->ether_dhost[4], eth_header->ether_dhost[5]);

    // Imprimer le type de protocole Ethernet
    printf("Ethernet Type: %s\n", get_ethertype_name(ntohs(eth_header->ether_type)));

    // Analyser le protocole de la couche suivante
    switch (ntohs(eth_header->ether_type)) {
        case ETHERTYPE_IP:
            analyze_ip(packet + sizeof(struct ether_header), ntohs(eth_header->ether_type));
            break;
        // Ajoutez d'autres cas pour d'autres protocoles si nécessaire
    }
}



void analyze_ip(const unsigned char *packet, int length) {
    (void)(length);  // Pour éviter un warning (unused parameter
    struct ip *ip_header = (struct ip *)packet;
    
    // Afficher l'adresse IP source et de destination
    printf("IP Source: %s\n", inet_ntoa(ip_header->ip_src));
    printf("IP Destination: %s\n", inet_ntoa(ip_header->ip_dst));

    // Imprimer le protocole IP
    printf("IP Protocol: %s\n", get_ip_protocol_name(ip_header->ip_p));

    // Vous pouvez également afficher d'autres champs de l'en-tête IP si nécessaire
}