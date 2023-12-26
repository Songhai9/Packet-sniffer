#include "../include/ethernet.h"
#include "../include/ip.h"
#include "../include/arp.h"
#include <stdio.h>
#include <netinet/if_ether.h>

extern int verbose_level;

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

    if (verbose_level == 1)
        printf("Ethernet | ");
    else if (verbose_level == 2) {
        printf("Ethernet Header: Destination MAC : %s | Source MAC : %s\n", dest_mac, src_mac);
    }
    else {
        printf("Ethernet Header:\n");
        printf("    |-Mac MAC: %s\n", dest_mac);
        printf("    |-Mac MAC: %s\n", src_mac);
        printf("    |-Protocol: %s\n", get_ethertype_description(ntohs(eth_header->ether_type)));
    }

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
