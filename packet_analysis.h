#ifndef PACKET_ANALYSIS_H
#define PACKET_ANALYSIS_H

#include <pcap/pcap.h>
#include <netinet/if_ether.h>  // Pour l'en-tête Ethernet
#include <net/ethernet.h>
#include <netinet/ip.h>  // Pour l'en-tête IP
#include <netinet/udp.h>  // Nécessaire pour la structure udphdr
#include <netinet/tcp.h>
#include <arpa/inet.h>        // For inet_ntoa()

// Fonction pour convertir un nombre hexidécimal en décimal
int hex_to_decimal(const char hex[]);

// Fonctions pour analyser la couche Ethernet
const char* get_ethertype_description(uint16_t ethertype);
void analyze_ethernet(const unsigned char *packet, long unsigned int length);

// Fonctions pour analyser la couche IP
void analyze_ip(const unsigned char *packet, unsigned int length);
void analyze_tcp(const unsigned char *packet, int total_length);
void analyze_udp(const unsigned char *packet);
void analyze_arp(const unsigned char *packet, long unsigned int length);


#endif // PACKET_ANALYSIS_H
