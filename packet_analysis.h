#ifndef PACKET_ANALYSIS_H
#define PACKET_ANALYSIS_H

#include <netinet/if_ether.h>  // Pour l'en-tête Ethernet
#include <net/ethernet.h>
#include <netinet/ip.h>  // Pour l'en-tête IP

// Fonction pour analyser la couche Ethernet
void analyze_ethernet(const unsigned char *packet);
// Fonction pour analyser la couche IP
void analyze_ip(const unsigned char *packet, int length);

#endif // PACKET_ANALYSIS_H
