// dns.h

#ifndef DNS_H
#define DNS_H

#include <stdint.h>

// Structure basique pour l'en-tête DNS
struct dns_header {
    uint16_t id;       // Identifiant de requête
    uint16_t flags;    // Drapeaux DNS
    uint16_t qdcount;  // Nombre de questions
    uint16_t ancount;  // Nombre de réponses
    uint16_t nscount;  // Nombre d'autorités
    uint16_t arcount;  // Nombre de ressources supplémentaires
};

void analyze_dns(const unsigned char *packet, unsigned int length);

#endif // DNS_H
