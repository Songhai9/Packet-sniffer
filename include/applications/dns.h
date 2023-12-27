#ifndef DNS_H
#define DNS_H

#include <stdint.h>

// Structure de l'en-tête DNS
typedef struct {
    uint16_t id;       // Identifiant
    uint16_t flags;    // Drapeaux
    uint16_t qdcount;  // Nombre de questions
    uint16_t ancount;  // Nombre de réponses
    uint16_t nscount;  // Nombre d'enregistrements d'autorité
    uint16_t arcount;  // Nombre d'enregistrements supplémentaires
} dns_header_t;

// Structure d'une question DNS
typedef struct {
    // Le nom et le type seront traités dynamiquement dans le code
    uint16_t type;     // Type
    uint16_t class;    // Classe
} dns_question_t;

// Prototypes de fonctions
void analyze_dns(const unsigned char *packet, unsigned int length);

#endif // DNS_H
