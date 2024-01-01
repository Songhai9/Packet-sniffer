#ifndef BOOTP_H
#define BOOTP_H

#include <stdint.h>
#include <arpa/inet.h> // Pour les fonctions de conversion d'adresse réseau

// Structure de l'en-tête BOOTP/DHCP
typedef struct {
    uint8_t op;       // Message op code / message type
    uint8_t htype;    // Hardware address type
    uint8_t hlen;     // Hardware address length
    uint8_t hops;     // Hops
    uint32_t xid;     // Transaction ID
    uint16_t secs;    // Seconds elapsed
    uint16_t flags;   // Flags
    uint32_t ciaddr;  // Client IP address
    uint32_t yiaddr;  // 'Your' (client) IP address
    uint32_t siaddr;  // Next server IP address
    uint32_t giaddr;  // Relay agent IP address
    uint8_t chaddr[16];   // Client hardware address
    uint8_t sname[64];    // Server host name
    uint8_t file[128];    // Boot file name
    uint8_t vend[];       // Vendor-specific area
} __attribute__((packed)) bootp_dhcp_header;

// Fonctions publiques
void analyze_bootp_dhcp(const unsigned char *packet, unsigned int length);

#endif // BOOTP_H
