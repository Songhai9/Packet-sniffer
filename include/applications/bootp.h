#ifndef BOOTP_H
#define BOOTP_H

#include <stdint.h>

/**
 * @file bootp.h
 * @brief Fichier d'en-tête pour le traitement des paquets BOOTP/DHCP.
 *
 * Ce fichier contient la déclaration de la structure pour analyser les paquets BOOTP/DHCP.
 */

/**
 * @struct bootp_t
 * @brief Représente la partie fixe d'un message BOOTP/DHCP.
 *
 * @var bootp_t::op
 * Code opérationnel du message / type de message.
 * @var bootp_t::htype
 * Type d'adresse matérielle.
 * @var bootp_t::hlen
 * Longueur de l'adresse matérielle.
 * @var bootp_t::hops
 * Nombre de sauts.
 * @var bootp_t::xid
 * Identifiant de transaction.
 * @var bootp_t::secs
 * Secondes écoulées.
 * @var bootp_t::flags
 * Drapeaux.
 * @var bootp_t::ciaddr
 * Adresse IP client.
 * @var bootp_t::yiaddr
 * Adresse IP 'votre' (client).
 * @var bootp_t::siaddr
 * Adresse IP du serveur suivant.
 * @var bootp_t::giaddr
 * Adresse IP de l'agent relais.
 * @var bootp_t::chaddr
 * Adresse matérielle client.
 * @var bootp_t::sname
 * Nom d'hôte du serveur.
 * @var bootp_t::file
 * Nom du fichier de démarrage.
 */
typedef struct
{
    uint8_t op;         // Message op code / message type
    uint8_t htype;      // Hardware address type
    uint8_t hlen;       // Hardware address length
    uint8_t hops;       // Hops
    uint32_t xid;       // Transaction ID
    uint16_t secs;      // Seconds elapsed
    uint16_t flags;     // Flags
    uint32_t ciaddr;    // Client IP address
    uint32_t yiaddr;    // 'Your' (client) IP address
    uint32_t siaddr;    // Next server IP address
    uint32_t giaddr;    // Relay agent IP address
    uint8_t chaddr[16]; // Client hardware address
    uint8_t sname[64];  // Server host name
    uint8_t file[128];  // Boot file name
} dhcp_message_t;

// Codes d'option DHCP
#define DHCP_OPTION_SUBNET_MASK 1
#define DHCP_OPTION_ROUTER 3
#define DHCP_OPTION_DNS_SERVER 6
#define DHCP_OPTION_HOSTNAME 12
#define DHCP_OPTION_REQUESTED_IP 50
#define DHCP_OPTION_IP_LEASE_TIME 51
#define DHCP_OPTION_MESSAGE_TYPE 53
#define DHCP_OPTION_SERVER_IDENTIFIER 54
#define DHCP_OPTION_PARAMETER_REQUEST 55
#define DHCP_CLIENT_IDENTIFIER 61
#define DHCP_OPTION_END 255

// Types de messages DHCP
#define DHCP_DISCOVER 1
#define DHCP_OFFER 2
#define DHCP_REQUEST 3
#define DHCP_DECLINE 4
#define DHCP_ACK 5
#define DHCP_NAK 6
#define DHCP_RELEASE 7
#define DHCP_INFORM 8

// Function prototype for DHCP message analysis
void analyze_dhcp(const unsigned char *packet, unsigned int length);

unsigned char *print_bootp_packet(const unsigned char *packet, unsigned int length, unsigned char *options);

#endif // BOOTP_H
