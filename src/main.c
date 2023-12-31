#include "../include/packet_capture.h"
#include "../include/arp.h"
#include "../include/ethernet.h"
#include "../include/ip.h"
#include "../include/tcp.h"
#include "../include/udp.h"
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <pcap.h>

int verbose_level = 3;

int main(int argc, char *argv[])
{

    char *interface = NULL;
    char *input_file = NULL;
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    // struct pcap_pkthdr header;
    // const unsigned char *packet;
    int opt;

    while ((opt = getopt(argc, argv, "i:o:v:")) != -1)
    {
        switch (opt)
        {
        case 'i':
            interface = optarg;
            break;
        case 'o':
            input_file = optarg;
            break;
        case 'v':
            verbose_level = atoi(optarg);
            if (verbose_level < 1 || verbose_level > 3)
            {
                fprintf(stderr, "Invalid verbosity level\n");
                exit(EXIT_FAILURE);
            }
            break;
        default: /* '?' */
            fprintf(stderr, "Usage: %s -i <interface>\n", argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    open_output_file(NULL);

    if (interface == NULL && input_file == NULL)
    {
        // Exemple de trame
        // Exemple de trame ICMP (Echo Request)
        uint8_t trame_icmp[] = {
            // En-tête Ethernet
            0x00, 0x1a, 0xa0, 0x02, 0xbf, 0x0e, // Adresse MAC destination
            0x00, 0x18, 0x8b, 0x01, 0x9e, 0x00, // Adresse MAC source
            0x08, 0x00,                         // Type Ethernet (0x0800 pour IP)
            // En-tête IP
            0x45, 0x00, 0x00, 0x54, 0x00, 0x00, 0x40, 0x00, // Version, IHL, Type de service, Longueur totale, Identifiant, Drapeaux, Fragment Offset
            0x40, 0x01, 0xa6, 0x82,                         // TTL, Protocole (ICMP), Checksum
            0xc0, 0xa8, 0x01, 0x02,                         // Adresse IP source
            0xc0, 0xa8, 0x01, 0x01,                         // Adresse IP destination
            // En-tête ICMP (Echo Request)
            0x08, 0x00, // Type et Code (8 pour Echo Request)
            0xf7, 0xff, // Checksum
            0x00, 0x01, // Identifiant
            0x00, 0x01, // Numéro de séquence
            // Données ICMP (optionnel)
            0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
            0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70,
            0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x61,
            0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69};

        uint8_t trame_ip[] = {
            0x00, 0x1a, 0xa0, 0x02, 0xbf, 0x0e, // Adresse MAC destination
            0x00, 0x18, 0x8b, 0x01, 0x9e, 0x00, // Adresse MAC source
            0x08, 0x00,                         // Type Ethernet (0x0800 pour IP)
            // En-tête IP
            0x45,                   // Version et IHL (5*4 = 20 octets)
            0x00,                   // Type de service
            0x00, 0x3c,             // Longueur totale
            0x1c, 0x46,             // Identifiant
            0x40, 0x00,             // Flags et Fragment Offset
            0x40,                   // TTL
            0x06,                   // Protocole (TCP)
            0xa6, 0x2c,             // Somme de contrôle de l'en-tête
            0x0a, 0x00, 0x02, 0x0f, // Adresse IP source
            0xac, 0xd9, 0x01, 0x66  // Adresse IP destination
            // Le reste de la trame contiendrait les données TCP/IP ou autre payload
        };

        uint8_t trame_udp_dns[] = {
            // En-tête Ethernet
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // Adresse MAC destination (fictive)
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // Adresse MAC source (fictive)
            0x08, 0x00,                         // Type: IPv4

            // En-tête IP (simplifié)
            0x45, 0x00, 0x00, 0x3c, 0x1a, 0x2b, 0x00, 0x00, 0x40, 0x11, 0xa6, 0xec,
            0xc0, 0xa8, 0x01, 0x02, // IP source: 192.168.1.2
            0xc0, 0xa8, 0x01, 0x01, // IP destination: 192.168.1.1

            // En-tête UDP
            0xe9, 0x7a, 0x00, 0x35, // Ports source (59770) et destination (53 pour DNS)
            0x00, 0x28, 0x72, 0xb7, // Longueur UDP et somme de contrôle

            // Message DNS
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
            0x00, 0x01, 0x00, 0x01 // Question DNS pour example.com, Type A, Classe IN
        };

        uint8_t trame_arp[] = {
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Destination MAC: Broadcast
            0x00, 0x1a, 0xa0, 0x02, 0xbf, 0x0e, // Source MAC
            0x08, 0x06,                         // Type: ARP (0x0806)
            0x00, 0x01,                         // Hardware type: Ethernet (1)
            0x08, 0x00,                         // Protocol type: IPv4 (0x0800)
            0x06,                               // Hardware size: 6
            0x04,                               // Protocol size: 4
            0x00, 0x01,                         // Opcode: request (1)
            0x00, 0x1a, 0xa0, 0x02, 0xbf, 0x0e, // Sender MAC
            0xc0, 0xa8, 0x01, 0x64,             // Sender IP: 192.168.1.100
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Target MAC: Unknown
            0xc0, 0xa8, 0x01, 0x01              // Target IP: 192.168.1.1
        };

        uint8_t trame_http[] = {
            // En-tête Ethernet (fictif)
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x08, 0x00,

            // En-tête IP (simplifié)
            0x45, 0x00, 0x00, 0x3c, 0x1a, 0x2b, 0x00, 0x00, 0x40, 0x06, 0xa6, 0xec, 0xc0, 0xa8, 0x01, 0x02, 0xc0, 0xa8, 0x01, 0x01,

            // En-tête TCP (simplifié)
            0x00, 0x50, 0x1F, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x20, 0x00, 0x72, 0xb7, 0x00, 0x00,

            // Données HTTP (exemple de requête GET avec un corps de message)
            // "GET /index.html HTTP/1.1\r\nHost: www.example.com\r\nContent-Length: 13\r\n\r\nHello, world!"
            0x47, 0x45, 0x54, 0x20, 0x2f, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x2e, 0x68, 0x74, 0x6d, 0x6c, 0x20,
            0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x0d, 0x0a, 0x48, 0x6f, 0x73, 0x74, 0x3a, 0x20,
            0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x0d,
            0x0a, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x4c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x3a,
            0x20, 0x31, 0x33, 0x0d, 0x0a, 0x0d, 0x0a, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x77, 0x6f,
            0x72, 0x6c, 0x64, 0x21};

        uint8_t trame_ftp[] = {
            // En-tête Ethernet
            0x00, 0x1a, 0xa0, 0x02, 0xbf, 0x0e, // Adresse MAC destination
            0x00, 0x18, 0x8b, 0x01, 0x9e, 0x00, // Adresse MAC source
            0x08, 0x00,                         // Type Ethernet (0x0800 pour IP)
            // En-tête IP (simplifiée, les valeurs spécifiques ne sont pas critiques pour cet exemple)
            0x45, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x40, 0x00, // Version, IHL, Type de service, Longueur totale
            0x40, 0x06, 0x00, 0x00,                         // TTL, Protocole (TCP), Checksum (non calculé)
            0xc0, 0xa8, 0x01, 0x02,                         // Adresse IP source
            0xc0, 0xa8, 0x01, 0x01,                         // Adresse IP destination
            // En-tête TCP (simplifiée, les valeurs spécifiques ne sont pas critiques pour cet exemple)
            0x00, 0x15, 0x00, 0x00, // Ports source et destination (port 21 pour FTP)
            0x00, 0x00, 0x00, 0x00, // Numéro de séquence
            0x00, 0x00, 0x00, 0x00, // Numéro d'acquittement
            0x50, 0x02, 0x20, 0x00, // Taille de l'en-tête, Flags, Fenêtre
            0x00, 0x00, 0x00, 0x00, // Checksum (non calculé), Pointeur urgent
            // Données TCP représentant une commande FTP
            0x55, 0x53, 0x45, 0x52, 0x20,                         // 'USER '
            0x61, 0x6E, 0x6F, 0x6E, 0x79, 0x6D, 0x6F, 0x75, 0x73, // 'anonymous'
            0x0D, 0x0A                                            // '\r\n'

        };

        uint8_t trame_smtp[] = {
            // En-tête Ethernet
            0x00, 0x1a, 0xa0, 0x02, 0xbf, 0x0e, // Adresse MAC destination
            0x00, 0x18, 0x8b, 0x01, 0x9e, 0x00, // Adresse MAC source
            0x08, 0x00,                         // Type Ethernet (0x0800 pour IP)
            // En-tête IP (simplifiée, les valeurs spécifiques ne sont pas critiques pour cet exemple)
            0x45, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x40, 0x00, // Version, IHL, Type de service, Longueur totale
            0x40, 0x06, 0x00, 0x00,                         // TTL, Protocole (TCP), Checksum (non calculé)
            0xc0, 0xa8, 0x01, 0x02,                         // Adresse IP source
            0xc0, 0xa8, 0x01, 0x01,                         // Adresse IP destination
            // En-tête TCP (simplifiée, les valeurs spécifiques ne sont pas critiques pour cet exemple)
            0x00, 0x19, 0x00, 0x00, // Ports source et destination (port 25 pour SMTP)
            0x00, 0x00, 0x00, 0x00, // Numéro de séquence
            0x00, 0x00, 0x00, 0x00, // Numéro d'acquittement
            0x50, 0x02, 0x20, 0x00, // Taille de l'en-tête, Flags, Fenêtre
            0x00, 0x00, 0x00, 0x00, // Checksum (non calculé), Pointeur urgent
            // Données TCP représentant une commande SMTP
            'H', 'E', 'L', 'O', ' ', 'e', 'x', 'a',
            'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
            '\r', '\n'};

        uint8_t trame_pop[] = {
            // En-tête Ethernet
            0x00, 0x1a, 0xa0, 0x02, 0xbf, 0x0e, // Adresse MAC destination
            0x00, 0x18, 0x8b, 0x01, 0x9e, 0x00, // Adresse MAC source
            0x08, 0x00,                         // Type Ethernet (0x0800 pour IP)
            // En-tête IP (simplifiée, les valeurs spécifiques ne sont pas critiques pour cet exemple)
            0x45, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x40, 0x00, // Version, IHL, Type de service, Longueur totale
            0x40, 0x06, 0x00, 0x00,                         // TTL, Protocole (TCP), Checksum (non calculé)
            0xc0, 0xa8, 0x01, 0x02,                         // Adresse IP source
            0xc0, 0xa8, 0x01, 0x01,                         // Adresse IP destination
            // En-tête TCP (simplifiée, les valeurs spécifiques ne sont pas critiques pour cet exemple)
            0x00, 0x6e, 0x00, 0x00, // Ports source et destination (port 110 pour POP)
            0x00, 0x00, 0x00, 0x00, // Numéro de séquence
            0x00, 0x00, 0x00, 0x00, // Numéro d'acquittement
            0x50, 0x02, 0x20, 0x00, // Taille de l'en-tête, Flags, Fenêtre
            0x00, 0x00, 0x00, 0x00, // Checksum (non calculé), Pointeur urgent
            // Données TCP représentant une commande POP
            0x55, 0x53, 0x45, 0x52, 0x20,                         // 'USER '
            0x61, 0x6E, 0x6F, 0x6E, 0x79, 0x6D, 0x6F, 0x75, 0x73, // 'anonymous'
            0x0D, 0x0A                                            // '\r\n'
        };

        uint8_t trame_imap[] = {
            // En-tête Ethernet
            0x00, 0x1a, 0xa0, 0x02, 0xbf, 0x0e, // Adresse MAC destination
            0x00, 0x18, 0x8b, 0x01, 0x9e, 0x00, // Adresse MAC source
            0x08, 0x00,                         // Type Ethernet (0x0800 pour IP)
            // En-tête IP (simplifiée, les valeurs spécifiques ne sont pas critiques pour cet exemple)
            0x45, 0x00, 0x00, 0x5C, 0x00, 0x00, 0x40, 0x00, // Version, IHL, TOS, Longueur totale
            0x40, 0x06, 0x00, 0x00,                         // TTL, Protocole (TCP), Checksum (non calculé)
            0xc0, 0xa8, 0x01, 0x02,                         // Adresse IP source
            0xc0, 0xa8, 0x01, 0x01,                         // Adresse IP destination
            // En-tête TCP (simplifiée, les valeurs spécifiques ne sont pas critiques pour cet exemple)
            0x00, 0x8f, 0x00, 0x00, // Ports source et destination (port 143 pour IMAP)
            0x00, 0x00, 0x00, 0x00, // Numéro de séquence
            0x00, 0x00, 0x00, 0x00, // Numéro d'acquittement
            0x50, 0x02, 0x20, 0x00, // Taille de l'en-tête, Flags, Fenêtre
            0x00, 0x00, 0x00, 0x00, // Checksum (non calculé), Pointeur urgent
            // Données TCP représentant une réponse IMAP
            // "A1 OK [CAPABILITY IMAP4rev1 LITERAL+ ID ENABLE STARTTLS AUTH=PLAIN] Logged in\r\n"
            0x41, 0x31, 0x20, 0x4F, 0x4B, 0x20, 0x5B, 0x43, 0x41, 0x50, 0x41, 0x42, 0x49, 0x4C, 0x49, 0x54,
            0x59, 0x20, 0x49, 0x4D, 0x41, 0x50, 0x34, 0x72, 0x65, 0x76, 0x31, 0x20, 0x4C, 0x49, 0x54, 0x45,
            0x52, 0x41, 0x4C, 0x2B, 0x20, 0x49, 0x44, 0x20, 0x45, 0x4E, 0x41, 0x42, 0x4C, 0x45, 0x20, 0x53,
            0x54, 0x41, 0x52, 0x54, 0x54, 0x4C, 0x53, 0x20, 0x41, 0x55, 0x54, 0x48, 0x3D, 0x50, 0x4C, 0x41,
            0x49, 0x4E, 0x5D, 0x20, 0x4C, 0x6F, 0x67, 0x67, 0x65, 0x64, 0x20, 0x69, 0x6E, 0x0D, 0x0A};

        uint8_t trame_sctp[] = {
            // En-tête Ethernet
            0x00, 0x1a, 0xa0, 0x02, 0xbf, 0x0e, // Adresse MAC destination
            0x00, 0x18, 0x8b, 0x01, 0x9e, 0x00, // Adresse MAC source
            0x08, 0x00,                         // Type Ethernet (0x0800 pour IP)

            // En-tête IP
            0x45, 0x00, 0x00, 0x3c, 0x12, 0x34, 0x40, 0x00, // Version, IHL, Type de service, Longueur totale, Identifiant, Drapeaux, Fragment Offset
            0x40, 0x84, 0x00, 0x00,                         // TTL, Protocole (SCTP), Checksum
            0xc0, 0xa8, 0x01, 0x02,                         // Adresse IP source
            0xc0, 0xa8, 0x01, 0x01,                         // Adresse IP destination

            // En-tête SCTP
            0x1a, 0x2b, 0x3c, 0x4d, // Source Port
            0x4d, 0x3c, 0x2b, 0x1a, // Destination Port
            0xde, 0xad, 0xbe, 0xef, // Verification Tag
            0x00, 0x00, 0x00, 0x00, // Checksum (à calculer)

            // Chunk SCTP (exemple avec un chunk DATA)
            0x00,       // Chunk Type: DATA
            0x03,       // Chunk Flags
            0x00, 0x14, // Chunk Length
            // Données du Chunk DATA (exemple simple)
            0x00, 0x01, 0x00, 0x00, // TSN
            0x00, 0x00, 0x00, 0x01, // Stream Identifier
            0x00, 0x00, 0x00, 0x00, // Stream Sequence Number
            0x00, 0x00, 0x00, 0x00  // Payload Protocol Identifier
        };

        uint8_t trame_ldap[] = {
            // En-tête Ethernet
            0x00, 0x1a, 0xa0, 0x02, 0xbf, 0x0e, // Adresse MAC destination
            0x00, 0x18, 0x8b, 0x01, 0x9e, 0x00, // Adresse MAC source
            0x08, 0x00,                         // Type Ethernet (0x0800 pour IP)
            // En-tête IP (simplifiée, les valeurs spécifiques ne sont pas critiques pour cet exemple)
            0x45, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x40, 0x00, // Version, IHL, Type de service, Longueur totale
            0x40, 0x06, 0x00, 0x00,                         // TTL, Protocole (TCP), Checksum (non calculé)
            0xc0, 0xa8, 0x01, 0x02,                         // Adresse IP source
            0xc0, 0xa8, 0x01, 0x01,                         // Adresse IP destination
            // En-tête TCP (simplifiée, les valeurs spécifiques ne sont pas critiques pour cet exemple)
            0x01, 0x85, 0x01, 0x85, // Ports source et destination (port 389 pour LDAP)
            0x00, 0x00, 0x00, 0x00, // Numéro de séquence
            0x00, 0x00, 0x00, 0x00, // Numéro d'acquittement
            0x50, 0x02, 0x20, 0x00, // Taille de l'en-tête, Flags, Fenêtre
            0x00, 0x00, 0x00, 0x00, // Checksum (non calculé), Pointeur urgent
            // Données TCP représentant une opération LDAP (BIND request)
            // Note : Ceci est un exemple simplifié et les valeurs spécifiques ne sont pas dérivées d'une réelle opération LDAP
            0x30, 0x1c, 0x02, 0x01, 0x01, 0x60, 0x17, 0x02, // Début de l'opération LDAP (BIND request)
            0x01, 0x03, 0x04, 0x0e, 0x63, 0x6e, 0x3d, 0x61, // Suite de l'opération
            0x64, 0x6d, 0x69, 0x6e, 0x80, 0x05, 0x73, 0x65, // Suite de l'opération
            0x63, 0x72, 0x65, 0x74                          // Fin de l'opération (mot de passe 'secret')
        };

        uint8_t trame_telnet[] = {
            // En-tête Ethernet
            0x00, 0x1b, 0xc0, 0x03, 0xdf, 0x1e, // Adresse MAC destination
            0x00, 0x19, 0x8c, 0x02, 0xaf, 0x10, // Adresse MAC source
            0x08, 0x00,                         // Type Ethernet (0x0800 pour IP)
            // En-tête IP (simplifiée)
            0x45, 0x00, 0x00, 0x3c, 0x00, 0x01, 0x40, 0x00, // Version, IHL, Type de service, Longueur totale
            0x40, 0x06, 0x00, 0x00,                         // TTL, Protocole (TCP), Checksum (non calculé)
            0xc0, 0xa8, 0x01, 0x03,                         // Adresse IP source
            0xc0, 0xa8, 0x01, 0x04,                         // Adresse IP destination
            // En-tête TCP (simplifiée)
            0x00, 0x17, 0x00, 0x17, // Ports source et destination (port 23 pour Telnet)
            0x00, 0x00, 0x00, 0x00, // Numéro de séquence
            0x00, 0x00, 0x00, 0x00, // Numéro d'acquittement
            0x50, 0x02, 0x20, 0x00, // Taille de l'en-tête, Flags, Fenêtre
            0x00, 0x00, 0x00, 0x00, // Checksum (non calculé), Pointeur urgent
            // Données Telnet
            0xFF, 0xFB, 0x03,             // IAC, WILL, SUPPRESS GO AHEAD (commande Telnet)
            0x42, 0x6F, 0x6E, 0x6A, 0x6F, // "Bonjo"
            0xFF, 0xFE, 0x18,             // IAC, DON'T, LOGOUT (commande Telnet)
            0x75, 0x72                    // "ur"
        };

        // Déclarer un tableau contenant les trames, puis les analyser
        const uint8_t *trames[] = {trame_ip, trame_udp_dns, trame_arp, trame_icmp, trame_http,
                                   trame_ftp, trame_smtp, trame_pop, trame_imap, trame_sctp,
                                   trame_ldap, trame_telnet};
        for (int i = 0; i < 12; i++)
        {
            printf("Trame %d:\n", i + 1);
            analyze_ethernet(trames[i], sizeof(trame_ip));
            printf("\n");
        }
    }
    else if (interface != NULL)
    {
        start_packet_capture(interface);
    }
    else if (input_file != NULL)
    {
        handle = pcap_open_offline(input_file, errbuf);
        if (handle == NULL)
        {
            fprintf(stderr, "Couldn't open file %s: %s\n", input_file, errbuf);
            exit(EXIT_FAILURE);
        }
        pcap_loop(handle, 0, packet_handler, NULL);
        pcap_close(handle);
    }
    else
    {
        fprintf(stderr, "Invalid number of arguments\n");
        fprintf(stderr, "Usage: %s [-i] <interface> or %s [-o] <output_file>\nExemple: sudo ./packet_analyzer wlp0s20f3\n", argv[0], argv[0]);
        exit(EXIT_FAILURE);
    }

    close_output_file();
    return 0;
}