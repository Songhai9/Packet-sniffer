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

int main(int argc, char *argv[]) {

    char *interface = NULL;
    char *input_file = NULL;
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    // struct pcap_pkthdr header;
    // const unsigned char *packet;
    int opt;

    while ((opt = getopt(argc, argv, "i:o:v:")) != -1) {
        switch (opt) {
            case 'i':
                interface = optarg;
                break;
            case 'o':
                input_file = optarg;
                break;
            case 'v':
                verbose_level = atoi(optarg);
                if (verbose_level < 1 || verbose_level > 3) {
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

    if (interface == NULL && input_file == NULL) {
        // Exemple de trame
        // Exemple de trame ICMP (Echo Request)
        uint8_t trame_icmp[] = {
            // En-tête Ethernet
            0x00, 0x1a, 0xa0, 0x02, 0xbf, 0x0e, // Adresse MAC destination
            0x00, 0x18, 0x8b, 0x01, 0x9e, 0x00, // Adresse MAC source
            0x08, 0x00,                         // Type Ethernet (0x0800 pour IP)
            // En-tête IP
            0x45, 0x00, 0x00, 0x54, 0x00, 0x00, 0x40, 0x00, // Version, IHL, Type de service, Longueur totale, Identifiant, Drapeaux, Fragment Offset
            0x40, 0x01, 0xa6, 0x82, // TTL, Protocole (ICMP), Checksum
            0xc0, 0xa8, 0x01, 0x02, // Adresse IP source
            0xc0, 0xa8, 0x01, 0x01, // Adresse IP destination
            // En-tête ICMP (Echo Request)
            0x08, 0x00, // Type et Code (8 pour Echo Request)
            0xf7, 0xff, // Checksum
            0x00, 0x01, // Identifiant
            0x00, 0x01, // Numéro de séquence
            // Données ICMP (optionnel)
            0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
            0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70,
            0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x61,
            0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69
        };

        uint8_t trame_ip[] = {
            0x00, 0x1a, 0xa0, 0x02, 0xbf, 0x0e, // Adresse MAC destination
            0x00, 0x18, 0x8b, 0x01, 0x9e, 0x00, // Adresse MAC source
            0x08, 0x00,                         // Type Ethernet (0x0800 pour IP)
            // En-tête IP
            0x45,                               // Version et IHL (5*4 = 20 octets)
            0x00,                               // Type de service
            0x00, 0x3c,                         // Longueur totale
            0x1c, 0x46,                         // Identifiant
            0x40, 0x00,                         // Flags et Fragment Offset
            0x40,                               // TTL
            0x06,                               // Protocole (TCP)
            0xa6, 0x2c,                         // Somme de contrôle de l'en-tête
            0x0a, 0x00, 0x02, 0x0f,             // Adresse IP source
            0xac, 0xd9, 0x01, 0x66              // Adresse IP destination
            // Le reste de la trame contiendrait les données TCP/IP ou autre payload
        };

        uint8_t trame_udp_dns[] = {
            // En-tête Ethernet
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,  // Adresse MAC destination (fictive)
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66,  // Adresse MAC source (fictive)
            0x08, 0x00,                           // Type: IPv4

            // En-tête IP (simplifié)
            0x45, 0x00, 0x00, 0x3c, 0x1a, 0x2b, 0x00, 0x00, 0x40, 0x11, 0xa6, 0xec,
            0xc0, 0xa8, 0x01, 0x02,  // IP source: 192.168.1.2
            0xc0, 0xa8, 0x01, 0x01,  // IP destination: 192.168.1.1

            // En-tête UDP
            0xe9, 0x7a, 0x00, 0x35,  // Ports source (59770) et destination (53 pour DNS)
            0x00, 0x28, 0x72, 0xb7,  // Longueur UDP et somme de contrôle

            // Message DNS
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
            0x00, 0x01, 0x00, 0x01  // Question DNS pour example.com, Type A, Classe IN
        };



        uint8_t trame_arp[] = {
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Destination MAC: Broadcast
            0x00, 0x1a, 0xa0, 0x02, 0xbf, 0x0e, // Source MAC
            0x08, 0x06, // Type: ARP (0x0806)
            0x00, 0x01, // Hardware type: Ethernet (1)
            0x08, 0x00, // Protocol type: IPv4 (0x0800)
            0x06, // Hardware size: 6
            0x04, // Protocol size: 4
            0x00, 0x01, // Opcode: request (1)
            0x00, 0x1a, 0xa0, 0x02, 0xbf, 0x0e, // Sender MAC
            0xc0, 0xa8, 0x01, 0x64, // Sender IP: 192.168.1.100
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Target MAC: Unknown
            0xc0, 0xa8, 0x01, 0x01  // Target IP: 192.168.1.1
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
            0x72, 0x6c, 0x64, 0x21
        };


       // Déclarer un tableau contenant les trames, puis les analyser
        const uint8_t *trames[] = {trame_ip, trame_udp_dns, trame_arp, trame_icmp, trame_http};
        for (int i = 0; i < 5; i++) {
            printf("Trame %d:\n", i + 1);
            analyze_ethernet(trames[i], sizeof(trame_ip));
            printf("\n");
        }
    }
    else if (interface != NULL){
        start_packet_capture(interface);
    }
    else if (input_file != NULL){
        handle = pcap_open_offline(input_file, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Couldn't open file %s: %s\n", input_file, errbuf);
            exit(EXIT_FAILURE);
        }
        pcap_loop(handle, 0, packet_handler, NULL);
        pcap_close(handle);
    }
    else {
        fprintf(stderr, "Invalid number of arguments\n");
        fprintf(stderr, "Usage: %s [-i] <interface> or %s [-o] <output_file>\nExemple: sudo ./packet_analyzer wlp0s20f3\n", argv[0], argv[0]);
        exit(EXIT_FAILURE);
    }
    
    close_output_file();
    return 0;
}