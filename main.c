#include "packet_capture.h"
#include "packet_analysis.h"

int main(int argc, char *argv[]) {
    if (argc == 1) {
        // Exemple de trame
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

        uint8_t trame_udp[] = {
            0x52, 0x54, 0x00, 0x12, 0x35, 0x02, // Destination MAC
            0x08, 0x00, 0x27, 0x13, 0x37, 0x57, // Source MAC
            0x08, 0x00, // Type: IPv4 (0x0800)
            0x45, 0x00, // IP version and header length, Type of service
            0x00, 0x3c, // Total length
            0x66, 0x6c, // Identification
            0x40, 0x00, // Flags and fragment offset
            0x40, 0x11, // TTL, Protocol (UDP)
            0xb3, 0x97, // Header checksum
            0xc0, 0xa8, 0x00, 0x02, // Source IP
            0xc0, 0xa8, 0x00, 0x01, // Destination IP
            0xe0, 0x8a, // Source port
            0x00, 0x35, // Destination port (DNS)
            0x00, 0x28, // Length
            0x11, 0x31, // Checksum
            // Data (DNS query)
            0x2d, 0x2e, 0x1a, 0x01, 0x00, 0x00, 0x01, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 
            0x77, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 
            0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01
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

       // Déclarer un tableau contenant les trames, puis les analyser
        const uint8_t *trames[] = {trame_ip, trame_udp,trame_arp};
        for (int i = 0; i < 3; i++) {
            printf("Trame %d:\n", i + 1);
            analyze_ethernet(trames[i], sizeof(trame_ip));
            printf("\n");
        }
    }
    else if (argc == 2) {
        start_packet_capture(argv[1]);
    }
    else {
        fprintf(stderr, "Invalid number of arguments\n");
        fprintf(stderr, "Usage: %s <interface> or %s\nExemple: sudo ./packet_analyzer wlp0s20f3\n", argv[0], argv[0]);
        exit(EXIT_FAILURE);
    }

    

    return 0;
}
