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
            0x52, 0x54, 0x00, 0x12, 0x35, 0x02, 0x08, 0x00, 0x27, 0x13, 0x37, 0x57, 0x08, 0x00, 0x45, 0x00,
            0x00, 0x3c, 0x66, 0x6c, 0x40, 0x00, 0x40, 0x11, 0xb3, 0x97, 0xc0, 0xa8, 0x00, 0x02, 0xc0, 0xa8,
            0x00, 0x01, 0xe0, 0x8a, 0x00, 0x35, 0x00, 0x28, 0x11, 0x31, 0x2d, 0x2e, 0x1a, 0x01, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77, 0x06, 0x67, 0x6f, 0x6f, 0x67,
            0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01
        };
       // Déclarer un tableau contenant les trames, puis les analyser
        const uint8_t *trames[] = {trame_ip, trame_udp};
        for (int i = 0; i < 2; i++) {
            printf("Trame %d:\n", i + 1);
            analyze_ethernet(trames[i]);
            printf("\n");
        }
    }
    else if (argc == 2) {
        start_packet_capture(argv[1]);
    }
    else {
        fprintf(stderr, "Usage: %s <device>\nExemple: sudo ./packet_analyzer wlp0s20f3\n\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    

    return 0;
}
