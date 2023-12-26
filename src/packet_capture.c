#include "../include/packet_capture.h"
#include "../include/ethernet.h"
#include <signal.h>
#include <pcap.h>
#include <stdlib.h>

FILE *output_file;

void open_output_file(const char *filename) {
    if (filename == NULL) 
        filename = "../trames.txt";
    
    output_file = fopen(filename, "w");
    if (!output_file) {
        perror("Error opening output file");
        exit(EXIT_FAILURE);
    }
}

void close_output_file() {
    if (fclose(output_file) == EOF) {
        perror("Error closing output file");
        exit(EXIT_FAILURE);
    }
}

void start_packet_capture(char *device) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
        exit(EXIT_FAILURE);
    }

    // Open the output file
    // open_output_file();

    signal(SIGINT, handle_sigint);

    pcap_loop(handle, 0, packet_handler, NULL);

    // Close the output file after pcap_loop ends
    close_output_file();

    pcap_close(handle);
}

void handle_sigint(int sig) {
    (void)(sig);
    printf("\nFin de l'analyse\n");
    exit(0);
}

void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    static bpf_u_int32 count = 0; /* Packet counter */

    // Utilisation de user_data pour éviter un warning
    (void)(user_data);
    
    /* Increment our counter */
    fprintf(output_file, "Packet Count: %u\n", ++count);  /* Print the packet number */
    printf("Packet Count: %u\n", count);  /* Print the packet number */
    fprintf(output_file, "Received Packet Size: %u\n", pkthdr->len);  /* Print packet size */

    // Call the Ethernet analysis function
    analyze_ethernet(packet, pkthdr->len);
    for (bpf_u_int32 i = 0; i < pkthdr->len; i++) {
        fprintf(output_file, "%02x ", packet[i]);
        if (i !=0 && i % 16 == 0) {
            fprintf(output_file, "\n");
        }
    }
    fprintf(output_file, "\n\n");  /* Add a new line to separate each packet in the output */
    printf("\n\n");  /* Add a new line to separate each packet in the output */
}
