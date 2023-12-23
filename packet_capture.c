#include "packet_capture.h"
#include "packet_analysis.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

FILE *output_file;



void open_output_file() {
    output_file = fopen("trames.txt", "w");
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

void handle_sigint(int sig) {
    (void)(sig);
    printf("\nFin de l'analyse\n");
    close_output_file();  // Fermez le fichier de sortie
    exit(0);
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
    open_output_file();

    signal(SIGINT, handle_sigint);

    pcap_loop(handle, 0, packet_handler, NULL);

    // Close the output file after pcap_loop ends
    close_output_file();

    pcap_close(handle);
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

void analyze_arp(const unsigned char *packet, long unsigned int length) {
    struct arphdr *arp_header = (struct arphdr *) packet;

    if (length < sizeof(struct arphdr)) {
        printf("Truncated ARP packet\n");
        return;
    }

    printf("ARP Packet:\n");
    printf("  Hardware Type: %s (%d)\n", 
        (ntohs(arp_header->ar_hrd) == ARPHRD_ETHER) ? "Ethernet" : "Unknown", ntohs(arp_header->ar_hrd));
    printf("  Protocol Type: %04x\n", ntohs(arp_header->ar_pro));
    printf("  Hardware Size: %d\n", arp_header->ar_hln);
    printf("  Protocol Size: %d\n", arp_header->ar_pln);
    printf("  Opcode: %s (%d)\n", 
        (ntohs(arp_header->ar_op) == ARPOP_REQUEST) ? "Request" : "Reply", ntohs(arp_header->ar_op));

    // Pointers to addresses
    unsigned char *sender_mac = (unsigned char *)(packet + sizeof(struct arphdr));
    unsigned char *sender_ip = (unsigned char *)(packet + sizeof(struct arphdr) + arp_header->ar_hln);
    unsigned char *target_mac = (unsigned char *)(packet + sizeof(struct arphdr) + arp_header->ar_hln + arp_header->ar_pln);
    unsigned char *target_ip = (unsigned char *)(packet + sizeof(struct arphdr) + 2 * arp_header->ar_hln + arp_header->ar_pln);

    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, sender_ip, ip_str, INET_ADDRSTRLEN);
    printf("  Sender MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
        sender_mac[0], sender_mac[1], sender_mac[2], sender_mac[3], sender_mac[4], sender_mac[5]);
    printf("  Sender IP: %s\n", ip_str);

    inet_ntop(AF_INET, target_ip, ip_str, INET_ADDRSTRLEN);
    printf("  Target MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
        target_mac[0], target_mac[1], target_mac[2], target_mac[3], target_mac[4], target_mac[5]);
    printf("  Target IP: %s\n", ip_str);
}
