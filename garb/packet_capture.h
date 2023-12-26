#ifndef PACKET_CAPTURE_H
#define PACKET_CAPTURE_H

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

// Structure to hold packet info (if needed)
typedef struct {
    // Add fields as necessary
} packet_info;

// Function to start packet capturing
void start_packet_capture(char *device);

// Callback function to handle captured packets
void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet);




#endif // PACKET_CAPTURE_H
