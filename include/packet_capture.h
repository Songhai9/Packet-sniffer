#ifndef PACKET_CAPTURE_H
#define PACKET_CAPTURE_H

#include <pcap.h>

void start_packet_capture(char *device);
void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet);
void handle_sigint(int sig);
void open_output_file(const char *filename);
void close_output_file();

#endif // PACKET_CAPTURE_H
