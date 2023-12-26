#ifndef ETHERNET_H
#define ETHERNET_H

#include <netinet/if_ether.h>

const char* get_ethertype_description(uint16_t ethertype);
void analyze_ethernet(const unsigned char *packet, long unsigned int length);

#endif // ETHERNET_H
