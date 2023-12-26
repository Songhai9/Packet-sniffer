#ifndef IP_H
#define IP_H

#include <netinet/ip.h>

char* get_ip_protocol_name(uint8_t protocol);
void analyze_ip(const unsigned char *packet, unsigned int length);

#endif // IP_H
