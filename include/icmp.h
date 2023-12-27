// icmp.h

#ifndef ICMP_H
#define ICMP_H

#include <netinet/ip_icmp.h>

void analyze_icmp(const unsigned char *packet, unsigned int length);

#endif // ICMP_H
