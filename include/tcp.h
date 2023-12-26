#ifndef TCP_H
#define TCP_H

#include <netinet/tcp.h>

void analyze_tcp(const unsigned char *packet, int length);

#endif // TCP_H
