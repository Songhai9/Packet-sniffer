// telnet.h

#ifndef TELNET_H
#define TELNET_H

#include <stdint.h>

// Commandes Telnet
#define IAC 255
#define DO 253
#define DONT 254
#define WILL 251
#define WONT 252

// Déclarations des fonctions
void analyze_telnet(const unsigned char *packet, int length);
void parse_telnet_command(const unsigned char *packet, int length);
void handle_telnet_option(uint8_t command, uint8_t option);

#endif // TELNET_H
