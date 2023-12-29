#ifndef SMTP_H
#define SMTP_H

#include <stdint.h>

void analyze_smtp(const unsigned char *packet, unsigned int length);

#endif // SMTP_H
