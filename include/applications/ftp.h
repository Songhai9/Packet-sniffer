#ifndef FTP_H
#define FTP_H

#include <stdint.h>

typedef struct
{
    int code;         // Le code de réponse FTP
    const char *desc; // La description associée
} ftp_response;

void analyze_ftp(const unsigned char *packet, unsigned int length);

#endif // FTP_H
