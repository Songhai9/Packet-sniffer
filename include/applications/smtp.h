#ifndef SMTP_H
#define SMTP_H

#include <stdint.h>

typedef struct {
    int code;          // Le code de réponse SMTP
    const char *desc;  // La description associée
} smtp_response;

// Prototype de la fonction d'analyse SMTP
void analyze_smtp(const unsigned char *packet, unsigned int length);

#endif // SMTP_H
