#ifndef HTTP_H
#define HTTP_H

#include <stdint.h>

#define HTTP_MAX_HEADER_SIZE 2048 // Taille maximale de l'en-tête HTTP

typedef struct http_request
{
    char method[8];                     // Méthode HTTP (GET, POST, etc.)
    char uri[1024];                     // URI demandée
    char version[16];                   // Version HTTP
    char headers[HTTP_MAX_HEADER_SIZE]; // En-têtes HTTP
} http_request_t;

typedef struct http_response
{
    char version[16];                   // Version HTTP
    char status_code[4];                // Code de statut
    char reason_phrase[128];            // Phrase de statut
    char headers[HTTP_MAX_HEADER_SIZE]; // En-têtes HTTP
} http_response_t;

void analyze_http(const uint8_t *packet, unsigned int length);

#endif // HTTP_H
