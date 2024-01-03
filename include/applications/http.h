#ifndef HTTP_H
#define HTTP_H

#include <stdint.h>

#define HTTP_MAX_HEADER_SIZE 2048 // Taille maximale de l'en-tête HTTP

/**
 * @file http.h
 * @brief Fichier d'en-tête pour le traitement des paquets HTTP.
 *
 * Ce fichier contient les déclarations des structures et fonctions pour analyser les paquets HTTP.
 */

/**
 * @struct http_request
 * @brief Représente une requête HTTP.
 *
 * @var http_request::method
 * Méthode HTTP (GET, POST, etc.).
 * @var http_request::uri
 * URI demandée.
 * @var http_request::version
 * Version HTTP.
 * @var http_request::headers
 * En-têtes HTTP.
 */
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
