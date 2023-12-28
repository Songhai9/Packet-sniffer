#include "http.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

extern int verbose_level;

// Prototypes de fonctions internes
static void parse_http_request(const uint8_t *packet, http_request_t *request);
static void parse_http_response(const uint8_t *packet, http_response_t *response);
static void print_http_body(const uint8_t *body, size_t body_length);

void analyze_http(const uint8_t *packet, unsigned int length) {
    // Vérifier si la taille de la charge utile est suffisante pour contenir une requête ou une réponse HTTP
    if (length < 8) {
        return;
    }

    if (verbose_level == 1)
        printf("HTTP | ");
        
    else if (verbose_level == 2) {
        if (strncmp((const char *)packet, "HTTP", 4) != 0) {
            http_request_t request;
            parse_http_request(packet, &request);
            printf("HTTP Request : Method : %s | URI : %s | Version : %s\n", request.method, request.uri, request.version);
        } else {
            http_response_t response;
            parse_http_response(packet, &response);
            printf("HTTP Response : Version : %s | Status Code : %s | Reason Phrase : %s\n", response.version, response.status_code, response.reason_phrase);
        }
    }

    else if (verbose_level == 3) {
        // Vérifier si c'est une requête ou une réponse (par exemple en cherchant "HTTP" suivi d'un espace et d'une version)
        if (strncmp((const char *)packet, "HTTP", 4) != 0) {
            
            // C'est probablement une requête HTTP
            http_request_t request;
            parse_http_request(packet, &request);
            printf("    |- Request Method: %s\n", request.method);
            printf("    |- Request URI: %s\n", request.uri);
            printf("    |- HTTP Version: %s\n", request.version);
            printf("    |- Headers:\n%s\n", request.headers);

            // Trouver et afficher le corps du message HTTP si présent
            const char *body_start = strstr((const char *)packet, "\r\n\r\n");
            if (body_start) {
                body_start += 4; // Passer la ligne blanche
                const char *content_length_str = strstr((const char *)packet, "Content-Length: ");
                size_t body_length = 0;
                
                if (content_length_str) {
                    content_length_str += strlen("Content-Length: ");
                    body_length = strtol(content_length_str, NULL, 10);
                }

                // Assurez-vous que la longueur du corps ne dépasse pas la longueur de la trame restante
                size_t remaining_length = length - (body_start - (const char *)packet);
                if (body_length > remaining_length) {
                    body_length = remaining_length;
                }

                print_http_body((const uint8_t *)body_start, body_length);
            }

        } else {
            // C'est probablement une réponse HTTP
            http_response_t response;
            parse_http_response(packet, &response);
            printf("    |- HTTP Version: %s\n", response.version);
            printf("    |- Status Code: %s\n", response.status_code);
            printf("    |- Reason Phrase: %s\n", response.reason_phrase);
            printf("    |- Headers:\n%s\n", response.headers);

            // Trouver et afficher le corps du message HTTP si présent
            const char *body_start = strstr((const char *)packet, "\r\n\r\n");
            if (body_start) {
                body_start += 4; // Passer la ligne blanche
                const char *content_length_str = strstr((const char *)packet, "Content-Length: ");
                size_t body_length = 0;
                
                if (content_length_str) {
                    content_length_str += strlen("Content-Length: ");
                    body_length = strtol(content_length_str, NULL, 10);
                }

                // Assurez-vous que la longueur du corps ne dépasse pas la longueur de la trame restante
                size_t remaining_length = length - (body_start - (const char *)packet);
                if (body_length > remaining_length) {
                    body_length = remaining_length;
                }

                print_http_body((const uint8_t *)body_start, body_length);
            }
        }
    }
}

static void parse_http_request(const uint8_t *packet, http_request_t *request) {
    const char *ptr = (const char *)packet;
    // Extraire la méthode, l'URI et la version HTTP de la ligne de requête
    sscanf(ptr, "%s %s %s", request->method, request->uri, request->version);

    // Trouver la fin de la ligne de requête pour passer aux en-têtes
    ptr = strstr(ptr, "\r\n") + 2;
    
    // Copier les en-têtes jusqu'à la ligne blanche
    const char *end_of_headers = strstr(ptr, "\r\n\r\n");
    if (end_of_headers != NULL) {
        size_t headers_length = end_of_headers - ptr;
        if (headers_length < HTTP_MAX_HEADER_SIZE) {
            strncpy(request->headers, ptr, headers_length);
            // Assurez-vous que la chaîne est terminée correctement
            request->headers[headers_length] = '\0';
        }
    }
}


static void parse_http_response(const uint8_t *packet, http_response_t *response) {
    const char *ptr = (const char *)packet;
    // Extraire la version HTTP, le code de statut et la phrase de statut de la ligne de statut
    sscanf(ptr, "%s %s %s", response->version, response->status_code, response->reason_phrase);

    // Trouver la fin de la ligne de statut pour passer aux en-têtes
    ptr = strstr(ptr, "\r\n") + 2;
    
    // Copier les en-têtes jusqu'à la ligne blanche
    const char *end_of_headers = strstr(ptr, "\r\n\r\n");
    if (end_of_headers != NULL) {
        size_t headers_length = end_of_headers - ptr;
        if (headers_length < HTTP_MAX_HEADER_SIZE) {
            strncpy(response->headers, ptr, headers_length);
            // Assurez-vous que la chaîne est terminée correctement
            response->headers[headers_length] = '\0';
        }
    }
}

static void print_http_body(const uint8_t *body, size_t body_length) {
    printf("    |- Body:\n");
    for (size_t i = 0; i < body_length; i++) {
        printf("%c", body[i]);
    }
    printf("\n");
}




