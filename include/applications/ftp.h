#ifndef FTP_H
#define FTP_H

#include <stdint.h>

/**
 * @file ftp.h
 * @brief Fichier d'en-tête pour le traitement des paquets FTP.
 *
 * Ce fichier contient les déclarations des structures et fonctions pour analyser les paquets FTP.
 */

/**
 * @struct ftp_response
 * @brief Représente une réponse FTP.
 *
 * @var ftp_response::code
 * Code de réponse FTP.
 * @var ftp_response::desc
 * Description associée au code de réponse.
 */
typedef struct
{
    int code;         // Le code de réponse FTP
    const char *desc; // La description associée
} ftp_response;

void analyze_ftp(const unsigned char *packet, unsigned int length);

#endif // FTP_H
