#ifndef SMTP_H
#define SMTP_H

#include <stdint.h>

/**
 * @file smtp.h
 * @brief Fichier d'en-tête pour le traitement des paquets SMTP.
 *
 * Ce fichier contient les déclarations des fonctions pour analyser les paquets SMTP,
 * ainsi que la structure pour représenter les réponses SMTP.
 */

/**
 * @struct smtp_response
 * @brief Représente une réponse SMTP.
 *
 * @var smtp_response::code
 * Code de réponse SMTP.
 * @var smtp_response::desc
 * Description associée au code de réponse.
 */
typedef struct
{
    int code;         // Le code de réponse SMTP
    const char *desc; // La description associée
} smtp_response;

/**
 * @brief Analyse un paquet SMTP et affiche ses informations.
 * 
 * @param packet Le paquet SMTP à analyser.
 * @param length La longueur du paquet SMTP.
 */
void analyze_smtp(const unsigned char *packet, unsigned int length);

#endif // SMTP_H
