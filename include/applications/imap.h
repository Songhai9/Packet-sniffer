#ifndef IMAP_H
#define IMAP_H

#include <stdint.h>

/**
 * @file imap.h
 * @brief Fichier d'en-tête pour le traitement des paquets IMAP.
 *
 * Ce fichier contient la déclaration de la fonction pour analyser les paquets IMAP.
 */

/**
 * @brief Analyse un paquet IMAP et affiche ses informations.
 * 
 * @param packet Le paquet IMAP à analyser.
 * @param length La longueur du paquet IMAP.
 */
void analyze_imap(const unsigned char *packet, unsigned int length);

#endif // IMAP_H
