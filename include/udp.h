#ifndef UDP_H
#define UDP_H

#include <netinet/udp.h>

/**
 * @file udp.h
 * @brief Fichier d'en-tête pour le traitement des paquets UDP.
 *
 * Ce fichier contient la déclaration de la fonction pour analyser les paquets UDP.
 */

/**
 * @brief Analyse un paquet UDP et affiche ses informations.
 *
 * @param packet Le paquet UDP à analyser.
 */
void analyze_udp(const unsigned char *packet);

#endif // UDP_H
