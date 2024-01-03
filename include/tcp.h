#ifndef TCP_H
#define TCP_H

#include <netinet/tcp.h>

/**
 * @file tcp.h
 * @brief Fichier d'en-tête pour le traitement des paquets TCP.
 *
 * Ce fichier contient la déclaration de la fonction pour analyser les paquets TCP.
 */

/**
 * @brief Analyse un paquet TCP et affiche ses informations.
 *
 * @param packet Le paquet TCP à analyser.
 * @param length La longueur du paquet TCP.
 */
void analyze_tcp(const unsigned char *packet, int length);

#endif // TCP_H
