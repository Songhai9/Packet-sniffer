// icmp.h

#ifndef ICMP_H
#define ICMP_H

#include <netinet/ip_icmp.h>

/**
 * @file icmp.h
 * @brief Fichier d'en-tête pour le traitement des paquets ICMP.
 *
 * Ce fichier contient la déclaration de la fonction pour analyser les paquets ICMP.
 */

/**
 * @brief Analyse un paquet ICMP et affiche ses informations.
 * 
 * @param packet Le paquet ICMP à analyser.
 * @param length La longueur du paquet ICMP.
 */
void analyze_icmp(const unsigned char *packet, unsigned int length);

#endif // ICMP_H
