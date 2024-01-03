#ifndef ARP_H
#define ARP_H


/**
 * @file arp.h
 * @brief Fichier d'en-tête pour le traitement des paquets ARP.
 *
 * Ce fichier contient la déclaration de la fonction pour analyser les paquets ARP.
 */

/**
 * @brief Analyse un paquet ARP et affiche ses informations.
 * 
 * @param packet Le paquet ARP à analyser.
 * @param length La longueur du paquet ARP.
 */
void analyze_arp(const unsigned char *packet, long unsigned int length);

#endif // ARP_H
