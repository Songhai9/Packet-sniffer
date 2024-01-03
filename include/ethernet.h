#ifndef ETHERNET_H
#define ETHERNET_H

#include <netinet/if_ether.h>

/**
 * @file ethernet.h
 * @brief Fichier d'en-tête pour le traitement des trames Ethernet.
 *
 * Ce fichier contient les déclarations des fonctions pour analyser les trames Ethernet.
 */

/**
 * @brief Retourne une description textuelle pour le type de protocole Ethernet.
 * 
 * @param ethertype Le type de protocole Ethernet (par exemple, ETHERTYPE_IP).
 * @return La description textuelle du protocole Ethernet.
 */
const char *get_ethertype_description(uint16_t ethertype);

/**
 * @brief Analyse une trame Ethernet et affiche ses informations.
 * 
 * @param packet Le paquet Ethernet à analyser.
 * @param length La longueur du paquet Ethernet.
 */
void analyze_ethernet(const unsigned char *packet, long unsigned int length);

#endif // ETHERNET_H
