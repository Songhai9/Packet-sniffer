#ifndef IP_H
#define IP_H

#include <netinet/ip.h>


/**
 * @file ip.h
 * @brief Fichier d'en-tête pour le traitement des paquets IP.
 *
 * Ce fichier contient les déclarations des fonctions pour analyser les paquets IP.
 */

/**
 * @brief Retourne le nom du protocole IP en fonction de son identifiant.
 * 
 * @param protocol Identifiant du protocole IP (par exemple, IPPROTO_TCP).
 * @return Le nom du protocole IP sous forme de chaîne de caractères.
 */

const char *get_ip_protocol_name(uint8_t protocol);


/**
 * @brief Analyse un paquet IP et affiche ses informations.
 * 
 * @param packet Le paquet IP à analyser.
 * @param length La longueur du paquet IP.
 */

void analyze_ip(const unsigned char *packet, unsigned int length);

#endif // IP_H
