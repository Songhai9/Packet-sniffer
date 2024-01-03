// telnet.h

#ifndef TELNET_H
#define TELNET_H

#include <stdint.h>

// Commandes Telnet
#define IAC 255
#define DO 253
#define DONT 254
#define WILL 251
#define WONT 252

/**
 * @file telnet.h
 * @brief Fichier d'en-tête pour le traitement des paquets Telnet.
 *
 * Ce fichier contient les déclarations des fonctions pour analyser les paquets Telnet,
 * y compris le traitement des commandes et des options Telnet.
 */

/**
 * @brief Analyse un paquet Telnet et affiche ses informations.
 * 
 * @param packet Le paquet Telnet à analyser.
 * @param length La longueur du paquet Telnet.
 */
void analyze_telnet(const unsigned char *packet, int length);

/**
 * @brief Analyse les commandes Telnet dans un paquet et affiche les détails.
 * 
 * @param packet Le paquet contenant les commandes Telnet.
 * @param length La longueur de la partie commande du paquet.
 */
void parse_telnet_command(const unsigned char *packet, int length);

/**
 * @brief Gère les options Telnet en fonction de la commande reçue.
 * 
 * @param command La commande Telnet (DO, DONT, WILL, WONT).
 * @param option L'option Telnet spécifiée par la commande.
 */
void handle_telnet_option(uint8_t command, uint8_t option);

#endif // TELNET_H
