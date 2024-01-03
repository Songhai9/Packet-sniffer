#ifndef LDAP_H
#define LDAP_H

#include <stdint.h>

/**
 * @file ldap.h
 * @brief Fichier d'en-tête pour le traitement des paquets LDAP.
 *
 * Ce fichier contient la déclaration de la fonction pour analyser les paquets LDAP.
 */

/**
 * @brief Analyse un paquet LDAP et affiche ses informations.
 * 
 * @param packet Le paquet LDAP à analyser.
 * @param length La longueur du paquet LDAP.
 */
void analyze_ldap(const unsigned char *packet, unsigned int length);

#endif // LDAP_H
