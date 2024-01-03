#ifndef POP_H
#define POP_H

#include <stdint.h>

/**
 * @file pop.h
 * @brief Fichier d'en-tête pour le traitement des paquets POP.
 *
 * Ce fichier contient la déclaration de la fonction pour analyser les paquets POP.
 */

/**
 * @brief Analyse un paquet POP et affiche ses informations.
 * 
 * @param packet Le paquet POP à analyser.
 * @param length La longueur du paquet POP.
 */
void analyze_pop(const unsigned char *packet, unsigned int length);

#endif // POP_H
