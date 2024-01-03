#ifndef PACKET_CAPTURE_H
#define PACKET_CAPTURE_H

#include <pcap.h>

/**
 * @file packet_capture.h
 * @brief Fichier d'en-tête pour la capture de paquets réseau.
 * 
 * Ce fichier contient les déclarations des fonctions utilisées pour la capture 
 * et le traitement des paquets réseau.
 */

/**
 * @brief Démarre la capture de paquets sur un périphérique réseau.
 * 
 * @param device Nom du périphérique réseau sur lequel écouter.
 */
void start_packet_capture(char *device);

/**
 * @brief Gère les paquets capturés.
 * 
 * Cette fonction est appelée par pcap_loop() à chaque fois qu'un paquet est capturé.
 * 
 * @param user_data Données utilisateur passées à la fonction.
 * @param pkthdr En-tête du paquet capturé, fourni par pcap.
 * @param packet Les données du paquet capturé.
 */
void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet);

/**
 * @brief Gère le signal d'interruption (SIGINT) pour terminer proprement la capture.
 * 
 * @param sig Le numéro du signal reçu.
 */
void handle_sigint(int sig);

/**
 * @brief Ouvre un fichier pour écrire les données de paquets capturés.
 * 
 * @param filename Le nom du fichier à ouvrir pour l'écriture.
 */
void open_output_file(const char *filename);

/**
 * @brief Ferme le fichier de sortie de paquets capturés.
 */
void close_output_file();

#endif // PACKET_CAPTURE_H
