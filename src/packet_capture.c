#include "../include/packet_capture.h"
#include "../include/ethernet.h"
#include <signal.h>
#include <pcap.h>
#include <stdlib.h>

FILE *output_file;


/**
 * @brief Ouvre un fichier de sortie pour enregistrer les paquets capturés.
 *
 * Cette fonction ouvre un fichier pour écrire les données des paquets. Si aucun nom
 * n'est fourni, un nom par défaut est utilisé.
 *
 * @param filename Le nom du fichier à ouvrir ou NULL pour utiliser un nom par défaut.
 */

void open_output_file(const char *filename)
{
    // Utilisation d'un nom de fichier par défaut si aucun nom n'est fourni
    if (filename == NULL)
        filename = "../trames.txt";

    output_file = fopen(filename, "w");
    if (!output_file)
    {
        perror("Error opening output file");
        exit(EXIT_FAILURE);
    }
}


/**
 * @brief Ferme le fichier de sortie utilisé pour enregistrer les paquets.
 *
 * Cette fonction ferme le fichier ouvert par open_output_file. Si la fermeture échoue,
 * un message d'erreur est affiché.
 */

void close_output_file()
{
    if (fclose(output_file) == EOF)
    {
        perror("Error closing output file");
        exit(EXIT_FAILURE);
    }
}


/**
 * @brief Démarre la capture de paquets sur un périphérique réseau spécifié.
 * 
 * Ouvre l'interface réseau pour la capture en mode promiscuité, définit un gestionnaire
 * de signal pour SIGINT, et démarre la boucle de capture avec pcap_loop.
 * 
 * @param device Le nom du périphérique réseau sur lequel écouter.
 */

/**
 * Fonction pour démarrer la capture de paquets.
 * 
 * @param device Le nom de l'interface réseau à utiliser pour la capture.
 */
void start_packet_capture(char *device)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Impossible d'ouvrir le périphérique %s : %s\n", device, errbuf);
        exit(EXIT_FAILURE);
    }

    // Ouvrir le fichier de sortie
    // open_output_file();

    signal(SIGINT, handle_sigint);

    pcap_loop(handle, 0, packet_handler, NULL);

    // Fermer le fichier de sortie après la fin de pcap_loop
    close_output_file();

    pcap_close(handle);
}





/**
 * @brief Gestionnaire de signal pour SIGINT.
 * 
 * Cette fonction est appelée lorsque le signal SIGINT est reçu. Elle affiche un message indiquant la fin de l'analyse et quitte le programme.
 * 
 * @param sig Le numéro du signal.
 */
/**
 * @brief Signal handler for SIGINT.
 * 
 * This function is called when the SIGINT signal is received. It prints a message indicating the end of the analysis and exits the program.
 * 
 * @param sig The signal number.
 */
void handle_sigint(int sig)
{
    (void)(sig);
    printf("\nFin de l'analyse\n");
    exit(0);
}

/**
 * @brief Fonction de gestion des paquets.
 * 
 * Cette fonction est appelée pour chaque paquet capturé. Elle affiche des informations sur le paquet, appelle la fonction d'analyse Ethernet et affiche les données du paquet.
 * 
 * @param user_data Pointeur vers des données définies par l'utilisateur (non utilisées dans cette fonction).
 * @param pkthdr Pointeur vers la structure d'en-tête du paquet.
 * @param packet Pointeur vers les données du paquet.
 */
void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet)
{
    static bpf_u_int32 count = 0; /* Compteur de paquets */

    // Utilisation de user_data pour éviter un avertissement
    (void)(user_data);

    /* Incrémenter notre compteur */
    fprintf(output_file, "Nombre de paquets : %u\n", ++count);             /* Afficher le numéro du paquet */
    printf("Nombre de paquets : %u\n", count);                             /* Afficher le numéro du paquet */
    fprintf(output_file, "Taille du paquet reçu : %u\n", pkthdr->len);     /* Afficher la taille du paquet */

    // Appeler la fonction d'analyse Ethernet
    analyze_ethernet(packet, pkthdr->len);
    for (bpf_u_int32 i = 0; i < pkthdr->len; i++)
    {
        fprintf(output_file, "%02x ", packet[i]);
        if (i != 0 && i % 16 == 0)
        {
            fprintf(output_file, "\n");
        }
    }
    fprintf(output_file, "\n\n"); /* Ajouter une nouvelle ligne pour séparer chaque paquet dans la sortie */
    printf("\n\n");               /* Ajouter une nouvelle ligne pour séparer chaque paquet dans la sortie */
}
