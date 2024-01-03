#include "../../include/applications/pop.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>

extern int verbose_level;

// Commandes POP courantes
const char *pop_commands[] = {
    "USER", "PASS", "STAT", "LIST", "RETR", "DELE", "QUIT",
    NULL // Marqueur de fin de liste
};

/**
 * @brief Vérifie si un paquet contient une commande POP.
 * 
 * @param packet Le paquet à vérifier.
 * @return 1 si une commande POP est trouvée, 0 sinon.
 */
int contains_pop_command(const char *packet)
{
    for (int i = 0; pop_commands[i] != NULL; i++)
    {
        if (strstr(packet, pop_commands[i]) != NULL)
        {
            return 1; // Commande trouvée
        }
    }
    return 0; // Aucune commande trouvée
}

/**
 * @brief Analyse un paquet POP et affiche ses informations.
 * 
 * Cette fonction parcourt le paquet POP et affiche les commandes et réponses trouvées.
 * Elle adapte l'affichage en fonction du niveau de verbosité défini.
 * 
 * @param packet Le paquet POP à analyser.
 * @param length La longueur du paquet POP.
 */
void analyze_pop(const unsigned char *packet, unsigned int length)
{
    char buffer[length + 1];
    strncpy(buffer, (const char *)packet, length);
    buffer[length] = '\0';

    // Convertir la commande en majuscules pour une comparaison insensible à la casse
    unsigned int command_end = 0;
    while (command_end < length && buffer[command_end] != ' ' && buffer[command_end] != '\r' && buffer[command_end] != '\n')
    {
        buffer[command_end] = toupper((unsigned char)buffer[command_end]);
        command_end++;
    }

    if (verbose_level == 1)
        printf("| POP ");
    else
    {
        if (contains_pop_command(buffer))
        {
            if (verbose_level >= 2)
            {
                printf("POP Command: %s\n", buffer);
            }
            else
            {
                printf("POP Activity Detected but Unrecognized\n");
            }
        }
        else
        {
            // Traitement des réponses POP (commençant par +OK ou -ERR)
            if (strncmp(buffer, "+OK", 3) == 0 || strncmp(buffer, "-ERR", 4) == 0)
            {
                printf("POP Response: %s\n", buffer);
            }
            else
            {
                printf("POP Activity Detected but Unrecognized\n");
            }
        }
    }
}
