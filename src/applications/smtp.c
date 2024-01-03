#include "../../include/applications/smtp.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

extern int verbose_level;

const char *smtp_commands[] = {
    "HELO",
    "EHLO",
    "MAIL FROM:",
    "RCPT TO:",
    "DATA",
    "RSET",
    "VRFY",
    "EXPN",
    "HELP",
    "NOOP",
    "QUIT"};

/**
 * @brief Vérifie si un paquet contient une commande SMTP.
 *
 * @param packet Le paquet à vérifier.
 * @return 1 si une commande SMTP est trouvée, 0 sinon.
 */
int contains_smtp_command(const char *packet)
{
    for (int i = 0; smtp_commands[i] != NULL; i++)
    {
        if (strstr(packet, smtp_commands[i]) != NULL)
        {
            return 1; // Commande trouvée
        }
    }
    return 0; // Aucune commande trouvée
}

// Définition des réponses SMTP
smtp_response smtp_responses[] = {
    {220, "Service ready"},
    {250, "Requested mail action okay, completed"},
    {354, "Start mail input; end with <CRLF>.<CRLF>"},
    {421, "Service not available, closing transmission channel"},
    {450, "Requested mail action not taken: mailbox unavailable"},
    {550, "Requested action not taken: mailbox unavailable"},
    {0, NULL} // Marqueur de fin de tableau
};

// Fonction pour obtenir la description de la réponse SMTP
const char *get_smtp_response_desc(int code)
{
    for (int i = 0; smtp_responses[i].desc != NULL; i++)
    {
        if (smtp_responses[i].code == code)
        {
            return smtp_responses[i].desc;
        }
    }
    return "Unknown response code"; // Si le code n'est pas trouvé
}

/**
 * @brief Analyse un paquet SMTP et affiche ses informations.
 * 
 * Cette fonction parcourt le paquet SMTP et affiche les commandes et les réponses trouvées.
 * Elle adapte l'affichage en fonction du niveau de verbosité défini.
 * 
 * @param packet Le paquet SMTP à analyser.
 * @param length La longueur du paquet SMTP.
 */
void analyze_smtp(const unsigned char *packet, unsigned int length)
{
    char buffer[length + 1];
    strncpy(buffer, (const char *)packet, length);
    buffer[length] = '\0';

    // Trouver la fin de la commande (premier espace ou fin de ligne)
    unsigned int command_end = 0;
    while (command_end < length && buffer[command_end] != ' ' && buffer[command_end] != '\r' && buffer[command_end] != '\n')
    {
        buffer[command_end] = toupper((unsigned char)buffer[command_end]);
        command_end++;
    }

    if (verbose_level == 1)
        printf("| SMTP ");
    else
    {
        if (contains_smtp_command(buffer))
        {
            if (verbose_level == 3)
                printf("****************** SMTP Packet ******************\n");
            if (verbose_level >= 2)
            {
                printf("SMTP Command: %s\n", buffer);
            }
            else
            {
                printf("SMTP Activity Detected but Unrecognized\n");
            }
        }
        else
        {
            int response_code = strtol(buffer, NULL, 10);
            if (response_code > 0)
                printf("SMTP Response: %d %s\n", response_code, get_smtp_response_desc(response_code));
            else
                printf("SMTP Activity Detected but Unrecognized\n");
        }
    }
}
