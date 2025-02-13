#include "../../include/applications/ftp.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

extern int verbose_level;

// Une liste simple de commandes FTP connues
const char *ftp_commands[] = {
    "USER", "PASS", "ACCT", "CWD", "QUIT", "RETR", "STOR", "LIST", "NLST",
    "SITE", "SYST", "STAT", "HELP", "NOOP", "MKD", "RMD", "PWD", "CDUP",
    "STOU", "SMNT", "PORT", "PASV", "TYPE", "STRU", "MODE", "RNFR", "RNTO",
    "DELE", "MDTM", "SIZE", "REST", "ABOR", "RANG", "AUTH", "PBSZ", "PROT",
    NULL // Marqueur de fin de liste
};

/**
 * @brief Vérifie si un paquet contient une commande FTP.
 * 
 * @param packet Le paquet à vérifier.
 * @return 1 si une commande FTP est trouvée, 0 sinon.
 */
int contains_ftp_command(const char *packet)
{
    for (int i = 0; ftp_commands[i] != NULL; i++)
    {
        if (strstr(packet, ftp_commands[i]) != NULL)
        {
            return 1; // Commande trouvée
        }
    }
    return 0; // Aucune commande trouvée
}

// Définition des réponses FTP
ftp_response ftp_responses[] = {
    {200, "Command okay"},
    {220, "Service ready for new user"},
    {221, "Service closing control connection"},
    {230, "User logged in, proceed"},
    {425, "Can't open data connection"},
    {426, "Connection closed; transfer aborted"},
    {530, "Not logged in"},
    {550, "Requested action not taken"},
    {0, NULL} // Marqueur de fin de tableau
};

const char *get_ftp_response_desc(int code)
{
    for (int i = 0; ftp_responses[i].desc != NULL; i++)
    {
        if (ftp_responses[i].code == code)
        {
            return ftp_responses[i].desc;
        }
    }
    return "Unknown response code"; // Si le code n'est pas trouvé
}


/**
 * @brief Analyse un paquet FTP et affiche ses informations.
 * 
 * Cette fonction parcourt le paquet FTP et affiche les commandes et réponses trouvées.
 * Elle adapte l'affichage en fonction du niveau de verbosité défini.
 * 
 * @param packet Le paquet FTP à analyser.
 * @param length La longueur du paquet FTP.
 */
void analyze_ftp(const unsigned char *packet, unsigned int length)
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
        printf("| FTP");
    else
    {
        if (contains_ftp_command(buffer))
        {
            if (verbose_level >= 2)
            {
                if (verbose_level == 3)
                    printf("****************** SMTP Packet ******************\n");
                printf("FTP Command: %s\n", buffer);
            }
            else
            {
                printf("FTP Activity Detected but Unrecognized\n");
            }
        }
        else
        {
            if (verbose_level == 3)
                printf("****************** SMTP Packet ******************\n");
            int response_code = strtol(buffer, NULL, 10);
            if (response_code > 0)
                printf("FTP Response: %d %s\n", response_code, get_ftp_response_desc(response_code));
            else
                printf("FTP Activity Detected but Unrecognized\n");
        }
    }
}
