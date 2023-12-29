#include "ftp.h"
#include <stdio.h>
#include <string.h>

extern int verbose_level;

#include <string.h>
#include <stdio.h>
#include <ctype.h>

extern int verbose_level;

// Une liste simple de commandes FTP connues
const char *ftp_commands[] = {
    "USER", "PASS", "ACCT", "CWD", "QUIT", "RETR", "STOR", "LIST", "NLST", 
    "SITE", "SYST", "STAT", "HELP", "NOOP", "MKD", "RMD", "PWD", "CDUP", 
    "STOU", "SMNT", "PORT", "PASV", "TYPE", "STRU", "MODE", "RNFR", "RNTO",
    "DELE", "MDTM", "SIZE", "REST", "ABOR", "RANG", "AUTH", "PBSZ", "PROT",
    NULL  // Marqueur de fin de liste
};

// Fonction pour vérifier si un paquet contient une commande FTP
int contains_ftp_command(const char *packet) {
    for (int i = 0; ftp_commands[i] != NULL; i++) {
        if (strstr(packet, ftp_commands[i]) != NULL) {
            return 1;  // Commande trouvée
        }
    }
    return 0;  // Aucune commande trouvée
}

// Fonction pour analyser un paquet potentiellement FTP
void analyze_ftp(const unsigned char *packet, unsigned int length) {
    char buffer[length + 1];
    strncpy(buffer, (const char *)packet, length);
    buffer[length] = '\0';

    // Convertir le buffer en majuscules pour une comparaison insensible à la casse
    for (unsigned int i = 0; i < length; ++i) {
        buffer[i] = toupper((unsigned char)buffer[i]);
    }

    if (contains_ftp_command(buffer)) {
        if (verbose_level >= 2) {
            printf("FTP Command: %s\n", buffer);
        } else {
            printf("FTP Activity Detected but Unrecognized\n");
        }
    }
}

