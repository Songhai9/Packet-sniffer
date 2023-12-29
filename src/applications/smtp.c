#include "smtp.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>

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
    "QUIT"
};

// Fonction pour vérifier si un paquet contient une commande SMTP
int contains_smtp_command(const char *packet) {
    for (int i = 0; smtp_commands[i] != NULL; i++) {
        if (strstr(packet, smtp_commands[i]) != NULL) {
            return 1;  // Commande trouvée
        }
    }
    return 0;  // Aucune commande trouvée
}

// Fonction pour analyser un message SMTP
void analyze_smtp(const unsigned char *packet, unsigned int length) {
    char buffer[length + 1];
    strncpy(buffer, (const char *)packet, length);
    buffer[length] = '\0';

    // Convertir le buffer en majuscules pour une comparaison insensible à la casse
    for (unsigned int i = 0; i < length; ++i) {
        buffer[i] = toupper((unsigned char)buffer[i]);
    }

    if (contains_smtp_command(buffer)) {
        if (verbose_level >= 2) {
            printf("SMTP Command: %s\n", buffer);
        } else {
            printf("SMTP Activity Detected but Unrecognized\n");
        }
    }
}
