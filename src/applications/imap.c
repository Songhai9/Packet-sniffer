#include "imap.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>

extern int verbose_level;

// Fonction pour analyser un paquet potentiellement IMAP
void analyze_imap(const unsigned char *packet, unsigned int length)
{
    char buffer[length + 1];
    strncpy(buffer, (const char *)packet, length);
    buffer[length] = '\0';

    if (verbose_level == 1)
        printf("| IMAP ");
    else
    {
        // Analyse des commandes et réponses IMAP
        if (strncmp(buffer, "A", 1) == 0)
        { // Recherche d'un tag de commande typique dans IMAP
            if (verbose_level >= 2)
            {
                printf("IMAP Command: %s\n", buffer);
            }
            else
            {
                printf("IMAP Activity Detected\n");
            }
        }
        else
        {
            // Analyse basique des réponses - OK, NO, BAD
            if (strstr(buffer, "OK") != NULL)
            {
                printf("IMAP Response OK: %s\n", buffer);
            }
            else if (strstr(buffer, "NO") != NULL)
            {
                printf("IMAP Response NO: %s\n", buffer);
            }
            else if (strstr(buffer, "BAD") != NULL)
            {
                printf("IMAP Response BAD: %s\n", buffer);
            }
            else
            {
                printf("IMAP Activity Detected but Unrecognized\n");
            }
        }
    }
}
