#include "../include/applications/telnet.h"
#include <stdio.h>

extern int verbose_level;

// Fonction pour vérifier si un octet est une commande Telnet valide
int is_telnet_command(unsigned char byte)
{
    return byte == DO || byte == DONT || byte == WILL || byte == WONT;
}

void analyze_telnet(const unsigned char *packet, int length)
{
    int i = 0;
    int command_printed = 0; // Indicateur pour savoir si une commande a été imprimée

    if (verbose_level == 1)
    {
        printf("| Telnet");
    }
    else if (verbose_level == 2)
    {
        printf("Telnet Command(s)");
        printf("\n");
    }

    else
    {
        while (i < length)
        {
            if (packet[i] == IAC)
            {
                if (i + 2 < length && is_telnet_command(packet[i + 1]))
                {
                    printf("\nTelnet Command: ");
                    switch (packet[i + 1])
                    {
                    case DO:
                        printf("DO ");
                        break;
                    case DONT:
                        printf("DONT ");
                        break;
                    case WILL:
                        printf("WILL ");
                        break;
                    case WONT:
                        printf("WONT ");
                        break;
                    }
                    printf("Option: %d", packet[i + 2]);
                    i += 3;
                    command_printed = 1; // Marque qu'une commande a été imprimée
                }
                else
                {
                    i++; // Ignore les octets IAC non suivis d'une commande valide
                }
            }
            else if (packet[i] >= 32 && packet[i] <= 126)
            { // Caractères ASCII imprimables
                if (command_printed)
                {
                    printf("\n");
                    command_printed = 0; // Réinitialise l'indicateur
                }
                putchar(packet[i]);
                i++;
            }
            else
            {
                // S'arrête après avoir traité la dernière commande ou donnée textuelle
                break;
            }
        }
        printf("\n");
    }
}
