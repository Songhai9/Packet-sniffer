#include "../../include/applications/ldap.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>

extern int verbose_level;

// Liste des opérations LDAP connues
/* const char *ldap_operations[] = {
    "BindRequest", "BindResponse",
    "SearchRequest", "SearchResponse",
    "ModifyRequest", "ModifyResponse",
    "AddRequest", "AddResponse",
    "DelRequest", "DelResponse",
    "ModifyDNRequest", "ModifyDNResponse",
    "CompareRequest", "CompareResponse",
    "ExtendedRequest", "ExtendedResponse",
    NULL // Marqueur de fin de liste
};

int contains_ldap_operation(const char *operation)
{
    int i = 0;
    while (ldap_operations[i] != NULL)
    {
        if (strcmp(ldap_operations[i], operation) == 0)
        {
            return 1;
        }
        i++;
    }
    return 0;
} */

/**
 * @brief Analyse un paquet LDAP et affiche ses informations.
 * 
 * Cette fonction parcourt le paquet LDAP et affiche les opérations et réponses trouvées.
 * Elle adapte l'affichage en fonction du niveau de verbosité défini.
 * 
 * @param packet Le paquet LDAP à analyser.
 * @param length La longueur du paquet LDAP.
 */

void analyze_ldap(const unsigned char *packet, unsigned int length)
{
    char buffer[length + 1];
    strncpy(buffer, (const char *)packet, length);
    buffer[length] = '\0';

    // Convertir la commande en majuscules pour une comparaison insensible à la casse
    unsigned int operation_end = 0;
    while (operation_end < length && buffer[operation_end] != ' ' && buffer[operation_end] != '\r' && buffer[operation_end] != '\n')
    {
        buffer[operation_end] = toupper((unsigned char)buffer[operation_end]);
        operation_end++;
    }

    if (verbose_level == 1)
        printf("| LDAP ");
    else
    {
        if (verbose_level >= 2)
        {
            if (verbose_level == 3)
                printf("****************** LDAP Packet ******************\n");
            printf("LDAP Operation: ");
            for (unsigned int i = 0; i < operation_end; i++)
            {
                if (isprint((unsigned char)buffer[i]))
                {
                    printf("%c", buffer[i]);
                }
            }
            printf("\n");
        }
        else
        {
            printf("LDAP Activity Detected but Unrecognized\n");
        }
    }
}