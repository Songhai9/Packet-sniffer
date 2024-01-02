#include "../include/applications/ldap.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>

extern int verbose_level;

// Liste des opérations LDAP connues
const char *ldap_operations[] = {
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
}

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
        if (contains_ldap_operation(buffer))
        {
            if (verbose_level >= 2)
            {
                printf("LDAP Operation: %s\n", buffer);
            }
            else
            {
                printf("LDAP Activity Detected but Unrecognized\n");
            }
        }
        else
        {
            printf("LDAP Activity Detected but Unrecognized\n");
        }
    }
}