#include "../../include/applications/bootp.h"
#include <stdio.h>
#include <arpa/inet.h> // For ntohl() and ntohs() functions
#include <string.h>    // For strlen() function

extern int verbose_level;

// Prototype de la nouvelle fonction pour lire les options DHCP
void read_dhcp_options(const unsigned char *options, int length);

// Fonction qui prend en paramètre un paquet BOOTP et affiche tous les octets du paquet ap
unsigned char *print_bootp_packet(const unsigned char *packet, unsigned int length, unsigned char *options)
{
    unsigned int i = 0;
    unsigned int magic_cookie_index = 0;
    unsigned char magic_cookie[] = {0x63, 0x82, 0x53, 0x63}; // Magic cookie sequence

    // Find the index of the magic cookie sequence
    while (i < length - sizeof(magic_cookie))
    {
        if (memcmp(packet + i, magic_cookie, sizeof(magic_cookie)) == 0)
        {
            magic_cookie_index = i;
            break;
        }
        i++;
    }

    // Copy the bytes after the magic cookie to the end of the packet into the options array
    unsigned int options_length = length - magic_cookie_index - sizeof(magic_cookie);
    memcpy(options, packet + magic_cookie_index + sizeof(magic_cookie), options_length);

    // Print the hexadecimal bytes
    /* for (unsigned int j = 0; j < options_length; j++) {
        printf("%02x ", options[j]);
    }
    printf("\n"); */

    return options;
}

// Helper function to print MAC address in human-readable format
void print_mac_address(const uint8_t *mac)
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void analyze_dhcp(const unsigned char *packet, unsigned int length)
{
    if (length < sizeof(dhcp_message_t))
    {
        printf("Truncated DHCP packet\n");
        return;
    }

    // Stocker les options DHCP dans un tableau 'options'
    unsigned char options[length];
    print_bootp_packet(packet, length, options);

    if (verbose_level == 1)
    {
        printf("DHCP");
    }
    else if (verbose_level == 2)
    {
        printf("DHCP Packet : Op Code : %d ", ((dhcp_message_t *)packet)->op);
        if (options != NULL)
        {
            printf(" Options available\n");
        }
    }
    else
    {

        const dhcp_message_t *dhcp = (const dhcp_message_t *)packet;

        printf("****************** DHCP Message ******************\n");
        printf("    |-Op Code: %d\n", dhcp->op);
        printf("    |-Hardware Type: %d\n", dhcp->htype);
        printf("    |-Hardware Address Length: %d\n", dhcp->hlen);
        printf("    |-Hops: %d\n", dhcp->hops);
        printf("    |-Transaction ID: 0x%08x\n", ntohl(dhcp->xid));
        printf("    |-Seconds Elapsed: %d\n", ntohs(dhcp->secs));
        printf("    |-Flags: 0x%04x\n", ntohs(dhcp->flags));
        printf("    |-Client IP Address: %s\n", inet_ntoa(*(struct in_addr *)&dhcp->ciaddr));
        printf("    |-Your (client) IP Address: %s\n", inet_ntoa(*(struct in_addr *)&dhcp->yiaddr));
        printf("    |-Next Server IP Address: %s\n", inet_ntoa(*(struct in_addr *)&dhcp->siaddr));
        printf("    |-Relay Agent IP Address: %s\n", inet_ntoa(*(struct in_addr *)&dhcp->giaddr));

        // Formatting and printing client hardware address
        printf("    |-Client Hardware Address: ");
        print_mac_address(dhcp->chaddr);
        printf("\n");

        // Formatting and printing server name
        printf("    |-Server Name: ");
        if (strlen((const char *)dhcp->sname) == 0)
            printf("empty\n");
        else
            printf("%s\n", dhcp->sname);

        // Formatting and printing boot file name
        printf("    |-Boot File Name: ");
        if (strlen((const char *)dhcp->file) == 0)
            printf("empty\n");
        else
            printf("%s\n", dhcp->file);

        // Appel de la nouvelle fonction pour lire les options DHCP

        // S'il le tableau 'options' contient des données, nous les analysons
        // à partir d'après le magic cookie
        printf("****************** DHCP Options ******************\n");
        if (options[0] != 0)
        {
            read_dhcp_options(options, length);
        }
    }
}

void read_dhcp_options(const unsigned char *options, int length)
{
    int i = 0;
    while (i < length)
    {
        uint8_t code = options[i++];
        if (code == DHCP_OPTION_END)
        {
            printf("Option: End\n");
            break; // Option de fin
        }

        uint8_t len = options[i++];
        const unsigned char *data = options + i;

        switch (code)
        {
        case DHCP_OPTION_SUBNET_MASK: // Masque de sous-réseau
            printf("Option: Subnet Mask, Data: %s\n", inet_ntoa(*(struct in_addr *)data));
            break;
        case DHCP_OPTION_ROUTER: // Routeur
            printf("Option: Router, Data: %s\n", inet_ntoa(*(struct in_addr *)data));
            break;
        case DHCP_OPTION_DNS_SERVER:
        { // DNS
            printf("Option: DNS Server");
            for (int j = 0; j < len; j += 4)
            {
                printf(", Data: %s", inet_ntoa(*(struct in_addr *)(data + j)));
            }
            printf("\n");
            break;
        }
        case DHCP_OPTION_HOSTNAME: // Nom d'hôte
            printf("Option: Host Name, Data: %.*s\n", len, data);
            break;
        case DHCP_OPTION_REQUESTED_IP: // Adresse IP demandée
            printf("Option: Requested IP Address, Data: %s\n", inet_ntoa(*(struct in_addr *)data));
            break;
        case DHCP_OPTION_IP_LEASE_TIME: // Durée du bail IP
            printf("Option: IP Lease Time, Data: %u\n", ntohl(*(uint32_t *)data));
            break;
        case DHCP_OPTION_MESSAGE_TYPE: // Type de message DHCP
            printf("Option: DHCP Message Type, Data: %d\n", data[0]);
            break;
        case DHCP_OPTION_SERVER_IDENTIFIER: // Identifiant du serveur DHCP
            printf("Option: DHCP Server Identifier, Data: %s\n", inet_ntoa(*(struct in_addr *)data));
            break;
        case DHCP_OPTION_PARAMETER_REQUEST: // Liste de requête de paramètres
            printf("Option: Parameter Request List");
            for (int j = 0; j < len; j++)
            {
                printf(", Data: %d", data[j]);
            }
            printf("\n");
            break;
        case DHCP_CLIENT_IDENTIFIER: // Identifiant du client
            printf("Option: Client Identifier, Data: ");
            for (int j = 0; j < len; j++)
            {
                printf("%02x", data[j]);
            }
            printf("\n");
            break;
        default:
            printf("Option: %d, Length: %d, Data: ", code, len);
            for (int j = 0; j < len; j++)
            {
                printf("%02x", data[j]);
            }
            printf("\n");
            break;
        }

        i += len;
    }
}
