#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h> // Pour ntohl et ntohs
#include <netinet/in.h>
#include <string.h>
#include "../include/applications/bootp.h"

extern int verbose_level;

static void print_mac_address(const uint8_t *mac);
static void print_ip_address(uint32_t ip);
static void print_bootp_dhcp_header(const bootp_dhcp_header *header);
static void print_dhcp_option(const uint8_t *option);

// Fonction pour afficher l'adresse MAC formatée
void print_mac_address(const uint8_t *mac)
{
    printf("%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// Fonction pour afficher une adresse IP formatée
void print_ip_address(uint32_t ip)
{
    struct in_addr ip_addr;
    ip_addr.s_addr = ip;
    printf("%s", inet_ntoa(ip_addr));
}

// Fonction pour afficher les détails de l'en-tête BOOTP/DHCP
void print_bootp_dhcp_header(const bootp_dhcp_header *header)
{
    printf("BOOTP/DHCP Header:\n");
    printf("  Op: %d\n", header->op);
    printf("  Htype: %d\n", header->htype);
    printf("  Hlen: %d\n", header->hlen);
    printf("  Hops: %d\n", header->hops);
    printf("  Xid: %u\n", ntohl(header->xid));
    printf("  Secs: %d\n", ntohs(header->secs));
    printf("  Flags: %d\n", ntohs(header->flags));
    printf("  CIAddr: ");
    print_ip_address(header->ciaddr);
    printf("\n");
    printf("  YIAddr: ");
    print_ip_address(header->yiaddr);
    printf("\n");
    printf("  SIAddr: ");
    print_ip_address(header->siaddr);
    printf("\n");
    printf("  GIAddr: ");
    print_ip_address(header->giaddr);
    printf("\n");
    printf("  CHAddr: ");
    print_mac_address(header->chaddr);
    printf("\n");
    
    // Afficher sname si c'est non vide
    if (header->sname[0] != '\0') {
        printf("  SName: %s\n", header->sname);
    }

    // Afficher file si c'est non vide
    if (header->file[0] != '\0') {
        printf("  File: %s\n", header->file);
    }
}

// Fonction pour analyser et afficher une option DHCP
void print_dhcp_option(const uint8_t *option)
{
    uint8_t option_code = option[0];
    uint8_t option_length = option[1];
    const uint8_t *option_data = &option[2];

    printf("Option: %d ", option_code);

    switch (option_code)
    {
    case 1: // Subnet Mask
        if (option_length == 4)
        {
            struct in_addr subnet_mask;
            memcpy(&subnet_mask, option_data, sizeof(subnet_mask));
            printf("(Subnet Mask): %s\n", inet_ntoa(subnet_mask));
        }
        break;
    case 3: // Router
        printf("(Router): ");
        for (int i = 0; i < option_length; i += 4)
        {
            struct in_addr router;
            memcpy(&router, &option_data[i], sizeof(router));
            printf("%s ", inet_ntoa(router));
        }
        printf("\n");
        break;
    case 6: // Domain Name Server
        printf("(DNS): ");
        for (int i = 0; i < option_length; i += 4)
        {
            struct in_addr dns;
            memcpy(&dns, &option_data[i], sizeof(dns));
            printf("%s ", inet_ntoa(dns));
        }
        printf("\n");
        break;
    case 12: // Host Name
        printf("(Host Name): %.*s\n", option_length, option_data);
        break;
    case 15: // Domain Name
        printf("(Domain Name): %.*s\n", option_length, option_data);
        break;
    case 28: // Broadcast Address
        if (option_length == 4)
        {
            struct in_addr broadcast_address;
            memcpy(&broadcast_address, option_data, sizeof(broadcast_address));
            printf("(Broadcast Address): %s\n", inet_ntoa(broadcast_address));
        }
        break;
    case 50: // Requested IP Address
        if (option_length == 4)
        {
            struct in_addr requested_ip;
            memcpy(&requested_ip, option_data, sizeof(requested_ip));
            printf("(Requested IP Address): %s\n", inet_ntoa(requested_ip));
        }
        break;
    case 51: // Lease Time
        if (option_length == 4)
        {
            uint32_t lease_time = ntohl(*(uint32_t *)option_data);
            printf("(Lease Time): %u seconds\n", lease_time);
        }
        break;
    case 53: // DHCP Message Type
        if (option_length == 1)
        {
            const char *types[] = {"", "Discover", "Offer", "Request", "Decline", "Ack", "Nak", "Release", "Inform"};
            uint8_t message_type = option_data[0];
            if (message_type > 0 && message_type < sizeof(types) / sizeof(char *))
            {
                printf("(DHCP Message Type): %s\n", types[message_type]);
            }
            else
            {
                printf("(DHCP Message Type): Unknown\n");
            }
        }
        break;
    case 54: // Server Identifier
        if (option_length == 4)
        {
            struct in_addr server_id;
            memcpy(&server_id, option_data, sizeof(server_id));
            printf("(Server Identifier): %s\n", inet_ntoa(server_id));
        }
        break;
    // ... Autres options DHCP ...
    default:
        printf("(Unrecognized)\n");
        break;
    }
}

// Fonction principale pour analyser BOOTP/DHCP
void analyze_bootp_dhcp(const unsigned char *packet, unsigned int length)
{
    if (length < sizeof(bootp_dhcp_header))
    {
        printf("Truncated BOOTP/DHCP packet\n");
        return;
    }

    const bootp_dhcp_header *header = (const bootp_dhcp_header *)packet;

    // Afficher les détails de l'en-tête BOOTP/DHCP
    if (verbose_level > 1)
    {
        print_bootp_dhcp_header(header);
    }

    // Analyse des options DHCP qui commencent après l'en-tête BOOTP/DHCP fixe et le champ 'vend'
    const unsigned char *options = packet + 240; // La taille de l'en-tête BOOTP/DHCP sans les options
    unsigned int option_index = 0;
    while (option_index < length - 240 && options[option_index] != 0xFF)
    {
        if (options[option_index] == 0)
        { // Option Pad
            option_index++;
            continue;
        }
        print_dhcp_option(&options[option_index]);
        option_index += options[option_index + 1] + 2;
    }
}
