#include "../include/ip.h"
#include "../include/tcp.h"
#include "../include/udp.h"
#include "../include/icmp.h"
#include <netinet/ip.h>
#include <stdio.h>
#include <arpa/inet.h>

extern int verbose_level;


/**
 * @brief Obtient le nom du protocole IP en fonction de son identifiant.
 * 
 * @param protocol Identifiant du protocole IP.
 * @return Le nom du protocole IP.
 */
const char *get_ip_protocol_name(uint8_t protocol)
{
    switch (protocol)
    {
    case IPPROTO_TCP:
        return "TCP";
    case IPPROTO_UDP:
        return "UDP";
    case IPPROTO_ICMP:
        return "ICMP";
    default:
        return "Unknown";
    }
}


/**
 * @brief Analyse un paquet IP et affiche ses informations.
 * 
 * Cette fonction extrait et affiche les détails du paquet IP, tels que les adresses source et destination,
 * ainsi que le protocole de couche supérieure utilisé.
 * 
 * @param packet Le paquet IP à analyser.
 * @param length La longueur du paquet IP.
 */
void analyze_ip(const unsigned char *packet, unsigned int length)
{
    const struct iphdr *ip_header = (struct iphdr *)packet;

    char source[INET_ADDRSTRLEN];
    char dest[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->saddr), source, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->daddr), dest, INET_ADDRSTRLEN);

    if (verbose_level == 1)
        printf("| IP ");
    else if (verbose_level == 2)
        printf("IP Header : IP Version : %d | Protocol : %s | Source IP : %s | Destination IP : %s\n", ip_header->version, get_ip_protocol_name(ip_header->protocol), source, dest);
    else
    {
        printf("****************** IP Header ******************\n");
        printf("    |- IP Version: %d\n", ip_header->version);
        printf("    |- IP Header Length: %d bytes\n", ip_header->ihl * 4);
        printf("    |- Type of Service: %d\n", ip_header->tos);
        printf("    |- Total Length: %d\n", ntohs(ip_header->tot_len));
        printf("    |- Identification: %d\n", ntohs(ip_header->id));

        printf("    |- Flags: %d\n", ntohs(ip_header->frag_off) >> 13);
        printf("    |- Fragment Offset: %d\n", ntohs(ip_header->frag_off) & 0x1FFF);

        printf("    |- TTL: %d\n", ip_header->ttl);
        printf("    |- Protocol: %s\n", get_ip_protocol_name(ip_header->protocol));
        printf("    |- Header Checksum: %04x\n", ntohs(ip_header->check));

        printf("    |- Source IP: %s\n", source);
        printf("    |- Destination IP: %s\n", dest);
    }

    // Gérer les options IP si elles sont présentes
    if (ip_header->ihl > 5)
    {
        printf("IP Options: Present\n");
        // Traiter les options ici si nécessaire
    }

    if (ip_header->protocol == IPPROTO_TCP)
    {
        analyze_tcp(packet + ip_header->ihl * 4, length - ip_header->ihl * 4);
    }
    if (ip_header->protocol == IPPROTO_UDP)
    {
        analyze_udp(packet + ip_header->ihl * 4);
    }
    if (ip_header->protocol == IPPROTO_ICMP)
    {
        analyze_icmp(packet + ip_header->ihl * 4, length - ip_header->ihl * 4);
    }
}
