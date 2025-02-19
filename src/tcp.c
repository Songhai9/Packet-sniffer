#include "../include/tcp.h"
#include "../include/applications/dns.h"
#include "../include/applications/http.h"
#include "../include/applications/ftp.h"
#include "../include/applications/smtp.h"
#include "../include/applications/pop.h"
#include "../include/applications/imap.h"
#include "../include/applications/ldap.h"
#include "../include/applications/telnet.h"
#include <netinet/ip.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

extern int verbose_level;

/**
 * @brief Analyse un paquet TCP et affiche ses informations.
 * 
 * Cette fonction extrait et affiche les détails du paquet TCP, tels que les ports source et destination.
 * Elle adapte l'affichage en fonction du niveau de verbosité défini.
 * 
 * @param packet Le paquet TCP à analyser.
 * @param length La longueur du paquet TCP.
 */
void analyze_tcp(const unsigned char *packet, int length)
{
    const struct tcphdr *tcp_header = (const struct tcphdr *)packet;
    (void)length;

    uint16_t src_port = ntohs(tcp_header->source);
    uint16_t dest_port = ntohs(tcp_header->dest);

    if (verbose_level == 1)
        printf("| TCP ");
    else if (verbose_level == 2)
        printf("TCP Header : Source Port : %d | Destination Port : %d\n", ntohs(tcp_header->source), ntohs(tcp_header->dest));
    else
    {
        printf("****************** TCP Segment ******************\n");
        printf("    |- Source Port: %d\n", src_port);
        printf("    |- Destination Port: %d\n", dest_port);
        printf("    |- Sequence Number: %u\n", ntohl(tcp_header->seq));
        printf("    |- Acknowledgment Number: %u\n", ntohl(tcp_header->ack_seq));
        printf("    |- Header Length: %d bytes\n", tcp_header->doff * 4);
        printf("    |- Flags: %c%c%c%c%c%c\n",
               (tcp_header->urg ? 'U' : '.'),
               (tcp_header->ack ? 'A' : '.'),
               (tcp_header->psh ? 'P' : '.'),
               (tcp_header->rst ? 'R' : '.'),
               (tcp_header->syn ? 'S' : '.'),
               (tcp_header->fin ? 'F' : '.'));
        printf("    |- Window Size: %d\n", ntohs(tcp_header->window));
        printf("    |- Checksum: 0x%04x\n", ntohs(tcp_header->check));
        printf("    |- Urgent Pointer: %d\n", tcp_header->urg_ptr);
    }

    if (src_port == 53 || dest_port == 53)
    {
        analyze_dns(packet + sizeof(struct tcphdr), length - sizeof(struct tcphdr));
    }

    if (src_port == 80 || dest_port == 80)
    {
        // La charge utile commence après l'en-tête TCP
        const unsigned char *http_payload = packet + (tcp_header->doff * 4);
        int http_payload_length = length - (tcp_header->doff * 4);

        analyze_http(http_payload, http_payload_length);
    }

    if (src_port == 21 || dest_port == 21)
    {
        const unsigned char *ftp_payload = packet + (tcp_header->doff * 4);
        int ftp_payload_length = length - (tcp_header->doff * 4);

        analyze_ftp(ftp_payload, ftp_payload_length);
    }

    if (src_port == 25 || dest_port == 25)
    {
        // La charge utile commence après l'en-tête TCP
        const unsigned char *smtp_payload = packet + (tcp_header->doff * 4);
        int smtp_payload_length = length - (tcp_header->doff * 4);

        analyze_smtp(smtp_payload, smtp_payload_length);
    }

    if (src_port == 110 || dest_port == 110)
    {
        const unsigned char *pop_payload = packet + (tcp_header->doff * 4);
        int pop_payload_length = length - (tcp_header->doff * 4);

        analyze_pop(pop_payload, pop_payload_length);
    }

    if (src_port == 143 || dest_port == 143)
    {
        const unsigned char *imap_payload = packet + (tcp_header->doff * 4);
        int imap_payload_length = length - (tcp_header->doff * 4);

        analyze_imap(imap_payload, imap_payload_length);
    }

    if (src_port == 389 || dest_port == 389)
    {
        const unsigned char *ldap_payload = packet + (tcp_header->doff * 4);
        int ldap_payload_length = length - (tcp_header->doff * 4);

        analyze_ldap(ldap_payload, ldap_payload_length);
    }

    if (src_port == 23 || dest_port == 23)
    {
        const unsigned char *telnet_payload = packet + (tcp_header->doff * 4);
        int telnet_payload_length = length - (tcp_header->doff * 4);

        analyze_telnet(telnet_payload, telnet_payload_length);
    }
}