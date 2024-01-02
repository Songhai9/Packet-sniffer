TODO
✅ = Testé et fonctionnel 🟨 = Pas testé, fonctionnel 🟥 = Testé, non fonctionnel

CAPTURE
- [x] Packet capture ✅

ANALYSIS
--> PROTOCOLS
    - [x] Ethernet ✅
    - [x] IPv4 ✅
    - [x] IPv6 ✅
    - [x] UDP ✅
    - [x] TCP ✅
    - [x] ARP ✅
    - [x] ICMP ✅
--> APPLICATIONS
    - [x] DHCP ✅
    - [x] DNS ✅
    - [x] HTTP ✅
    - [x] FTP ✅
    - [x] SMTP ✅ ~
    - [x] SCTP 🟥 ~
    - [x] Telnet ✅
    - [x] LDAP 🟥
    - [x] POP ✅
    - [x] IMAP ✅ ~

OPTIONS
- [x] -i ✅
- [x] -o ✅
- [] -f
- [x] -v ✅


Structure :

analyseur-reseau/
│
├── src/                  # Dossier contenant les fichiers source (.c)
│   ├── main.c            # Point d'entrée principal, gestion des arguments
│   ├── ethernet.c        # Gestion des trames Ethernet
│   ├── ip.c              # Gestion du protocole IP
│   ├── arp.c             # Gestion du protocole ARP
│   ├── icmp.c            # Gestion du protocole ICMP
│   ├── tcp.c             # Gestion du protocole TCP
│   ├── udp.c             # Gestion du protocole UDP
│   └── protocols_applicatifs/
│       ├── dhcp.c        # Gestion du protocole DHCP
│       ├── dns.c         # Gestion du protocole DNS
│       ├── http.c        # Gestion du protocole HTTP
│       └── ...
│
├── include/              # Dossier contenant les fichiers d'en-tête (.h)
│   ├── ethernet.h
│   ├── ip.h
│   ├── arp.h
│   ├── icmp.h
│   ├── tcp.h
│   ├── udp.h
│   └── protocols_applicatifs/
│       ├── dhcp.h
│       ├── dns.h
│       ├── http.h
│       └── ...
│
└── Makefile              # Makefile pour la compilation