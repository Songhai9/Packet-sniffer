------------------------------------------------------- TODO ------------------------------------------------------------
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
    - [x] Telnet ✅
    - [x] LDAP ✅ ~
    - [x] POP ✅
    - [x] IMAP ✅ ~

OPTIONS
- [x] -i ✅
- [x] -o ✅
- [] -f
- [x] -v ✅



------------------------------------------------------- STRUCTURE -------------------------------------------------------

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


------------------------------------------------------ DESCRIPTION ------------------------------------------------------

PROJET ANALYSEUR RÉSEAU :

Le code de ce projet implémente un analyseur réseau simple.
Le Makefile pour compiler le code est fourni. Pour lancer le programme, il faut se rendre dans le dossier
'bin'.
Le programme a plusieurs modes de lancement :
- Sans fichier contenant des captures, le programme lance une analyse de trames prédéterminés et affiche les résultats comme il le ferait en 
temps normal. Initialement à but de test, il a été jugé pertinent de garder cet aspect, car il permet de montrer l'affichage de tous les protocoles pouvant être analysés par le programme.
- Avec l'option '-v' pour gérer la verbosité des résultats affichés par le programme. Lorsque ce n'est pas précisé, la verbosité est au maximum (3) par défaut. Il y a trois modes de verbosité allant de 1 à 3. Cette option est compatible avec ou sans fichier contenant des captures donné en paramètre.
- Avec l'option '-i [interface]', le programme analyse toutes les trames qui circulent par l'interface donné en paramètre. Il s'agit d'une analyse live.
- Avec l'option '-o [output-file]', le programme analyse toutes les trames qui sont dans le fichier 'output-file'. Cette option est conçu pour que l'output file soit un fichier .pcap obtenu grâve à l'utilisation de tcpdump. Un dossier 'input', avec un fichier est fourni pour tester l'option, encore une fois initialement implémenter à des fins de test, il a tout de même été conservé. Il s'agit de l'analyse offline.

Peu importe le mode de lancement du programme, celui-ci ouvrira en plus un fichier 'trame.txt' contenant le contenu brut des trames. Les résultats seront affichés en ligne de commande.

Une documentation Doxygen sur navigateur est disponible en exécutant la commande 'xdg-open index.html' dans le répertoire 'docs/html'. ('doxygen Doxyfile' pour la générer).

Les protocoles marqués d'un "~" sont des protocoles dont l'affichage est inconstant pour des raisons restées non identifiées. En effet, parfois des caractères parasites s'affichent.