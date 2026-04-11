<div class="note">

<u>Notes du traducteur :</u> Le guide initial a été traduit par [VETSEL Patrice](mailto:vetsel.patrice@wanadoo.fr) et la révision pour la version 2 de Shorewall a été effectuée par [Fabien Demassieux](mailto:fd03x@wanadoo.fr). J'ai assuré la révision pour l'adapter à la version 3, puis 4 de Shorewall. Si vous trouvez des erreurs ou des améliorations à y apporter vous pouvez [me contacter](mailto:guy@posteurs.com).

</div>

<div class="caution">

**Cet article s'applique à Shorewall 4.0 et à ses versions ultérieures. Si vous utilisez une version plus ancienne de Shorewall, référez-vous à la documentation s'appliquant à votre version.**

</div>

<div class="caution">

**Ne tentez pas d'installer Shorewall sur un système distant. Il est pratiquement certain que vous vous enfermerez à l'extérieur de ce système.**

</div>

# Introduction

Configurer Shorewall sur un système isolé Linux est très simple si vous comprenez les bases et suivez la documentation.

Ce guide ne prétend pas vous apprendre tous les rouages de Shorewall. Il se concentre sur ce qui est nécessaire pour configurer Shorewall dans son utilisation la plus courante :

- Un système Linux

- Une seule adresse IP externe

- Une connexion passant par un modem câble, ADSL, ISDN-RNIS, Frame Relay, RTC... ou bien une connexion à un réseau local (LAN) et vous souhaitez simplement protéger votre système Linux des autres systèmes sur ce réseau local.

## Pré-requis système

Shorewall a besoin que le package `iproute`/`iproute2` soit installé (avec la distribution RedHat, le package s'appelle `iproute`). Vous pouvez vérifier que le package est installé en contrôlant la présence du programme `ip` sur votre firewall. En tant que `root`, vous pouvez utiliser la commande `which` pour cela:

    [root@gateway root]# which ip
    /sbin/ip
    [root@gateway root]#

## Avant de commencer

Je vous recommande de commencer par une lecture complète du guide afin de vous familiariser avec les concepts mis en oeuvre, puis de recommencer la lecture et seulement alors d'appliquer vos modifications de configuration.

<div class="caution">

Si vous éditez vos fichiers de configuration sur un système Windows, vous devez les enregistrer comme des fichiers Unix si votre éditeur supporte cette option, sinon vous devez les convertir avec `dos2unix` avant d'essayer de les utiliser. De la même manière, si vous copiez un fichier de configuration depuis votre disque dur Windows vers une disquette, vous devez lancer `dos2unix` sur la copie avant de l'utiliser avec Shorewall.

Version Windows de dos2unix

Version Linux de dos2unix

</div>

## Conventions

Les points ou les modifications qui s'imposent sont indiqués par .

# PPTP/ADSL

Si vous êtes équipé d'un modem ADSL et que vous utilisez PPTP pour communiquer avec un serveur à travers ce modem, vous devez faire les changements [suivants](../features/PPTP.md#PPTP_ADSL) en plus de ceux décrits ci-dessous. ADSL avec PPTP est répandu en Europe, notamment en Autriche.

# Les Concepts de Shorewall

Les fichiers de configuration pour Shorewall sont situés dans le répertoire `/etc/shorewall` -- pour de simples paramétrages, vous n'aurez à faire qu'avec quelques-uns d'entre eux comme décrit dans ce guide. Après avoir [installé Shorewall](Install_fr.md),vous pourrez trouver les exemples de la manière suivante:

1.  Si vous avez installé shorewall en utilisant un RPM, les exemples seront dans le sous-répertoire `Samples/one-interface/` du répertoire de la documentation de Shorewall. Si vous ne savez pas où se trouve le répertoire de la documentation de Shorewall, vous pouvez trouver les exemples en utilisant cette commande:

        ~# rpm -ql shorewall | fgrep one-interface
        /usr/share/doc/packages/shorewall/Samples/one-interface
        /usr/share/doc/packages/shorewall/Samples/one-interface/interfaces
        /usr/share/doc/packages/shorewall/Samples/one-interface/policy
        /usr/share/doc/packages/shorewall/Samples/one-interface/rules
        /usr/share/doc/packages/shorewall/Samples/one-interface/zones
        ~#

2.  Si vous avez installé depuis le tarball, les exemples sont dans le répertoire `Samples/one-interface` du tarball.

3.  Si vous avez installé en utilisant un .deb de Shorewall 3.x, les exemples sont dans `/usr/share/doc/shorewall/examples/one-interface`. Il vous faut installer le paquetage shorewall-doc.

4.  Si vous avez installé en utilisant un .deb de Shorewall 4.x, les exemples sont dans `/usr/share/doc/shorewall/examples/one-interface`. Vous n'avez pas besoin d'installer le paquetage shorewall-doc pour pouvoir accéder aux exemples.

<div class="warning">

**Note aux utilisateurs de Debian et de Ubuntu**

Si vous vous servez du .deb pour installer, vous vous rendrez compte que votre répertoire `/etc/shorewall` est vide. Ceci est voulu. Les squelettes des fichiers de configuration se trouvent sur votre système dans le répertoire `/usr/share/doc/shorewall/default-config`. Copiez simplement les fichiers dont vous avez besoin depuis ce répertoire dans `/etc/shorewall`, puis modifiez ces copies.

</div>

Si vous installez la version 3.4.0 de Shorewall ou une version ultérieure, au fur et à mesure de la présentation de chaque fichier, je vous suggère de jeter un oeil à ceux qui sont physiquement présents sur votre système et que vous voyez la [page de manuel (man page)](../reference/configuration_file_basics.md#Manpages) pour ce fichier. Par exemple, tapez `man shorewall-zones` à l'invite du système pour voir la page de manuel du fichier `/etc/shorewall/zones`.

Si vous installez une version antérieure à shorewall 3.4.0, au fur et à mesure de la présentation de chaque fichier, je vous suggère de jeter un oeil à ceux qui sont physiquement présents sur votre système -- chacun de ces fichiers contient des instructions de configuration détaillées et des entrées par défaut.

Shorewall voit le réseau où il fonctionne, comme étant composé d'un ensemble de *zones*. Dans les fichiers de configuration fournis dans l'archive d'exemples pour une seule interface, deux zones seulement sont définies :

    #ZONE   TYPE    OPTIONS                 IN                      OUT
    #                                       OPTIONS                 OPTIONS
    fw      firewall
    net     ipv4

Les zones de Shorewall sont définies dans `/etc/shorewall/zones`.

Remarquez que Shorewall reconnaît le système de firewall comme étant sa propre zone. Le nom de la zone firewall (**fw** dans l'exemple plus haut) est stocké dans la variable d'environnement *\$FW,* qui peut être utilisée depuis l'ensemble des autres fichiers de configuration de Shorewall pour faire référence au firewall lui-même.

Les règles concernant le trafic à autoriser ou à interdire sont exprimées en utilisant les termes de zones.

- Vous exprimez votre politique par défaut pour les connexions d'une zone vers une autre zone dans le fichier [`/etc/shorewall/policy`](https://shorewall.org/manpages/shorewall-policy.html).

- Vous définissez les exceptions à ces politiques pas défaut dans le fichier [`/etc/shorewall/rules`](https://shorewall.org/manpages/shorewall-rules.html).

Pour chaque connexion demandant à entrer dans le firewall, la requête est en premier lieu vérifiée par rapport au contenu du fichier `/etc/shorewall/rules`. Si aucune règle dans ce fichier ne correspond à la demande de connexion alors la première politique dans le fichier `/etc/shorewall/policy` qui y correspond sera appliquée. S'il y a une [action commune](../reference/shorewall_extension_scripts.md) définie pour cette politique dans `/etc/shorewall/actions` ou dans `/usr/share/shorewall/actions.std` cette action commune sera exécutée avant que la politique ne soit appliquée. Le but de l'action commune est double:

- Elle ignore (DROP) ou rejette (REJECT) silencieusement le trafic courant qui n'est pas dangereux qui sans cela encombrerait votre fichier journal - les messages de broadcast, par exemple.

- Elle garantit que le trafic nécessaire à un fonctionnement normal est autorisé à traverser le firewall — ICMP *fragmentation-needed* par exemple

Le fichier `/etc/shorewall/policy` inclus dans l'archive d'exemple (one-interface) contient les politiques suivantes:

    #SOURCE ZONE   DESTINATION ZONE   POLICY   LOG LEVEL   LIMIT:BURST
    $FW            net                ACCEPT
    net            all                DROP     info
    all            all                REJECT   info

Ces politiques vont :

1.  Autoriser (ACCEPT) toute demande de connexion depuis le firewall vers internet

2.  Ignorer (DROP) toutes les demandes de connexion depuis internet vers votre firewall

3.  Rejeter (REJECT) toutes les autres requêtes de connexion. Shorewall à toujours besoin de cette dernière politique.

A ce point, éditez votre `/etc/shorewall/policy` et faites y les changements que vous désirez.

# Interface Externe

Le firewall possède une seule interface réseau. Lorsque la connexion internet passe par un "modem" câble ou ADSL, l'*Interface Externe* sera l'adaptateur ethernet qui est connecté à ce “Modem” (par exemple `eth0`). Par contre, si vous vous connectez par **PPPoE** (*Point-to-Point Protocol* over Ethernet) ou par **PPTP** *(Point-to-Point Tunneling Protocol),* l'interface externe sera une interface ppp (par exemple `ppp0`). Si vous vous connectez par un simple modem RTC, votre interface externe sera aussi `ppp0`. Si vous vous connectez en utilisant l'ISDN, votre interface externe sera `ippp0`.

<div class="caution">

Assurez-vous de savoir laquelle de vos interfaces est l'interface externe. Certains utilisateurs qui avaient configuré la mauvaise interface ont passé des heures avant de comprendre leur erreur. Si vous n'êtes pas sûr, tapez la commande `ip route ls` en tant que root. L'interface listée à la fin (default) devrait être votre interface externe.

Exemple:

    root@lists:~# ip route ls
    192.168.2.2 dev tun0  proto kernel  scope link  src 192.168.2.1 
    10.13.10.0/24 dev tun1  scope link 
    192.168.2.0/24 via 192.168.2.2 dev tun0 
    206.124.146.0/24 dev eth0  proto kernel  scope link  src 206.124.146.176 
    10.10.10.0/24 dev tun1  scope link 
    default via 206.124.146.254 dev eth0 
    root@lists:~# 

Dans cette exemple, l'interface externe est `eth0`.

</div>

Les fichiers de configuration d'exemple pour le firewall monoposte (one-interface) supposent que votre interface externe est `eth0`. Si votre configuration est différente, vous devrez modifier le fichier`/etc/shorewall/interfaces` en conséquence. Tant que vous y êtes, vous pourriez parcourir la liste des options qui sont spécifiées pour les interfaces. Quelques astuces:

<div class="tip">

Si votre interface vers l'extérieur est **`ppp0`** ou **`ippp0`**, vous pouvez remplacer le “detect” dans la seconde colonne par un “-” (sans guillemets).

</div>

<div class="tip">

Si votre interface vers l'extérieur est **`ppp0`** or **`ippp0`** ou si vous avez une adresse IP statique, vous pouvez enlever “dhcp” de la liste des options .

</div>

# Adresses IP

Avant d'aller plus loin, nous devons dire quelques mots au sujet des adresses IP. Normalement, votre Fournisseur d' Accès Internet (FAI) ne vous allouera qu'une seule adresse IP. Cette adresse peut vous être allouée par DHCP (Dynamic Host Configuration Protocol), lors de l'établissement de votre connexion (modem standard) ou bien lorsque vous établissez un autre type de connexion PPP (PPPoA, PPPoE, etc.). Dans certains cas , votre fournisseur peut vous allouer une adresse statique IP. Dans ce cas vous devez configurer l'interface externe de votre firewall afin d'utiliser cette adresse de manière permanente.

La RFC 1918 réserve des plages d'adresses IP pour utilisation dans les réseau privés:

    10.0.0.0    - 10.255.255.255
    172.16.0.0  - 172.31.255.255
    192.168.0.0 - 192.168.255.255

Ces adresses sont parfois nommées *non-routables* car les routeurs centraux d'internet ne transfèrent pas un paquet dont la destination est une adresse réservée par la RFC 1918. Dans certain cas cependant, les FAI (fournisseurs d'accès Internet) peuvent vous affecter une de ces adresses et utiliser la Traduction d'Adresses Réseau (NAT *Network Address Translation*) pour réécrire les en-têtes des paquets transmis en provenance ou à destination d'internet.

Avant de lancer Shorewall, **il faut impérativement regarder l'adresse IP de votre interface externe, et, si elle est dans l'une des plages précédentes, vous devez enlever l'option "norfc1918" dans la ligne concernant l'interface externe dans le fichier `/etc/shorewall/interfaces`**

<div class="tip">

Pour déterminer l'adresse IP de votre interface externe, en tant que root tapez `ip addr ls dev <interface>` à l'invite du système. \<*interface*\> étant votre interface externe. La ligne qui commence par *inet* vous donne votre adresse IP.

Exemple:

    root@lists:~# ip addr ls dev eth0
    2: eth0: <BROADCAST,MULTICAST,UP,10000> mtu 1500 qdisc htb qlen 1000
        link/ether 00:02:e3:08:48:4c brd ff:ff:ff:ff:ff:ff
        inet 206.124.146.176/24 brd 206.124.146.255 scope global eth0
        inet6 fe80::202:e3ff:fe08:484c/64 scope link 
           valid_lft forever preferred_lft forever
    root@lists:~# 

Dans cet exemple, l'adresse IP de votre interface externe est 206.124.146.176

</div>

.

# Journalisation (log)

Shorewall ne produit pas un fichier journal lui-même, mais il s'appuie sur votre [configuration de la journalisation système](../features/shorewall_logging.md). Les [commandes](https://shorewall.org/manpages/shorewall.html) suivantes nécessitent un bonne configuration de la journalisation, car elles ont besoin de connaitre le fichier dans lequel netfilter enregistre ses messages.

- `shorewall show log` (Affiche les 20 derniers messages enregistrés par netfilter)

- `shorewall logwatch` (Consulte le fichier journal à un intervalle régulier paramétrable)

- `shorewall dump` (Produit un état très détaillé à inclure à vos rapports d'anomalie)

Il est important que ces commandes fonctionnent correctement. En effet, lorsque vous rencontrez des problèmes de connexion alors que shorewall est actif, la première chose que vous devriez faire est de regarder le journal netfilter, et vous pourrez généralement résoudre rapidement votre problème en vous aidant de la [FAQ 17 de Shorewall](FAQ_fr.md#faq17).

La plupart du temps, les messages de Netfilter sont journalisés dans le fichier `/var/log/messages`. Certaines version récentes de SuSE/OpenSuSE sont pré configurées pour utiliser syslog-ng et journalisent les messages de netfilter dans le fichier `/var/log/firewall`.

Si votre distribution enregistre les message de netfilter dans un autre fichier que `/var/log/messages`, il faut modifier le paramètre LOGFILE dans le fichier `/etc/shorewall/shorewall.conf` et y spécifier le nom de votre fichier journal.

<div class="important">

Le paramètre LOGFILE ne contrôle pas le fichier dans lequel netfilter va enregistrer ses messages -- Il indique simplement à /sbin/`shorewall`où trouver le fichier journal.

</div>

# Permettre d'autres connexions

Shorewall inclue une collection de [macros](???) qui peuvent être utilisées pour rapidement autoriser ou refuser des services. Vous pouvez trouver une liste des macros comprises dans votre version de Shorewall en utilisant la commande `ls /usr/share/shorewall/macro.*` ou bien la commande `shorewall show macros` si vous utilisez une version 3.0.3 ou ultérieure de shorewall.

Si vous souhaitez autoriser des connexions depuis internet vers votre firewall et que vous avez trouvé une macro appropriée dans `/etc/shorewall/macro.*`, le format général d'une règle dans `/etc/shorewall/rules` est le suivant:

    #ACTION         SOURCE    DESTINATION     PROTO       DEST PORT(S)
    <macro>/ACCEPT  net       $FW

<div class="important">

Assurez-vous d'ajouter vos règles après la ligne contenant **SECTION NEW.**

</div>

    #ACTION     SOURCE    DESTINATION     PROTO       DEST PORT(S)
    Web/ACCEPT  net       $FW
    IMAP/ACCEPT net       $FW

Vous pouvez aussi choisir de coder vos règles directement, sans utiliser de macro pré-définie. Ceci sera nécessaire quand aucune macro pré-définie ne répond à vos besoins. Dans ce cas, le format général d'une règle dans `/etc/shorewall/rules` est:

    #ACTION   SOURCE    DESTINATION     PROTO       DEST PORT(S)
    ACCEPT    net       $FW             <protocol>  <port>

    #ACTION   SOURCE    DESTINATION     PROTO       DEST PORT(S)
    ACCEPT    net       $FW             tcp          80
    ACCEPT    net       $FW             tcp          143

Si vous ne savez pas quel port ou protocole utilise une application donnée, allez voir [ici](../features/ports.md).

<div class="important">

Je ne recommande pas d'activer `telnet` depuis/vers internet car il utilise du texte en clair (y compris pour le login !). Si vous voulez un accès shell à votre firewall, utilisez SSH:

    #ACTION     SOURCE    DESTINATION     PROTO       DEST PORT(S)
    SSH/ACCEPT  net       $FW           

</div>

Maintenant, éditez votre fichier de configuration `/etc/shorewall/``rules` pour ajouter, modifier ou supprimer d'autres connexions suivant vos besoins.

# Démarrer et Arrêter Votre Firewall

La [procédure d'installation](Install_fr.md) configure votre système pour lancer Shorewall dès le boot du système, mais le lancement est désactivé, de façon à ce que votre système ne tente pas de lancer Shorewall avant que la configuration ne soit terminée. Une fois que vous en avez fini avec la configuration du firewall, vous devez éditer /etc/shorewall/shorewall.conf et y mettre STARTUP_ENABLED=Yes.

<div class="important">

**Les utilisateurs des paquets .deb doivent éditer `/etc/default/shorewall` et mettre `startup=1`**.

</div>

<div class="important">

**Vous devez activer le lancement de Shorewall en éditant `/etc/shorewall/shorewall.conf` et en y mettant `STARTUP_ENABLED=Yes`.**

</div>

Le firewall est activé en utilisant la commande “`shorewall start`” et arrêté avec la commande “`shorewall stop`”. Lorsque le firewall est arrêté, le routage est autorisé sur les hôtes qui possèdent une entrée dans `/etc/shorewall/routestopped`. Un firewall qui tourne peut être relancé en utilisant la commande “`shorewall restart`”. Si vous voulez enlever toute trace de Shorewall sur votre configuration de Netfilter, utilisez “**shorewall clear**”

<div class="warning">

Si vous êtes connecté à votre firewall depuis internet, n'essayez pas d'exécuter une commande “`shorewall stop`” tant que vous n'avez pas ajouté une entrée dans `/etc/shorewall/routestopped` pour l'adresse IP à partir de laquelle vous êtes connecté . De la même manière, je vous déconseille d'utiliser “`shorewall restart`”; il est plus intéressant de créer [une configuration alternative](../reference/configuration_file_basics.md#Configs) et de la tester en utilisant la commande “[shorewall try](../reference/starting_and_stopping_shorewall.md)”

</div>

# Si cela ne marche pas

- Vérifiez à nouveau chacun des points repérés par un flèche rouge.

- Vérifiez vos [journaux](../features/shorewall_logging.md).

- Vérifiez le [Troubleshooting Guide](../reference/troubleshoot.md).

- Vérifiez la [FAQ](FAQ_fr.md).

# Autres Lectures Recommandées

Je vous recommande vivement de lire la [page des fonctionnalités générales des fichiers de configuration](../reference/configuration_file_basics.md) -- elle contient des astuces sur des possibilités de Shorewall qui peuvent rendre plus aisée l'administration de votre firewall Shorewall.
