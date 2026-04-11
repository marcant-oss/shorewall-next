<div class="note">

<u>Notes du traducteur :</u> Le guide initial a été traduit par [VETSEL Patrice](mailto:vetsel.patrice@wanadoo.fr) et la pour la version 2 de Shorewall a été effectuée par [Fabien Demassieux](mailto:fd03x@wanadoo.fr). J'ai assuré la révision pour l'adapter à la version 3 de Shorewall. Si vous trouvez des erreurs ou des améliorations à y apporter vous pouvez [me contacter](mailto:guy@posteurs.com).

</div>

<div class="caution">

**Cet article s'applique à Shorewall 4.0 et à ses versions ultérieures. Si vous utilisez une version plus ancienne de Shorewall, référez-vous à la documentation s'appliquant à votre version**.

</div>

<div class="caution">

**Ne tentez pas d'installer Shorewall sur un système distant. Il est pratiquement certain que vous vous enfermerez à l'extérieur de ce système.**

</div>

# Introduction

Mettre en place un système Linux en tant que firewall pour un petit réseau est une chose assez simple, si vous comprenez les bases et que vous suivez la documentation.

Ce guide ne prétend pas vous apprendre tous les rouages de Shorewall. Il se concentre sur ce qui est nécessaire pour configurer Shorewall dans son utilisation la plus courante:

- Un système Linux utilisé en tant que firewall/routeur pour un petit réseau local.
- **Une seule adresse IP publique.**
  <div class="note">

  Si vous avez plus d'une adresse IP publique, ce n'est pas le guide qui vous convient -- regardez plutôt du coté du [Guide de Configuration Shorewall](shorewall_setup_guide_fr.md).

  </div>
- Une connexion passant par un modem câble, ADSL, ISDN-RNIS, Frame Relay, RTC...

Voici le schéma d'une installation typique:

<figure id="Figure1">
<img src="images/basics.png" />
<figcaption>Configuration standard d'un firewall avec deux interfaces</figcaption>
</figure>

<div class="caution">

Si vous éditez vos fichiers de configuration sur un système Windows, vous devez les enregistrer comme des fichiers Unix si votre éditeur supporte cette option sinon vous devez les convertir avec `dos2unix` avant d'essayer de les utiliser. De la même manière, si vous copiez un fichier de configuration depuis votre disque dur Windows vers une disquette, vous devez lancer `dos2unix` sur la copie avant de l'utiliser avec Shorewall.

- [Windows Version of `dos2unix`](http://www.simtel.net/pub/pd/51438.html)

- [Linux Version of `dos2unix`](http://www.megaloman.com/%7Ehany/software/hd2u/)

</div>

## Pré-requis Système

Shorewall a besoin que le package `iproute`/`iproute2` soit installé (avec la distribution RedHat, le package s'appelle `iproute`). Vous pouvez vérifier que le package est installé en contrôlant la présence du programme `ip` sur votre firewall. En tant que `root`, vous pouvez utiliser la commande `which` pour cela:

    [root@gateway root]# which ip
    /sbin/ip
    [root@gateway root]#

Je vous recommande de commencer par une lecture complète du guide afin de vous familiariser avec les concepts mis en oeuvre, puis de recommencer la lecture et seulement alors d'appliquer vos modifications de configuration.

## Conventions

Les points où des modifications s'imposent sont indiqués par .

Les notes de configuration qui sont propres à LEAF/Bering sont marquées avec .

# PPTP/ADSL

Si vous êtes équipé d'un modem ADSL et que vous utilisez PPTP pour communiquer avec un serveur à travers ce modem, vous devez faire les changements [suivants](../features/PPTP.md#PPTP_ADSL) en plus de ceux décrits ci-dessous. ADSL avec PPTP est répandu en Europe, notamment en Autriche.

# Les Concepts de Shorewall

Les fichiers de configuration pour Shorewall sont situés dans le répertoire `/etc/shorewall` -- pour de simples paramétrages, vous n'aurez à faire qu'avec quelques-uns d'entre eux comme décrit dans ce guide.

<div class="warning">

**Note aux utilisateurs de Debian et de Ubuntu**

Si vous vous servez du .deb pour installer, vous vous rendrez compte que votre répertoire `/etc/shorewall` est vide. Ceci est voulu. Les squelettes des fichiers de configuration se trouvent sur votre système dans le répertoire `/usr/share/doc/shorewall/default-config`. Copiez simplement les fichiers dont vous avez besoin depuis ce répertoire dans `/etc/shorewall`, puis modifiez ces copies.

</div>

<div class="important">

Après avoir [installé Shorewall](Install_fr.md), vous pourrez trouver les exemples de la manière suivante:

1.  Si vous avez installé en utilisant un RPM, les exemples seront dans le sous-répertoire `Samples/two-interfaces/` du répertoire de la documentation de Shorewall. Si vous ne savez pas où se trouve le répertoire de la documentation de Shorewall, vous pouvez trouver les exemples en utilisant cette commande:

        ~# rpm -ql shorewall-common | fgrep two-interfaces
        /usr/share/doc/packages/shorewall/Samples/two-interfaces
        /usr/share/doc/packages/shorewall/Samples/two-interfaces/interfaces
        /usr/share/doc/packages/shorewall/Samples/two-interfaces/masq
        /usr/share/doc/packages/shorewall/Samples/two-interfaces/policy
        /usr/share/doc/packages/shorewall/Samples/two-interfaces/routestopped
        /usr/share/doc/packages/shorewall/Samples/two-interfaces/rules
        /usr/share/doc/packages/shorewall/Samples/two-interfaces/zones
        ~#

2.  Si vous avez installé depuis le tarball, les exemples sont dans le répertoire `Samples/two-interfaces` du tarball.

3.  Si vous avez installé en utilisant un .deb de Shorewall 3.x, les exemples sont dans `/usr/share/doc/shorewall/examples/two-interface`. Il vous faut installer le paquetage shorewall-doc.

4.  Si vous avez installé en utilisant un .deb de Shorewall 4.x, les exemples sont dans `/usr/share/doc/shorewall-common/examples/two-interface`. Vous n'avez pas besoin d'installer le paquetage shorewall-doc pour pouvoir accéder aux exemples.

</div>

Si vous installez la version 3.4.0 de Shorewall ou une version ultérieure, au fur et à mesure de la présentation de chaque fichier, je vous suggère de jeter un oeil à ceux qui sont physiquement présents sur votre système et que vous voyez la [page de manuel (man page)](../reference/configuration_file_basics.md#Manpages) pour ce fichier. Par exemple, tapez `man shorewall-zones` à l'invite du système pour voir la page de manuel du fichier `/etc/shorewall/zones`.

Si vous installez une version antérieure à shorewall 3.4.0, au fur et à mesure de la présentation de chaque fichier, je vous suggère de jeter un oeil à ceux qui sont physiquement présents sur votre système -- chacun de ces fichiers contient des instructions de configuration détaillées et des entrées par défaut.

Shorewall voit le réseau où il fonctionne, comme étant composé d'un ensemble de zones. Dans une configuration avec deux interfaces, les noms de zone suivants sont utilisés:

    #ZONE   TYPE     OPTIONS                 IN                      OUT
    #                                        OPTIONS                 OPTIONS
    fw      firewall
    net     ipv4
    loc     ipv4

Les zones de Shorewall sont définies dans le fichier [`/etc/shorewall/zones`](https://shorewall.org/manpages/shorewall-zones.html).

Remarquez que Shorewall reconnaît le système de firewall comme sa propre zone. Quand le fichier `/etc/shorewall/zones` est traité, le nom de la zone firewall est stocké dans la variable d'environnement *\$FW*, qui peut être utilisée depuis l'ensemble des autres fichiers de configuration de Shorewall pour faire référence au firewall lui-même.

Les règles à propos du trafic à autoriser et à interdire sont exprimées en utilisant le terme de zones.

- Vous exprimez votre politique par défaut pour les connexions d'une zone vers une autre zone dans le fichier [`/etc/shorewall/``policy`](https://shorewall.org/manpages/shorewall-policy.html).
- Vous définissez les exceptions à ces politiques pas défaut dans le fichier [`/etc/shorewall/rules`](https://shorewall.org/manpages/shorewall-rules.html).

Pour chaque connexion demandant à entrer dans le firewall, la requête est en premier lieu vérifiée par rapport au contenu du fichier `/etc/shorewall/rules`. Si aucune règle dans ce fichier ne correspond à la demande de connexion alors la première politique dans le fichier `/etc/shorewall/policy` qui y correspond sera appliquée. S'il y a une [action commune](../reference/shorewall_extension_scripts.md) définie pour cette politique dans `/etc/shorewall/actions` ou dans `/usr/share/shorewall/actions.std` cette action commune sera exécutée avant que la politique ne soit appliquée. Le but de l'action commune est double:

- Elle ignore (DROP) ou rejette (REJECT) silencieusement le trafic courant qui n'est pas dangereux qui sans cela encombrerait votre fichier journal - les messages de broadcast, par exemple.

- Elle garantit que le trafic nécessaire à un fonctionnement normal est autorisé à traverser le firewall — ICMP *fragmentation-needed* par exemple

Le fichier `/etc/shorewall/policy` inclus dans l'archive d'exemple (two-interface) contient les politiques suivantes:

    #SOURCE    DEST        POLICY      LOG LEVEL    LIMIT:BURST
    loc        net         ACCEPT
    net        all         DROP        info
    all        all         REJECT      info

Dans le fichier d'exemple (two-interface), la ligne suivante est incluse mais elle est commentée. Si vous voulez que votre firewall puisse avoir un accès complet aux serveurs sur internet, dé-commentez cette ligne.

    #SOURCE    DEST        POLICY      LOG LEVEL    LIMIT:BURST
    $FW        net         ACCEPT

Ces politiques vont:

- Autoriser (ACCEPT) toutes les demandes de connexion depuis votre réseau local vers internet

- Ignorer (DROP) toutes les demandes de connexion depuis internet vers votre firewall ou votre réseau local

- Autoriser (ACCEPT) toutes les demandes de connexion de votre firewall vers internet (si vous avez dé-commenté la politique additionnelle)

- Rejeter (REJECT) toutes les autres requêtes de connexion.

Il est important de remarquer que les politiques Shorewall (ainsi que les règles) font référence à des **connexions** et non pas à un flux de paquets. Avec les politiques définies dans le fichier `/etc/shorewall/policy` présenté plus haut, les connexions sont autorisées de la zone “loc” vers la zone “net” même si les connexions ne sont pas permises de la zone “loc” vers le firewall lui-même.

A ce point, éditez votre fichier `/etc/shorewall/``policy` et faites-y les changements que vous désirez.

# Interfaces Réseau

![](images/basics.png)

Le firewall possède deux interfaces réseau. Lorsque la connexion internet passe par un “modem” câble ou ADSL, *l'*Interface Externe** sera l'adaptateur ethernet qui est connecté à ce “Modem” (par exemple `eth0`). Par contre, si vous vous connectez avec PPPoE (Point-to-Point Protocol over Ethernet) ou avec PPTP (Point-to-Point Tunneling Protocol), l'interface externe sera une interface ppp (par exemple `ppp0`). Si vous vous connectez avec un simple modem RTC, votre interface externe sera aussi `ppp0`. Si vous vous connectez en utilisant l'ISDN, votre interface externe sera `ippp0`.

<div class="caution">

Assurez-vous de savoir laquelle de vos interfaces est l'interface externe. Certains utilisateurs qui avaient configuré la mauvaise interface ont passé des heures avant de comprendre leur erreur. Si vous n'êtes pas sûr, tapez la commande `ip route ls` en tant que root. L'interface listée à la fin (default) devrait être votre interface externe.

Exemple:

    root@lists:~# ip route ls
    192.168.1.1 dev eth0  scope link 
    192.168.2.2 dev tun0  proto kernel  scope link  src 192.168.2.1 
    192.168.3.0/24 dev br0  proto kernel  scope link  src 192.168.3.254 
    10.13.10.0/24 dev tun1  scope link 
    192.168.2.0/24 via 192.168.2.2 dev tun0 
    192.168.1.0/24 dev br0  proto kernel  scope link  src 192.168.1.254 
    206.124.146.0/24 dev eth0  proto kernel  scope link  src 206.124.146.176 
    10.10.10.0/24 dev tun1  scope link 
    default via 206.124.146.254 dev eth0 
    root@lists:~# 

Dans cette exemple, l'interface externe est `eth0`.

</div>

**Si votre interface vers l'extérieur est** **ppp0** ou **ippp0** **alors il faut mettre `CLAMPMSS=yes` dans le fichier `/etc/shorewall/``shorewall.conf`**.

Votre *Interface Interne* (interface vers votre réseau local LAN) sera un adaptateur ethernet (`eth1` or `eth0`) et sera connectée à un hub ou un switch. Vos autres ordinateurs seront connectés à ce même hub ou switch (note: Si vous avez un seul ordinateur, vous pouvez y connecter le firewall directement en utilisant un câble croisé).

<div class="warning">

**Ne connectez pas les interfaces interne et externe sur le même hub ou le même switch, sauf à des fins de test**. Vous pouvez tester en utilisant ce type de configuration si vous spécifiez l'option **arp_filter** ou l'option **arp_ignore** dans le fichier `/etc/shorewall/``interfaces, et ce` pour toutes les interfaces connectées au hub/switch commun. **Il est très fortement déconseillé d'utiliser une telle configuration avec un firewall en production**.

</div>

Le fichier de configuration d'exemple pour un firewall à deux interfaces suppose que votre interface externe est `eth0` et que l'interface interne est `eth1`. Si votre configuration est différente, vous devrez modifier le fichier`/etc/shorewall/interfaces` en conséquence. Tant que vous y êtes, vous pourriez parcourir la liste des options qui sont spécifiées pour les interfaces. Quelques astuces:

<div class="tip">

Si votre interface vers l'extérieur est `ppp0` ou `ippp0`, vous pouvez remplacer le detect dans la seconde colonne par un “-” (sans guillemets).

</div>

<div class="tip">

Si votre interface vers l'extérieur est `ppp0` or `ippp0` ou si vous avez une adresse IP statique, vous pouvez enlever `dhcp` dans la liste des options .

</div>

<div class="tip">

Si votre interface est un bridge utilisant l'utilitaire `brctl` alors **vous devez ajouter l'option `routeback` à la liste des options**.

</div>

# Adresses IP

Avant d'aller plus loin, nous devons dire quelques mots au sujet des adresses IP. Normalement, votre Fournisseur d' Accès Internet (FAI) ne vous allouera qu'une seule adresse IP. Cette adresse peut vous être allouée par DHCP (Dynamic Host Configuration Protocol), lors de l'établissement de votre connexion (modem standard) ou bien lorsque vous établissez un autre type de connexion PPP (PPPoA, PPPoE, etc.). Dans certains cas , votre fournisseur peut vous allouer une adresse statique IP. Dans ce cas vous devez configurer l'interface externe de votre firewall afin d'utiliser cette adresse de manière permanente.

Quelle que soit la façon dont votre adresse externe vous est attribuée, elle va être partagée par tous vos systèmes lors de l'accès à internet. Vous devrez assigner vos propres adresses au machines de votre réseau local (votre interface interne sur le firewall ainsi que les autres ordinateurs). La RFC 1918 réserve des plages d'adresses IP pour l'utilisation dans les réseau privés:

    10.0.0.0    - 10.255.255.255
    172.16.0.0  - 172.31.255.255
    192.168.0.0 - 192.168.255.255

Avant de lancer Shorewall, **il faut regarder l'adresse IP de votre interface externe, et, si elle est dans l'une des plages précédentes, vous devez enlever l'option "norfc1918" dans la ligne concernant l'interface externe dans le fichier `/etc/shorewall/interfaces`**.

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

Vous devrez allouer vos adresses depuis le même sous-réseau (subnet). Pour ce faire, nous pouvons considérer un sous-réseau comme étant une plage d'adresses `allant de x.y.z.0 à x.y.z.255`. Un tel sous-réseau aura un masque (subnet mask) `de 255.255.255.0`. L'adresse `x.y.z.0` est réservée comme l'adresse de sous-réseau *(Subnet Address*) et l'adresse `x.y.z.255` est réservée en tant qu'adresse de diffusion (*broadcast*). Dans Shorewall, un tel sous-réseau est décrit en utilisant [la notation CIDR (Classless InterDomain Routing)](shorewall_setup_guide_fr.md#Subnets) qui consiste en l'adresse du sous-réseau suivie par`/`24. Le “24” indiquant le nombre consécutif de bits à “1” dans la partie gauche du masque de sous-réseau.

|                         |
|:------------------------|
| Etendue:                |
| Adresse de sous-réseau: |
| Adresse de diffusion:   |
| Notation CIDR:          |

Un exemple de sous-réseau :

La convention veut que l'on affecte à l'interface interne du firewall la première adresse utilisable du sous-réseau (`10.10.10.1` dans l'exemple précédent) ou bien la dernière adresse utilisable (`10.10.10.254`).

L'un des objectifs de la gestion en sous-réseaux est de permettre à tous les ordinateurs du sous-réseau de savoir avec quels autres ordinateurs ils peuvent communiquer directement. Pour communiquer avec des systèmes en dehors du sous-réseau auquel ils appartiennent, les ordinateurs doivent envoyer leurs paquets par l'intermédiaire d'une passerelle (gateway).

Vos ordinateurs locaux (computer 1 et computer 2 dans le diagramme) doivent être configurés avec leur passerelle par défaut (default gateway) pointant sur l'adresse IP de l'interface interne du firewall.

Cette brève présentation ne fait qu'effleurer la question des sous-réseaux et du routage. Si vous voulez en apprendre plus sur l'adressage IP et le routage, je recommande “IP Fundamentals: What Everyone Needs to Know about Addressing & Routing”, Thomas A. Maufer, Prentice-Hall, 1999, ISBN 0-13-975483-0 ([link](http://www.phptr.com/browse/product.asp?product_id={58D4F6D4-54C5-48BA-8EDD-86EBD7A42AF6})).

Dans le reste de ce guide on prendra l'hypothèse que vous avez configuré votre réseau comme montré ci-dessous :

![](images/basics1.png)

La passerelle par défaut pour les ordinateurs Computer 1 et Computer 2 sera `10.10.10.254`.

<div class="warning">

Votre FAI (fournisseur d'accès internet) pourrait vous allouer une adresse de la **RFC 1918** pour votre interface externe. Si cette adresse est le sous-réseau `10.10.10.0/24` alors **vous aurez besoin d'un sous-réseau RFC 1918 DIFFÉRENT pour votre réseau local**.

</div>

# IP Masquerading (SNAT)

On désigne parfois les adresses réservées par la RFC 1918 comme étant non-routables, car les routeurs centraux d'internet (backbone) ne font pas suivre les paquets qui ont une adresse de destination appartenant à la RFC-1918. Lorsqu'un de vos systèmes en local (supposons Computer 1 dans le [schéma ci-dessus](#Diagram)) envoie une demande de connexion à un serveur internet, le firewall doit effectuer une traduction d'adresse réseau ou *Network Address Translation (*NAT). Le firewall réécrit l'adresse source dans le paquet et la remplace par l'adresse de l'interface externe du firewall; en d'autres termes, le firewall fait croire à l'hôte destination sur internet que c'est le firewall lui même qui initie la connexion. Ceci est nécessaire afin que l'hôte de destination soit capable de renvoyer les paquets au firewall (souvenez vous que les paquets qui ont pour adresse de destination une adresse réservée par la RFC 1918 ne peuvent pas être routés à travers internet, donc l'hôte internet ne peut adresser sa réponse à l'ordinateur 1). Lorsque le firewall reçoit le paquet de réponse, il réécrit l'adresse de destination à `10.10.10.1` et fait passer le paquet vers l'ordinateur Computer 1.

Sur les systèmes Linux, ce procédé est souvent appelé *IP Masquerading* mais vous verrez aussi le terme de traduction d'adresses source ou *Source Network Address Translation* (SNAT). Shorewall suit la convention utilisée avec Netfilter:

- *Masquerade* désigne le cas ou vous laissez votre firewall détecter automatiquement l'adresse de votre interface externe.

- *SNAT* désigne le cas où vous spécifiez explicitement l'adresse source des paquets sortant de votre réseau local.

Sous Shorewall, autant le *Masquerading* que la *SNAT* sont configurés avec des entrées dans le fichier `/etc/shorewall/masq`. Vous utiliserez normalement le Masquerading si votre adresse IP externe est dynamique, et la SNAT si votre adresse IP externe est statique.

Si l'interface externe de votre firewall est `eth0`, vous n'avez pas besoin de modifier le fichier fourni avec [l'exemple](#Concepts). Dans le cas contraire, éditez `/etc/shorewall/masq` et changez la première colonne par le nom de votre interface externe, et la seconde colonne par le nom de votre interface interne.

Si votre adresse externe IP est statique, vous pouvez la mettre dans la troisième colonne (SNAT) dans `/etc/shorewall/``masq` si vous le désirez. De toutes façons votre firewall fonctionnera bien si vous laissez cette colonne vide. Le fait de mettre votre adresse IP statique dans la troisième colonne permet un traitement des paquets sortants un peu plus efficace.

Si vous utilisez un paquetage Debian, vérifiez dans votre fichier de configuration `shorewall.conf` que la valeur suivante est convenablement paramétrée, sinon faites les changements nécessaires:

- `IP_FORWARDING=On`

# Transfert de ports (DNAT)

Un de vos objectifs est peut-être de faire tourner un ou plusieurs serveurs sur nos ordinateurs locaux. Comme ces ordinateurs ont une adresse RFC-1918, il n' est pas possible pour les clients sur internet de s'y connecter directement. Il faudra plutôt à que ces clients adressent leurs demandes de connexion au firewall qui réécrira l'adresse de votre serveur comme adresse de destination, puis lui fera passer le paquet. Lorsque votre serveur retournera sa réponse, le firewall appliquera automatiquement une règle [SNAT](#SNAT) pour réécrire l'adresse source dans la réponse.

Ce procédé est appelé transfert de port (*Port Forwarding)* ou traduction d'adresses réseau destination ou *Destination Network Address Translation* (DNAT). Vous configurez le transfert de port en utilisant des règles DNAT dans le fichier `/etc/shorewall/rules`.

La forme générale d'une simple règle de transfert de port dans `/etc/shorewall/rules` est:

    #ACTION   SOURCE    DEST                                          PROTO      DEST PORT(S)
    DNAT      net       loc:<server local ip address>[:<server port>] <protocol> <port>

<div class="important">

Assurez-vous d'ajouter vos règles après la ligne contenant **SECTION NEW.**

</div>

<div class="important">

Le serveur doit avoir une adresse IP statique. Si vous utilisez DHCP pour attribuer les adresses de votre système local, vous devez configurer votre serveur DHCP pour qu'il attribue toujours la même adresse IP aux hôtes cible d'une règle DNAT.

</div>

Shorewall possède des [macros](../concepts/Macros.md) pour de nombreuses applications. Regardez le résultat de la commande `shorewall show macros` pour avoir une liste des macros comprises dans votre version de Shorewall. Les macros simplifient la création de règles DNAT en fournissant directement le protocole et le(s) port(s) pour un service standard comme on peut le voir dans les exemples suivants:

Si vous voulez faire tourner un serveur Web sur l'ordinateur Computer 2 dans le [diagramme ci-dessus](#Diagram) et que vous voulez faire passer les requêtes TCP sur le port 80 à ce système :

    #ACTION   SOURCE    DEST             PROTO     DEST PORT(S)
    Web/DNAT  net       loc:10.10.10.2

Si vous faites tourner un serveur FTP sur l'ordinateur [Computer 1](#Diagram) et que vous voulez re-diriger les requêtes TCP entrantes sur le port 21 vers ce système:

    #ACTION    SOURCE    DEST            PROTO     DEST PORT(S)
    FTP/DNAT   net       loc:10.10.10.1  

Pour FTP, vous aurez aussi besoin d'avoir le support du suivi de connexion et du NAT pour FTP dans votre noyau (kernel). Pour les noyaux fournis dans une distribution, cela veut dire que les modules `ip_conntrack_ftp` et `ip_nat_ftp` (`nf_conntrack_ftp` et `nf_nat_ftp` dans les noyaux 2.6) doivent être disponibles. Shorewall chargera automatiquement ces modules si ils sont disponibles à leur emplacement habituel `/lib/modules/<kernel version>/kernel/net/ipv4/netfilter`. Pour plus d'information, reportez-vous à la documentation [Shorewall FTP](../features/FTP.md).

Deux points importants sont à garder en mémoire :

- Vous devez tester les règles précédentes depuis un client à l'extérieur de votre réseau local (c.a.d., ne pas tester depuis un navigateur tournant sur l'ordinateur Computer 1 ou Computer 2 ni sur le firewall). Si vous voulez avoir la possibilité d'accéder à votre serveur web ou FTP depuis l'intérieur de votre firewall en utilisant l'adresse de l'interface externe IP, consultez [Shorewall FAQ \#2](FAQ_fr.md#faq2).

- Quelques Fournisseurs d'Accès Internet (FAI) bloquent les requêtes de connexion entrantes sur le port 80. Si vous avez des problèmes pour vous connecter à votre serveur web, essayez la règle suivante et connectez vous sur le port 5000 (c.a.d., connectez vous à `http://w.x.y.z:5000 ou w.x.y.z` est votre IP externe).

      #ACTION    SOURCE    DEST               PROTO     DEST PORT(S)
      DNAT       net       loc:10.10.10.2:80  tcp       5000

Maintenant, modifiez `/etc/shorewall/rules` pour ajouter les règles DNAT dont vous avez besoin.

<div class="important">

Quand vous testez des règles DNAT telles que celles présentées plus haut, **vous devez les tester depuis un client A L'EXTÉRIEUR DE VOTRE FIREWALL** (depuis la zone “net”). Vous ne pouvez pas tester ces règles de l'intérieur !

Pour des astuces en cas de problème avec la DNAT, [allez lire les FAQ 1a et 1b](FAQ_fr.md#faq1a).

</div>

Si vous avez besoin d'information pour paramétrer les règles DNAT pour des adresses externes multiples, consultez la [Shorewall Aliased Interface documentation](Shorewall_and_Aliased_Interfaces.md) et le [Guide de configuration Shorewall](shorewall_setup_guide_fr.md#dnat).

# Service de Noms de Domaines (DNS)

Normalement, quand vous vous connectez à votre fournisseur d'accès (FAI), en même temps que vous obtenez votre adresse IP, votre “resolver” pour le Service des Noms de Domaines ou *Domain Name Service* (DNS) pour le firewall est configuré automatiquement (c.a.d., le fichier `/etc/resolv.conf` est mis à jour). Il arrive que votre fournisseur d'accès vous donne une paire d'adresse IP pour les serveurs DNS afin que vous configuriez manuellement vos serveurs de noms primaire et secondaire. Quelle que soit la manière dont le DNS est configuré sur votre firewall, il est de votre responsabilité de configurer le “resolver” sur chacun de vos systèmes internes. Vous pouvez procéder d'une de ces deux façons :

- Vous pouvez configurer votre système interne pour utiliser les serveurs de noms de votre fournisseur d'accès. Si votre fournisseur vous donne les adresses de ses serveurs ou si ces adresses sont disponibles sur son site web, vous pouvez les utiliser pour configurer vos systèmes internes. Si cette information n' est pas disponible, regardez dans `/etc/resolv.conf` sur votre firewall -- les noms des serveurs sont donnés dans l'enregistrement "`nameserver`" de ce fichier.
- <span id="cachingdns"></span>Vous pouvez configurer un cache DNS (*Caching Name Server)* sur votre firewall. Red Hat fournit un RPM pour serveur cache DNS (ce RPM à aussi besoin aussi du paquetage RPM `bind`) et pour les utilisateurs de Bering, il y a le paquetage `dnscache.lrp`. Si vous adoptez cette approche, vous configurez vos systèmes internes pour utiliser le firewall lui même comme étant le seul serveur de noms primaire. Vous utilisez l'adresse IP interne du firewall (`10.10.10.254` dans l'exemple précédent) pour adresse du serveur de nom. Pour permettre à vos systèmes locaux d'accéder à votre serveur cache DNS, vous devez ouvrir le port 53 (à la fois UDP and TCP) depuis le réseau local vers le firewall; vous ferez ceci en ajoutant les règles suivantes dans `/etc/shorewall/``rules`.
      #ACTION    SOURCE    DEST               PROTO     DEST PORT(S)
      DNS/ACCEPT loc       $FW

# Autres Connexions

Les fichiers exemples inclus dans l'archive pour le firewall à deux interfaces (two-interface) contiennent les règles suivantes :

    #ACTION     SOURCE    DEST               PROTO     DEST PORT(S)
    DNS/ACCEPT  $FW       net

Ces règles autorisent l'accès DNS à partir de votre firewall et peuvent être enlevées si vous avez dé-commenté la ligne dans `/etc/shorewall/``policy` autorisant toutes les connexions depuis le firewall vers internet.

Dans la règle ci-dessus, “`DNS/ACCEPT`” est un exemple d'*invocation d'une macro*. Shorewall offre un certain nombre de macros pré-définies (voir `/usr/share/shorewall/macro.*`). Vous pouvez également [ajouter vos propres macros](../concepts/Macros.md).

Vous n'êtes pas obligés d'utiliser des macros. Vous pouvez aussi ajouter des régles dans le fichier `/etc/shorewall/rules`. Shorewall démarrera légèrement plus rapidement si vous codez directement vos règles que si vous utilisez les macros. La régle vue ci-dessus aurait également pu être codée comme cela:

    #ACTION    SOURCE    DEST               PROTO     DEST PORT(S)
    ACCEPT     $FW       net                udp       53
    ACCEPT     $FW       net                tcp       53

Au cas ou Shorewall n'inclue pas de macro pré-définie qui vous convienne, vous pouvez définir une macro vous-même ou bien coder directement les régles appropriées.

L'exemple inclue aussi la règle suivante:

    #ACTION      SOURCE    DEST               PROTO     DEST PORT(S)
    SSH/ACCEPT   loc       $FW

Cette régle autorise un serveur SSH sur votre firewall et la connexion à celui-ci depuis votre réseau local.

Si vous souhaitez autoriser d'autre connexions de votre firewall vers d'autres systèmes, la syntaxe générale d'une macro est:

    #ACTION         SOURCE    DEST               PROTO      DEST PORT(S)
    <macro>/ACCEPT  $FW       <destination zone>

La syntaxe générale lorsqu'on n'utilise pas de macro est:

    #ACTION    SOURCE    DEST               PROTO      DEST PORT(S)
    ACCEPT     $FW       <destination zone> <protocol> <port>

Si vous voulez ouvrir un serveur web sur votre firewall et que vous voulez le rendre accessible depuis le réseau local et depuis l'extérieur:

    #ACTION     SOURCE    DEST               PROTO     DEST PORT(S)
    Web/ACCEPT  net       $FW
    Web/ACCEPT  loc       $FW

Ces deux régles devraient évidemment s'ajouter à celles listées avant dans “[Vous pouvez configurer un cache DNS sur votre firewall](#cachingdns)”.

Si vous ne savez pas quel port(s) et protocole(s) une application particulière utilise, vous pouvez regarder [ici](../features/ports.md).

<div class="important">

Je ne recommande pas d'autoriser `telnet` vers/de internet parce qu'il utilise du texte en clair (même pour le login !). Si vous voulez un accès shell à votre firewall, utilisez SSH:

    #ACTION      SOURCE    DEST               PROTO     DEST PORT(S)
    SSH/ACCEPT   net       $FW

</div>

Les utilisateurs de Bering pourront ajouter les deux régles suivantes pour rester compatible avec la configuration du firewall de Jacques (Jacques's Shorewall configuration).

    #ACTION    SOURCE    DEST    PROTO     DEST PORT(S)
    ACCEPT     loc       $FW     udp       53          #Allow DNS Cache to work
    ACCEPT     loc       $FW     tcp       80          #Allow Weblet to work

Maintenant, éditez votre fichier de configuration `/etc/shorewall/``rules` pour ajouter, modifier ou supprimer d'autres connexions suivant vos besoins.

# Journalisation (log)

Shorewall ne produit pas un fichier journal lui-même, mais il s'appuie sur votre [configuration de la journalisation système](../features/shorewall_logging.md). Les [commandes](https://shorewall.org/manpages/shorewall.html) suivantes nécessitent un bonne configuration de la journalisation, car elles ont besoin de connaître le fichier dans lequel netfilter enregistre ses messages.

- `shorewall show log` (Affiche les 20 derniers messages enregistrés par netfilter)

- `shorewall logwatch` (Consulte le fichier journal à un intervalle régulier paramétrable)

- `shorewall dump` (Produit un état très détaillé à inclure à vos rapports d'anomalie)

Il est important que ces commandes fonctionnent correctement. En effet, lorsque vous rencontrez des problèmes de connexion alors que shorewall est actif, la première chose que vous devriez faire est de regarder le journal netfilter, et vous pourrez généralement résoudre rapidement votre problème en vous aidant de la [FAQ 17 de Shorewall](FAQ_fr.md#faq17).

La plupart du temps, les messages de Netfilter sont journalisés dans le fichier `/var/log/messages`. Certaines version récentes de SuSE/OpenSuSE sont pré configurées pour utiliser syslog-ng et journalisent les messages de netfilter dans le fichier `/var/log/firewall`.

Si votre distribution enregistre les message de netfilter dans un autre fichier que `/var/log/messages`, il faut modifier le paramètre LOGFILE dans le fichier `/etc/shorewall/shorewall.conf` et y spécifier le nom de votre fichier journal.

<div class="important">

Le paramètre LOGFILE ne contrôle pas le fichier dans lequel netfilter va enregistrer ses messages -- Il indique simplement à /sbin/`shorewall`où trouver le fichier journal.

</div>

# Quelques Points à Garder en Mémoire

- **Vous ne pouvez pas tester votre firewall depuis l'intérieur de votre réseau**. Envoyer des requêtes à l'adresse IP externe de votre firewall ne signifie pas qu'elle seront associées à votre interface externe ou à la zone “net”. Tout trafic généré par le réseau local sera associé à l'interface locale et sera traité comme du trafic du réseau local vers le firewall (loc-\>fw).

- **Les adresses IP sont des propriétés des systèmes, pas des interfaces**. C'est une erreur de croire que votre firewall est capable de faire suivre (*forward*) des paquets simplement parce que vous pouvez faire un `ping` sur l'adresse IP de toutes les interfaces du firewall depuis le réseau local. La seule conclusion que vous puissiez tirer dans ce cas est que le lien entre le réseau local et le firewall fonctionne et que vous avez probablement la bonne adresse de passerelle par défaut sur votre système.

- **Toutes les adresses IP configurées sur le firewall sont dans la zone \$FW (fw)**. Si 192.168.1.254 est l'adresse IP de votre interface interne, alors vous pouvez écrire “**\$FW:192.168.1.254**” dans une régle mais vous ne devez pas écrire “**loc:192.168.1.254**”. C'est aussi une absurdité d'ajouter 192.168.1.254 à la zone **loc** en utilisant une entrée dans `/etc/shorewall/hosts`.

- **Les paquets de retour (reply) ne suivent PAS automatiquement le chemin inverse de la requête d'origine**. Tous les paquets sont routés en se référant à la table de routage respective de chaque hôte à chaque étape du trajet. Ce problème se produit en général lorsque on installe un firewall Shorewall en parallèle à une passerelle existante et qu'on essaye d'utiliser des règles DNAT dans Shorewall sans changer la passerelle par défaut sur les systèmes recevant les requêtes transférées (forwarded). Les requêtes passent dans le firewall Shorewall où l'adresse de destination IP est réécrite, mais la réponse revient par l'ancienne passerelle qui, elle, ne modifiera pas le paquet.

- **Shorewall lui-même n'a aucune notion du dedans et du dehors**. Ces concepts dépendent de la façon dont Shorewall est configuré.

# Démarrer et Arrêter Votre Firewall

La [procédure d'installation](Install_fr.md) configure votre système pour lancer Shorewall dès le boot du système, mais le lancement est désactivé, de façon à ce que votre système ne tente pas de lancer Shorewall avant que la configuration ne soit terminée. Une fois que vous en avez fini avec la configuration du firewall, vous devez éditer /etc/shorewall/shorewall.conf et y mettre STARTUP_ENABLED=Yes.

<div class="important">

Les utilisateurs des paquetages .deb doivent éditer `/etc/default/``shorewall` et mettre `startup=1`.

</div>

Le firewall est activé en utilisant la commande “`shorewall start`” et arrêté avec la commande “`shorewall stop`”. Lorsque le firewall est arrêté, le routage est autorisé sur les hôtes qui possèdent une entrée dans `/etc/shorewall/routestopped`. Un firewall qui tourne peut être relancé en utilisant la commande “`shorewall restart`”. Si vous voulez enlever toute trace de Shorewall sur votre configuration de Netfilter, utilisez “**shorewall clear**”

Les fichier de l'exemple Firewall à Deux Interfaces (two-interface) supposent que vous voulez autoriser le routage depuis ou vers `eth1` (le réseau local) lorsque Shorewall est arrêté. Si votre réseau local n' est pas connecté à `eth1` ou que vous voulez permettre l'accès depuis ou vers d'autres hôtes, modifiez `/etc/shorewall/``routestopped` en conséquence.

<div class="warning">

Si vous êtes connecté à votre firewall depuis internet, n'essayez pas d'exécuter une commande “`shorewall stop`” tant que vous n'avez pas ajouté une entrée dans `/etc/shorewall/routestopped` pour l'adresse IP à partir de laquelle vous êtes connecté . De la même manière, je vous déconseille d'utiliser “`shorewall restart`”; il est plus intéressant de créer [une configuration alternative](../reference/configuration_file_basics.md#Configs) et de la tester en utilisant la commande “[shorewall try](../reference/starting_and_stopping_shorewall.md)”

</div>

# Si cela ne marche pas

- Vérifiez à nouveau chacun des points repérés par un flèche rouge.

- Vérifiez vos [journaux](../features/shorewall_logging.md).

- Vérifiez le [Troubleshooting Guide](../reference/troubleshoot.md).

- Vérifiez la [FAQ](FAQ_fr.md).

# Autres Lectures Recommandées

Je vous recommande vivement de lire la [page des Fonctionnalités Générales des Fichiers de Configuration](../reference/configuration_file_basics.md) -- elle contient des astuces sur des possibilités de Shorewall qui peuvent rendre plus aisée l'administration de votre firewall Shorewall.

# Ajouter un Segment Sans-fil à votre Firewall à deux interfaces

Maintenant que vous avez une configuration à deux interfaces qui marche, l'étape suivante logique est d'ajouter un réseau sans-fil. La première chose à faire est d'ajouter une carte à votre firewall, soit une carte sans-fil soit une carte ethernet reliée à un point d'accès sans-fil.

<div class="caution">

Quant vous ajoutez une carte réseau à un machine, il se peut qu'elle ne soit pas détectée comme celle suivant la plus haute interface. Par exemple, si vous avez deux cartes sur votre système (`eth0` and `eth1`) et que vous en ajoutez une troisième qui utilise le même driver qu'une des deux autres, cette troisième carte ne sera pas obligatoirement détectée en tant que `eth2`. Elle peut très bien être détectée en tant que `eth0` ou `eth1`! Vous pouvez soit faire avec, soit intervertir les cartes dans les slots jusqu'à obtenir la valeur `eth2`pour la nouvelle carte.

**Update**: Les distributions s'améliorent sur ce point. SuSE associe maintenant un nom d'interface unique à chaque adresse MAC. D'autres distributions ont des paquetages additionnels qui permettent de gérer la relation entre l'adresse MAC et le nom de périphérique.

</div>

Votre nouveau réseau ressemblera à la figure ci-dessous.

La première chose à remarquer est que les ordinateurs sur votre réseau sans-fil seront sur un sous-réseau différent de celui de votre réseau local câblé LAN. Dans l'exemple, nous avons choisi de lui attribuer le réseau 10.10.11.0/24. Les ordinateurs Computer 3 et Computer 4 seront configurés avec une passerelle par défaut dont l'adresse IP sera 10.10.11.254.

Ensuite, nous avons choisi d'inclure le réseau sans-fil à la zone local. Puisque Shorewall autorise le trafic intra-zone par défaut, le trafic pourra circuler librement entre le réseau local câblé et le réseau sans-fil.

Il n'y a que deux changements à effectuer à la configuration de Shorewall:

- Une entrée doit être ajouté au fichier d'interfaces `/etc/shorewall/interfaces` pour l'interface du réseau sans-fil. Si l'interface du réseau sans-fil est `wlan0`, l'entrée correspondante devrait ressembler à:

      #ZONE     INTERFACE       BROADCAST          OPTIONS
      loc       wlan0           detect             maclist

  Comme montré dans l'entrée ci-dessus, je recommande d'utiliser l'[option maclist](../features/MAC_Validation.md) pour le segment sans-fil. En ajoutant les entrées pour les ordinateurs Computer 3 et Computer 4 dans le fichier `/etc/shorewall/maclist`, vous contribuez à vous assurer que vos voisins n'utiliseront pas votre connexion internet. Commencez sans cette option. Lorsque tout fonctionne, ajoutez l'option et configurez votre fichier `/etc/shorewall/maclist`.

- Vous devez ajouter une entrée au fichier `/etc/shorewall/masq` afin de permettre le trafic de votre réseau sans-fil vers internet. Si votre interface internet est `eth0` et votre interface sans-fil est `wlan0`, l'entrée sera:

      #INTERFACE           SUBNET             ADDRESS
      eth0                 wlan0

Autre chose. Pour que le réseau Microsoft fonctionne entre réseau filaire et sans-fil, vous avez besoin d'un serveur WINS ou bien d'un PDC. Personnellement, j'utilise Samba configuré en serveur WINS sur mon firewall. Utiliser un serveur WINS sur le firewall nécessite de configurer les régles nécessaires listées dans le [document Shorewall/Samba](samba.md).
