<div class="note">

<u>Notes du traducteur :</u> Le guide initial a été traduit par [VETSEL Patrice](mailto:vetsel.patrice@wanadoo.fr) et la révision pour la version 2 de Shorewall a été effectuée par [Fabien Demassieux](mailto:fd03x@wanadoo.fr). J'ai assuré la révision pour l'adapter à la version 3 de Shorewall. Si vous trouvez des erreurs ou des améliorations à y apporter vous pouvez [me contacter](mailto:guy@posteurs.com).

</div>

<div class="caution">

**Cet article s'applique à Shorewall 3.0 et à ses versions ultérieures. Si vous utilisez une version plus ancienne de Shorewall, référez-vous à la documentation s'appliquant à votre version**.

</div>

# Introduction

Mettre en place un système Linux en tant que firewall pour un petit réseau contenant une DMZ est une chose assez simple, si vous comprenez les bases et que vous suivez la documentation.

Ce guide ne prétend pas vous apprendre tous les rouages de Shorewall. Il se concentre sur ce qui est nécessaire pour configurer Shorewall dans son utilisation la plus courante:

- Un système Linux utilisé en tant que firewall/routeur pour un petit réseau local.

- Une seule adresse IP publique.

  <div class="note">

  Si vous avez plus d'une adresse IP, ce n'est pas le guide qui vous convient -- regardez plutôt du coté du [Guide de Configuration Shorewall](shorewall_setup_guide_fr.md).

  </div>

- Une DMZ connectée sur une interface ethernet séparée. L'objet d'une DMZ est d'isoler les systèmes de votre réseau local de vos serveurs qui sont exposés sur internet, de telle manière que, si un de ces serveurs était compromis, il reste encore un firewall entre le système compromis et vos systèmes locaux.

- Une connexion internet par le biais d'un modem câble, ADSL, ISDN-RNIS, "Frame Relay", RTC ...

Voici le schéma d'une installation typique.

<figure>
<img src="images/dmz1.png" />
<figcaption>Schéma d'une installation typique</figcaption>
</figure>

## Pré-requis Système

Shorewall a besoin que le paquetage `iproute`/`iproute2` soit installé (avec la distribution RedHat, le paquetage s'appelle `iproute`). Vous pouvez contrôler que le package est installé en vérifiant la présence du programme `ip` sur votre firewall. En tant que `root`, vous pouvez utiliser la commande `which` pour cela:

    [root@gateway root]# which ip
    /sbin/ip
    [root@gateway root]#

## Avant de commencer

Je vous recommande de commencer par une lecture complète du guide afin de vous familiariser avec les concepts mis en oeuvre, puis de recommencer la lecture et seulement alors d'appliquer vos modifications de configuration.

<div class="caution">

Si vous éditez vos fichiers de configuration sur un système Windows, vous devez les enregistrer comme des fichiers Unix si votre éditeur supporte cette option sinon vous devez les convertir avec `dos2unix` avant d'essayer de les utiliser. De la même manière, si vous copiez un fichier de configuration depuis votre disque dur Windows vers une disquette, vous devez lancer `dos2unix` sur la copie avant de l'utiliser avec Shorewall.

Version Windows de dos2unix

Version Linux de dos2unix

</div>

## Conventions

Les points où des modifications s'imposent sont indiqués par .

Les notes de configuration qui sont propres à LEAF/Bering sont marquées avec .

# PPTP/ADSL

Si vous êtes équipé d'un modem ADSL et que vous utilisez PPTP pour communiquer avec un serveur à travers ce modem, vous devez faire les changements [suivants](../features/PPTP.md#PPTP_ADSL) en plus de ceux décrits ci-dessous. ADSL avec PPTP est répandu en Europe, notamment en Autriche.

# Les Concepts de Shorewall

Les fichiers de configuration pour Shorewall sont situés dans le répertoire /etc/shorewall -- pour de simples paramétrages, vous n'aurez à faire qu'avec quelques-uns d'entre eux comme décrit dans ce guide.

<div class="warning">

**Note aux utilisateurs de Debian et de Ubuntu**

Si vous vous servez du .deb pour installer, vous vous rendrez compte que votre répertoire `/etc/shorewall` est vide. Ceci est voulu. Les squelettes des fichiers de configuration se trouvent sur votre système dans le répertoire `/usr/share/doc/shorewall/default-config`. Copiez simplement les fichiers dont vous avez besoin depuis ce répertoire dans `/etc/shorewall`, puis modifiez ces copies.

Remarquez que vous devez copier`/usr/share/doc/shorewall/default-config/shorewall.conf` et `/usr/share/doc/shorewall/default-config/modules` dans `/etc/shorewall` même si vous ne modifiez pas ces fichiers.

</div>

Après avoir installé Shorewall, vous pourrez trouver les exemples de la manière suivante:

1.  Si vous avez installé en utilisant un RPM, les exemples seront dans le sous-répertoire `Samples/three-interfaces/` du répertoire de la documentation de Shorewall. Si vous ne savez pas où se trouve le répertoire de la documentation de Shorewall, vous pouvez trouver les exemples en utilisant cette commande:

        ~# rpm -ql shorewall | fgrep three-interfaces
        /usr/share/doc/packages/shorewall/Samples/three-interfaces
        /usr/share/doc/packages/shorewall/Samples/three-interfaces/interfaces
        /usr/share/doc/packages/shorewall/Samples/three-interfaces/masq
        /usr/share/doc/packages/shorewall/Samples/three-interfaces/policy
        /usr/share/doc/packages/shorewall/Samples/three-interfaces/routestopped
        /usr/share/doc/packages/shorewall/Samples/three-interfaces/rules
        /usr/share/doc/packages/shorewall/Samples/three-interfaces/zones
        ~#

2.  Si vous avez installé depuis le tarball, les exemples sont dans le répertoire `Samples/three-interfaces` du tarball.

3.  Si vous avez installé en utilisant un .deb, les exemples sont dans `/usr/share/doc/shorewall/examples/three-interfaces`.

Au fur et à mesure de la présentation de chaque fichier, je vous suggère de jeter un oeil à ceux physiquement présents sur votre système -- chacun des fichiers contient des instructions de configuration détaillées et des entrées par défaut.

Shorewall voit le réseau où il fonctionne, comme étant composé d'un ensemble de zones. Dans une configuration avec trois interfaces, les noms des zones suivants sont utilisés:

    #ZONE   TYPE   OPTIONS                 IN                      OUT
    #                                      OPTIONS                 OPTIONS
    fw      firewall
    net     ipv4
    loc     ipv4
    dmz     ipv4

Les zones de Shorewall sont définies dans le fichier [`/etc/shorewall/``zones`](https://shorewall.org/Documentation.html#Zones).

Remarquez que Shorewall reconnaît le système de firewall comme sa propre zone. Quand le fichier `/etc/shorewall/zones` est traité, le nom de la zone firewall est stocké dans la variable d'environnement *\$FW* qui peut être utilisée depuis l'ensemble des autres fichiers de configuration de Shorewall, pour faire référence au firewall lui-même.

Les règles à propos du trafic à autoriser et à interdire sont exprimées en utilisant le terme de zones.

- Vous exprimez votre politique par défaut pour les connexions d'une zone vers une autre zone dans le fichier [`/etc/shorewall/``policy`](https://shorewall.org/Documentation.html#Policy).

- Vous définissez les exceptions à ces politiques pas défaut dans le fichier [`/etc/shorewall/``rules`](https://shorewall.org/Documentation.html#Rules).

Pour chaque connexion demandant à entrer dans le firewall, la requête est en premier lieu vérifiée par rapport au contenu du fichier `/etc/shorewall/rules`. Si aucune règle dans ce fichier ne correspond à la demande de connexion, alors la première politique dans le fichier `/etc/shorewall/policy` qui y correspond sera appliquée. S'il y a une [action commune](../reference/shorewall_extension_scripts.md) définie pour cette politique dans `/etc/shorewall/actions` ou dans `/usr/share/shorewall/actions.std` cette action commune sera exécutée avant que la politique ne soit appliquée. Le but de l'action commune est double:

- Elle ignore (DROP) ou rejete (REJECT) silencieusement le traffic courant qui n'est pas dangeureux qui sans cela encombrerait votre fichier journal - les messages de broadcast, par exemple.

- Elle garantit que le traffic nécessaire à un fonctionnement normal est autorisé à traverser le firewall — ICMP *fragmentation-needed* par exemple

Le fichier /etc/shorewall/policy inclus dans l'archive d'exemple (three-interface) contient les politiques suivantes:

    #SOURCE    DEST        POLICY      LOG LEVEL    LIMIT:BURST
    loc        net         ACCEPT
    net        all         DROP        info
    all        all         REJECT      info

<div class="important">

Dans le fichier d'exemple (three-interface), la ligne suivante est incluse mais elle est commentée. Si vous voulez que votre firewall puisse avoir un accès complet aux serveurs sur internet, dé-commentez la ligne.

    #SOURCE    DEST        POLICY      LOG LEVEL    LIMIT:BURST
    $FW         net         ACCEPT

</div>

Les politiques précédentes vont:

- Autoriser (ACCEPT) toutes les demandes de connexion depuis votre réseau local vers internet

- Ignorer (DROP) toutes les demandes de connexion depuis internet vers votre firewall ou votre réseau local

- Autoriser (ACCEPT) toutes les demandes de connexion de votre firewall vers internet (si vous avez dé-commenté la politique additionnelle)

- Rejeter (REJECT) toutes les autres requêtes de connexion.

Maintenant, éditez votre propre fichier `/etc/shorewall/policy` et faites-y les changements que vous désirez.

# Les Interfaces Réseau

<figure>
<img src="images/dmz1.png" />
<figcaption>DMZ</figcaption>
</figure>

Le firewall possède trois interfaces réseau. Lorsque la connexion internet passe par un “modem” câble ou ADSL **l'Interface Externe** sera l'adaptateur ethernet qui est connecté à ce “Modem” (par exemple `eth0`). Par contre, si vous vous connectez avec PPPoE (Point-to-Point Protocol over Ethernet) ou avec PPTP (Point-to-Point Tunneling Protocol), l'interface externe sera une interface ppp (par exemple `ppp0`). Si vous vous connectez avec un simple modem RTC, votre interface externe sera aussi `ppp0`. Si vous vous connectez en utilisant l'ISDN, votre interface externe sera `ippp0`.

**Si votre interface vers l'extérieur est `ppp0` ou `ippp0` alors vous mettrez CLAMPMSS=yes dans le fichier `/etc/shorewall/shorewall.conf`**.

Votre *Interface locale* sera un adaptateur ethernet (`eth0`, `eth1` or `eth2`) et sera connecté à un hub ou à un switch. Vos ordinateurs locaux seront connectés à ce même hub ou switch (note : si vous n'avez qu'un seul ordinateur en local, vous pouvez le connecter directement au firewall par un câble croisé).

Votre *interface DMZ* sera aussi un adaptateur ethernet (`eth0`, `eth1` or `eth2`) et sera connectée à un hub ou à un switch. Vos ordinateurs appartenant à la DMZ seront connectés à ce même hub ou switch (note : si vous n'avez qu'un seul ordinateur dans la DMZ, vous pouvez le connecter directement au firewall par un câble croisé).

<div class="warning">

**Ne connectez pas les interfaces interne et externe sur le même hub ou le même switch, sauf à des fins de test**. Vous pouvez tester en utilisant ce type de configuration si vous spécifiez l'option **arp_filter** ou l'option **arp_ignore** dans le fichier `/etc/shorewall/``interfaces, et ce` pour toutes les interfaces connectées au hub/switch commun. **Il est très fortement déconseillé d'utiliser une telle configuration avec un firewall en production**.

</div>

Le fichier de configuration d'exemple pour le firewall à trois interfaces suppose que votre interface externe est `eth0`, que l'interface locale est `eth1` et que la DMZ est sur l'interface `eth2`. Si votre configuration est différente, vous devrez modifier le fichier`/etc/shorewall/interfaces` en conséquence. Tant que vous y êtes, vous pourriez parcourir la liste des options qui sont spécifiées pour les interfaces. Quelques astuces:

<div class="tip">

Si votre interface vers l'extérieur est `ppp0` ou `ippp0`, vous pouvez remplacer le “detect” dans la seconde colonne par un “-” (sans guillemets).

</div>

<div class="tip">

Si votre interface vers l'extérieur est `ppp0` or `ippp0` ou si vous avez une adresse IP statique, vous pouvez enlever “dhcp” dans la liste des options .

</div>

# Adresses IP

Avant d'aller plus loin, nous devons dire quelques mots au sujet des adresses IP. Normalement, votre Fournisseur d' Accès Internet (FAI) ne vous allouera qu'une seule adresse IP. Cette adresse peut vous être allouée par DHCP (Dynamic Host Configuration Protocol), lors de l'établissement de votre connexion (modem standard) ou bien lorsque vous établissez un autre type de connexion PPP (PPPoA, PPPoE, etc.). Dans certains cas , votre fournisseur peut vous allouer une adresse statique IP. Dans ce cas vous devez configurer l'interface externe de votre firewall afin d'utiliser cette adresse de manière permanente.

Quelle que soit la façon dont votre adresse externe vous est attribuée, elle va être partagée par tous vos systèmes lors de l'accès à internet. Vous devrez assigner vos propres adresses au machines de votre réseau local (votre interface interne sur le firewall ainsi que les autres ordinateurs). La RFC 1918 réserve des plages d'adresses IP pour l'utilisation dans les réseau privés:

    10.0.0.0    - 10.255.255.255
    172.16.0.0  - 172.31.255.255
    192.168.0.0 - 192.168.255.255

Avant de lancer Shorewall, **il faut regarder l'adresse IP de votre interface externe, et, si elle est dans l'une des plages précédentes, vous devez enlever l'option "norfc1918" dans la ligne concernant l'interface externe dans le fichier `/etc/shorewall/interfaces`**.

Vous devrez allouer vos adresses depuis le même sous-réseau (subnet). Pour ce faire, nous pouvons considérer un sous-réseau comme étant une plage d'adresses `allant de x.y.z.0 à x.y.z.255`. Un tel sous-réseau aura un masque (subnet mask) `de 255.255.255.0`. L'adresse `x.y.z.0` est réservée comme l'adresse de sous-réseau *(Subnet Address*) et l'adresse `x.y.z.255` est réservée en tant qu'adresse de diffusion (*broadcast*). Dans Shorewall, un tel sous-réseau est décrit en utilisant [la notation CIDR (Classless InterDomain Routing)](shorewall_setup_guide_fr.md#Subnets) qui consiste en l'adresse du sous-réseau suivie par`/`24. Le “24” indiquant le nombre consécutif de bits à “1” dans la partie gauche du masque de sous-réseau.

|                         |
|:------------------------|
| Etendue:                |
| Adresse de sous-réseau: |
| Adresse de diffusion:   |
| Notation CIDR:          |

Un exemple de sous-réseau (sub-network) :

La convention veut que l'on affecte à l'interface interne du firewall la première adresse utilisable du sous-réseau (`10.10.10.1` dans l'exemple précédent) ou bien la dernière adresse utilisable (`10.10.10.254`).

L'un des objectifs de la gestion en sous-réseaux est de permettre à tous les ordinateurs du sous-réseau de savoir avec quels autres ordinateurs ils peuvent communiquer directement. Pour communiquer avec des systèmes en dehors du sous-réseau auquel ils appartiennent, les ordinateurs doivent envoyer leurs paquets par l'intermédiaire d'une passerelle (gateway).

Vos ordinateurs locaux (computer 1 et computer 2 dans le diagramme) doivent être configurés avec leur passerelle par défaut (default gateway) pointant sur l'adresse IP de l'interface interne du firewall. Les ordinateurs de votre DMZ (DMZ Computer 1 et DMZ computer 2) devraient être configurés avec leur passerelle par défaut (default gateway) pointant sur l'adresse IP de l'interface DMZ du firewall.

Cette brève présentation ne fait qu'effleurer la question des sous-réseaux et du routage. Si vous voulez en apprendre plus sur l'adressage IP et le routage, je recommande “IP Fundamentals: What Everyone Needs to Know about Addressing & Routing”, Thomas A. Maufer, Prentice-Hall, 1999, ISBN 0-13-975483-0 ([lien](http://www.phptr.com/browse/product.asp?product_id={58D4F6D4-54C5-48BA-8EDD-86EBD7A42AF6})).

Le reste de ce guide suppose que vous avez configuré votre réseau comme montré ci-dessous :

<figure>
<img src="images/dmz2.png" alt="La passerelle par défaut pour la DMZ sera 10.10.11.254 et la passerelle par défaut pour les ordinateurs locaux sera 10.10.10.254. Votre FAI pourrait allouer une adresse RFC 1918 à votre interface externe. Si cette adresse est le sous-réseau 10.10.10.0/24 alors vous aurez besoin d&#39;un sous-réseau RFC 1918 DIFFÉRENT pour votre réseau local." />
<figcaption>DMZ</figcaption>
</figure>

# IP Masquerading (SNAT)

Les adresses réservées par la RFC 1918 sont parfois désignées comme non-routables car les routeurs centraux d'internet (backbone) ne font pas suivre les paquets qui ont une adresse de destination appartenant à la RFC-1918. Lorsqu'un de vos systèmes en local (supposons Computer 1) envoie une demande de connexion à un serveur internet, le firewall doit effectuer une traduction d'adresse réseau ou *Network Address Translation (*NAT). Le firewall réécrit l'adresse source dans le paquet et la remplace par l'adresse de l'interface externe du firewall; en d'autres termes, le firewall fait croire que c'est lui même qui initie la connexion. Ceci est nécessaire afin que l'hôte de destination soit capable de renvoyer les paquets au firewall (souvenez vous que les paquets qui ont pour adresse de destination une adresse réservée par la RFC 1918 ne peuvent pas être routés à travers internet, donc l'hôte internet ne peut adresser sa réponse à l'ordinateur 1). Lorsque le firewall reçoit le paquet de réponse, il réécrit l'adresse de destination à `10.10.10.1` et fait passer le paquet vers l'ordinateur Computer 1.

Sur les systèmes Linux, ce procédé est souvent appelé *IP Masquerading* mais vous verrez aussi le terme de traduction d'adresses source ou *Source Network Address Translation* (SNAT). Shorewall suit la convention utilisée avec Netfilter:

- *Masquerade* désigne le cas ou vous laissez votre firewall détecter automatiquement l'adresse de votre interface externe.

- *SNAT* désigne le cas où vous spécifiez explicitement l'adresse source des paquets sortant de votre réseau local.

Sous Shorewall, autant le *Masquerading* que la *SNAT* sont configurés avec des entrées dans le fichier `/etc/shorewall/masq`. Vous utiliserez normalement le Masquerading si votre adresse IP externe est dynamique, et la SNAT si votre adresse IP externe est statique.

Si votre interface externe est `eth0`, si votre interface locale est `eth1` et que votre interface pour la DMZ est `eth2`, vous n'avez pas besoin de modifier le fichier fourni avec l'exemple. Dans le cas contraire, éditez `/etc/shorewall/``masq` et changez-le en conséquence.

Si, malgré les avertissements, vous utilisez ce guide et que vous voulez faire du NAT un-à-un (one-to-one NAT) ou du Proxy ARP pour votre DMZ, enlevez l'entrée pour `eth2` de `/etc/shorewall/masq`.

Si votre adresse externe IP est statique, vous pouvez la mettre dans la troisième colonne dans `/etc/shorewall/``masq` si vous le désirez. De toutes façons votre firewall fonctionnera bien si vous laissez cette colonne vide. Le fait de mettre votre adresse IP statique dans la troisième colonne permet un traitement des paquets sortants un peu plus efficace.

Si vous utilisez un paquetage Debian, vérifiez dans votre fichier de configuration `shorewall.conf` que la valeur suivante est convenablement paramétrée, sinon faites les changements nécessaires:

- `IP_FORWARDING=On`

# Transfert de ports (DNAT)

Un de nos objectifs est de faire tourner un ou plusieurs serveurs sur nos ordinateurs dans la DMZ. Puisque ces ordinateurs ont une adresse RFC-1918, il n'est pas possible pour les clients sur internet de s'y connecter directement. Il faudra plutôt à que ces clients adressent leurs demandes de connexion au firewall qui réécrira l'adresse de votre serveur comme adresse de destination, puis lui fera passer le paquet. Lorsque votre serveur retournera sa réponse, le firewall appliquera automatiquement une règle SNAT pour réécrire l'adresse source dans la réponse.

Ce procédé est appelé transfert de port (*Port Forwarding)* ou traduction d'adresses réseau destination ou *Destination Network Address Translation* (DNAT). Vous configurez le transfert de port en utilisant des règles DNAT dans le fichier `/etc/shorewall/rules`.

La forme générale d'une simple règle de transfert de port dans `/etc/shorewall/rules` est:

    #ACTION   SOURCE    DEST                                          PROTO      DEST PORT(S)
    DNAT      net       dmz:<server local IP address>[:<server port>] <protocol> <port>

Si vous ne spécifiez pas *`<server port>`*, il est supposé être le même que *`<port>`*.

<div class="important">

Assurez-vous d'ajouter vos règles après la ligne contenant **SECTION NEW.**

</div>

    #ACTION     SOURCE    DEST                PROTO      DEST PORT(S)
    Web/DNAT     net    dmz:10.10.11.2  
    Web/ACCEPT   loc    dmz:10.10.11.2

- L'entrée 1 fait suivre le port 80 depuis internet vers la DMZ.

- L'entrée 2 autorise les connexions depuis le réseau local.

Plusieurs points importants sont à garder en mémoire :

- Lorsque vous vous connectez à votre serveur à partir de votre réseau local, vous devez utiliser l'adresse IP interne du serveur (`10.10.11.2`).

- Quelques Fournisseurs d'Accès Internet (FAI) bloquent les requêtes de connexion entrantes sur le port 80. Si vous avez des problèmes pour vous connecter à votre serveur web, essayez la règle suivante et connectez vous sur le port 5000 (c.a.d., connectez vous à `http://w.x.y.z:5000 ou w.x.y.z` est votre IP externe).

      #ACTION   SOURCE    DEST                PROTO      DEST PORT(S)    SOURCE
      #                                                                  PORT(S)
      DNAT      net       dmz:10.10.11.2:80   tcp        80              5000

- Si vous voulez avoir la possibilité de vous connecter à votre serveur depuis le réseau local en utilisant votre adresse externe, et si vous avez une adresse IP externe statique (fixe), vous pouvez remplacer la règle loc-\>dmz précédente par :

      #ACTION   SOURCE    DEST            PROTO  DEST PORT(S)  SOURCE   ORIGINAL
      #                                                        PORT(S)  DEST
      DNAT      loc       dmz:10.10.11.2  tcp    80            -        <external IP>

  Si vous avez une IP dynamique, vous devez vous assurer que votre interface externe est en route avant de lancer Shorewall et vous devez suivre les étapes suivantes (en supposant que votre interface externe est `eth0`):

  1.  Insérez ce qui suit dans /etc/shorewall/params:

      `ETH0_IP=$(find_interface_address eth0)`

  2.  Votre règle `loc->dmz` deviendra:

          #ACTION   SOURCE    DEST             PROTO   DEST PORT(S)  SOURCE   ORIGINAL
          #                                                          PORT(S)  DEST
          DNAT      loc       dmz:10.10.11.2   tcp     80            -        $ETH0_IP

- Si vous voulez accéder à votre serveur depuis la DMZ en utilisant votre adresse IP externe, regardez la [FAQ 2a](FAQ_fr.md#faq2a).

Maintenant, modifiez `/etc/shorewall/rules` pour ajouter les règles DNAT dont vous avez besoin.

<div class="important">

Quand vous testez des règles DNAT telles que celles présentées plus haut, **vous devez les tester depuis un client A L'EXTÉRIEUR DE VOTRE FIREWALL** (depuis la zone “net”). Vous ne pouvez pas tester ces règles de l'intérieur !

Pour des astuces en cas de problème avec la DNAT, [allez lire les FAQ 1a et 1b](FAQ_fr.md#faq1a).

</div>

# Service de Noms de Domaines (DNS)

Normalement, quand vous vous connectez à votre fournisseur d'accès (FAI), en même temps que vous obtenez votre adresse IP, votre “resolver” pour le Service des Noms de Domaines ou *Domain Name Service* (DNS) pour le firewall est configuré automatiquement (c.a.d., le fichier `/etc/resolv.conf` est mis à jour). Il arrive que votre fournisseur d'accès vous donne une paire d'adresse IP pour les serveurs DNS afin que vous configuriez manuellement vos serveurs de noms primaire et secondaire. Quelle que soit la manière dont le DNS est configuré sur votre firewall, il est de votre responsabilité de configurer le “resolver” sur chacun de vos systèmes internes. Vous pouvez procéder d'une de ces deux façons :

- Vous pouvez configurer votre système interne pour utiliser les serveurs de noms de votre fournisseur d'accès. Si votre fournisseur vous donne les adresses de ses serveurs ou si ces adresses sont disponibles sur son site web, vous pouvez les utiliser pour configurer vos systèmes internes. Si cette information n' est pas disponible, regardez dans `/etc/resolv.conf` sur votre firewall -- les noms des serveurs sont donnés dans l'enregistrement "`nameserver`" de ce fichier.
- <span id="cachingdns"></span>Vous pouvez configurer un cache DNS (*Caching Name Server)* sur votre firewall. Red Hat fournit un RPM pour serveur cache DNS (ce RPM à aussi besoin aussi du paquetage RPM `bind`) et pour les utilisateurs de Bering, il y a le paquetage `dnscache.lrp`. Si vous adoptez cette approche, vous configurez vos systèmes internes pour utiliser le firewall lui même comme étant le seul serveur de noms primaire. Vous utilisez l'adresse IP interne du firewall (`10.10.10.254` dans l'exemple précédent) pour adresse du serveur de nom. Pour permettre à vos systèmes locaux d'accéder à votre serveur cache DNS, vous devez ouvrir le port 53 (à la fois UDP and TCP) depuis le réseau local vers le firewall; vous ferez ceci en ajoutant les règles suivantes dans `/etc/shorewall/``rules`.

Si vous faites tourner le serveur de noms sur le firewall:

    #ACTION     SOURCE    DEST                PROTO      DEST PORT(S)                      
    DNS/ACCEPT  loc       $FW
    DNS/ACCEPT  dmz       $FW            

Si vous faites tourner le serveur de noms sur l'ordinateur 1 de la DMZ:

    #ACTION     SOURCE    DEST                PROTO      DEST PORT(S)                      
    DNS/ACCEPT  loc       dmz:10.10.11.1
    DNS/ACCEPT  $FW       dmz:10.10.11.1             

Dans la régle ci-dessus, “DNS/ACCEPT” est un exemple d'utilisation d'une macro prédéfinie. Shorewall comprend un certain nombre de macros prédéfinies et vous pouvez [ajouter les vôtres](../concepts/Macros.md). Vous pouvez trouver une liste des macros comprises dans votre version de Shorewall en utilisant la commande `ls /usr/share/shorewall/macro.*` ou bien la commande `shorewall show macros` si vous utilisez une version 3.0.3 ou ultérieure de Shorewall.

Vous n'êtes pas obligé d'utiliser des macros prédéfinies et vous pouvez codez vos régles vous-même dans le fichier `/etc/shorewall/rules`. Le premier exemple vu plus haut (serveur de noms sur le firewall) aurait pu être codé comme suit:

    #ACTION   SOURCE    DEST                PROTO      DEST PORT(S)                      
    ACCEPT    loc       $FW                 tcp        53
    ACCEPT    loc       $FW                 udp        53
    ACCEPT    dmz       $FW                 tcp        53
    ACCEPT    dmz       $FW                 udp        53              

Au cas ou Shorewall n'inclue pas de macro pré-définie qui vous convienne, vous pouvez définir une macro vous-même ou bien coder directement les régles appropriées. Si vous ne savez pas quel port(s) et protocole(s) une application particulière utilise, vous pouvez regarder [ici](../features/ports.md).

# Autres Connexions

Les fichiers exemples inclus dans l'archive (three-interface) contiennent la règle suivante :

    #ACTION     SOURCE    DEST                PROTO      DEST PORT(S)                      
    DNS/ACCEPT  $FW       net       

Cette règle autorise l'accès DNS à partir de votre firewall. Elle peut être enlevée si vous avez dé-commenté la ligne dans `/etc/shorewall/``policy` autorisant toutes les connexions depuis le firewall vers internet.

L'exemple inclue aussi:

    #ACTION     SOURCE    DEST                PROTO      DEST PORT(S)                      
    SSH/ACCEPT  loc       $FW
    SSH/ACCEPT  loc       dmz        

Ces régles autorisent un serveur SSH sur votre firewall et sur chacun des systèmes de votre DMZ et permettent de s'y connecter depuis vos systèmes locaux (zone “loc”).

Si vous désirez autoriser d'autres connexions entre vos systèmes, la syntaxe générale d'une macro pré-définie est:

    #ACTION         SOURCE        DEST                PROTO      DEST PORT(S)                      
    <macro>/ACCEPT  <source zone> <destination zone>

La syntaxe générale lorsqu'on n'utilise pas de macro pré-définie est:

    #ACTION   SOURCE        DEST                PROTO      DEST PORT(S)                      
    ACCEPT    <source zone> <destination zone>  <protocol> <port> 

En utilisant une macro pré-définie:

    #ACTION     SOURCE    DEST                PROTO      DEST PORT(S)
    DNS/ACCEPT  net       $FW

En n'utilisant pas de macro pré-définie:

    #ACTION   SOURCE    DEST                PROTO      DEST PORT(S)                      
    ACCEPT    net       $FW                 tcp        53
    ACCEPT    net       $FW                 udp        53        

Ces deux régles viennent évidemment s'ajouter à celles présentées plus haut dans “[Vous pouvez configurer un cache DNS sur votre firewall](#cachingdns)”.

Si vous ne savez pas quel port(s) et protocole(s) une application particulière utilise, vous pouvez regarder [ici](../features/ports.md).

<div class="important">

Je ne recommande pas d'autoriser `telnet` vers/de internet parce qu'il utilise du texte en clair (même pour le login !). Si vous voulez un accès shell à votre firewall, utilisez SSH :

    #ACTION     SOURCE    DEST                PROTO      DEST PORT(S)                      
    SSH/ACCEPT  net       $FW

</div>

Les utilisateurs de Bering pourront ajouter les deux régles suivantes pour être compatible avec la configuration du firewall de Jacques (Jacques's Shorewall configuration).

    #ACTION   SOURCE    DEST                PROTO      DEST PORT(S)                      
    ACCEPT    loc       $FW                 udp        53
    ACCEPT    net       $FW                 tcp        80       

- L'entrée 1 autorise l'utilisation du Cache DNS.

- L'entrée 2 autorise le “weblet” à fonctionner.

Maintenant, éditez votre fichier de configuration `/etc/shorewall/``rules` pour ajouter, modifier ou supprimer d'autres connexions suivant vos besoins.

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

Les fichiers de l'exemple Firewall à Trois Interfaces (three-interface) supposent que vous voulez autoriser le routage depuis ou vers `eth1` (votre réseau local) et `eth2` (votre DMZ) lorsque Shorewall est arrêté. Si ces interfaces ne sont pas connectées à votre réseau local ou à votre DMZ, ou bien que vous voulez permettre l'accès depuis ou vers d'autres hôtes, modifiez `/etc/shorewall/``routestopped` en conséquence.

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
