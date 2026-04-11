<div class="note">

<u>Notes du traducteur :</u> Si vous trouvez des erreurs ou si vous avez des améliorations à apporter à cette documentation vous pouvez [me contacter](mailto:guy@posteurs.com).

</div>

<div class="caution">

**Cet article s'applique à Shorewall 3.0 et à ses versions ultérieures. Si vous utilisez une version plus ancienne de Shorewall, référez-vous à la documentation s'appliquant à votre version.**

</div>

# Contexte

Les systèmes sur lesquels tourne Shorewall fonctionnent en général comme des routeurs. Dans le modèle de référence OSI (Open System Interconnect), un routeur opère au niveau 3. Shorewall peut également être déployé sur un système GNU Linux se comportant comme un pont (bridge). Les ponts sont des équipements de niveau 2 dans le modèle OSI (pensez à un pont comme à un switch ethernet).

Voici quelques-unes des différences entre les routeurs et les ponts:

1.  Les routeurs déterminent la destination d'un paquet en fonction de l'adresse IP de destination alors que les ponts routent le trafic en fonction de l'adresse MAC de destination de la trame ethernet.

2.  Par conséquent, les routeurs peuvent être connectés à plusieurs réseaux IP alors qu'un pont ne peut appartenir qu'à un seul réseau.

3.  Dans la plupart des configurations, les routeurs ne font pas suivre les paquets de diffusion (broadcast) alors que les ponts le font.

    <div class="note">

    Les conditions dans lesquelles un routeur peut ou doit faire suivre les paquets de diffusion sont décrites dans la section 4 de la RFC 1812.

    </div>

# Pré-requis système

<div class="warning">

**LE SUPPORT POUR LES PONTS TEL QU'IL EST DECRIT DANS CET ARTICLE RISQUE D'ETRE ABANDONNE.** Les fonctions sous-jacentes de netfilter sur lesquelles le pont filtrant de Shorewall reposent sont en train d'être abandonnées et il n'est pas certain que Shorewall puisse continuer à supporter les ponts filtrants tels qu'ils sont décrits ici.

Dans [un autre article (en anglais)](https://shorewall.org/NewBridge.html), je décris comment configurer avec Shorewall un pont-routeur qui fonctionnera avec les versions futures du kernel.

</div>

N'importe quelle version de Shorewall fera l'affaire si vous avez besoin d'un pont mais que vous n'avez pas besoin de restreindre le trafic à travers ce pont. Pour plus de détails, reportez vous à la [Documentation pour un pont simple](../features/SimpleBridge.md).

Pour utiliser Shorewall comme pont filtrant:

- Votre noyau doit être compilé avec le support pour les ponts (CONFIG_BRIDGE=m ou CONFIG_BRIDGE=y).

- Votre noyau doit comprendre l'intégration bridge/netfilter (CONFIG_BRIDGE_NETFILTER=y).

- Votre noyau doit être compilé avec le support pour les correspondances physdev de Netfilter (CONFIG_IP_NF_MATCH_PHYSDEV=m ou CONFIG_IP_NF_MATCH_PHYSDEV=y). Le support des correspondances physdev est en standard dans le noyau 2.6 mais doit être patché dans les noyaux 2.4 (voir [icit](http://linux-net.osdl.org/index.php/Bridge)). Les utilisateurs de Bering et de Bering uCLibc doivent trouver et installer ipt_physdev.o pour leur distribution puis ajouter “ipt_physdev” au fichier `/etc/modules`.

- Votre version d'`iptables` doit offrir le support pour les correspondances physdev. Ceci est le cas avec iptables 1.2.9 et toutes ses versions ultérieures.

- Vous devez avoir installé le paquetage des utilitaires pour les ponts (bridge-utils).

# Application

Le diagramme au dessous présente une application classique d'un pont/firewall. Il y a déjà un routeur installé qui supporte un réseau local sur son interface interne et vous voulez insérer un firewall entre ce routeur et les systèmes de ce réseau local. Dans notre exemple, le réseau local utilise des adresses de la RFC 1918 mais ceci n'est pas obligatoire. Le pont marcherait de la même façon si on utilisait des adresses IP publiques (n'oubliez pas qu'un pont ne s'occupe pas d'adresses IP).

Il existe des différences clé entre cette configuration et une configuration normale de Shorewall:

- Le système Shorewall Pont/Firewall ne possède qu'une seule adresse IP même si il dispose de deux interfaces ethernet ! Cette adresse IP est configurée sur le pont même au lieu de l'être sur l'une des cartes réseau.

- Les systèmes connectés au LAN sont configurés avec l'adresse du routeur IP (192.168.1.254 dans notre exemple) comme passerelle par défaut.

- `traceroute` ne détectera pas le Pont/Firewall comme un routeur intermédiaire

- Si le routeur exécute un serveur DHCP, les hôtes connectés au réseau local peuvent utiliser ce serveur sans avoir à exécuter `dhcrelay` sure le Pont/Firewal.

<div class="warning">

L'insertion d'un pont filtrant entre un routeur et un ensemble d'hôtes locaux ne fonctionne que si ces machines locales forment un réseau IP unique. Dans le schéma ci-dessus, tous les hôtes dans la zone loc sont dans le réseau 192.168.1.0/24. Si le routeur doit router entre plusieurs réseaux locaux par la même interface physique (plusieurs réseaux IP partagent le même réseau local), l'insertion d'un pont filtrant entre le routeur et le réseau local ne fonctionnera pas.

</div>

Voici d'autres possibilités -- Il pourrait y avoir un hub ou un switch entre le routeur et le Pont/Firewall, et il pourrait y avoir d'autres systèmes connectés à ce hub ou ce switch. Tous les systèmes du coté local du routeur devraient toujours être configurés avec des adresses IP prises dans 192.168.1./24.

# Configuration du pont

Configure le pont est une chose assez simple. On se sert de l'utilitaire `brctl` issu du paquetage bridge-utils. Vous trouverez des informations sur la configuration d'un pont à <http://linux-net.osdl.org/index.php/Bridge>.

Malheureusement peu de distributions Linux ont de bons outils de configuration pour un pont et les outils de configuration réseau graphiques ne détectent pas la présence d'un pont. Voici l'extrait d'un fichier de configuration Debian pour un pont à deux interfaces et ayant une adresse IP statique:

>     auto br0
>     iface br0 inet static
>             address 192.168.1.253
>             netmask 255.255.255.0
>             network 192.168.1.0
>             broadcast 192.168.1.255
>             pre-up /sbin/ip link set eth0 up
>             pre-up /sbin/ip link set eth1 up
>             pre-up /usr/sbin/brctl addbr br0
>             pre-up /usr/sbin/brctl addif br0 eth0
>             pre-up /usr/sbin/brctl addif br0 eth1

Bien qu'il ne soit pas obligatoire de donner une adresse IP à un pont, le faire permet au Pont/Firewall d'accéder à d'autres systèmes et permet également l'administration distante du pont. Le pont doit aussi avoir une adresse IP pour que les politiques et les règles REJECT fonctionnent correctement - sinon les règles REJECT se comporteront exactement de la même manière que des règles DROP. Enfin, si un pont fait partie d'un [Pont/Routeur](#bridge-router), il est également indispensable de lui donner une adresse IP.

<div class="important">

Avant de configurer Shorewall, assurerez-vous d'avoir un pont qui fonctionne et qui se lance au boot.

</div>

On peut attribuer une adresse IP au pont par DHCP.

Voici un fichier `/etc/sysconfig/network/ifcfg-br0` issu d'un système SUSE:

>     BOOTPROTO='dhcp'
>     REMOTE_IPADDR=''
>     STARTMODE='onboot'
>     UNIQUE='3hqH.MjuOqWfSZ+C'
>     WIRELESS='no'
>     MTU=''

Voici un fichier /`etc/sysconfig/network-scripts/ifcfg-br0` issu d'un système Mandriva:

>     DEVICE=br0
>     BOOTPROTO=dhcp
>     ONBOOT=yes

Aussi bien sur les systèmes SUSE que sur les systèmes Mandriva, il faudra un script séparé pour configurer le pont.

Voilà les scripts dont je me sers sur un système SUSE 9.1.

> `/etc/sysconfig/network/ifcfg-br0`
>
>     BOOTPROTO='dhcp'
>     REMOTE_IPADDR=''
>     STARTMODE='onboot'
>     UNIQUE='3hqH.MjuOqWfSZ+C'
>     WIRELESS='no'
>     MTU=''
>
> `/etc/init.d/bridge`
>
>     #!/bin/sh
>
>     ################################################################################
>     #   Script to create a bridge
>     #
>     #     (c) 2004 - Tom Eastep (teastep@shorewall.net)
>     #
>     #   Modify the following variables to match your configuration
>     #
>     #### BEGIN INIT INFO
>     # Provides:       bridge
>     # Required-Start: coldplug
>     # Required-Stop:
>     # Default-Start:  2 3 5
>     # Default-Stop:   0 1 6
>     # Description:    starts and stops a bridge
>     ### END INIT INFO
>     #
>     # chkconfig: 2345 05 89
>     # description: GRE/IP Tunnel
>     #
>     ################################################################################
>
>
>     PATH=$PATH:/sbin:/usr/sbin:/usr/local/sbin
>
>     INTERFACES="eth1 eth0"
>     BRIDGE="br0"
>     MODULES="tulip"
>
>     do_stop() {
>         echo "Stopping Bridge $BRIDGE"
>         brctl delbr $BRIDGE
>         for interface in $INTERFACES; do
>             ip link set $interface down
>         done
>     }
>
>     do_start() {
>
>           echo "Starting Bridge $BRIDGE"
>           for module in $MODULES; do
>               modprobe $module
>           done
>
>           sleep 5
>
>           for interface in $INTERFACES; do
>               ip link set $interface up
>           done
>
>           brctl addbr $BRIDGE
>
>           for interface in $INTERFACES; do
>               brctl addif $BRIDGE $interface
>           done
>     }
>
>     case "$1" in
>       start)
>           do_start
>         ;;
>       stop)
>           do_stop
>         ;;
>       restart)
>           do_stop
>           sleep 1
>           do_start
>         ;;
>       *)
>         echo "Usage: $0 {start|stop|restart}"
>         exit 1
>     esac
>     exit 0

Voici une contribution de Axel Westerhold qui propose cet exemple de configuration d'un pont ayant une adresse statique sur un système Fedora (Core 1 and Core 2 Test 1). Remarquez que ces fichiers configurent également le pont ce qui évite d'avoir à écrire un script de configuration séparé.

> `/etc/sysconfig/network-scripts/ifcfg-br0:`
>
>     DEVICE=br0
>     TYPE=Bridge
>     IPADDR=192.168.50.14
>     NETMASK=255.255.255.0
>     ONBOOT=yes
>
> `/etc/sysconfig/network-scripts/ifcfg-eth0:`
>
>     DEVICE=eth0
>     TYPE=ETHER
>     BRIDGE=br0
>     ONBOOT=yes
>
> `/etc/sysconfig/network-scripts/ifcfg-eth1:`
>
>     DEVICE=eth1
>     TYPE=ETHER
>     BRIDGE=br0
>     ONBOOT=yes

Florin Grad de Mandriva fournit ce script pour configurer un pont:

>     #!/bin/sh
>     # chkconfig: 2345 05 89
>     # description: Layer 2 Bridge
>     #
>
>     [ -f /etc/sysconfig/bridge ] && . /etc/sysconfig/bridge
>
>     PATH=$PATH:/sbin:/usr/sbin:/usr/local/sbin
>
>     do_stop() {
>         echo "Stopping Bridge"
>         for i in $INTERFACES $BRIDGE_INTERFACE ; do
>             ip link set $i down
>         done
>         brctl delbr $BRIDGE_INTERFACE
>     }
>
>     do_start() {
>
>        echo "Starting Bridge"
>        for i in $INTERFACES ; do
>             ip link set $i up
>        done
>        brctl addbr br0
>        for i in $INTERFACES ; do
>             ip link set $i up
>             brctl addif br0 $i 
>        done
>        ifup $BRIDGE_INTERFACE 
>     }
>
>     case "$1" in
>       start)
>           do_start
>         ;;
>       stop)
>           do_stop
>         ;;
>       restart)
>           do_stop
>           sleep 1
>           do_start
>         ;;
>       *)
>         echo "Usage: $0 {start|stop|restart}"
>         exit 1
>     esac
>     exit 0
>
> Le fichier `/etc/sysconfig/bridge`:
>
>     BRIDGE_INTERFACE=br0          #The name of your Bridge
>     INTERFACES="eth0 eth1"        #The physical interfaces to be bridged

Andrzej Szelachowski a proposé la contribution suivante:

>     Here is how I configured bridge in Slackware:
>
>     1) I had to compile bridge-utils (It's not in the standard distribution)
>     2) I've created rc.bridge in /etc/rc.d:
>
>     #########################
>     #! /bin/sh
>
>     ifconfig eth0 0.0.0.0
>     ifconfig eth1 0.0.0.0
>     #ifconfig lo 127.0.0.1 #this line should be uncommented if you don't use rc.inet1
>
>     brctl addbr most
>
>     brctl addif most eth0
>     brctl addif most eth1
>
>     ifconfig most 192.168.1.31 netmask 255.255.255.0 up 
>     #route add default gw 192.168.1.1 metric 1 #this line should be uncommented if
>                                                #you don't use rc.inet1
>     #########################
>
>     3) I made rc.brige executable and added the following line to /etc/rc.d/rc.local
>
>     /etc/rc.d/rc.bridge 

Joshua Schmidlkofer a écrit:

>     Bridge Setup for Gentoo
>
>     #install bridge-utils
>     emerge bridge-utils
>
>     ## create a link for net.br0
>     cd /etc/init.d
>     ln -s net.eth0 net.br0
>
>     # Remove net.eth*, add net.br0 and bridge.
>     rc-update del net.eth0
>     rc-update del net.eth1
>     rc-update add net.br0 default
>     rc-update add bridge boot
>
>
>
>     /etc/conf.d/bridge:
>
>       #bridge contains the name of each bridge you want created.
>       bridge="br0"
>
>       # bridge_<bridge>_devices contains the devices to use at bridge startup.
>       bridge_br0_devices="eth0 eth1"
>
>     /etc/conf.d/net
>
>        iface_br0="10.0.0.1     broadcast 10.0.0.255 netmask 255.255.255.0"
>        #for dhcp:
>        #iface_br0="dhcp"
>        #comment this out if you use dhcp.
>        gateway="eth0/10.0.0.1" 

Les utilisateurs qui réussissent dans la configuration d'un pont sur d'autres distributions que celles présentées plus haut, sont encouragés à [m'envoyer](mailto:webmaster@shorewall.net) leurs configurations afin que je puisse les publier ici.

# Configuration de Shorewall

Dans Shorewall, on active le mode Pont avec l'option BRIDGING du fichier `/etc/shorewall/shorewall.conf`:

    BRIDGING=Yes

Dans le scénario présenté plus haut, il y aurait probablement deux zones définies. - une pour internet et une pour le réseau local, ce qui donnerait un fichier `/etc/shorewall/zones` comme celui-ci:

    #ZONE   TYPE            OPTIONS
    fw      firewall
    net     ipv4
    loc     ipv4
    #LAST LINE - ADD YOUR ENTRIES ABOVE THIS ONE - DO NOT REMOVE

Une politique habituelle à deux zones est parfaitement adaptée à ce cas — `/etc/shorewall/policy`:

    #SOURCE     DEST        POLICY        LOG       LIMIT:BURST
    loc         net         ACCEPT
    net         all         DROP          info
    all         all         REJECT        info
    #LAST LINE - ADD YOUR ENTRIES ABOVE THIS ONE - DO NOT REMOVE

Puisque c'est le pont lui-même qui est configuré avec une adresse IP, seul ce dispositif doit être défini pour Shorewall dans `/etc/shorewall/interfaces`:

    #ZONE    INTERFACE      BROADCAST       OPTIONS
    -       br0             192.168.1.255
    #LAST LINE -- ADD YOUR ENTRIES BEFORE THIS ONE -- DO NOT REMOVE

Les zones sont définies en utilisant le fichier `/etc/shorewall/hosts`. En supposant que le routeur est connecté à `eth0` et que le switch est connecté à `eth1`:

    #ZONE           HOST(S)                         OPTIONS
    net             br0:eth0
    loc             br0:eth1
    #LAST LINE -- ADD YOUR ENTRIES BEFORE THIS LINE -- DO NOT REMOVE

Même lorsque Shorewall est arrêté, vous voudrez probablement autoriser le trafic à transiter par le pont — `/etc/shorewall/routestopped`:

    #INTERFACE      HOST(S)         OPTIONS
    br0             192.168.1.0/24  routeback
    #LAST LINE -- ADD YOUR ENTRIES BEFORE THIS ONE -- DO NOT REMOVE

Pour la définition de votre jeu de règles pour votre firewall, vous pouvez prendre comme point de départ le fichier `/etc/shorewall/rules` présenté dans l'exemple de Firewall à Deux Interfaces.

# Combinaison Pont/Routeur

Un système Shorewall n'a pas à s'exécuter exclusivement comme un pont ou bien comme un routeur -- il peut parfaitement faire les deux. Voici un exemple:

Il s'agit quasiment de la même configuration que celle présentée dans le [Guide de Configuration de Shorewall](shorewall_setup_guide_fr.md) si ce n'est que la DMZ utilise un pont plutôt qu'un Proxy ARP. Les modifications à apporter à la configuration présentée dans le Guide de Configuration sont les suivants:

1.  Le fichier `/etc/shorewall/proxyarp` doit être vide dans cette configuration.

2.  Le fichier `/etc/shorewall/interfaces` ressemble à ceci:

        #ZONE    INTERFACE      BROADCAST     OPTIONS
        -        br0            detect        routefilter
        loc      eth1           detect

3.  Le fichier `/etc/shorewall/hosts` devrait avoir:

        #ZONE    HOSTS                        OPTIONS
        net      br0:eth0
        dmz      br0:eth2

4.  Les systèmes en DMZ ont besoin d'avoir une route par 192.0.2.176 vers le réseau 192.168.201.0/24 afin qu'ils puissent communiquer avec le réseau local.

# Limites

Avec certaines cartes sans fil, le mode pont ne fonctionne pas — vous pouvez regarder à <http://linux-net.osdl.org/index.php/Bridge>.

# Liens

- [Vous trouverez ici un article en Espagnol](http://wiki.buenosaireslibre.org/HowTos_2fBridgedFirewall) qui présente de manière détaillée comment “ponter” un réseau public et un réseau local avec Shorewall. Il s'agit d'une autre configuration en Pont/Routeur.
