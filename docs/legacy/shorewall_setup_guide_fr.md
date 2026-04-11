<div class="note">

<u>Notes du traducteur :</u> Le traduction initiale a été réalisée par [Fabien Demassieux](mailto:fd03x@wanadoo.fr). J'ai assuré la révision pour l'adapter à la version 3 de Shorewall. Si vous trouvez des erreurs ou des améliorations à y apporter vous pouvez [me contacter](mailto:guy@posteurs.com).

</div>

<div class="caution">

**Cet article s'applique à Shorewall 3.0 et à ses versions ultérieures. Si vous utilisez une version plus ancienne de Shorewall, référez-vous à la documentation s'appliquant à votre version.**

</div>

# Introduction

Ce guide est destiné aux utilisateurs qui configurent Shorewall dans un environnement où un ensemble d'adresses IP publiques doit être pris en compte ainsi qu'à ceux qui souhaitent en savoir plus à propos de Shorewall que ce que contiennent le guides pour une utilisation avec une [adresse IP unique](../reference/shorewall_quickstart_guide.md). Le champs d'application étant très large, ce guide vous donnera des indications générales à suivre et vous indiquera d'autres ressources si nécessaire.

<div class="caution">

Shorewall a besoin que le paquetage `iproute`/`iproute2` soit installé (avec la distribution RedHat, le paquetage s'appelle `iproute`). Vous pouvez contrôler que le paquetage est installé en vérifiant la présence du programme `ip` sur votre firewall. En tant que `root`, vous pouvez utiliser la commande `which` pour cela:

    [root@gateway root]# which ip
    /sbin/ip
    [root@gateway root]#

Je vous recommande de commencer par une lecture complète du guide afin de vous familiariser avec les concepts mis en oeuvre, puis de recommencer la lecture et seulement alors d'appliquer vos modifications de configuration.

Les points où des modifications s'imposent sont indiqués par .

</div>

<div class="caution">

Si vous éditez vos fichiers de configuration sur un système Windows, vous devez les enregistrer comme des fichiers Unix si votre éditeur supporte cette option sinon vous devez les convertir avec `dos2unix` avant d'essayer de les utiliser. De la même manière, si vous copiez un fichier de configuration depuis votre disque dur Windows vers une disquette, vous devez lancer `dos2unix` sur la copie avant de l'utiliser avec Shorewall.

Version Windows de dos2unix

Version Linux de dos2unix

</div>

# Les Concepts de Shorewall

Les fichiers de configuration pour Shorewall sont situés dans le répertoire /etc/shorewall -- pour de simples paramétrages, vous n'aurez à faire qu'avec quelques-uns d'entre eux comme décrit dans ce guide. Des squelettes de fichiers sont créés durant [la procédure d'installation de Shorewall](Install_fr.md).

<div class="warning">

**Note aux utilisateurs de Debian**

Si vous vous servez du .deb pour installer, vous vous rendrez compte que votre répertoire `/etc/shorewall` est vide. Ceci est voulu. Les squelettes des fichiers de configuration se trouvent sur votre système dans le répertoire `/usr/share/doc/shorewall/default-config`. Copiez simplement les fichiers dont vous avez besoin depuis ce répertoire dans `/etc/shorewall`, puis modifiez ces copies.

Remarquez que vous devez copier`/usr/share/doc/shorewall/default-config/shorewall.conf` et `/usr/share/doc/shorewall/default-config/modules` dans `/etc/shorewall` même si vous ne modifiez pas ces fichiers.

</div>

Au fur et à mesure de la présentation de chaque fichier, je vous suggère de jeter un oeil à ceux physiquement présents sur votre système -- chacun des fichiers contient des instructions de configuration détaillées et des entrées par défaut.

Shorewall voit le réseau où il fonctionne, comme étant composé d'un ensemble de zones. Dans ce guide nous utiliserons les zones suivantes:

fw  
Le firewall lui-même.

net  
L'internet public.

loc  
Un réseau local privé utilisant des adresses IP privées.

dmz  
Une zone démilitarisée (DMZ) contenant les serveurs publiquement accessibles.

Les Zones sont définies dans le fichier `/etc/shorewall/zones`.

<div class="important">

Le fichier `/etc/shorewall/zones` fourni avec la distribution est vide. Vous pouvez créer l'ensemble de zones standard décrites au-dessus en copiant puis en collant ce qui suit dans le fichier:

    #ZONE   TYPE             OPTIONS
    fw      firewall
    net     ipv4
    loc     ipv4
    dmz     ipv4

</div>

Remarquez que Shorewall reconnaît aussi le système firewall comme sa propre zone - l'exemple ci-dessus suit la convention qui veut que la zone firewall soit nommée **fw**. Le nom de la zone firewall (**fw** dans l'exemple plus haut) est stocké dans la variable d'environnement *\$FW* lorsque le fichier `/etc/shorewall/zones` est traité. A l'exception du nom attribué à la zone firewall, Shorewall n'attache aucune signification aux noms de zone. Le zones sont entièrement ce que VOUS en faites. Ceci signifie que vous ne devriez pas attendre de Shorewall qu'il fasse quoi que ce soit de spécial “car il s'agit de la zone internet” ou “car ceci est la DMZ”.

Éditez le fichier `/etc/shorewall/zones` et faites-y les changements nécessaires.

Les règles qui concernent le trafic à autoriser ou à refuser sous exprimées en termes de Zones.

- Vous exprimez les politiques par défaut entre une zone et une autre zone dans le fichier `/etc/shorewall/policy`.

- Vous définissez les exceptions à ces politiques par défaut dans le fichier `/etc/shorewall/rules`.

Shorewall est construit sur les mécanismes de [Netfilter](http://www.netfilter.org), service de filtrage du noyau (kernel). Netfilter fournit une [fonction de suivi de connexion](http://www.cs.princeton.edu/~jns/security/iptables/iptables_conntrack.html) qui permet une analyse d'état des paquets (stateful inspection). Cette propriété permet aux règles du firewall d'être définies en termes de connexions plutôt qu'en termes de paquets. Avec Shorewall, vous:

1.  Identifiez la zone source (client).

2.  Identifiez la zone destination (serveur).

3.  Si la politique depuis la zone du client vers la zone du serveur est ce que vous souhaitez pour cette paire client/serveur, vous n'avez rien de plus à faire.

4.  Si la politique n'est pas ce que vous souhaitez, alors vous devez ajouter une règle. Cette règle est exprimée en termes de zone client et de zone serveur.

**Autoriser les connexions d'un certain type depuis la zone A vers le firewall et depuis firewall vers la zone B **NE SIGNIFIE PAS que ces connections sont autorisés de la zone A à la zone B**** (autrement dit, les connexions impliquant la zone firewall ne sont pas transitives).

Pour chaque connexion demandant à entrer dans le firewall, la requête est en premier lieu vérifiée par rapport au fichier `/etc/shorewall/rules`. Si aucune règle dans ce fichier ne correspond à la demande de connexion alors la première politique dans le fichier `/etc/shorewall/policy` qui y correspond sera appliquée. S'il y a une [action par défaut](../reference/shorewall_extension_scripts.md) définie pour cette politique dans `/etc/shorewall/actions` ou dans `/usr/share/shorewall/actions.std` cette action commune sera exécutée avant que l'action spécifiée dans `/etc/shorewall/rules` ne soit appliquée.

Avant Shorewall 2.2.0, le fichier `/etc/shorewall/policy` avait les politiques suivantes:

    #SOURCE ZONE     DESTINATION ZONE    POLICY     LOG     LIMIT:BURST
    #                                               LEVEL
    fw               net                 ACCEPT
    net              all                 DROP       info
    all              all                 REJECT     info

<div class="important">

Le fichier de politiques distribué actuellement est vide. Vous pouvez y copier et coller les entrées présentées ci-dessus comme point de départ, puis l'adapter à vos propres politiques.

</div>

Les politiques précédentes vont:

1.  Autoriser (ACCEPT) toutes les connexions de votre réseau local vers internet

2.  Ignorer (DROP) toutes les tentatives de connexions d'internet vers le firewall ou vers votre réseau local et enregistrer dans vos journaux (log) un message au niveau info ([vous trouverez ici la description des niveaux de journalisation](../features/shorewall_logging.md)).

3.  Rejeter (REJECT) toutes les autres demandes de connexion et générer un message de niveau info dans votre journal. Quant la requête est rejetée et que le protocole est TCP, le firewall retourne un paquet RST. Pour tous les autres protocoles, quand une requête est rejetée, le firewall renvoie un paquet ICMP port-unreachable.

Maintenant, éditez votre `/etc/shorewall/policy`et apportez-y tous les changements que vous souhaitez.

# Interfaces Réseau

Dans la suite du guide, nous nous référerons au schéma ci-dessous. Bien qu'il puisse ne pas correspondre à votre propre réseau, il peut être utilisé pour illustrer les aspects importants de la configuration de Shorewall.

Sur ce schéma:

- La zone DMZ est composée des systèmes DMZ 1 et DMZ 2. On utilise une DMZ pour isoler ses serveurs accessibles depuis internet de ses systèmes locaux. Ainsi si un des serveurs de la DMZ est compromis, vous avez encore un firewall entre le système compromis et vos systèmes locaux.

- La zone “local” est composée des systèmes Local 1, Local 2 et Local 3.

- Tous les systèmes à l'extérieur du firewall, y compris ceux de votre FAI, sont dans la zone internet.

La façon la plus simple pour définir les zones est d'associer le nom de la zone (définie précédemment dans `/etc/shorewall/zones`) à une interface réseau. Ceci est fait dans le fichier [/etc/shorewall/interfaces](https://shorewall.org/Documentation.html#Interfaces).

Le firewall illustré ci-dessus à trois interfaces réseau. Lorsque la connexion internet passe par un “modem” câble ou ADSL **l'Interface Externe** sera l'adaptateur ethernet qui est connecté à ce “Modem” (par exemple `eth0`). Par contre, si vous vous connectez avec PPPoE (Point-to-Point Protocol over Ethernet) ou avec PPTP (Point-to-Point Tunneling Protocol), l'interface externe sera une interface ppp (par exemple `ppp0`). Si vous vous connectez avec un simple modem RTC, votre interface externe sera aussi `ppp0`. Si vous vous connectez en utilisant l'ISDN, votre interface externe sera `ippp0`.

**Si votre interface vers l'extérieur est `ppp0` ou `ippp0` alors vous mettrez CLAMPMSS=yes dans le fichier `/etc/shorewall/shorewall.conf`**.

Votre *Interface locale* sera un adaptateur ethernet (`eth0`, `eth1` or `eth2`) et sera connectée à un hub ou à un switch. Vos ordinateurs locaux seront connectés à ce même hub ou switch (note : si vous n'avez qu'un seul ordinateur en local, vous pouvez le connecter directement au firewall par un câble croisé).

Votre *interface DMZ* sera aussi un adaptateur ethernet (`eth0`, `eth1` or `eth2`) et sera connecté à un hub ou un à switch. Vos ordinateurs appartenant à la DMZ seront connectés à ce même hub ou switch (note : si vous n'avez qu'un seul ordinateur dans la DMZ, vous pouvez le connecter directement au firewall par un câble croisé).

<div class="warning">

**Ne connectez pas les interfaces interne et externe sur le même hub ou le même switch, sauf à des fins de test**. Vous pouvez tester en utilisant ce type de configuration si vous spécifiez l'option **arp_filter** ou l'option **arp_ignore** dans le fichier `/etc/shorewall/``interfaces, et ce` pour toutes les interfaces connectées au hub/switch commun. **Il est très fortement déconseillé d'utiliser une telle configuration avec un firewall en production**.

</div>

Dans la suite, nous supposerons que:

- L'interface externe est `eth0`.

- L'interface locale est `eth1`.

- L'interface DMZ est `eth2`.

La configuration par défaut de Shorewall ne définit le contenu d'aucune zone. Pour définir la configuration présentée plus haut, le fichier [/etc/shorewall/interfaces](https://shorewall.org/Documentation.html#Interfaces) doit contenir:

    #ZONE    INTERFACE      BROADCAST     OPTIONS
    net      eth0           detect        rfc1918
    loc      eth1           detect
    dmz      eth2           detect

Remarquez que la zone \$FW n'a aucune entrée dans le fichier `/etc/shorewall/interfaces.`

Éditez le fichier `/etc/shorewall/interfaces.` Définissez les interfaces du réseau de votre firewall et associez chacune d'entre elles à une zone. Si vous avez une zone qui est connectée par plus d'une interface, incluez simplement une entrée pour chaque interface et répétez le nom de zone autant de fois que nécessaire.

    #ZONE    INTERFACE      BROADCAST     OPTIONS
    net      eth0           detect        rfc1918
    loc      eth1           detect
    loc      eth2           detect

Vous pouvez définir des zones plus compliquées en utilisant le fichier`/etc/shorewall/hosts` mais dans la plus part des cas, cela ne sera pas nécessaire. Vous trouverez des exemples dans [Shorewall_and_Aliased_Interfaces.html](Shorewall_and_Aliased_Interfaces.md) et [Multiple_Zones.html](../concepts/Multiple_Zones.md).

# Adressage, Sous-réseaux et Routage

Normalement, votre FAI vous attribue un ensemble d'adresses IP publiques. Vous utiliserez une de ces adresses pour configurer l'interface externe de votre firewall. Vous déciderez ensuite comment utiliser le reste de vos adresses. Avant d'aborder ce point, il nous faut rappeler le contexte.

Si vous êtes déjà familier de l'adressage IP et du routage, vous pouvez directement aller à la prochaine section.

La présentation qui suit ne fait que d'effleurer les questions de l'adressage et du routage. Si vous vous voulez en apprendre plus sur l'adressage IP et le routage, je vous recommande “IP Fundamentals: What Everyone Needs to Know about Addressing & Routing”, Thomas A. Maufer, Prentice-Hall, 1999, ISBN 0-13-975483-0 ([lien](http://www.phptr.com/browse/product.asp?product_id={58D4F6D4-54C5-48BA-8EDD-86EBD7A42AF6})).

## Adressage IP

Les adresses IP version 4 (IPv4) sont codées sur 32 bits. La notation w.x.y.z fait référence à une adresse dont l'octet de poids fort a pour valeur “w”, le suivant a pour valeur “x”, etc. Si nous prenons l'adresse 192.0.2.14 et que nous l'exprimons en hexadécimal, nous obtenons

    C0.00.02.0E

et si nous la regardons comme un entier de 32 bits nous avons

    C000020E

## Sous-réseaux

Vous entendrez encore aujourd'hui les termes de “Réseau de classe A”, “Réseau de classe B” et “Réseau de classe C”. Au début de l'existence de l'IP, les réseaux ne pouvaient avoir que trois tailles (il y avait aussi les réseaux de classe D mais il étaient utilisés différemment):

Classe A - masque de sous-réseau 255.0.0.0, taille = 2 \*\* 24

Classe B - masque de sous-réseau 255.255.0.0, taille = 2 \*\* 16

Classe C - masque de sous-réseau 255.255.255.0, taille = 256

La classe d'un réseau était déterminée de façon unique par la valeur de l'octet de poids fort de son adresse, ainsi en regardant une adresse IP on pouvait déterminer immédiatement la valeur du masque réseau. Le masque réseau est un nombre qui combiné à une adresse par un ET logique, isole l'adresse du réseau auquel cette adresse appartient. Le reste de l'adresse est le *numéro d'hôte*. Par exemple, dans l'adresse de classe C 192.0.2.14, la valeur hexadécimale de l'adresse du réseau est C00002 et le numéro d'hôte est 0E.

Comme internet se développait, il devint clair qu'un partitionnement aussi grossier de l'espace d'adresses de 32 bits allait être très limitatif (rapidement, les grandes sociétés et les universités s'étaient déjà attribuées leur propre réseau de classe A !). Après quelques faux départs, la technique courante du sous-adressage de ces réseaux en plus petits sous-réseaux évolua. On fait référence à cette technique sous l'appellation de Routage Inter-Domaine Sans Classe ou *Classless InterDomain Routing* (CIDR). Aujourd'hui, les systèmes avec lesquels vous travaillez sont probablement compatibles avec la notation CIDR. La gestion des réseaux basée sur les Classes est du domaine du passé.

Un *sous-réseau* (*subnet* ou *subnetwork*) est un ensemble contigu d'adresses IP tel que:

1.  Le nombre d'adresses dans le jeu est un multiple de 2.

2.  La première adresse dans le jeu est un multiple de la taille du jeu.

3.  La première adresse du sous-réseau est réservée et on s'y réfère comme étant *l'adresse du sous-réseau*.

4.  La dernière adresse du sous-réseau est réservée comme *adresse de diffusion (broadcast) du sous-réseau*.

Comme vous pouvez le constater par cette définition, dans chaque sous-réseau de taille n il y a (n - 2) adresses utilisables (adresses qui peuvent être attribuées à un hôte). La première et la dernière adresse du sous-réseau sont utilisées respectivement pour identifier l'adresse du sous-réseau et l'adresse de diffusion du sous-réseau. En conséquence, de petits sous-réseaux sont plus gourmands en adresses IP que des sous-réseaux plus étendus.

Comme n est une puissance de deux, nous pouvons aisément calculer le *Logarithme à base 2 de n* (log2). La taille et le logarithme à base 2 pour les tailles de sous-réseau les plus communes sont donnés par la table suivante:

|       |            |                   |
|-------|------------|-------------------|
| **n** | **log2 n** | **(32 - log2 n)** |
| 8     | 3          | 29                |
| 16    | 4          | 28                |
| 32    | 5          | 27                |
| 64    | 6          | 26                |
| 128   | 7          | 25                |
| 256   | 8          | 24                |
| 512   | 9          | 23                |
| 1024  | 10         | 22                |
| 2048  | 11         | 21                |
| 4096  | 12         | 20                |
| 8192  | 13         | 19                |
| 16384 | 14         | 18                |
| 32768 | 15         | 17                |
| 65536 | 16         | 16                |

Logarithmes base 2

Vous constaterez que la table ci-dessus contient aussi une colonne (32 - log2 **n**). Ce nombre est le *Masque de Sous-réseau à Longueur Variable* ou *Variable Length Subnet Mask* (VLSM) pour un sous-réseau de taille n. De la table ci-dessus, nous pouvons déduire la suivante, qui est plus facile à utiliser.

|                           |          |                           |
|---------------------------|----------|---------------------------|
| **Taille du sous-réseau** | **VLSM** | **Masque de sous-réseau** |
| 8                         | /29      | 255.255.255.248           |
| 16                        | /28      | 255.255.255.240           |
| 32                        | /27      | 255.255.255.224           |
| 64                        | /26      | 255.255.255.192           |
| 128                       | /25      | 255.255.255.128           |
| 256                       | /24      | 255.255.255.0             |
| 512                       | /23      | 255.255.254.0             |
| 1024                      | /22      | 255.255.252.0             |
| 2048                      | /21      | 255.255.248.0             |
| 4096                      | /20      | 255.255.240.0             |
| 8192                      | /19      | 255.255.224.0             |
| 16384                     | /18      | 255.255.192.0             |
| 32768                     | /17      | 255.255.128.0             |
| 65536                     | /16      | 255.255.0.0               |
| 2 \*\* 24                 | /8       | 255.0.0.0                 |

VLSM

Notez que le VLSM est écrit avec un slash (“/”) -- vous entendrez souvent nommer un réseau de taille 64 comme étant un “slash 26” et un de taille 8 comme étant un “slash 29”.

Le masque de sous-réseau est simplement un nombre de 32 bits avec les premiers bits correspondant au VLSM positionnés à “1” et les bits suivants à “0”. Par exemple, pour un sous-réseau de taille 64, le masque de sous-réseau débute par 26 bits à “1”:

    11111111111111111111111111000000 = FFFFFFC0 = FF.FF.FF.C0 = 255.255.255.192

Le masque de sous-réseau a la propriété suivante: si vous appliquez un ET logique entre le masque de sous-réseau et une adresse dans le sous-réseau, le résultat est l'adresse du sous-réseau. Tout aussi important, si vous appliquer un ET logique entre le masque de sous-réseau et une adresse en dehors du sous-réseau, le résultat n'est PAS l'adresse du sous-réseau. Comme nous le verrons après, cette propriété du masque de sous-réseau est très importante dans le routage.

Pour un sous-réseau dont l'adresse est **a.b.c.d** et dont le VLSM est **/v**, nous notons le sous-réseau “**a.b.c.d/v**” en utilisant la **notation CIDR**.

|                             |                           |
|-----------------------------|---------------------------|
| **Sous-réseau:**            | 10.10.10.0 - 10.10.10.127 |
| **Taille du sous-réseau:**  | 128                       |
| **Adresse du sous-réseau:** | 10.10.10.0                |
| **Adresse de diffusion:**   | 10.10.10.127              |
| **Notation CIDR:**          | 10.10.10.0/25             |

Un exemple de sous-réseau :

Il existe deux sous-réseaux dégénérés qui doivent être mentionnés: le sous-réseau avec un seul membre et le sous-réseau avec 2 \*\* 32 membres.

|                           |                   |                           |                   |
|---------------------------|-------------------|---------------------------|-------------------|
| **Taille du sous-réseau** | **Longueur VLSM** | **Masque de sous-réseau** | **Notation CIDR** |
| 1                         | 32                | 255.255.255.255           | a.b.c.d/32        |
| 32                        | 0                 | 0.0.0.0                   | 0.0.0.0/0         |

/32 and /0

Ainsi, chaque adresse **a.b.c.d** peut aussi être écrite **a.b.c.d/32** et l'ensemble des adresses possibles est écrit **0.0.0.0/0**.

Un utilisateur de Shorewall a proposé cette très utile [représentation graphique](https://shorewall.org/pub/shorewall/contrib/IPSubNetMask.html) de ces informations.

Dans la suite, nous utiliserons la notation **a.b.c.d/v** pour décrire la configuration IP d'une interface réseau (l'utilitaire `ip` utilise aussi cette syntaxe). Dans cette notation l'interface est configurée avec une adresse ip **a.b.c.d** avec le masque de sous-réseau qui correspond au VLSM /**v**.

L'interface est configurée avec l'adresse IP 192.0.2.65 et le masque de sous-réseau 255.255.255.248.

/sbin/shorewall propose une commande `ipcalc` qui calcule automatiquement les informations d'un \[sous-\]réseau.

    shorewall ipcalc 10.10.10.0/25
       CIDR=10.10.10.0/25
       NETMASK=255.255.255.128
       NETWORK=10.10.10.0
       BROADCAST=10.10.10.127

    shorewall ipcalc 10.10.10.0 255.255.255.128
       CIDR=10.10.10.0/25
       NETMASK=255.255.255.128
       NETWORK=10.10.10.0
       BROADCAST=10.10.10.127

## Routage

L'un des objectifs de la gestion en sous-réseaux est qu'elle pose les bases pour le routage. Ci-dessous se trouve la table de routage de mon firewall:

    [root@gateway root]# netstat -nr
    Kernel IP routing table
    Destination     Gateway         Genmask         Flgs MSS Win irtt Iface
    192.168.9.1     0.0.0.0         255.255.255.255 UH   40  0      0 texas
    206.124.146.177 0.0.0.0         255.255.255.255 UH   40  0      0 eth1
    206.124.146.180 0.0.0.0         255.255.255.255 UH   40  0      0 eth3
    192.168.3.0     0.0.0.0         255.255.255.0   U    40  0      0 eth3
    192.168.2.0     0.0.0.0         255.255.255.0   U    40  0      0 eth1
    192.168.1.0     0.0.0.0         255.255.255.0   U    40  0      0 eth2
    206.124.146.0   0.0.0.0         255.255.255.0   U    40  0      0 eth0
    192.168.9.0     192.0.2.223     255.255.255.0   UG   40  0      0 texas
    127.0.0.0       0.0.0.0         255.0.0.0       U    40  0      0 lo
    0.0.0.0         206.124.146.254 0.0.0.0         UG   40  0      0 eth0
    [root@gateway root]#

L'interface *texas* est un tunnel GRE vers un site pair à Dallas, au Texas.

Les trois premières routes sont des routes vers des hôtes (*host routes)* puisqu'elles indiquent comment aller vers un hôte unique. Dans la sortie de `netstat`, cela se voit très bien au masque de sous-réseau (Genmask) à 255.255.255.255, ou bien au drapeau à “H” dans la colonne “Flags” . Les autres routes sont des routes réseau car elles indiquent au noyau comment router des paquets à un sous-réseau. La dernière route est *la route par défaut*. La passerelle mentionnée dans cette route est appelée *la passerelle par défaut (default gateway).*

Quant le noyau essaye d'envoyer un paquet à une adresse IP **A**, il commence au début de la table de routage et:

- **Il réalise un ET logique entre A** et la valeur du masque de sou-réseau pour cette entrée de la table.

- Ce résultat est comparé avec la valeur de la “Destination” dans cette entrée de la table.

- Si le résultat et la valeur de la “Destination” sont identiques, alors:

  - Si la colonne “Gateway” n'est pas nulle, le paquet est envoyé à la passerelle par l'interface nommée dans la colonne “Iface”.

  - Sinon, le paquet est directement envoyé à **A** à travers l'interface nommée dans la colonne “iface”.

- Sinon, les étapes précédentes sont répétées sur l'entrée suivante de la table.

Puisque la route par défaut correspond à toutes les adresses IP (**A** ET 0.0.0.0 = 0.0.0.0), les paquets qui ne correspondent à aucune des autres entrées de la table de routage sont envoyés à la passerelle par défaut qui est généralement un routeur de votre FAI.

Prenons un exemple. Supposons que vous souhaitiez router un paquet à 192.168.1.5. Cette adresse ne correspond à aucune route d'hôte dans la table mais lorsque nous faisons le ET logique de cette adresse avec 255.255.255.0, le résultat est 192.168.1.0 qui correspond à cette entrée de la table:

    192.168.1.0   0.0.0.0       255.255.255.0   U     40  0         0 eth2

Donc, pour router ce paquet à 192.168.1.5, il faudra le transmettre directement à l'interface eth2.

Un point important doit être souligné -- tous les paquets sont envoyés en utilisant la table de routage et les paquets en réponse ne sont pas un cas particulier. Il semble exister une idée fausse comme quoi les paquets réponses seraient comme les saumons et contiendraient une sorte de code génétique qui leur permettrait suivre la même route empruntée par les paquets de requête (request) à l'aller. Ce n'est pas le cas. Les réponses peuvent prendre un chemin totalement différent de celui pris par les paquets de la requête client à l'aller -- Ces routes sont totalement indépendantes.

## Protocole de Résolution d'Adresse (ARP)

Quant on envoie des paquets sur ethernet, les adresses IP ne sont pas utilisées. L'adressage ethernet est basé sur les adresses MAC (*Media Access Control)*. Chaque carte ethernet à sa propre adresse MAC unique qui est gravée dans une PROM lors de sa fabrication. Vous pouvez obtenir l'adresse MAC d'une carte ethernet grâce à l'utilitaire “`ip`”:

    [root@gateway root]# ip addr show eth0
    2: eth0: <BROADCAST,MULTICAST,UP> mtu 1500 qdisc htb qlen 100
    link/ether 02:00:08:e3:fa:55 brd ff:ff:ff:ff:ff:ff
    inet 206.124.146.176/24 brd 206.124.146.255 scope global eth0
    inet 206.124.146.178/24 brd 206.124.146.255 scope global secondary eth0
    inet 206.124.146.179/24 brd 206.124.146.255 scope global secondary eth0
    [root@gateway root]#

Comme vous pouvez le constater, l'adresse MAC est codée sur 6 octets (48 bits). L'adresse MAC est généralement imprimée sur la carte elle-même.

Comme IP utilise les adresses IP et ethernet les adresses MAC, il faut un mécanisme pour transcrire une adresse IP en adresse MAC. C'est ce dont est chargé le protocole de résolution d'adresse (*Address Resolution Protocol* ARP). Voici ARP en action:

    [root@gateway root]# tcpdump -nei eth2 arp
    tcpdump: listening on eth2
    09:56:49.766757 2:0:8:e3:4c:48 0:6:25:aa:8a:f0 arp 42:
                    arp who-has 192.168.1.19 tell 192.168.1.254
    09:56:49.769372 0:6:25:aa:8a:f0 2:0:8:e3:4c:48 arp 60:
                    arp reply 192.168.1.19 is-at 0:6:25:aa:8a:f0

    2 packets received by filter
    0 packets dropped by kernel
    [root@gateway root]#

Dans cet échange , 192.168.1.254 (MAC 2:0:8:e3:4c:48) veut connaître l'adresse MAC du périphérique qui a l'adresse IP 192.168.1.19. Le système ayant cette adresse IP répond que l'adresse MAC du périphérique avec l'adresse IP 192.168.1.19 est 0:6:25:aa:8a:f0.

Afin de ne pas avoir à échanger des information ARP chaque fois qu'un paquet doit être envoyé, le système maintient un cache des correspondances IP\<-\> MAC. Vous pouvez voir le contenu du cache ARP sur votre système (y compris sur les systèmes Windows) en utilisant la commande `arp`

    [root@gateway root]# arp -na
    ? (206.124.146.177) at 00:A0:C9:15:39:78 [ether] on eth1
    ? (192.168.1.3) at 00:A0:CC:63:66:89 [ether] on eth2
    ? (192.168.1.5) at 00:A0:CC:DB:31:C4 [ether] on eth2
    ? (206.124.146.254) at 00:03:6C:8A:18:38 [ether] on eth0
    ? (192.168.1.19) at 00:06:25:AA:8A:F0 [ether] on eth2

Les points d'interrogation au début des lignes sont le résultat de l'utilisation de l'option “n” qui empêche le programme `arp` de résoudre le noms DNS pour les adresses IP (la commande `arp` de Windows n'accepte pas cette option) . Si je n'avais pas utilisé pas cette option, les points d'interrogation seraient remplacés par les noms pleinement qualifiés (FQDN) correspondant à chaque adresse IP. Remarquez que la dernière information dans le cache correspond à celle que nous avons vue en utilisant `tcpdump` à l'instant.

## RFC 1918

Les adresses IP sont allouées par l'IANA ([Internet Assigned Number Authority](http://www.iana.org/)) qui délégue les allocations sur une base géographique aux Registres Internet Régionaux (RIR). Par exemple, les allocations pour les Etats-Unis et l'Afrique sub-Saharienne sont déléguées à l'ARIN ([American Registry for Internet Numbers](http://www.arin.net/)). Ces RIRs peuvent à leur tour déléguer à des bureaux nationaux. La plupart d'entre nous ne traite pas avec ces autorités mais obtient plutôt ses adresse IP de son FAI.

Dans la réalité, on ne peut en général pas se permettre d'avoir autant d'adresses IP publiques que l'on a de périphériques en nécessitant une. C'est cette raison qui nous amène à utiliser des adresses IP privées. La RFC 1918 réserve plusieurs plages d'adresses à cette fin :

    10.0.0.0    - 10.255.255.255
    172.16.0.0  - 172.31.255.255
    192.168.0.0 - 192.168.255.255

Les adresses réservées par la RFC 1918 sont parfois appelées non-routables car les routeurs d'infrastructure internet ne feront pas suivre (forward) les paquets qui ont une adresse de destination de la RFC 1918. Cela est compréhensible puisque chacun peut choisir n'importe laquelle ces adresses pour son usage privé. Mais le terme de non-routable est quelque peu malencontreux car il peut amener à conclure de manière erronée que le trafic destiné à une de ces adresses ne peut être envoyé à travers un routeur. Ceci est faux et les routeurs privés, dont votre firewall Shorewall, peuvent parfaitement faire suivre du trafic avec des adresses conformes à la RFC 1918.

Quant on choisit des adresses dans ces plages, il faut bien avoir à l'esprit les choses suivantes:

- Comme l'espace des adresses IPv4 s'épuise, de plus en plus d'organisation (y compris les FAI) commencent à utiliser les adresses RFC 1918 dans leurs infrastructures.

- Vous ne devez pas utiliser d'adresse IP qui soit utilisée par votre FAI ou une autre organisation avec laquelle vous souhaitez établir une liaison VPN

C'est pourquoi c'est une bonne idée de vérifier après de votre FAI s'il n'utilise pas (ou ne prévoie pas d'utiliser) des adresses privées avant de décider quelles adresses que vous allez utiliser.

<div class="note">

**Dans ce document, les adresses IP externes “réelles” sont dans la plage 192.0.2.x. Les adresses du réseau 192.0.2.0/24 sont réservées par RFC 3330 pour l'utilisation d'adresses IP publiques dans les exemples imprimés ainsi que dans les réseaux de test. Ces adresses ne doivent pas être confondues avec les adresses 192.168.0.0/16, qui comme décrit ci-dessus, sont réservées par la RFC 1918 pour une utilisation privée.**

</div>

# Configurer votre Réseau

Le choix d'une configuration pour votre réseau dépend d'abord du nombre d'adresses IP publiques dont vous disposez et du nombre d'adresses IP dont vous avez besoin. Quel que soit le nombre d'adresses dont vous disposez, votre FAI peut vous servir ce jeu d'adresses de deux manières:

- **Routées** - Le trafic vers chacune de vos adresses publiques sera routé à travers une seule adresse de passerelle. Cela sera généralement fait si votre FAI vous attribue un sous-réseau complet (/29 ou plus). Dans ce cas, vous affecterez l'adresse de cette passerelle comme étant l'adresse de l'interface externe de votre firewall/routeur.

- **Non routées** - Votre FAI enverra le trafic à chacune de vos adresses directement.

Dans les paragraphes qui suivent, nous étudierons chacun de ces cas séparément.

Avant de commencer, il y a une chose que vous devez vérifier:

Si vous utilisez un paquetage Debian, vérifiez votre fichier `shorewall.conf` afin de vous assurer que les paramètres suivants sont convenablement fixés. Si ce n'est pas le cas, appliquez les changements nécessaires:

- IP_FORWARDING=On

## Routé

Supposons que votre fournisseur d'accès vous ait assigné le sous-réseau 192.0.2.64/28 routé par 192.0.2.65. Vous avez les adresses IP 192.0.2.64 - 192.0.2.79 et l'adresse externe de votre firewall est 192.0.2.65. Votre FAI vous a aussi dit que vous devez utiliser le masque de sous-réseau 255.255.255.0 (ainsi, votre /28 est un sous-ensemble du /24, plus grand). Avec autant d'adresses IP, vous pouvez scinder votre réseau /28 en deux sous-réseaux /29 et configurer votre réseau comme l'indique le diagramme suivant.

Dans l'exemple, la zone démilitarisé DMZ est dans le sous-réseau 192.0.2.64/29 et le réseau local est dans 192.0.2.72/29. La passerelle par défaut pour les hôtes dans la DMZ doit être configurée à 192.0.2.66 et la passerelle par défaut pour ceux du réseau local doit être configurée à 192.0.2.73.

Notez que cette solution est plutôt gourmande en adresses publiques puisqu'elle utilise 192.0.2.64 et 192.0.2.72 pour les adresses de sous-réseau, 192.0.2.71 et 192.0.2.79 pour les adresses de diffusion (broadcast) du réseau, et 192.0.2.66 et 168.0.2.73 pour les adresses internes sur le firewall/routeur. Elle montre néammoins comment la gestion en sous-réseaux peut fonctionner. Et si nous avions un réseau /24 plutôt qu'un /28, l'utilisation de 6 adresses IP parmi les 256 disponibles serait largement justifiée par la simplicité du paramétrage.

Le lecteur attentif aura peut-être remarqué que l'interface externe du firewall/Routeur est en fait incluse dans le sous-réseau DMZ (192.0.2.64/29). On peut se demander ce qui se passe quand l'hôte DMZ 1 (192.0.2.67) essaye de communiquer avec 192.0.2.65. La table de routage sur l'hôte DMZ 1 doit ressembler à cela:

    Kernel IP routing table
    Destination    Gateway     Genmask         Flags MSS Window irtt Iface
    192.0.2.64     0.0.0.0     255.255.255.248 U     40  0         0 eth0
    0.0.0.0        192.0.2.66  0.0.0.0         UG    40  0         0 eth0

Donc, lorsque l'hôte DMZ 1 voudra communiquer avec 192.0.2.65, il enverra une requête ARP "qui-a 192.0.2.65" alors qu'aucune interface sur le segment ethernet DMZ n'a cette adresse IP. Assez bizarrement, le firewall répondra à la requête avec **<u>l'adresse MAC de sa propre interface DMZ</u>** ! DMZ 1 peut alors envoyer des trames ethernet adressées à cette adresse MAC et les trames seront reçues correctement par le firewall/routeur.

L'avertissement fait plus haut qui déconseille très fortement la connexion de plusieurs interfaces du firewall/routeur à un même hub ou switch est une conséquence directe de ce comportement plutôt inattendu d'ARP de la part du noyau Linux. Quant une requête ARP destinée à une des adresses du firewall/routeur est envoyée par un autre système connecté au même hub ou switch, toutes les interfaces du firewall qui y sont connectées peuvent répondre ! C'est alors la course à savoir quelle réponse “c'est-ici” atteindra la première l'émetteur de la requête.

## Non routé

Si vous êtes dans la situation précédente mais que votre trafic n'est pas routé par votre FAI, vous pouvez configurer votre réseau exactement comme décrit plus haut, au prix d'une légère contorsion supplémentaire: spécifiez simplement l'option “`proxyarp`” sur les trois interfaces du firewall dans le fichier `/etc/shorewall/interfaces`.

La plupart d'entre nous n'ont pas le luxe d'avoir suffisamment d'adresses publiques IP pour configurer leur réseau comme indiqué dans l'exemple précédent (même si la configuration est routée).

**Dans le reste de cette section, supposons que notre FAI nous ait assigné la plage d'adresses IP 192.0.2.176-180, qu'il nous ait dit d'utiliser le masque de sous-réseau 255.255.255.0 et que la passerelle par défaut soit 192.0.2.254.**

De toute évidence, ce jeu d'adresses ne comprend pas de sous-réseau et n'a pas suffisamment d'adresses pour toutes les interfaces de notre réseau. Nous pouvons utiliser quatre techniques différentes pour contourner ce problème.

- La traduction d'adresses source (*Source Network Address Translation* **SNAT**).

- La traduction d'adresses destination *(Destination Network Address Translation* **DNAT**) nommée aussi transfert ou suivi de port *(Port Forwarding*).

- ***Le* Proxy ARP**.

- La traduction d'adresses réseau *(Network Address Translation* NAT) à laquelle on fait aussi référence sous l'appellation de un-à-un NAT (one-to-one NAT).

Souvent, une combinaison de ces techniques est utilisée. Chacune d'entre elles sera détaillée dans la section suivante.

### SNAT

Avec la SNAT, un segment interne du réseau local est configuré en utilisant des adresses de la RFC 1918. Quant un hôte **A** sur ce segment interne initie une connexion vers un hôte **B** sur internet, le firewall/routeur réécrit les entêtes IP de la requête pour utiliser une de vos adresses publiques IP en tant qu'adresse source. Quant **B** répond et que la réponse est reçue par le firewall, le firewall change l'adresse destination par celle de la RFC 1918 de **A** et transfère la réponse à **A.**

Supposons que vous décidiez d'utiliser la SNAT sur votre zone locale. Supposons également que vous utilisiez l'adresse publique 192.0.2.176 à la fois comme adresse externe du firewall et comme adresse source des requêtes internet envoyées depuis cette zone.

On a assigné à la zone locale le sous-réseau 192.168.201.0/29 (masque de sous-réseau 255.255.255.248).

Dans ce cas, les systèmes de la zone locale seraient configurés avec 192.168.201.1 comme passerelle par défaut (adresse IP de l'interface local du firewall).

La SNAT est configurée dans Shorewall avec le fichier

/etc/shorewall/masq

.

    #INTERFACE     SUBNET               ADDRESS
    eth0           192.168.201.0/29     192.0.2.176

Cet exemple utilise la technique normale qui assigne la même adresse publique IP pour l'interface externe du firewall et pour la SNAT. Si vous souhaitez utiliser une adresse IP différente, vous pouvez soit utiliser les outils de configuration réseau de votre distribution Linux pour ajouter cette adresse IP, soit mettre la variable ADD_SNAT_ALIASES=Yes dans `/etc/shorewall/shorewall.conf` et Shorewall ajoutera l'adresse pour vous.

### DNAT

Quand la SNAT est utilisée, il est impossible pour les hôtes sur internet d'initialiser une connexion avec un des systèmes internes puisque ces systèmes n'ont pas d'adresses publiques IP. La DNAT fournit une méthode pour autoriser des connexions sélectionnées depuis internet.

Supposons que votre fille souhaite héberger un serveur Web sur son système "Local 3". Vous pourriez autoriser les connexions d'internet à son serveur en ajoutant l'entrée suivante dans le fichier `/etc/shorewall/rules`:

    #ACTION  SOURCE  DEST               PROTO  DEST    SOURCE    ORIGINAL
    #                                          PORT(S) PORT(S)   DEST
    DNAT     net     loc:192.168.201.4  tcp    www

Si une des amies de votre fille avec une adresse **A** veut accéder au serveur de votre fille, elle peut se connecter à http://192.0.2.176 (l'adresse IP externe de votre firewall). Le firewall réécrira l'adresse IP de destination à 192.168.201.4 (le système de votre fille) et lui fera suivre la requête. Quand le serveur de votre fille répondra, le firewall remettra l'adresse source à 192.0.2.176 et retournera la réponse à **A**.

Cet exemple utilise l'adresse externe IP du firewall pour la DNAT. Vous pouvez utiliser une autre de vos adresses IP publiques. Pour cela, mettez-la dans la colonne ORIGINAL DEST de la règle ci-dessus. Par contre, Shorewall n'ajoutera pas à votre place cette adresse à l'interface externe du firewall.

<div class="important">

Quand vous testez des règles DNAT comme celles présentée plus haut, vous devez le faire depuis un client A L'EXTÉRIEUR DE VOTRE FIREWALL (depuis la zone “net”). Vous ne pouvez pas tester ces règles de l'intérieur !

Pour quelques astuces sur la résolution de problèmes avec la DNAT, [voyez les FAQ 1a et 1b](FAQ_fr.md#faq1a).

</div>

### Proxy ARP

Le principe du proxy ARP est:

- On attribue à un hôte **H** derrière notre firewall une de nos adresses publiques **A** et on lui donne le même masque de sous-réseau **M** que celui de l'interface externe du firewall.

- Le firewall répond aux requêtes ARP “qui-a-l'adresse” **A** émises par les hôtes à l'extérieur du firewall.

- Lorsque c'est l'hôte **H** qui émet une requête “qui-a-l'adresse” **pour un hôte** situé à l'extérieur du firewall et appartenant au sous-réseau défini par **A** et **M**, c'est le firewall qui répondra à **H** avec l'adresse MAC de l'interface du firewall à laquelle est raccordé **H**.

Pour une description plus complète du fonctionnement du Proxy ARP, vous pouvez vous référer à la [Documentation du Proxy Shorewall](../features/ProxyARP.md).

Supposons que nous décidions d'utiliser le Proxy ARP sur la DMZ de notre exemple de réseau.

Ici, nous avons assigné les adresses IP 192.0.2.177 au système DMZ 1 et 192.0.2.178 au système DMZ 2. Remarquez que nous avons assigné une adresse RFC 1918 et un masque de sous-réseau arbitraires à l'interface DMZ de notre firewall. Cette adresse et ce masque ne sont pas pertinents - vérifiez juste que celle-ci n'est en conflit avec aucun autre sous-réseau déjà défini.

La configuration du Proxy ARP est faite dans le fichier [`/etc/shorewall/proxyarp`](../features/ProxyARP.md).

    #ADDRESS     INTERFACE    EXTERNAL      HAVE ROUTE        PERSISTANT
    192.0.2.177  eth2         eth0          No
    192.0.2.178  eth2         eth0          No

La variable HAVE ROUTE étant à No, Shorewall ajoutera les routes d'hôte pour 192.0.2.177 et 192.0.2.178 par `eth2`. Les interfaces ethernet des machines DMZ 1 et DMZ 2 devront être configurées avec les adresses IP données plus haut, mais elles devront avoir la même passerelle par défaut que le firewall lui-même (192.0.2.254 dans notre exemple). Autrement dit, elles doivent être configurées exactement comme si elles étaient parallèles au firewall plutôt que derrière lui.

<div class="caution">

**Ne pas ajouter le(s) adresse(s) traitées par le proxy ARP (192.0.2.177 et 192.0.2.178 dans l'exemple ci-dessus) à l'interface externe du firewall (eth0 dans cet exemple).**

</div>

Un mot de mise en garde. En général, les FAI configurent leurs routeurs avec un timeout de cache ARP assez élevé. Si vous déplacez un système parallèle à votre firewall derrière le Proxy ARP du firewall, cela peut mettre des HEURES avant que ce système ne puisse communiquer avec internet. Il y a deux choses que vous pouvez essayer de faire:

1.  (Salutations à Bradey Honsinger) Une lecture de “TCP/IP Illustrated, Vol 1” de Richard Stevens révèle qu'un paquet ARP “gratuit” (gratuitous) peut amener le routeur de votre FAI à rafraîchir son cache (section 4.7). Un paquet ARP “gratuit” est simplement une requête d'un hôte demandant l'adresse MAC associée à sa propre adresse IP.

    En plus de garantir que cette adresse IP n'est pas dupliquée, “si l'hôte qui envoie la commande ARP ‘gratuit’ vient juste de changer son adresse matérielle ..., ce paquet force tous les autres hôtes...qui ont une entrée dans leur cache ARP pour l'ancienne adresse matérielle à mettre leurs caches à jour”

    Ce qui est exactement, bien sûr, ce que vous souhaitez faire lorsque vous basculez un hôte qui était directement exposé sur internet vers l'arrière de votre firewall Shorewall en utilisant le proxy ARP (ou en faisant du NAT un-à-un pour la même raison). Heureusement, les versions récentes du paquetage `iputils` de Redhat comprennent `arping`, dont l'option "-U" fait cela:

        arping -U -I <net if> <newly proxied IP>

        arping -U -I eth0 66.58.99.83 # for example

    Stevens continue en mentionnant que certains systèmes ne répondent pas correctement à la commande ARP “gratuit”, mais une recherche sur google pour “arping -U” semble démontrer que cela fonctionne dans la plupart des cas.

2.  Vous pouvez appeler votre FAI et lui demander de purger l'entrée obsolète de son cache ARP, mais la plupart ne voudront ou ne pourront le faire.

Vous pouvez vérifier si le cache ARP de votre FAI est obsolète en utilisant `ping` et `tcpdump`. Supposez que vous pensez que la passerelle routeur a une entrée ARP obsolète pour 192.0.2.177. Sur le firewall, lancez `tcpdump` de cette façon:

    tcpdump -nei eth0 icmp

Maintenant depuis 192.0.2.177, `ping`ez la passerelle de votre FAI (que nous supposons être 192.0.2.254):

    ping 192.0.2.254

Nous pouvons maintenant observer le résultat de `tcpdump`:

    13:35:12.159321 0:4:e2:20:20:33 0:0:77:95:dd:19 ip 98:
                    192.0.2.177 > 192.0.2.254: icmp: echo request (DF)
    13:35:12.207615 0:0:77:95:dd:19 0:c0:a8:50:b2:57 ip 98:
                    192.0.2.254 > 192.0.2.177 : icmp: echo reply

Remarquez que l'adresse source MAC dans la requête echo est différente de l'adresse MAC de destination dans la réponse echo ! Dans ce cas, 0:4:e2:20:20:33 était l'adresse MAC de l'interface réseau `eth0` du firewall tandis que 0:c0:a8:50:b2:57 était l'adresse MAC de la carte réseau de DMZ 1. En d'autre termes, le cache ARP de la passerelle associe encore 192.0.2.177 avec la carte réseau de DMZ 1 plutôt qu'avec l'interface `eth0` du firewall.

### NAT un-à-un

Avec le NAT un-à-un (one-to-one NAT), vous attribuez des adresses RFC 1918 à vos systèmes puis vous établissez une correspondance un pour un de ces adresses avec les adresses IP publiques. Pour les occurrences des connexions sortantes, la traduction d'adresses sources (SNAT) sera alors effectuée. Pour les occurrences des connexions entrantes, c'est la traduction d'adresses destination (DNAT) qui sera réalisée.

Voyons avec l'exemple précédent du serveur web de votre fille tournant sur le système Local 3.

Souvenons-nous que dans cette configuration, le réseau local utilise la SNAT et qu'il partage l'IP externe du firewall (192.0.2.176) pour les connexions sortantes. On obtient ce résultat grâce à l'entrée suivante dans le fichier `/etc/shorewall/masq`:

    #INTERFACE     SUBNET               ADDRESS
    eth0           192.168.201.0/29     192.0.2.176

Supposons maintenant que vous ayez décidé d'allouer à votre fille sa propre adresse IP (192.0.2.179) pour l'ensemble des connexions entrantes et sortantes. Vous pouvez faire cela en ajoutant cette entrée dans le fichier`/etc/shorewall/nat`.

    #EXTERNAL   INTERFACE   INTERNAL       ALL INTERFACES   LOCAL
    192.0.2.179 eth0        192.168.201.4  No               No

Avec cette entrée active, votre fille a sa propre adresse IP et les deux autres systèmes locaux partagent l'adresse IP du firewall.

Une fois que la relation entre 192.0.2.179 et192.168.201.4 est établie avec l'entrée ci-dessus dans le fichier `nat`, l'utilisation d'une règle d'une règle DNAT pour le serveur Web de votre fille n'est plus appropriée -- vous devriez plutôt utiliser une simple règle ACCEPT:

    #ACTION  SOURCE  DEST               PROTO  DEST    SOURCE    ORIGINAL
    #                                          PORT(S) PORT(S)   DEST
    ACCEPT   net     loc:192.168.201.4  tcp    www

Un mot de mise en garde. En général, les FAI configurent leurs routeurs avec un timeout de cache ARP assez élevé. Si vous déplacez un système parallèle à votre firewall derrière le Proxy ARP du firewall, cela peut mettre des HEURES avant que ce système ne puisse communiquer avec internet. Il y a deux choses que vous pouvez essayer de faire:

1.  (Salutations à Bradey Honsinger) Une lecture de “TCP/IP Illustrated, Vol 1” de Richard Stevens révèle qu'un paquet ARP “gratuit” (gratuitous) peut amener le routeur de votre FAI à rafraîchir son cache (section 4.7). Un paquet ARP “gratuit” est simplement une requête d'un hôte demandant l'adresse MAC associée à sa propre adresse IP.

    En plus de garantir que cette adresse IP n'est pas dupliquée, “si l'hôte qui envoie la commande ARP ‘gratuit’ vient juste de changer son adresse matérielle ..., ce paquet force tous les autres hôtes...qui ont une entrée dans leur cache ARP pour l'ancienne adresse matérielle à mettre leurs caches à jour”

    Ce qui est exactement, bien sûr, ce que vous souhaitez faire lorsque vous basculez un hôte qui était directement exposé sur internet vers l'arrière de votre firewall Shorewall en utilisant le proxy ARP (ou en faisant du NAT un-à-un pour la même raison). Heureusement, les versions récentes du paquetage `iputils` de Redhat comprennent `arping`, dont l'option "-U" fait cela:

        arping -U -I <net if> <newly proxied IP>

        arping -U -I eth0 66.58.99.83 # for example

    Stevens continue en mentionnant que certains systèmes ne répondent pas correctement à la commande ARP “gratuit”, mais une recherche sur google pour “arping -U” semble démontrer que cela fonctionne dans la plupart des cas.

2.  Vous pouvez appeler votre FAI et lui demander de purger l'entrée obsolète de son cache ARP, mais la plupart ne voudront ou ne pourront le faire.

Vous pouvez vérifier si le cache ARP de votre FAI est obsolète en utilisant `ping` et `tcpdump`. Supposez que vous pensez que la passerelle routeur a une entrée ARP obsolète pour 192.0.2.177. Sur le firewall, lancez `tcpdump` de cette façon:

    tcpdump -nei eth0 icmp

Maintenant depuis 192.0.2.177, `ping`ez la passerelle de votre FAI (que nous supposons être 192.0.2.254):

    ping 192.0.2.254

Nous pouvons maintenant observer le résultat de `tcpdump`:

    13:35:12.159321 0:4:e2:20:20:33 0:0:77:95:dd:19 ip 98:
                    192.0.2.177 > 192.0.2.254: icmp: echo request (DF)
    13:35:12.207615 0:0:77:95:dd:19 0:c0:a8:50:b2:57 ip 98:
                    192.0.2.254 > 192.0.2.177 : icmp: echo reply

Remarquez que l'adresse source MAC dans la requête echo est différente de l'adresse MAC de destination dans la réponse echo ! Dans ce cas, 0:4:e2:20:20:33 était l'adresse MAC de l'interface réseau `eth0` du firewall tandis que 0:c0:a8:50:b2:57 était l'adresse MAC de la carte réseau de DMZ 1. En d'autre termes, le cache ARP de la passerelle associe encore 192.0.2.177 avec la carte réseau de DMZ 1 plutôt qu'avec l'interface `eth0` du firewall.

## Règles

<div class="note">

Shorewall dispose d'un mécanisme de [macros](../concepts/Macros.md) comprenant des macros pour de nombreuses applications standard. Dans cette section nous n'utiliserons pas de macro. mais nous définirons les règles directement.

</div>

Avec les politiques définies plus tôt dans ce document, vos systèmes locaux (Local 1-3) peuvent accéder à n'importe quel serveur sur internet alors que la DMZ ne peut accéder à aucun autre hôte, dont le firewall. A l'exception des règles NAT qui entraînent la traduction d'adresses et permettent aux requêtes de connexion traduites de passer à travers le firewall, la façon d'autoriser des requêtes à travers votre firewall est d'utiliser des règles ACCEPT.

<div class="note">

Puisque les colonnes SOURCE PORT et ORIG. DEST. ne sont pas utilisées dans cette section, elle ne seront pas affichées.

</div>

Vous souhaiter certainement autoriser le `ping` entre vos zones:

    #ACTION  SOURCE  DEST               PROTO  DEST   
    #                                          PORT(S)
    ACCEPT   net     dmz                icmp   echo-request
    ACCEPT   net     loc                icmp   echo-request
    ACCEPT   dmz     loc                icmp   echo-request
    ACCEPT   loc     dmz                icmp   echo-request

Supposons que vous avez des serveurs mail et pop3 actifs sur le système DMZ 2, et un serveur Web sur le système DMZ 1. Les règles dont vous avez besoin sont:

    #ACTION  SOURCE          DEST               PROTO  DEST    COMMENTS 
    #                                                  PORT(S)
    ACCEPT   net             dmz:192.0.2.178    tcp    smtp    #Mail from
                                                               #Internet
    ACCEPT   net             dmz:192.0.2.178    tcp    pop3    #Pop3 from
                                                               #Internet
    ACCEPT   loc             dmz:192.0.2.178    tcp    smtp    #Mail from local
                                                               #Network
    ACCEPT   loc             dmz:192.0.2.178    tcp    pop3    #Pop3 from local
                                                               #Network
    ACCEPT   $FW             dmz:192.0.2.178    tcp    smtp    #Mail from the
                                                               #Firewall
    ACCEPT   dmz:192.0.2.178 net                tcp    smtp    #Mail to the
                                                               #Internet
    ACCEPT   net             dmz:192.0.2.177    tcp    http    #WWW from
                                                               #Internet
    ACCEPT   net             dmz:192.0.2.177    tcp    https   #Secure WWW
                                                               #from Internet
    ACCEPT   loc             dmz:192.0.2.177    tcp    https   #Secure WWW
                                                               #from local
                                                               #Network

Si vous utilisez un serveur DNS public sur 192.0.2.177, vous devez ajouter les règles suivantes:

    #ACTION  SOURCE          DEST               PROTO  DEST    COMMENTS 
    #                                                  PORT(S)
    ACCEPT   net             dmz:192.0.2.177    udp    domain  #UDP DNS from
                                                               #Internet
    ACCEPT   net             dmz:192.0.2.177    tcp    domain  #TCP DNS from
                                                               #Internet
    ACCEPT   loc             dmz:192.0.2.177    udp    domain  #UDP DNS from
                                                               #Local Network
    ACCEPT   loc             dmz:192.0.2.177    tcp    domain  #TCP DNS from
                                                               #Local Network
    ACCEPT   $FW             dmz:192.0.2.177    udp    domain  #UDP DNS from
                                                               #the Firewall
    ACCEPT   $FW             dmz:192.0.2.177    tcp    domain  #TCP DNS from
                                                               #the Firewall
    ACCEPT   dmz:192.0.2.177 net                udp    domain  #UDP DNS to
                                                               #the Internet
    ACCEPT   dmz:192.0.2.177 net                tcp    domain  #TCPP DNS to
                                                               #the Internet

Vous souhaiterez probablement communiquer depuis votre réseau local avec votre firewall et les systèmes en DMZ -- Je recommande SSH qui, grâce à son utilitaire `scp` peut aussi faire de la diffusion et de la mise à jour de logiciels.

    #ACTION  SOURCE          DEST               PROTO  DEST    COMMENTS 
    #                                           PORT(S)
    ACCEPT   loc             dmz                tcp    ssh     #SSH to the DMZ
    ACCEPT   net             $FW                tcp    ssh     #SSH to the
                                                               #Firewall

## D'autres petites choses

La discussion précédente reflète ma préférence personnelle pour l'utilisation d'un Proxy ARP associé à mes serveurs en DMZ et de SNAT/NAT pour les systèmes locaux. Je préfère utiliser la NAT seulement dans le cas ou un système qui fait partie d'un sous-réseau RFC 1918 à besoin d'avoir sa propre adresse IP publique.

Si vous ne l'avez déjà fait, ce serait une bonne idée de parcourir le fichier [`/etc/shorewall/shorewall.conf`](https://shorewall.org/Documentation.html#Config) juste pour voir si autre chose pourrait vous intéresser. Vous pouvez aussi regarder les autres fichiers de configuration que vous n'avez pas touchés pour avoir un aperçu des autres possibilités de Shorewall.

Dans le cas ou vous auriez perdu le fil, vous trouverez ci-dessous un jeu final des fichiers de configuration pour le réseau de notre exemple. Seuls les fichiers de la configuration initiale qui ont été modifiés sont présentés.

`/etc/shorewall/interfaces` (Les "options" sont très dépendantes des sites).

    #ZONE    INTERFACE      BROADCAST     OPTIONS
    net      eth0           detect        rfc1918,routefilter
    loc      eth1           detect
    dmz      eth2           detect

La configuration décrite ici nécessite que votre réseau soit démarré avant que Shorewall ne puisse se lancer. Ceci laisse un petit intervalle de temps durant lequel vous n'avez pas la protection d'un firewall.

Si vous remplacez le “detect” dans les entrées ci-dessus par la valeurs des adresses de diffusion (broadcoast) réelles, vous pouvez activer Shorewall avant de monter vos interfaces réseau.

    #ZONE    INTERFACE      BROADCAST     OPTIONS
    net      eth0           192.0.2.255   rfc1918
    loc      eth1           192.168.201.7
    dmz      eth2           192.168.202.7

`/etc/shorewall/masq` - Réseau Local

    #INTERFACE     SUBNET               ADDRESS
    eth0           192.168.201.0/29     192.0.2.176

`/etc/shorewall/proxyarp` - DMZ

    #ADDRESS     EXTERNAL     INTERFACE     HAVE ROUTE
    192.0.2.177  eth2         eth0          No
    192.0.2.178  eth2         eth0          No

`/etc/shorewall/nat`- Le système de ma fille

    #EXTERNAL   INTERFACE   INTERNAL       ALL INTERFACES   LOCAL
    192.0.2.179 eth0        192.168.201.4  No               No

`/etc/shorewall/rules`

    #ACTION  SOURCE          DEST               PROTO  DEST    COMMENTS 
    #                                                  PORT(S)
    ACCEPT   net             dmz                icmp   echo-request
    ACCEPT   net             loc                icmp   echo-request
    ACCEPT   dmz             loc                icmp   echo-request
    ACCEPT   loc             dmz                icmp   echo-request
    ACCEPT   net             loc:192.168.201.4  tcp    www     #Daughter's
                                                               #Server
    ACCEPT   net             dmz:192.0.2.178    tcp    smtp    #Mail from
                                                               #Internet
    ACCEPT   net             dmz:192.0.2.178    tcp    pop3    #Pop3 from
                                                               #Internet
    ACCEPT   loc             dmz:192.0.2.178    tcp    smtp    #Mail from local
                                                               #Network
    ACCEPT   loc             dmz:192.0.2.178    tcp    pop3    #Pop3 from local
                                                               #Network
    ACCEPT   $FW             dmz:192.0.2.178    tcp    smtp    #Mail from the
                                                               #Firewall
    ACCEPT   dmz:192.0.2.178 net                tcp    smtp    #Mail to the
                                                               #Internet
    ACCEPT   net             dmz:192.0.2.177    tcp    http    #WWW from
                                                               #Internet
    ACCEPT   net             dmz:192.0.2.177    tcp    https   #Secure WWW
                                                               #from Internet
    ACCEPT   loc             dmz:192.0.2.177    tcp    https   #Secure WWW
                                                               #from local
                                                               #Network
    ACCEPT   net             dmz:192.0.2.177    udp    domain  #UDP DNS from
                                                               #Internet
    ACCEPT   net             dmz:192.0.2.177    tcp    domain  #TCP DNS from
                                                               #Internet
    ACCEPT   loc             dmz:192.0.2.177    udp    domain  #UDP DNS from
                                                               #Local Network
    ACCEPT   loc             dmz:192.0.2.177    tcp    domain  #TCP DNS from
                                                               #Local Network
    ACCEPT   $FW             dmz:192.0.2.177    udp    domain  #UDP DNS from
                                                               #the Firewall
    ACCEPT   $FW             dmz:192.0.2.177    tcp    domain  #TCP DNS from
                                                               #the Firewall
    ACCEPT   dmz:192.0.2.177 net                udp    domain  #UDP DNS to
                                                               #the Internet
    ACCEPT   dmz:192.0.2.177 net                tcp    domain  #TCPP DNS to
                                                               #the Internet
    ACCEPT   loc             dmz                tcp    ssh     #SSH to the DMZ
    ACCEPT   net             $FW                tcp    ssh     #SSH to the
                                                               #Firewall

# DNS

Compte tenu des adresses RFC 1918 et des adresses publiques utilisées dans cette configuration, la seule façon logique de faire est d'avoir des serveurs DNS interne et externe séparés. Vous pouvez combiner les deux dans un unique serveur BIND 9 utilisant les vues (Views). Si vous n'êtes pas intéressé par les vues BIND 9, vous pouvez allez à la section suivante.

Supposons que votre domaine est foobar.net. Vous voulez que les deux systèmes en DMZ s'appellent www.foobar.net et mail.foobar.net, et vous voulez que les trois systèmes locaux s'appellent winken.foobar.net, blinken.foobar.net et nod.foobar.net. Vous voulez que le firewall soit connu à l'extérieur sous le nom de firewall.foobar.net, que son interface vers le réseau local soit nommée gateway.foobar.net et que son interface vers la DMZ soit dmz.foobar.net. Mettons le serveur DNS sur 192.0.2.177 qui sera aussi connu sous le nom de ns1.foobar.net.

Le fichier `/etc/named.conf` devrait ressembler à cela:

    options {
            directory "/var/named";
            listen-on { 127.0.0.1 ; 192.0.2.177; };
            transfer-format many-answers;
            max-transfer-time-in 60;

    allow-transfer {
            // Servers allowed to request zone tranfers 
           <secondary NS IP>; };
    };

    logging {
            channel xfer-log {
                    file "/var/log/named/bind-xfer.log";
                    print-category yes;
                    print-severity yes;
                    print-time yes;
                    severity info;
    };

            category xfer-in { xfer-log; };
            category xfer-out { xfer-log; };
            category notify { xfer-log; };
    };

    #
    # This is the view presented to our internal systems
    #

    view "internal" {
            #
            # These are the clients that see this view
            #
            match-clients { 192.168.201.0/29;
                            192.168.202.0/29;
                            127.0.0.0/8;
                            192.0.2.176/32; 
                            192.0.2.178/32;
                            192.0.2.179/32;
                            192.0.2.180/32; };
            #
            # If this server can't complete the request, it should use
            # outside servers to do so
            #
            recursion yes;

            zone "." in {
                    type hint;
                    file "int/root.cache";
            };

            zone "foobar.net" in {
                    type master;
                    notify no;
                    allow-update { none; };
                    file "int/db.foobar";
            };

            zone "0.0.127.in-addr.arpa" in {
                    type master;
                    notify no;
                    allow-update { none; };
                    file "int/db.127.0.0";
            };

            zone "201.168.192.in-addr.arpa" in {
                    type master;
                    notify no;
                    allow-update { none; };
                    file "int/db.192.168.201";
            };

            zone "202.168.192.in-addr.arpa" in {
                    type master;
                    notify no;
                    allow-update { none; };
                    file "int/db.192.168.202";
            };

            zone "176.2.0.192.in-addr.arpa" in {
                    type master;
                    notify no;
                    allow-update { none; };
                    file "db.192.0.2.176";
            };
     
            zone "177.2.0.192.in-addr.arpa" in {
                    type master;
                    notify no;
                    allow-update { none; };
                    file "db.192.0.2.177";
            };

            zone "178.2.0.192.in-addr.arpa" in {
                    type master;
                    notify no;
                    allow-update { none; };
                    file "db.192.0.2.178";
            };

            zone "179.2.0.192.in-addr.arpa" in {
                    type master;
                    notify no;
                    allow-update { none; };
                    file "db.206.124.146.179";
            };

    };
    #
    # This is the view that we present to the outside world
    #
    view "external" {
             match-clients { any; };
             #
             # If we can't answer the query, we tell the client so
             #
             recursion no;

             zone "foobar.net" in {
                     type master;
                     notify yes;
                     allow-update {none; };
                     file "ext/db.foobar";
             };

             zone "176.2.0.192.in-addr.arpa" in {
                     type master;
                     notify yes;
                     allow-update { none; };
                     file "db.192.0.2.176";
             };

             zone "177.2.0.192.in-addr.arpa" in {
                     type master;
                     notify yes;
                     allow-update { none; };
                     file "db.192.0.2.177";
             };

             zone "178.2.0.192.in-addr.arpa" in {
                     type master;
                     notify yes;
                     allow-update { none; };
                     file "db.192.0.2.178";
             };

             zone "179.2.0.192.in-addr.arpa" in {
                     type master;
                     notify yes;
                     allow-update { none; };
                     file "db.192.0.2.179";
             };
    };

Voici les fichiers du répertoire `/var/named` (ceux qui ne sont pas présentés font en général partie de votre distribution BIND).

`db.192.0.2.176` - Zone inverse (reverse) pour l'interface externe du firewall

    ; ############################################################
    ; Start of Authority (Inverse Address Arpa) for 192.0.2.176/32
    ; Filename: db.192.0.2.176
    ; ############################################################
    @ 604800 IN SOA ns1.foobar.net. netadmin.foobar.net. (
                            2001102303 ; serial
                            10800 ; refresh (3 hour)
                            3600 ; retry (1 hour)
                            604800 ; expire (7 days)
                            86400 ) ; minimum (1 day)
    ;
    ; ############################################################
    ; Specify Name Servers for all Reverse Lookups (IN-ADDR.ARPA)
    ; ############################################################
    @        604800  IN NS   ns1.foobar.net.
    @        604800  IN NS   <name of secondary ns>.
    ;
    ; ############################################################
    ; Iverse Address Arpa Records (PTR's) 
    ; ############################################################
    176.2.0.192.in-addr.arpa. 86400 IN PTR firewall.foobar.net.

`db.192.0.2.177` - Zone inverse pour le serveur www

    ; ############################################################
    ; Start of Authority (Inverse Address Arpa) for 192.0.2.177/32
    ; Filename: db.192.0.2.177
    ; ############################################################
    @ 604800 IN SOA ns1.foobar.net. netadmin.foobar.net. (
                            2001102303 ; serial
                            10800 ; refresh (3 hour)
                            3600 ; retry (1 hour)
                            604800 ; expire (7 days)
                            86400 ) ; minimum (1 day)
    ;
    ; ############################################################
    ; Specify Name Servers for all Reverse Lookups (IN-ADDR.ARPA)
    ; ############################################################
    @        604800  IN NS   ns1.foobar.net.
    @        604800  IN NS   <name of secondary ns>.
    ;
    ; ############################################################
    ; Iverse Address Arpa Records (PTR's) 
    ; ############################################################
    177.2.0.192.in-addr.arpa. 86400 IN PTR www.foobar.net.

`db.192.0.2.178` - Zone inverse du serveur mail

    ; ############################################################
    ; Start of Authority (Inverse Address Arpa) for 192.0.2.178/32
    ; Filename: db.192.0.2.178
    ; ############################################################
    @ 604800 IN SOA ns1.foobar.net. netadmin.foobar.net. (
                          2001102303 ; serial
                          10800 ; refresh (3 hour)
                          3600 ; retry (1 hour)
                          604800 ; expire (7 days)
                          86400 ) ; minimum (1 day)
    ;
    ; ############################################################
    ; Specify Name Servers for all Reverse Lookups (IN-ADDR.ARPA)
    ; ############################################################
    @        604800  IN NS   ns1.foobar.net.
    @        604800  IN NS   <name of secondary ns>.
    ;
    ; ############################################################
    ; Iverse Address Arpa Records (PTR's) 
    ; ############################################################
    178.2.0.192.in-addr.arpa. 86400 IN PTR mail.foobar.net.

`db.192.0.2.179` - Zone inverse du serveur web public de votre fille

    ; ############################################################
    ; Start of Authority (Inverse Address Arpa) for 192.0.2.179/32
    ; Filename: db.192.0.2.179
    ; ############################################################
    @ 604800 IN SOA ns1.foobar.net. netadmin.foobar.net. (
                          2001102303 ; serial
                          10800 ; refresh (3 hour)
                          3600 ; retry (1 hour)
                          604800 ; expire (7 days)
                          86400 ) ; minimum (1 day)
    ;
    ; ############################################################
    ; Specify Name Servers for all Reverse Lookups (IN-ADDR.ARPA)
    ; ############################################################
    @        604800  IN NS   ns1.foobar.net.
    @        604800  IN NS   <name of secondary ns>.
    ;
    ; ############################################################
    ; Iverse Address Arpa Records (PTR's) 
    ; ############################################################
    179.2.0.192.in-addr.arpa. 86400 IN PTR nod.foobar.net.

`int/db.127.0.0` - Zone inverse pour localhost

    ; ############################################################
    ; Start of Authority (Inverse Address Arpa) for 127.0.0.0/8
    ; Filename: db.127.0.0
    ; ############################################################
    @ 604800 IN SOA ns1.foobar.net. netadmin.foobar.net. (
                                 2001092901 ; serial
                                 10800 ; refresh (3 hour)
                                 3600 ; retry (1 hour)
                                 604800 ; expire (7 days)
                                 86400 ) ; minimum (1 day)
    ; ############################################################
    ; Specify Name Servers for all Reverse Lookups (IN-ADDR.ARPA)
    ; ############################################################
    @     604800          IN NS   ns1.foobar.net.

    ; ############################################################
    ; Iverse Address Arpa Records (PTR's)
    ; ############################################################
    1       86400           IN PTR  localhost.foobar.net.

`int/db.192.168.201` - Zone inverse pour le réseau local. Cela ne sera visible que depuis les clients internes

    ; ############################################################
    ; Start of Authority (Inverse Address Arpa) for 192.168.201.0/29
    ; Filename: db.192.168.201
    ; ############################################################
    @ 604800 IN SOA ns1.foobar.net netadmin.foobar.net. (
                                    2002032501 ; serial
                                    10800 ; refresh (3 hour)
                                    3600 ; retry (1 hour)
                                    604800 ; expire (7 days)
                                    86400 ) ; minimum (1 day)

    ; ############################################################
    ; Specify Name Servers for all Reverse Lookups (IN-ADDR.ARPA)
    ; ############################################################
    @       604800          IN NS   ns1.foobar.net.
    ; ############################################################
    ; Iverse Address Arpa Records (PTR's)
    ; ############################################################
    1       86400           IN PTR  gateway.foobar.net.
    2       86400           IN PTR  winken.foobar.net.
    3       86400           IN PTR  blinken.foobar.net.
    4       86400           IN PTR  nod.foobar.net.

`int/db.192.168.202` - Zone inverse de l'interface DMZ du firewall

    ; ############################################################
    ; Start of Authority (Inverse Address Arpa) for 192.168.202.0/29
    ; Filename: db.192.168.202
    ; ############################################################
    @ 604800 IN SOA ns1.foobar.net netadmin.foobar.net. (
                                    2002032501 ; serial
                                    10800 ; refresh (3 hour)
                                    3600 ; retry (1 hour)
                                    604800 ; expire (7 days)
                                    86400 ) ; minimum (1 day)

    ; ############################################################
    ; Specify Name Servers for all Reverse Lookups (IN-ADDR.ARPA)
    ; ############################################################
    @             604800  IN NS   ns1.foobar.net.

    ; ############################################################
    ; Iverse Address Arpa Records (PTR's)
    ; ############################################################
    1               86400 IN PTR  dmz.foobar.net.

`int/db.foobar`- Forward zone pour les clients internes.

    ;##############################################################
    ; Start of Authority for foobar.net.
    ; Filename: db.foobar
    ;##############################################################
    @ 604800 IN SOA ns1.foobar.net. netadmin.foobar.net. (
                            2002071501 ; serial
                            10800 ; refresh (3 hour)
                            3600 ; retry (1 hour)
                            604800 ; expire (7 days)
                            86400 ); minimum (1 day)
    ;############################################################
    ; foobar.net Nameserver Records (NS)
    ;############################################################
    @                 604800  IN NS   ns1.foobar.net.

    ;############################################################
    ; Foobar.net Office Records (ADDRESS)
    ;############################################################
    localhost 86400   IN A    127.0.0.1

    firewall       86400   IN A    192.0.2.176
    www            86400   IN A    192.0.2.177
    ns1            86400   IN A    192.0.2.177
    mail           86400   IN A    192.0.2.178 

    gateway        86400   IN A    192.168.201.1
    winken         86400   IN A    192.168.201.2
    blinken        86400   IN A    192.168.201.3
    nod            86400   IN A    192.168.201.4

    dmz            86400   IN A    192.168.202.1

`ext/db.foobar`- Forward zone pour les clients externes

    ;##############################################################
    ; Start of Authority for foobar.net.
    ; Filename: db.foobar
    ;##############################################################
    @ 86400 IN SOA ns1.foobar.net. netadmin.foobar.net. (
                            2002052901 ; serial
                            10800 ; refresh (3 hour)
                            3600 ; retry (1 hour)
                            604800 ; expire (7 days)
                            86400 ); minimum (1 day)
    ;############################################################
    ; Foobar.net Nameserver Records (NS)
    ;############################################################
    @                86400   IN NS   ns1.foobar.net.
    @                86400   IN NS   <secondary NS>.
    ;############################################################
    ; Foobar.net        Foobar Wa Office Records (ADDRESS)
    ;############################################################
    localhost         86400   IN A    127.0.0.1
    ;
    ; The firewall itself
    ;
    firewall          86400   IN A    192.0.2.176
    ;
    ; The DMZ
    ;
    ns1               86400   IN A    192.0.2.177
    www               86400   IN A    192.0.2.177
    mail              86400   IN A    192.0.2.178
    ;
    ; The Local Network
    ;
    nod             86400   IN A    192.0.2.179

    ;############################################################
    ; Current Aliases for foobar.net (CNAME)
    ;############################################################

    ;############################################################
    ; foobar.net MX Records (MAIL EXCHANGER)
    ;############################################################
    foobar.net.      86400   IN A    192.0.2.177
                     86400   IN MX 0 mail.foobar.net.
                     86400   IN MX 1 <backup MX>.

# Quelques Points à Garder en Mémoire

- **Vous ne pouvez pas tester votre firewall depuis l'intérieur de votre réseau**. Envoyer des requêtes à l'adresse IP externe de votre firewall ne signifie pas qu'elle seront associées à votre interface externe ou à la zone “net”. Tout trafic généré par le réseau local sera associé à l'interface locale et sera traité comme du trafic du réseau local ver le firewall (loc-\>fw).

- **Les adresses IP sont des propriétés des systèmes, pas des interfaces**. C'est une erreur de croire que votre firewall est capable de faire suivre (*forward*) des paquets simplement parce que vous pouvez faire un `ping` sur l'adresse IP de toutes les interfaces du firewall depuis le réseau local. La seule conclusion que vous puissiez faire dans ce cas est que le lien entre le réseau local et le firewall fonctionne et que vous avez probablement la bonne adresse de passerelle par défaut sur votre système.

- **Toutes les adresses IP configurées sur le firewall sont dans la zone \$FW (fw)**. Si 192.168.1.254 est l'adresse IP de votre interface interne, alors vous pouvez écrire “**\$FW:192.168.1.254**” dans une régle mais vous ne devez pas écrire “**loc:192.168.1.254**”. C'est aussi une absurdité d'ajouter 192.168.1.254 à la zone **loc** en utilisant une entrée dans `/etc/shorewall/hosts`.

- **Les paquets de retour (reply) ne suivent PAS automatiquement le chemin inverse de la requête d'origine**. Tous les paquets sont routés en se référant à la table de routage respective de chaque hôte à chaque étape du trajet. Ce problème se produit en général lorsque on installe un firewall Shorewall en parallèle à une passerelle existante et qu'on essaye d'utiliser des règles DNAT dans Shorewall sans changer la passerelle par défaut sur les systèmes recevant les requêtes transférées (forwarded). Les requêtes passent dans le firewall Shorewall où l'adresse de destination IP est réécrite, mais la réponse revient par l'ancienne passerelle qui, elle, ne modifiera pas le paquet.

- **Shorewall lui-même n'a aucune notion du dedans et du dehors**. Ces concepts dépendent de la façon dont Shorewall est configuré.

# Démarrer et Arrêter Votre Firewall

La [procédure d'installation](Install_fr.md) configure votre système pour lancer Shorewall dès le boot du système, mais le lancement est désactivé, de façon à ce que votre système ne tente pas de lancer Shorewall avant que la configuration ne soit terminée. Une fois que vous en avez fini avec la configuration du firewall, vous devez éditer /etc/shorewall/shorewall.conf et y mettre STARTUP_ENABLED=Yes.

<div class="important">

Les utilisateurs des paquetages .deb doivent éditer `/etc/default/``shorewall` et mettre `startup=1`.

</div>

Le firewall est activé en utilisant la commande “`shorewall start`” et arrêté avec la commande “`shorewall stop`”. Lorsque le firewall est arrêté, le routage est autorisé sur les hôtes qui possèdent une entrée dans `/etc/shorewall/routestopped`. Un firewall qui tourne peut être relancé en utilisant la commande “`shorewall restart`”. Si vous voulez enlever toute trace de Shorewall sur votre configuration de Netfilter, utilisez “**shorewall clear**”

Modifiez `/etc/shorewall/``routestopped` pour y configurer les hôtes auxquels vous voulez accéder lorsque le firewall est arrêté.

<div class="warning">

Si vous êtes connecté à votre firewall depuis internet, n'essayez pas d'exécuter une commande “`shorewall stop`” tant que vous n'avez pas ajouté une entrée dans `/etc/shorewall/routestopped` pour l'adresse IP à partir de laquelle vous êtes connecté . De la même manière, je vous déconseille d'utiliser “`shorewall restart`”; il est plus intéressant de créer [une configuration alternative](../reference/configuration_file_basics.md#Configs) et de la tester en utilisant la commande “[shorewall try](../reference/starting_and_stopping_shorewall.md)”

</div>
