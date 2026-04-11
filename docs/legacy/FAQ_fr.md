<div class="note">

<u>Notes du traducteur :</u> Si vous trouvez des erreurs ou si vous avez des améliorations à apporter à cette traduction vous pouvez [me contacter](mailto:guy@posteurs.com).

</div>

<div class="caution">

**Cet article s'applique à Shorewall 3.0 et à ses versions ultérieures. Si vous utilisez une version plus ancienne de Shorewall, référez-vous à la documentation s'appliquant à votre version.**

</div>

# Installation de Shorewall

## Où puis-je trouver des instructions d'installation et de configuration pas à pas ?

**Réponse:** Allez voir les [guides de démarrage rapide](../reference/shorewall_quickstart_guide.md).

## (FAQ 37) Je viens d'installer Shorewall sur Debian et le répertoire /etc/shorewall est vide!!!

**Réponse:**

<div class="important">

Après avoir installé le paquetage .deb, avant de commencer à configurer Shorewall, vous devriez prendre connaissance de ce conseil de Lorenzo Martignoni, le mainteneur Debian de Shorewall:

“Pour plus d'information quant à l'utilisation de Shorewall sur un système Debian vous devriez aller voir le fichier /usr/share/doc/shorewall/README.Debian distribué avec le paquetage Debian de Shorewall.”

</div>

Si vous vous servez du .deb pour installer, vous vous rendrez compte que votre répertoire `/etc/shorewall` est vide. Ceci est voulu. Les squelettes des fichiers de configuration se trouvent sur votre système dans le répertoire `/usr/share/doc/shorewall/default-config`. Copiez simplement les fichiers dont vous avez besoin depuis ce répertoire dans `/etc/shorewall`, puis modifiez ces copies.

Remarquez que vous devez copier `/usr/share/doc/shorewall/default-config/shorewall.conf` et `/usr/share/doc/shorewall/default-config/modules` dans `/etc/shorewall` même si vous ne modifiez pas ces fichiers.

## (FAQ 44) Je n'arrive pas à installer ou mettre à jour le RPM - J'ai le message d'erreur "error: failed dependencies:iproute is needed..."

**Réponse**: Lisez les [Instructions d'installation](Install_fr.md)!

## (FAQ 50) Quand j'installe ou que je mets à jour, j'obtiens de multiples instances du message suivant "warning: user teastep does not exist - using root"

**Réponse:** Vous pouvez sans aucun risque ignorer ce message. Il était dû à une erreur mineure de paquetage qui a été corrigée depuis. Cela ne change rien dans l'utilisation de Shorewall.

# Transfert de port (Redirection de Port)

## (FAQ 1) Je veux rediriger le port UDP 7777 vers mon PC personnel qui a l'adresse 192.1683.1.5. J'ai cherché partout et je ne trouve pas comment faire.

**Réponse:** Le premier exemple de la [documentation du fichier rules](https://shorewall.org/Documentation.html#Rules) vous indique comment faire du transfert de port avec Shorewall. Le format d'une règle de redirection de port vers un système local se présente comme suit:

    #ACTION    SOURCE      DEST                                   PROTO        DEST PORT
    DNAT       net         loc:<adresse IP locale>[:<port local>] <protocole>  <n° port>

Ainsi pour rediriger le port UDP 7777 vers le système interne 192.168.1.5, la règle est:

    #ACTION    SOURCE   DEST             PROTO    DEST PORT
    DNAT       net      loc:192.168.1.5  udp      7777

Si vous voulez rediriger vers un système interne les requêtes envoyées à une adresse donnée (*\<IP externe\>*) sur votre firewall:

    #ACTION SOURCE DEST                                   PROTO       DEST PORT  SOURCE  ORIGINAL
    #                                                                            PORT    DEST.
    DNAT    net    loc:<adresse IP locale>[:<port local>]<protocole>  <n° port>   -       <IP externe>

Enfin, si vous avez besoin de rediriger une plage de ports, spécifiez la plage de ports \<premier port\>:\<dernier port\> dans la colonne DEST PORT.

### (FAQ 1a) D'accord -- j'ai suivi toutes ces instruction, mais cela ne marche toujours pas.

**Réponse:** Ceci se produit généralement lorsque:

- Vous tentez de tester depuis l'intérieur de votre firewall (non, cela ne marchera pas -- allez voir la [FAQ 2](#faq2) ).

- Vous avez un problème plus élémentaire de configuration de votre système local (celui vers lequel vous tentez de rediriger les paquets), une mauvaise passerelle par défaut par exemple (elle devrait être configurée avec l'adresse IP de l'interface interne de votre firewall).

- Votre FAI bloque le trafic entrant sur ce port particulier.

- Vous utilisez une version de Mandriva antérieure à la 10.0 final et vous avez configuré le partage de connexion internet. Si c'est le cas, le nom de votre zone locale n'est pas 'loc' mais 'masq' (dans vos règles changez toutes les instances de 'loc' pour 'masq'). Vous pouvez envisager de ré-installer Shorewall avec une configuration conforme à la documentation de Shorewall. Voir le guide [Firewall à deux interfaces](two-interface_fr.md) pour plus de détails.

### (FAQ 1b) J'ai malgré tout encore des problèmes avec la redirection de port

**Réponse:** pour aller plus avant dans le diagnostic du problème:

- En tant que root, tapez “ `iptables -t nat -Z` ”. Ceci remet à zéro les compteurs Netfilter de la table nat.

- Essayez de vous connecter au port redirigé depuis un hôte externe.

- En tant que root, tapez “ `shorewall[-lite] show nat` ”

- Repérez la règle DNAT appropriée. Elle sera dans une chaîne nommée \<*zone source*\>\_dnat (“net_dnat” dans les exemples ci-dessus).

- Est-ce que le décompte de paquets dans la première colonne est supérieur à zéro ? Si cela est le cas, la requête de connexion atteint le firewall et est bien redirigée vers le serveur. Dans ce cas, le problème vient en général de l'absence de paramètrage ou d'un paramètrage erroné de la passerelle par défaut sur le système local (celui vers lequel vous essayez de transférer les paquets -- sa passerelle par défaut devrait être l'adresse IP de l'interface du firewall connectée à ce système local).

- Si le décompte de paquets est égal à zéro:

  - La requête de connexion n'arrive pas jusqu'à votre serveur (il est possible que votre FAI bloque ce port)

  - Vous essayez de vous connecter à une adresse IP secondaire sur votre firewall et votre règle ne redirige que l'adresse IP primaire (dans votre règle DNAT vous devez spécifier l'adresse IP secondaire dans la colonne “ORIG. DEST.”)

  - Pour d'autres raisons, votre règle DNAT ne correspond pas à la requête de connexion. Dans ce cas, pour aller plus loin dans le diagnostic, vous pourrez avoir à vous servir d'un “sniffer” de paquets comme tcpdump ou ethereal.

  - Si le nombre de paquets est différent de zéro, vérifiez dans votre log si la connexion est droppée ou rejetée. Si c'est le cas, il est possible que vous ayez un problème de définition de zone qui fasse que le serveur soit dans une zone différente de ce qui est spécifié dans la colonne DEST. A l'invite root, tapez "`shorewall[-lite] show zones`" et assurez-vous que vous avez bien spécifié dan la colonne DEST la **première** zone de la liste qui correspond à OUT=\<dev\> et DEST=\<ip\> dans le message REJECT/DROP de votre fichier log.

### (FAQ 1c) Je voudrais que lorsque je me connecte depuis internet au port 1022 de mon firewall, cette connexion soit redirigée vers le port 22 de mon système local 192.168.1.3. Comment faire ?

**Réponse**:Dans le fichier /`etc/shorewall/rules`:

    #ACTION    SOURCE   DEST                PROTO    DEST PORT
    DNAT       net      loc:192.168.1.3:22  tcp      1022

### (FAQ 1d) J'ai un serveur web dans man DMZ et j'utilise le transfert de port pour rendre ce serveur accessible depuis internet. Cela fonctionne très bien sauf lorsque mes utilisateurs locaux essayent de se connecter au serveur en utilisant l'adresse IP externe du firewall.

**Réponse**: Supposons que:

- L'adresse IP externe est 206.124.146.176 sur `eth0`.

- L'adresse IP du serveur est 192.168.2.4

Vous pouvez activer l'accès au serveur depuis votre réseau local en utilisant l'adresse IP externe du firewall. Pour cela, vous pouvez ajouter cette règle:

    #ACTION    SOURCE   DEST                PROTO    DEST PORT(S)    SOURCE      ORIGINAL
    #                                                                PORT        DEST                 
    DNAT       loc      dmz:192.168.2.4     tcp      80              -           206.124.146.176

Si votre adresse IP externe est dynamique, vous devez faire comme suit:

Dans `/etc/shorewall/params`:

    ETH0_IP=`find_interface_address eth0`       

Pour les utilisateurs de 2.1.0 et des versions ultérieures:

    ETH0_IP=`find_first_interface_address eth0`

Et votre règle DNAT deviendra:

    #ACTION    SOURCE        DEST               PROTO    DEST PORT   SOURCE    ORIGINAL
    #                                                                PORT      DEST.
    DNAT       loc           dmz:192.168.2.4    tcp      80          -         $ETH0_IP

### (FAQ 1e) Dans le but de décourager les attaques en force brute, je voudrais rediriger toutes les connexions internet arrivant sur un port non standard (4104) vers le port 22 du firewall/routeur. J'ai remarqué que lorsque je paramètre une règle REDIRECT sur le firewall, il ouvre sur internet les deux ports 4104 et 22 . Est-il possible de rediriger seulement le port 4104 vers le port 22 de localhost et que toutes les tentatives de connexion depuis internet au port 22 soient ignorées ?

**Réponse:** avec l'aimable autorisation de Ryan: en supposant que l'adresse de l'interface locale de votre firewall soit 192.168.1.1, si vous configurez SSHD pour qu'il n'écoute que sur cette interface et que vous ajoutez la règle suivante, le port 4104 sera en écoute sur internet et le port 22 sera en écoute sur votre LAN.

    #ACTION SOURCE  DEST                    PROTO   DEST PORT(S)
    DNAT    net     fw:192.168.1.1:22       tcp     4104

## (FAQ 30) Quand doit-on utiliser des règles DNAT et quand doit-on utiliser des règles ACCEPT ?

**Réponse**: Je vous suggère de revenir au [guides de démarrage rapide](../reference/shorewall_quickstart_guide.md) adapté à votre configuration. Ces guides couvrent ce sujet sous un angle didactique. Vous devriez utiliser des règles DNAT pour les connexions qui doivent aller dans le sens inverse de celles en provenance de la SNAT/Masquerade. Ainsi, si vous utilisez la SNAT ou Masquerade depuis votre réseau local vers internet, vous aurez besoin d'utiliser des règles DNAT pour autoriser les connexions d'internet vers votre réseau local. Vous utiliserez également des règles DNAT si vous voulez ré-écrire l'adresse IP ou le numéro de port destination. Si vous avez besoin d'intercepter des connexions lorsqu'elles arrivent sur le firewall et que vous voulez les traiter sur le firewall lui-même, vous utiliserez une règle REDIRECT. Dans tous les autres cas, vous utiliserez ACCEPT.

## (FAQ 38) Où trouver plus d'information sur la DNAT?

**Réponse**: Ian Allen a écrit cet article au sujet de la [DNAT et Linux](http://ian.idallen.ca/dnat.txt).

## (FAQ 48) Comment configurer un proxy transparent avec Shorewall?

**Réponse**: Vous pouvez voir [Shorewall et Squid](../features/Shorewall_Squid_Usage.md).

# DNS et Transfert de Port/Traduction d'Adresses Réseau NAT

## (FAQ 2) Je transfère (port forward) toutes les requêtes web soumises à www.mondomaine.com (IP 130.151.100.69) vers le système 192.168.1.5 de mon réseau local. Les clients externes peuvent accéder à http://www.mondomaine.com mais les clients internes ne le peuvent pas.

**Réponse:** j'ai deux objections à cette configuration.

- Avoir un serveur sur votre réseau local accessible depuis internet est comme élever des loups à coté de votre poulailler. Si le serveur est compromis, il n'y a rien entre ce serveur et vos autres systèmes locaux. Pour le prix d'un adaptateur ethernet et d'un câble croisé, vous pouvez mettre votre serveur en DMZ de telle façon qu'il soit isolé de vos systèmes locaux - en supposant que le serveur puisse être installé à coté de votre firewall, bien entendu :-)

- La meilleure solutions pour l'accessibilité à votre serveur est d'utiliser les “vues” de [Bind Version 9](shorewall_setup_guide_fr.md#DNS) (ou bien d'utiliser un serveur DNS séparé pour les clients locaux) afin que www.mondomaine.com soit résolu en 130.141.100.69 pour les clients externes et en 192.168.1.5 pour les clients internes. C'est ce que je fait ici à shorewall.net pour mes systèmes locaux qui utilisent la NAT un-à-un (one-to-one NAT).

Supposons que votre interface externe soit eth0, que votre interface interne soit eth1 et que eth1 ait l'adresse 192.168.1.254 sur le sous-réseau 192.168.1.0/24:

<div class="warning">

tout le trafic redirigé par cette bidouille sera vu par le serveur comme provenant du firewall (192.168.1.254) au lieu de venir du client d'origine! Ce qui fait que les logs d'accès du serveur seront inutilisables pour déterminer quels hôtes locaux accèdent au serveur.

</div>

- Dans `/etc/shorewall/interfaces`:

      #ZONE    INTERFACE    BROADCAST    OPTIONS
      loc      eth1         detect       routeback    

- Dans `/etc/shorewall/masq`:

      #INTERFACE              SUBNET          ADDRESS         PROTO   PORT(S)
      eth1:192.168.1.5        eth1            192.168.1.254   tcp     www

- Dans `/etc/shorewall/rules`:

      #ACTION    SOURCE       DEST               PROTO    DEST PORT   SOURCE    ORIGINAL
      #                                                               PORT      DEST.
      DNAT       loc          loc:192.168.1.5    tcp      www         -         130.151.100.69

  Bien entendu, cette règle ne fonctionnera que si vous avez une adresse IP externe statique. Si vous avez une adresse dynamique vous devez inclure ceci dans `/etc/shorewall/param`s:

      ETH0_IP=`find_first_interface_address eth0`        

  et votre règle DNAT deviendra:

      #ACTION    SOURCE        DEST               PROTO    DEST PORT   SOURCE    ORIGINAL
      #                                                                PORT      DEST.
      DNAT       loc           loc:192.168.1.5    tcp      www         -         $ETH0_IP

  Lorsque vous utilisez cette technique, il vous faudra configurer votre client DHCP/PPPoE de façon à ce qu'il relance shorewall chaque fois qu'il obtient une nouvelle adresse IP.

### (FAQ 2a) J'ai une zone “Z” avec un sous-réseau RFC 1918 et j'utilise la NAT un-à-un (one-to-one NAT) pour assigner des adresses non-RFC1918 aux hôtes de la zone “Z”. Les hôtes dans la zone “Z” ne peuvent pas communiquer entre eux en utilisant leur adresse externe (adresses non-FRC1918) et donc ils ne peuvent pas communiquer en utilisant leurs noms DNS.

<div class="note">

Si la colonne ALL INTERFACES dans le fichier /etc/shorewall/nat est vide ou contient “Yes”, vous verrez aussi dans votre journal des messages comme celui-ci à chaque fois que vous tenterez d'accéder à un hôte de la zone Z depuis un autre hôte de la zone Z en utilisant son adresse publique:

    Oct 4 10:26:40 netgw kernel:
              Shorewall:FORWARD:REJECT:IN=eth1 OUT=eth1 SRC=192.168.118.200
              DST=192.168.118.210 LEN=48 TOS=0x00 PREC=0x00 TTL=127 ID=1342 DF
              PROTO=TCP SPT=1494 DPT=1491 WINDOW=17472 RES=0x00 ACK SYN URGP=0

</div>

**Réponse:** C'est encore un problème très bien résolu par l'utilisation des “vues” de [Bind Version 9](shorewall_setup_guide_fr.md#DNS). Les clients internes comme les clients externes peuvent alors accéder aux hôtes “NATés” en utilisant leur nom réseau.

Une autre bonne façon d'approcher le problème est d'abandonner la NAT un-à-un au profit du Proxy ARP. De cette façon, les machines dans Z ont des adresses non-RFC1918 et on peut y accéder aussi bien depuis l'intérieur que depuis l'extérieur en utilisant la même adresse.

Si vous n'aimez pas ces solutions et que vous préférez bêtement router tout le trafic de Z vers Z par votre firewall:

1.  Activez l'option routeback sur l'interface vers Z.

2.  Mettez “Yes” dans la colonne ALL INTERFACES du fichier nat.

<!-- -->

    Zone: dmz Interface: eth2 Ssous-réseau: 192.168.2.0/24 Addresse: 192.168.2.254

Dans le fichier `/etc/shorewall/interfaces`:

    #ZONE    INTERFACE    BROADCAST       OPTIONS
    dmz      eth2         192.168.2.255   routeback 

Dans le fichier `/etc/shorewall/na`t, assurez-vous d'avoir “Yes” dans la colonne ALL INTERFACES.

Dans le fichier `/etc/shorewall/masq`:

    #INTERFACE    SUBNETS     ADDRESS
    eth2          eth2        192.168.2.254

Tout comme dans la bidouille présentée dans la FAQ2 ci-dessus, le trafic de la dmz vers la dmz semblera provenir du firewall et non du véritable hôte source.

### (FAQ 2b) J'ai un serveur web dans ma DMZ et je me sers du transfert de port pour le rendre accessible sur internet en tant que www.mondomaine.com. Cela marche très bien sauf pour mes utilisateurs locaux lorsqu'ils tentent de se connecter à www.mondomaine.com.

**Réponse**: Supposons que:

- L'adresse externe IP soit 206.124.146.176 sur `eth0` (www.mondomaine.com).

- L'adresse IP du serveur soit 192.168.2.4

Vous pouvez autoriser les machines du réseau local à accéder à votre serveur en utilisant l'adresse IP externe du firewall. Il suffit d'ajouter cette règle:

    #ACTION    SOURCE   DEST                PROTO    DEST PORT(S)    SOURCE      ORIGINAL
    #                                                                PORT        DEST                 
    DNAT       loc      dmz:192.168.2.4     tcp      80              -           206.124.146.176

Si votre adresse IP externe vous est allouée dynamiquement, vous devez faire comme suit:

Dans le fichier `/etc/shorewall/params`:

    ETH0_IP=`find_first_interface_address eth0`  

Et votre règle DNAT deviendra:

    #ACTION    SOURCE        DEST               PROTO    DEST PORT   SOURCE    ORIGINAL
    #                                                                PORT      DEST.
    DNAT       loc           dmz:192.168.2.4    tcp      80          -         $ETH0_IP

<div class="warning">

Avec des adresses IP dynamiques, vous n'utiliserez pas `shorewall[-lite] save` ni `shorewall[-lite] restore`.

</div>

### (FAQ 2c) J'ai essayé d'appliquer la réponse à la FAQ 2 à mon interface externe et à la zone net. Cela ne marche pas. Pourquoi ?

**Réponse**: Avez-vous activé **IP_FORWARDING=On** dans `shorewall.conf`?

# Netmeeting/MSN

## (FAQ 3) Je veux utiliser Netmeeting ou la messagerie instantanée MSN avec Shorewall. Que faire ?

**Réponse:** Il existe un [module de suivi de connexion H.323](http://www.kfki.hu/%7Ekadlec/sw/netfilter/newnat-suite/) qui est d'un grand secours avec Netmeeting. Prenez cependant en compte cet article récent d'un des développeurs de Netfilter:

>     > Je sais que PoM -ng va traiter ce problème, mais en attendant qu'il soit prêt,
>     > et que tous les extras y soient portés, existe-t-il un moyen d'utiliser le patch
>     > noyau pour le module de suivi de connexion H.323 avec un noyau 2.6 ?
>     > j'utilise un noyau 2.6.1 et le noyau 2.4 n'est pas installé sur le système, c'est 
>     > pourquoi je ne peux pas envisager de revenir en 2.4 ... et le module n'a pas
>     > encore été porté en 2.6, dommage.
>     > Quelles options ai-je à part d'installer une application gatekeeper (qui ne 
>     > fonctionne pas dans mon réseau) ou un proxy (ce que je préférerais éviter) ?
>
>     Je suggère à tous de configurer un proxy (gatekeeper): le module est vraiment 
>     nul et ne mérite pas d'exister. Ça a été un très bon outil de développement et
>     de deboguage de l'interface newnat.

Vous pouvez aller voir [ici](UPnP.md) une solution pour la messagerie instantanée MSN. Vous devez avoir conscience que cette solution comporte des risques de sécurité significatifs. Vous pouvez également vérifier auprès de la liste de diffusion de Netfilter à <http://www.netfilter.org>.

# Ports ouverts

## (FAQ 51) Comment ouvrir des ports dans Shorewall?

**Réponse:** Aucune personne ayant installé Shorewall en utilisant un des [Guides de Démarrage Rapide](../reference/shorewall_quickstart_guide.md) ne devrait avoir à poser cette question.

Quel que soit le guide que vous avez utilisé, toutes les communications sortantes sont ouvertes par défaut. Vous n'avez donc pas à "ouvrir de port" en sortie.

En entrée:

- Si vous avez installé en utilisant le guide Firewall Monoposte (une interface), [relisez cette section SVP](standalone_fr.md#Open).

- Si vous avez utilisé le guide Firewall à deux interfaces pour installer merci de relire ces sections: [Transfert de ports (DNAT)](two-interface_fr.md#DNAT), et [Autres connexions](two-interface_fr.md#Open)

- Si vous avez utilisé le guide Firewall à trois interfaces pour installer merci de relire ces sections: [Transfert de ports (DNAT)](../reference/three-interface.md#DNAT) et [Autres Connexions](../reference/three-interface.md#Open)

- Si vous avez installé en utilisant le [Guide de configuration Shorewall](shorewall_setup_guide_fr.md) vous feriez mieux de lire le guide à nouveau -- vous avez vraiment raté beaucoup de choses.

Voyez également la [section Transfert de Ports de cette FAQ](#PortForwarding).

## (FAQ 4) Je viens juste d'utiliser un scanner de port en ligne pour vérifier le paramètrage de mon firewall et certains ports apparaissent “fermés” (closed) alors que d'autres sont “bloqués” (blocked). Pourquoi ?

**Réponse:** La configuration par défaut de Shorewall invoque l'action **Drop** avant de mettre en oeuvre une politique DROP, et la politique par défaut d'internet vers toutes les zones est DROP. L'action Drop est définie dans le fichier `/usr/share/shorewall/action.Drop` qui invoque lui-même la macro **Auth** (définie dans le fichier `/usr/share/shorewall/macro.Auth`) qui spécifie l'action **REJECT** (c.a.d., **Auth/REJECT**). Cela est nécessaire pour éviter les problèmes de connexion sortante à des services qui utilisent le mécanisme “Auth” pour identifier les utilisateurs. C'est le seul service configuré par défaut pour rejeter (REJECT) les paquets.

Si vous voyez d'autres ports TCP fermés autres que le port 113 (auth) c'est que vous avez ajouté des règles REJECT pour ces ports ou bien qu'un routeur à l'extérieur de votre firewall répond aux requêtes de connexion sur ce port.

### (FAQ 4a) Je viens d'exécuter un scan UDP de mon firewall avec nmap et il trouve des centaines de ports ouverts!!!!

**Réponse:** Respirez à fond et lisez la section man de nmap au sujet des scans UDP. Si nmap n'a **aucun** retour de votre firewall, il donnera ce port comme étant ouvert. Si vous voulez voir quels sont les ports UDP réellement ouverts, modifiez temporairement votre politique net-\>all pour REJECT, relancez Shorewall et refaites le scan UDP nmap.

### (FAQ 4b) Quoi que je change dans mes règles, Il y a un port que je n'arrive pas à fermer.

J'avais une règle qui autorisait telnet de mon réseau local vers mon firewall. Je l'ai enlevée et j'ai relancé Shorewall mais ma session telnet fonctionne encore!!!

**Réponse:** Les règles traitent de l'établissement de nouvelles connexions. Lorsqu'une connexion est établie par le firewall, elle restera utilisable jusqu'à la déconnexion tcp ou jusqu'au time out pour les autres protocoles. Si vous fermez votre session telnet et que vous essayez d'établir un nouvelle session, votre firewall bloquera cette tentative.

### (FAQ 4c) Comment utiliser Shorewall avec PortSentry?

[**Answer:** Vous trouverez ici la description](https://shorewall.org/pub/shorewall/contrib/PortsentryHOWTO.txt) d'une bonne intégration de Shorewall et PortSentry.

## (FAQ 4d) Comment utiliser Shorewall avec Snort-Inline?

**Réponse:** [Allez voir cette contribution](http://www.catherders.com/tiki-view_blog_post.php?blogId=1&postId=71) de Michael Cooke.

# Problèmes de connexion

## (FAQ 5) J'ai installé Shorewall et je ne peux plus “pinger” à travers le firewall

**Réponse:** Pour une description complète de la gestion du “ping” par Shorewall, voyez [cette page](../features/ping.md).

## (FAQ 15) Mes systèmes locaux ne peuvent rien voir sur internet

**Réponse:** Chaque fois que je lis “mes systèmes ne peuvent rien voir sur internet”, je me demande où l'auteur a bien pu acheter des ordinateurs avec des yeux et ce que ces ordinateurs peuvent bien “voir” lorsque tout fonctionne convenablement. Ceci mis à part, les causes habituelles à ce type de problèmes sont:

1.  L'adresse de la passerelle par défaut n'est pas configurée à l'adresse de l'interface locale du firewall sur chacun des systèmes locaux.

2.  L'entré pour le réseau local dans le fichier `/etc/shorewall/masq` est erronée ou manquante.

3.  La configuration du DNS sur les systèmes locaux est mauvaise ou bien l'utilisateur fait tourner un serveur DNS sur le firewall et il n'a pas autorisé le port 53 UDP et TCP de son firewall vers internet.

4.  Le forwarding n'est pas activé (ceci est souvent le cas pour les utilisateurs Debian). Exécutez cette commande:

        cat /proc/sys/net/ipv4/ip_forward

    Si la valeur est 0 (zéro) mettez **IP_FORWARDING=On** dans le fichier `/etc/shorewall/shorewall.conf` et relancez Shorewall.

## (FAQ 29) FTP ne fonctionne pas

**Réponse**: Voir la page [Shorewall et FTP](../features/FTP.md).

## (FAQ 33) Depuis mes clients derrière le firewall les connexions vers certains sites échouent. Les connexions vers les mêmes sites, mais depuis le firewall fonctionnent. Qu'est-ce qui ne va pas ?

**Réponse**: Très probablement, il vous faudra mettre CLAMPMSS=Yes dans le fichier [/etc/shorewall/shorewall.conf](https://shorewall.org/Documentation.html#Conf).

## (FAQ 35) J'ai deux interfaces ethernet vers mon réseau local que j'ai montées en pont (bridge). Quand Shorewall est démarré, je n'arrive pas à faire passer le trafic à travers le pont. J'ai défini l'interface pont (br0) comme interface locale dans /etc/shorewall/interfaces. Les interfaces ethernet “pontées” ne sont pas définies pour Shorewall. Comment demander à Shorewall d'autoriser le trafic à travers le pont ?

**Réponse**: ajouter l'option routeback à l'interface `br0` dans le fichier [/etc/shorewall/interfaces](https://shorewall.org/Documentation.html#Interfaces).

Pour plus d'information sur ce type de configuration, voir la documentation pour [un pont simple avec Shorewall](../features/SimpleBridge.md).

# Journalisation

## (FAQ 6) Où sont enregistrés les messages de journalisation et comment modifier leur destination ?

**Réponse:** NetFilter utilise l'équivalent noyau de syslog (voir “man syslog”) pour journaliser les messages. Il utilise toujours le dispositif LOG_KERN (voir “man openlog”) et vous devez choisir le niveau de journalisation (log level, voir “man syslog”) dans vos [politiques](https://shorewall.org/Documentation.html#Policy) et dans vos [règles](https://shorewall.org/Documentation.html#Rules). La destination des messages journalisés par syslog est contrôlée avec `/etc/syslog.conf` (voir “man syslog.conf”). Lorsque vous avez modifié `/etc/syslog.conf`, assurez-vous de redémarrer syslogd (sur un système RedHat, “service syslog restart”).

Par défaut, les versions plus anciennes de Shorewall limitaient le taux de journalisation des messages grâce à des [paramètres](https://shorewall.org/Documentation.html#Conf) du fichier `/etc/shorewall/shorewall.conf` -- Si vous voulez journaliser tous les messages, positionnez ces paramètres comme suit:

    LOGLIMIT=""
    LOGBURST=""

On peut également [paramétrer Shorewall pour qu'il enregistre les messages de journalisation dans un fichier séparé](../features/shorewall_logging.md).

### (FAQ 6a) Existe-t-il des analyseur de journal qui fonctionnent avec Shorewall?

**Réponse:** Voilà plusieurs liens qui peuvent vous aider:

              https://shorewall.org/pub/shorewall/parsefw/
              http://www.fireparse.com
              http://cert.uni-stuttgart.de/projects/fwlogwatch
              http://www.logwatch.org
              http://gege.org/iptables
              http://home.regit.org/ulogd-php.html
            

Personnellement, j'utilise Logwatch. Il m'envoie chaque jour par courriel un rapport pour chacun de mes différents systèmes. Chaque rapport résume l'activité journalisée sur le système correspondant.

### (FAQ 6b) Mes journaux sont inondés de messages DROP pour des requêtes de connections sur le port 10619. Puis-je exclure temporairement de la journalisation Shorewall les messages d'erreur pour ce port ?

**Réponse**: Ajoutez temporairement la règle suivante:

    #ACTION   SOURCE    DEST    PROTO    DEST PORT(S)
    DROP      net       fw      udp      10619

Sinon, si vous ne mettez pas le paramètre BLACKLIST_LOGLEVEL et que vous avez spécifié l'option 'blacklist' sur votre interface externe dans le fichier `/etc/shorewall/interfaces`, vous pouvez blacklister le port. Dans le fichier `/etc/shorewall/blacklist`:

    #ADDRESS/SUBNET         PROTOCOL        PORT
    -                       udp             10619

### (FAQ 6d) Pourquoi l'adresse MAC dans les messages de journalisation Shorewall est-elle si longue ? Je pensais que l'adresse MAC ne faisait que 6 octets.

**Réponse**: Ce qui est labelisé comme adresse MAC dans les messages de journalisation Shorewall est en fait l'entête de la trame ethernet. Elle contient:

- l'adresse MAC de destination (6 octets)

- l'adresse MAC source (6 octets)

- le type de trame ethernet (2 octets)

<!-- -->

    MAC=00:04:4c:dc:e2:28:00:b0:8e:cf:3c:4c:08:00

- adresse MAC de destination = 00:04:4c:dc:e2:28

- adresse MAC source = 00:b0:8e:cf:3c:4c

- type de trame ethernet = 08:00 (IP Version 4)

## (FAQ 16) Shorewall écrit ses messages de journalisation directement sur ma console et la rend inutilisable!

**Réponse:**

- Trouvez où klogd est démarré (ce sera depuis un des fichiers du répertoire `/etc/init.d` -- sysklogd, klogd, ...). Modifiez ce fichier ou le fichier de configuration approprié de telle manière que klogd soit démarré avec “-c *\<n\>* ” avec *\<n\>* étant un niveau de journalisation inférieur ou égal à 5; ou alors

- Voir la page man de “dmesg” (“man dmesg”). Vous devez ajouter une commande “dmesg” adaptée dans vos scripts de démarrage ou la placer dans le fichier `/etc/shorewall/start`.

<div class="tip">

Sous RedHat et Mandriva, le [niveau de journalisation](../features/shorewall_logging.md) maximum envoyé à la console est spécifié par la variable LOGLEVEL du fichier `/etc/sysconfig/init`. Positionnez “LOGLEVEL=5” pour éliminer de la console les messages de niveau info.

</div>

<div class="tip">

Sous Debian, vous pouvez mettre KLOGD=“-c 5” dans le fichier `/etc/init.d/klogd` afin d'éliminer de la console les messages de niveau info (log level 6).

</div>

<div class="tip">

Sous SUSE, ajoutez “-c 5” à KLOGD_PARAMS dans le fichier `/etc/sysconfig/syslog` fin d'éliminer de la console les messages de niveau info (log level 6).

</div>

## (FAQ 17) Pourquoi ces paquets sont-ils ignorés/rejetés (dropped/rejected)? Comment décode-t-on les messages de journalisation Shorewall?

**Réponse:** Avec Shorewall, les paquets ignorés/rejetés peuvent avoir été journalisés en sortie d'un certain nombre de chaînes (comme indiqué dans le message):

man1918 or logdrop  
L'adresse destination est listée dans le fichier `/usr/share/shorewall/rfc1918` avec une cible **logdrop** -- voir `/usr/share/shorewall/rfc1918`.

rfc1918 or logdrop  
L'adresse source ou destination est listée dans le fichier `/usr/share/shorewall/rfc1918` avec un cible **logdrop** -- voir `/usr/share/shorewall/rfc1918`.

<div class="note">

Si vous voyez des paquets rejetés par la chaîne rfc1918 et que ni l'adresse IP source ni l'adresse IP de destination ne sont réservées par la RFC 1918, cela provient la plupart du temps d'un ancien fichier `rfc1918` dans `/etc/shorewall` (ceci arrive le plus fréquemment lorsque vous utilisez une Debian ou un de ses dérivés). Le fichier `rfc1918` incluait aussi bien les *bogons* que les trois plages réservées par la RFC 1918. Il était installé dans le répertoire `/etc/shorewall`. Maintenant le fichier ne contient que les trois plages d'adresse de la RFC 1918 et il est installé dans le répertoire `/usr/share/shorewall`. Retirez le fichier rfc1918 périmé de votre répertoire `/etc/shorewall`.

</div>

all2\<zone\>, \<zone\>2all or all2all  
Vous avez une [politique](https://shorewall.org/Documentation.html#Policy) qui spécifie un niveau de journalisation et ce paquet a été journalisé par cette politique. Si vous voulez autoriser (ACCEPT) ce trafic, il vous faudra une [règle](https://shorewall.org/Documentation.html#Rules) à cette fin.

\<zone1\>2\<zone2\>  
Ou bien vous avez une [politique](https://shorewall.org/Documentation.html#Policy) pour le trafic de la **\<zone1\>** vers la **\<zone2\>** qui spécifie un niveau de journalisation et ce paquet a été journalisé par cette politique ou alors ce paquet correspond à une [règle](https://shorewall.org/Documentation.html#Rules) incluant un niveau de journalisation.

A partir de Shorewall 3.3.3, les paquets loggés par ces chaines peuvent avoir une source et/ou une destination n'appartenant à aucune zone définie (voir le résultat de la commande `shorewall[-lite] show zones`). Souvenez-vous que l'appartenance à une zone nécessite à la fois une interface du firewall et une adresse ip.

@\<source\>2\<dest\>  
Vous avez une politique pour le trafic de \<**source**\> vers \<**dest**\> dans laquelle vous avez spécifié un taux de limitation des connexions TCP (les valeurs dans la colonne LIMIT:BURST). Les paquet journalisé dépassait cette limite et a été ignoré (DROP). Il faut noter que ces messages au journal sont eux-même sévèrement limités afin qu'une inondation SYN (syn-flood) ne provoque pas un déni de service (DOS) secondaire par un nombre excessif de messages de journalisation. Ces messages ont été introduits dans Shorewall 2.2.0 Beta 7.

\<interface\>\_mac  
Ce paquet a été journalisé par l'[option d'interface](https://shorewall.org/Documentation.html#Interfaces) **maclist** .

logpkt  
Ce paquet a été journalisé par l'[option d'interface](https://shorewall.org/Documentation.html#Interfaces) **logunclean**.

badpkt  
Ce paquet a été journalisé par l'[option d'interface](https://shorewall.org/Documentation.html#Interfaces) **dropunclean** tel que spécifié dans le paramètre **LOGUNCLEAN** du fichier [`/etc/shorewall/shorewall.conf`](https://shorewall.org/Documentation.html#Conf) .

blacklst  
Ce paquet a été journalisé parce que l'adresse IP source est inscrite dans la liste noire `/etc/shorewall/blacklist`.

INPUT or FORWARD  
Ce paquet a une adresse IP source qui n'est définie dans aucune de vos zones (“`shorewall[-lite] show zones`” et regardez les définitions de zones) ou alors la chaîne est FORWARD et l'adresse IP de destination ne figure dans aucune de vos zones définies. Si la chaîne est FORWARD et les interfaces IN et OUT sont identiques, vous avez sans doute besoin de l'option **routeback** sur cette interface dans le fichier `/etc/shorewall/interfaces` ou bien vous avez besoin de l'option **routeback** pour l'entrée adéquate dans le fichier`/etc/shorewall/hosts`.

A partir de 3.3.3, de tels paquets peuvent aussi être loggés par les chaines \<zone\>2all et all2all.

OUTPUT  
Ce paquet a une adresse IP destination qui n'est définie dans aucune de vos zones (“shorewall check” et regardez les définitions de zones).

A partir Shorewall 3.3.3, de tels paquets peuvent aussi être loggés par les chaines fw2all et all2all.

logflags  
Ce paquet a été journalisé parce qu'il a échoué aux contrôles mis en oeuvre par l'[option d'interface](https://shorewall.org/Documentation.html#Interfaces) **tcpflags**.

<!-- -->

    Jun 27 15:37:56 gateway kernel:
            Shorewall:all2all:REJECT:IN=eth2
              OUT=eth1
              SRC=192.168.2.2
              DST=192.168.1.3 LEN=67 TOS=0x00 PREC=0x00 TTL=63 ID=5805 DF PROTO=UDP
            SPT=1803 DPT=53 LEN=47

Examinons les partie importantes de ce message:

all2all:REJECT  
Ce paquet a été rejeté (REJECT) par la chaîne **all2all** -- le paquet a été rejeté par la politique “all”-\>“all” REJECT (voir [all2all](#all2all) ci-dessus).

IN=eth2  
Le paquet est arrivé dans le firewall par eth2. Lorsque vous voyez “IN=” sans aucun nom d'interface, c'est que le paquet provient du firewall lui-même.

OUT=eth1  
Si il avait été autorisé, ce paquet aurait été transmis à eth1. Lorsque vous voyez “OUT=” sans aucun nom d'interface, c'est que le paquet aurait été traité par le firewall lui-même.

<div class="note">

Lorsqu'une règle DNAT est journalisée, on n'a jamais de OUT= parce que le paquet est journalisé avant d'être routé. Par ailleurs, la journalisation DNAT donnera l'adresse IP destination et le numéro de port destination d'*origine*.

</div>

SRC=192.168.2.2  
Ce paquet a été envoyé par 192.168.2.2

DST=192.168.1.3  
Ce paquet a pour destination 192.168.1.3

PROTO=UDP  
Le protocole est UDP

DPT=53  
Le port de destination est le port 53 (DNS)

Pour plus d'informations concernant les messages de journalisation, voir <http://logi.cc/linux/netfilter-log-format.php3>.

Dans ce cas, 192.168.2.2 était dans la zone “dmz” et 192.168.1.3 était dans la zone “loc”. Il me manquait la règle suivante:

    ACCEPT dmz loc udp 53

## (FAQ 21) Je vois occasionnellement ces étranges messages dans mon journal. De quoi s'agit-il?

    Nov 25 18:58:52 linux kernel:
          Shorewall:net2all:DROP:IN=eth1 OUT=
          MAC=00:60:1d:f0:a6:f9:00:60:1d:f6:35:50:08:00 SRC=206.124.146.179
          DST=192.0.2.3 LEN=56 TOS=0x00 PREC=0x00 TTL=110 ID=18558 PROTO=ICMP
          TYPE=3 CODE=3 [SRC=192.0.2.3 DST=172.16.1.10 LEN=128 TOS=0x00 PREC=0x00
          TTL=47 ID=0 DF PROTO=UDP SPT=53 DPT=2857 LEN=108 ]

192.0.2.3 est externe à mon firewall... mon réseau local est 172.16.0.0/24

**Réponse:** Bien que la plupart des gens associent ICMP (Internet Control Message Protocol) à “ping”, ICMP est une pièce clé de IP. ICMP sert à informer l'expéditeur d'un paquet des problèmes rencontrés. C'est ce qui se produit ici. Malheureusement, de nombreuses implémentations ne fonctionnent pas dès lors que la traduction d'adresses est impliquée (y compris SNAT, DNAT et Masquerade). C'est ce que vous voyez avec à travers ces messages. Quand Netfilter renvoie ces messages, la partie précédent le "\[" décrit le paquet ICMP, et la partie entre "\[" et "\]" décrit le paquet pour lequel ICMP répond.

Voici mon interprétation de ce qui se passe -- pour confirmer l'analyse, il faudrait avoir un “sniffeur” de paquets à chacune des extrémités de la connexion.

L'hôte 172.16.1.10 placé derrière la passerelle NAT 206.124.146.179 a envoyé une requête DNS UDP à 192.0.2.3 et votre serveur DNS a tenté d'envoyer un réponse (l'information en réponse est entre les crochets -- remarquez le port source 53 qui indique qu'il s'agit d'une réponse DNS). Quand la réponse a été envoyée à 206.124.146.179, le firewall a réécrit l'adresse IP destination à 172.16.1.10 puis a fait suivre le paquet à 172.16.1.10 qui n'avait plus de connexion UDP sur le port 2857. Ceci provoque la génération d'un message ICMP port unreachable (type 3, code 3) en retour vers 192.0.2.3. Ce paquet est renvoyé par 206.124.146.179 qui change correctement l'adresse source dans le paquet pour 206.124.146.179 mais ne modifie pas de la même façon l'IP destination dans la réponse DNS d'origine. Lorsque le paquet ICMP atteint votre firewall (192.0.2.3), celui-ci n'a aucun enregistrement lui indiquant qu'il a envoyé une réponse DNS à 172.16.1.10 et par conséquent ce paquet ICMP semble n'être associé à rien de ce qui a été envoyé. Le résultat est que ce paquet est journalisé et ignoré (DROP) par la chaîne all2all. J'ai également vu des cas dans lesquels la source IP dans le paquet ICMP lui-même n'est pas ré-écrite à l'adresse externe de la passerelle NAT distante. Dans ce cas votre firewall va journaliser et ignorer (DROP) le paquet par la chaîne rfc1918 cas son IP source est réservée par la RFC 1918.

## (FAQ 52) Quand je blackliste une adresse IP avec "shorewall\[-lite\] drop www.xxx.yyy.zzz", pourquoi est-ce qu'il y a toujours des entrées REDIRECT et DNAT en provenance de cette adresse dans mon journal ?

J'ai blacklisté l'adresse 130.252.100.59 avec la commande `shorewall drop 130.252.100.59` mais je vois toujours ces messages dans le journal:

    Jan 30 15:38:34 server Shorewall:net_dnat:REDIRECT:IN=eth1 OUT= MAC=00:4f:4e:14:97:8e:00:01:5c:23:24:cc:08:00
                           SRC=130.252.100.59 DST=206.124.146.176 LEN=64 TOS=0x00 PREC=0x00 TTL=43 ID=42444 DF
                           PROTO=TCP SPT=2215 DPT=139 WINDOW=53760 RES=0x00 SYN URGP=0

**Réponse**: Veuillez vous référer à [Shorewall Netfilter Documentation](../concepts/NetfilterOverview.md). La journalisation des règles REDIRECT et DNAT se produit dans la chaîne PREROUTING de la table nat dans laquelle l'adresse est toujours valide. Le blacklistage se produit dans les chaînes INPUT et FORWARD de la table filter qui ne sont traversées que plus tard.

## (FAQ 56) Quand je démarre ou redémarre Shorewall, je vois ces messages dans mon fichier log. Est-ce grave ?

>     modprobe: Can't locate module ipt_physdev
>     modprobe: Can't locate module iptable_raw

**Réponse:** Non. Ceci se produit lorsque shorewall teste votre système pour déterminer les fonctions qu'il supporte. Ils ne présentent aucun risque.

# Routage

## (FAQ 32) J'ai deux connexions internet avec deux FAI différents sur mon firewall. Comment le configurer avec Shorewall?

**Réponse**: voir cet article sur [Shorewall et le routage](../features/MultiISP.md).

## (FAQ 49) Quand je démarre Shorewall, ma table de routage est détruite. Pourquoi Shorewall fait-il cela?

**Réponse**: Ceci est en général la conséquence d'une bêtise dans la configuration du NAT un-à-un (one-to-one NAT):

1.  Vous spécifiez l'adresse IP primaire d'une interface dans la colonne EXTERNAL du fichier `/etc/shorewall/nat` alors que la documentation et les commentaires dans le fichier vous mettent en garde contre une telle configuration.

2.  Vous spécifiez ADD_IP_ALIASES=Yes et RETAIN_ALIASES=No dans le fichier `/etc/shorewall/shorewall.conf`.

Cette combinaison fait détruire par Shorewall l'adresse primaire de l'interface réseau spécifiée dans la colonne INTERFACE, ce qui a en général pour conséquence de détruire routes les routes sortantes de cette interface. La solution est de **ne pas spécifier l'adresse primaire d'une interface dans la colonne EXTERNAL**.

# Démarrer et arrêter Shorewall

## (FAQ 7) Quand j'arrête Shorewall avec la commande “shorewall\[-lite\] stop”, je ne peux plus me connecter à quoi que ce soit. Pourquoi cette commande ne fonctionne-t-elle pas?

**Réponse**: La commande “ `stop` ” est prévue pour mettre votre firewall dans un état de sécurité où seuls les hôtes listés dans le fichier `/etc/shorewall/routestopped` sont activés. Si vous voulez ouvrir complètement votre firewall, il vous faut utiliser la commande “`shorewall clear`”.

## (FAQ 8) Quand je tente de lancer Shorewall sur RedHat, je reçois des messages d'erreur insmod -- qu'est-ce qui ne va pas?

**Réponse:** La sortie que vous avez ressemble à ceci:

    /lib/modules/2.4.17/kernel/net/ipv4/netfilter/ip_tables.o: init_module: Device or resource busy
    Hint: insmod errors can be caused by incorrect module parameters, including invalid IO or IRQ parameters
    /lib/modules/2.4.17/kernel/net/ipv4/netfilter/ip_tables.o: insmod
    /lib/modules/2.4.17/kernel/net/ipv4/netfilter/ip_tables.o failed
    /lib/modules/2.4.17/kernel/net/ipv4/netfilter/ip_tables.o: insmod ip_tables failed
    iptables v1.2.3: can't initialize iptables table `nat': iptables who? (do you need to insmod?)
    Perhaps iptables or your kernel needs to be upgraded.

En général, ce problème est corrigé par la séquence de commandes qui suit:

    service ipchains stop
    chkconfig --delete ipchains
    rmmod ipchains

Par ailleurs, assurez-vous d'avoir vérifié dans l'[errata](https://shorewall.org/errata.html) que vous n'avez pas de problèmes lié à la version d'iptables (v1.2.3) distribuée avec RH7.2.

### (FAQ 8a) Quand je tente de lancer Shorewall sur une RedHat, je reçois un message qui me renvoie à la FAQ \#8

**Réponse:** Ceci se traite en général avec la séquence de commandes présentée ci-dessus dans la [(FAQ 8) Quand je tente de lancer Shorewall sur RedHat, je reçois des messages d'erreur insmod -- qu'est-ce qui ne va pas?](#faq8).

## (FAQ 9) Pourquoi Shorewall ne réussit-il pas à détecter convenablement mes interfaces au démarrage?

Je viens d'installer Shorewall et quand je lance la commande start, voilà ce qui se passe :

    Processing /etc/shorewall/params ...
    Processing /etc/shorewall/shorewall.conf ...
    Starting Shorewall...
    Loading Modules...
    Initializing...
    Determining Zones...
       Zones: net loc
    Validating interfaces file...
    Validating hosts file...
    Determining Hosts in Zones...
        Net Zone: eth0:0.0.0.0/0
        Local Zone: eth1:0.0.0.0/0
    Deleting user chains...
    Creating input Chains...
    ...

Pourquoi est-ce que Shorewall ne détecte-t-il pas correctement mes interfaces?

**Réponse:** La sortie ci-dessus est parfaitement normale. La zone Net est définie comme étant composée de toutes les machines connectées à eth0 et la zone Local est définie comme étant composée de toutes celles connectées à eth1. Si vous utilisez Shorewall 1.4.10 ou une version plus récente, vous pouvez envisager de paramétrer l'[option d'interface](https://shorewall.org/Documentation.html#Interfaces) **detectnet** pour votre interface locale (eth1 dans l'exemple ce-dessus). Ceci forcera Shorewall à restreindre la zone locale aux seuls réseaux routés par cette interface.

## (FAQ 22) Je voudrais exécuter certaines commandes iptables au démarrage de Shorewall. Dans quel fichier les mettre?

**Réponse**: Vous pouvez placer ces commandes dans une des [Scripts d'Extension Shorewall](../reference/shorewall_extension_scripts.md). Assurez-vous de bien examiner le contenu des chaînes que vos commandes vont modifier afin d'être certain que ces commandes feront bien ce qu'elles sont censées faire. De nombreuses commandes publiées dans des guides (HOWTOs) ainsi que dans d'autres modes opératoires font usage de la commande -A qui ajoute les règles en fin de chaîne. La plupart des chaînes construites par Shorewall se terminent par une règle inconditionnelle DROP, ACCEPT ou REJECT et donc toute règle que vous pourriez ajouter après serait ignorée. Consultez “man iptables” et prenez connaissance de la commande -I (--insert).

## (FAQ 34) Comment accélérer le démarrage (start/restart)?

**Réponse**: L'utilisation d'un shell léger tel que `ash` peut diminuer de façon très significative le temps nécessaire pour démarrer (**start**/**restart**) Shorewall. Voyez la variable SHOREWALL_SHELL dans le fichier `shorewall.conf`.

Utilisez un émulateur de terminal rapide -- en particulier la console KDE défile beaucoup plus vite que le terminal Gnome. Vous pouvez également utiliser l'option '-q' si vous redémarrez à distance ou depuis un terminal lent (ou rediriger la sortie vers un fichier comme dans `shorewall restart > /dev/null`).

Mettez votre matériel à niveau. De nombreux utilisateurs ont constaté que même une amélioration modeste de la CPU et de la vitesse de la mémoire (par exemple passer d'un P3 avec de la SDRAM à un P4 avec de la DDR) avait des effets très significatifs. Les CPU dotées de la technologie EM64T, aussi bien celles d'AMD que celles d'Intel, montrent des performances de redémarrage très acceptables, même si vous avez un jeu de règles assez complexe.

Shorewall offre également une fonction de démarrage rapide. Pour l'utiliser:

1.  Avec Shorewall dans l'[état démarré](../reference/starting_and_stopping_shorewall.md), exécutez `shorewall save`. Cela va créer le script `/var/lib/shorewall/restore`.

2.  Utilisez l'option **-f** avec la commande start (par exemple, `shorewall -f start`). Ceci forcera Shorewall à chercher le script `/var/lib/shorewall/restore` et à l'exécuter si il existe. Exécuter `/var/lib/shorewall/restore` prend beaucoup moins de temps que d'exécuter un `shorewall start` complet.

3.  Le script `/etc/init.d/shorewall` exécuté au démarrage du système utilise l'option **-f**.

4.  Le script `/var/lib/shorewall/restore` peut être exécuté à tout moment pour restaurer le firewall. Il peut être invoqué directement ou bien indirectement en utilisant la commande `shorewall restore`.

Si vous modifiez votre configuration de Shorewall, vous devez exécuter un **shorewall start** (sans **-f**) ou un `shorewall restart` avant de refaire un `shorewall save`. La commande `shorewall save` sauvegarde la configuration qui tournait au moment où elle a été exécutée et non celle que représentent les fichiers de configuration que vous avez modifiés.

De même, si vous modifiez votre configuration Shorewall et que vous êtes satisfait du résultat, vous devez exécuter une commande `shorewall save`, sans quoi vous reviendriez à l'ancienne configuration enregistrée dans `/var/lib/shorewall/restore` lors du prochain démarrage de votre système.

Finalement, le temps pendant lequel les nouvelles connexions sont bloquées durant le redémarrage de Shorewall peut être réduit dans de très grande proportions en upgradant vers Shorewall 3.2 ou une version ultérieure. A partir de la 3.2, `shorewall [re]start` procède en deux étapes:

1.  La configuration courante est compilée afin de produire un programme shell conçu pour votre configuration.

2.  Si la compilation se déroule sans erreur, le programme compilé est exécuté pour \[re\]démarrer votre firewall.

## (FAQ 43) Je viens d'installer le RPM Shorewall et Shorewall ne démarre pas au lancement du système (boot).

**Réponse**: Quand vous installez avec la commande "rpm -U", Shorewall n'exécute pas les outils de votre distribution qui configurent le démarrage de Shorewall. Vous devrez exécuter cet outils vous-même (insserv, chkconfig, run-level editor, …) pour que Shorewall démarre aux niveaux d'exécutions (run-level) auxquels vous voulez l'utiliser.

## (FAQ 45) Pourquoi est-ce que "shorewall\[-lite\] start" échoue lorsque je tente de mettre en place SNAT/Masquerade?

`shorewall start` produit la sortie suivante:

    …
    Processing /etc/shorewall/policy...
       Policy ACCEPT for fw to net using chain fw2net
       Policy ACCEPT for loc0 to net using chain loc02net
       Policy ACCEPT for loc1 to net using chain loc12net
       Policy ACCEPT for wlan to net using chain wlan2net
    Masqueraded Networks and Hosts:
    iptables: Invalid argument
       ERROR: Command "/sbin/iptables -t nat -A …" Failed

**Réponse**: Dans 99.999% des cas, cette erreur provient d'un problème de comptabilité des versions d'iptables et du noyau.

1.  Votre iptables doit être compilé en utilisant un arbre de sources du noyau qui soit compatible au niveau Netfilter avec le noyau que vous exécutez sur votre système.

2.  Si vous recompilez iptables avec les paramètres par défaut puis que vous l'installez, il sera installé dans `/usr/local/sbin/iptables`. Comme on peut le voir ci-dessus, votre variable IPTABLES est configurée à `/sbin/iptables` dans votre fichier `shorewall.conf`.

## (FAQ 59) Après le démarrage de Shorewall, de nombreux modules netfilter inutilisés sont chargés. Comment éviter cela ?

**Réponse**: Copiez `/usr/share/shorewall/modules` (ou `/usr/share/shorewall/xmodules` suivant le cas) vers `/etc/shorewall/modules` et modifiez cette copie pour qu'elle ne contienne que les modules dont vous avez besoin.

## (FAQ 61) Je viens juste d'installer le nouveau kernel Debian, et maintenant "shorewall start" échoue avec le message "ipt_policy: matchsize 116 != 308". Qu'est-ce qui ne va pas?

**Réponse**: Votre version d'iptables est incompatible avec votre kernel.

- recompilez iptables en utilisant les headers de votre nouveau kernel; ou bien

- si vous n'avez pas besoin du support de "policy match" (vous n'utilisez pas l'implémentation IPSEC du kernel 2.6) vous pouvez renommer `/lib/iptables/libipt_policy.so`.

# Multiples FAIs

## (FAQ 57) J'ai configuré deux FAIs dans Shorewall mais quand j'essaye d'utiliser le second, cela ne fonctionne pas.

**Réponse**: La documentation Multi-ISP vous recommande très fortement d'utiliser l'option d'équilibrage **(balance)** pour tous les FAIs même si vous voulez spécifier manuellement quel FAI utiliser. Si vous ne le faites pas et que votre table principale de routage n'a qu'une seule route par défaut, vous devez désactiver le filtrage de route. Ne spécifiez pas l'option **routefilter** sur l'autre interface dans `/etc/shorewall/interfaces` et désactivez toute protections contre *le spoofing d'adresses IP* que votre distribution pourrait offrir.

## (FAQ 58) Mais si je spécifie 'balance' est-ce que shorewall ne va pas équilibrer le trafic entre les interfaces ? Je ne veux pas qu'il le fasse !

**Réponse**: Supposez que vous vouliez que tout le trafic passe par le FAI1 (mark 1) jusqu'à ce que vous spécifiez différemment. Dans ce cas, ajoutez simplement ces deux règles comme premières règles de marquage dans votre fichier `/etc/shorewall/tcrules`:

    #MARK         SOURCE           DEST
    1:P           0.0.0.0/0
    1:P           $FW
    <other MARK rules>

Maintenant, tout le trafic qui n'est pas marqué par une de vos autres règles de marquage aura mark=1 et sera envoyé par le FAI1. Ceci fonctionnera que l'option **balance** soit spécifiée ou pas.

# Au sujet de Shorewall

## (FAQ 10) Sur quelles distributions Shorewall tourne-t-il?

**Réponse**: Shorewall fonctionnera sur n'importe quelle distribution GNU/Linux distribution réunissant les [pré-requis Shorewall](../concepts/shorewall_prerequisites.md) indiqués dans ce document.

## (FAQ 11) Quelles sont les caractéristiques de Shorewall ?

**Réponse**: voir la [liste des caractéristiques de Shorewall](../concepts/shorewall_features.md).

## (FAQ 12) Existe-t-il une interface graphique?

**Réponse:** Oui. Webmin offre le support de Shorewall 3.x à partir dans sa version 1.300. Voir <http://www.webmin.com>

## (FAQ 13) Pourquoi l'avez-vous appelé “Shorewall”?

**Réponse:** Shorewall est le résultat de la concaténation de “ *Shore*line” ([la ville où je vis](http://www.cityofshoreline.com)) et de “Fire*wall* ”. En fait le nom complet du produit est “Shoreline Firewall” mais on utilise plus communément “Shorewall”.

## (FAQ 23) Pourquoi utilisez-vous des polices de caractères aussi affreuses sur votre site web?

**Réponse**: Le site web de Shorewall est presque entièrement neutre en ce qui concerne les polices (à l'exception de quelques pages il ne spécifie explicitement aucune police). Les polices que vous voyez sont largement celles configurées par défaut dans votre navigateur. Si vous ne les aimez pas reconfigurez votre navigateur.

## (FAQ 25) Comment savoir quelle version de Shorewall ou de Shorewall Lite j'utilise?

**Réponse**: A l'invite du système, tapez:

    /sbin/shorewall[-lite] version      

## (FAQ 31) Est-ce que Shorewall fournit une protection contre....

IP Spoofing: envoyer des paquets par l'interface WAN en se servant d'adresses IP du réseau local comme adresse source?  
**Réponse**: Oui.

Tear Drop: Envoyer des paquets contenant des fragments qui se recouvrent ?  
**Réponse**: Ceci est de la responsabilité de la pile IP, ce n'est pas celle d'un firewall basé sur Netfilter car le ré-assemblage des fragments est fait avant que le filtre de paquets ne voie chaque paquet.

Smurf and Fraggle: Envoyer des paquets qui utilisent comme adresse source l'adresse de diffusion (broadcast) du WAN ou du LAN?  
**Réponse**: On peut configurer Shorewall pour le faire avec sa fonction de [liste noire (blacklist)](blacklisting_support.md). A partir de la version 2.0.0, Shorewall filtre ces paquets avec l'option d'interface nosmurfs dans le fichier [/etc/shorewall/interfaces](https://shorewall.org/Documentation.html#Interfaces).

Land Attack: Envoyer des paquets utilisant la même adresse comme source et comme destination?  
**Réponse**: Oui lorsque l'[option d'interface routefilter](https://shorewall.org/Documentation.html#Interfaces) est sélectionnée.

DOS: Déni de Service SYN Dos - ICMP Dos - protection DOS par hôte  
**Réponse**: Shorewall offre la possibilité de limiter les paquets SYN les paquets ICMP. Netfilter tel qu'il est inclus dans les noyaux Linux standard ne supporte pas la mise en oeuvre de limitations par hôte distant sauf en utilisant une règle explicite qui spécifie l'adresse IP de l'hôte. Cette forme de limitation est supportée par Shorewall.

## (FAQ 36) Est-ce que Shorewall tourne sur le noyau Linux 2.6?

**Réponse**: Shorewall fonctionne avec les noyaux 2.6 avec les deux restrictions suivantes:

- Dans les noyaux 2.6 jusqu'au 2.6.16, Netfilter/iptables n'offre pas un support complet d'IPSEC -- il existe des patch pour le noyau et pour iptables. Vous trouverez des détails à la page [Shorewall IPSEC-2.6](../features/IPSEC-2.6.md).

- Les noyaux 2.6 n'offrent pas le support des options logunclean et dropunclean du fichier `/etc/shorewall/interfaces`. Le support de ces options a également été retiré de Shorewall dans la version 2.0.0.

# RFC 1918

## (FAQ 14) Je suis connecté avec un modem câble qui a son propre serveur web interne utilisé pour le paramétrage et la supervision. Mais bien entendu, si j'active le blocage des adresse de la RFC 1918 sur mon interface internet eth0, le serveur web du modem est bloqué lui aussi.

Est-il possible de rajouter une règle avant la règle de blocage rfc1918 de façon à autoriser tout le trafic en provenance et à destination de 192.168.100.1, adresse de mon modem, tout en continuant à filtrer les autres adresses rfc1918?

**Réponse**: Ajoutez ce qui suit dans le fichier [/etc/shorewall/rfc1918](https://shorewall.org/Documentation.html#rfc1918) (Remarque: Si vous utilisez 2.0.0 ou une version ultérieure, il est possible que ayez à préalablement à copier le fichier `/usr/share/shorewall/rfc1918` vers `/etc/shorewall/rfc1918`):

Assurez-vous d'ajouter l'entrée AU-DESSUS de l'entrée pour 192.168.0.0/16.

    #SUBNET        TARGET
    192.168.100.1  RETURN

<div class="note">

Si vous ajoutez une seconde adresse IP à l'interface externe de votre firewall qui corresponde à l'adresse du modem, vous devez ajouter une entrée pour cette adresse dans le fichier `/etc/shorewall/rfc1918`. Par exemple, si vous configurez l'adresse 192.168.100.2 sur votre firewall, vous devrez ajouter les deux entrées suivantes dans le fichier `/etc/shorewall/rfc1918`:

    #SUBNET        TARGET
    192.168.100.1  RETURN
    192.168.100.2  RETURN

</div>

### (FAQ 14a) Bien qu'il assigne des adresses IP publiques, le serveur DHCP de mon FAI a une adresse de la RFC 1918. Si j'active le filtrage RFC 1918 sur mon interface externe, mon client DHCP ne peut plus renouveler son bail.

**Réponse**: La solution est la même que dans la [FAQ 14](#faq14) présentée au-dessus. Substituez-y simplement l'adresse du serveur DHCP de votre FAI.

### (FAQ 14b) Je me connecte à internet par PPPoE. Quand j'essaye de me connecter au serveur web incorporé à mon modem DSL, la connexion est refusée.

Dans mon journal je peux voir ce qui suit:

    Mar  1 18:20:07 Mail kernel: Shorewall:OUTPUT:REJECT:IN= OUT=eth0 SRC=192.168.1.2 DST=192.168.1.1 LEN=60
    TOS=0x00 PREC=0x00 TTL=64 ID=26774 DF PROTO=TCP SPT=32797 DPT=80 WINDOW=5840 RES=0x00 SYN URGP=0 

**Réponse**: Le fait que le message soit journalisé par la chaîne OUTPUT signifie que l'adresse de destination n'appartient à aucune des zones définies (voir la [FAQ 17](#faq17)). Vous devez:

1.  Ajouter une zone pour votre modem dans le fichier `/etc/shorewall/zones`:

        #ZONE    TYPE          OPTIONS
        modem    ipv4

2.  Dans le fichier `/etc/shorewall/interfaces`, associer cette zone avec l'interface à laquelle votre modem est connecté (eth0 dans l'exemple):

        #ZONE      INTERFACE   BROADCAST    OPTIONS
        modem      eth0        detect

3.  Autoriser le trafic web vers le modem dans le fichier `/etc/shorewall/rules`:

        #ACTION    SOURCE      DEST      PROTO     DEST PORT(S)
        ACCEPT     fw          modem     tcp       80
        ACCEPT     loc         modem     tcp       80

Notez qu'un grand nombre de ces modems cable/DSL n'a pas de passerelle par défaut ou alors que leur passerelle par défaut est fixée à une adresse IP différente de l'adresse que vous avez attribuée à votre interface externe. Dans un cas comme dans l'autre, vous pouvez avoir des difficultés à naviguer sur votre modem depuis votre réseau local, même si toutes les routes sont correctement établies sur votre firewall. Pour résoudre ce problème, on “masquerade” le trafic depuis réseau local vers le modem.

`/etc/shorewall/masq`:

    #INTERFACE         SUBNET          ADDRESS
    eth0               eth1                        # eth1 = interface to local network

A titre d'exemple lorsque le modem cable/ADSL est “ponté” (bridge), vous pouvez aller voir [ma configuration](XenMyWay.md). Dans ce cas, je “masquerade” en utilisant l'adresse IP de mon interface locale!

# Adresses Alias IP/Interfaces virtuelles

## (FAQ 18) Existe-t-il un moyen d'utiliser des adresses IP aliasées avec Shorewall, et de maintenir des jeux de règles séparés pour ces différentes adresses IP?

**Réponse:** Oui. Voyez [Shorewall et les interfaces aliasées](Shorewall_and_Aliased_Interfaces.md).

# Shorewall Lite

## (FAQ 53) Qu'est-ce que Shorewall Lite?

**Réponse**: Shorewall Lite est un produit partenaire de Shorewall. Il est conçu pour vous permettre de maintenir les informations de toutes vos configurations de Shorewall sur un seul système dans votre réseau. Pour plus de détails, voir [Compiled Firewall script documentation](CompiledPrograms.md#Lite).

## (FAQ 54) Si je veux installer Shorewall Lite, est-ce que je dois aussi installer Shorewall sur le même système ?

**Réponse**: Non. En fait, nous recommandons que vous n'installiez pas Shorewall sur les systèmes sur lesquels vous souhaitez utiliser Shorewall Lite. Vous devez avoir installé Shorewall sur au moins un des systèmes de votre réseau pour pouvoir utiliser Shorewall Lite.

## (FAQ 55) Comment décider quel produit utiliser - Shorewall ou Shorewall Lite?

**Réponse**: Si vous prévoyez d'avoir un seul firewall, Shorewall est le choix logique. Je pense aussi que Shorewall est le choix le plus approprié pour un portable car vous pouvez avoir à changer sa configuration lorsque vous êtes en déplacement. Dans tous les autres cas, Shorewall Lite fonctionnera très bien. A shorewall.net, les deux portables ainsi que mon ordinateur de bureau linux sont installés avec la version complète de Shorewall. Tous les autres systèmes Linux qui ont un firewall utilisent Shorewall Lite et leurs répertoires de configuration sont sur mon ordinateur de bureau.

## (FAQ 60) Quelles restrictions de compatibilité existent entre Shorewall et Shorewall Lite

**Réponse**: Voir le tableau ci-dessous (C = Complètement compatible avec toutes les fonctionnalités disponibles, P1 = Compatible mais la totalité des fonctions de Shorewall ne sont pas disponibles, P2 = Compatible mais la totalité des fonctions de Shorewall Lite ne sont pas disponibles, I = incompatible).

|                     |
|:-------------------:|
| **Shorewall 3.2.0** |
| **Shorewall 3.2.1** |
| **Shorewall 3.2.2** |
| **Shorewall 3.2.3** |

# Divers

## (FAQ 20) Je viens d'installer un serveur. Dois-je modifier Shorewall pour autoriser les accès internet à mon serveur?

**Réponse** : Oui. Consultez le [guides de démarrage rapide](../reference/shorewall_quickstart_guide.md) que vous avez utilisé pour votre configuration initiale afin d'avoir des informations nécessaires à l'écriture des règles pour votre serveur.

## (FAQ 24) Comment puis-je autoriser des connexions internet au port ssh, par exemple, mais seulement depuis certaines adresses IP spécifiques?

**Réponse** : Dans la colonne SOURCE de la règle, faites suivre “net” de “:” puis d'une liste séparée par des virgules d'adresses de machines ou de sous-réseaux

    net:<ip1>,<ip2>,...

    ACCEPT net:192.0.2.16/28,192.0.2.44 fw tcp 22

## (FAQ 26) Quand j'essaye d'utiliser nmap avec n'importe laquelle des options SYN depuis le firewall lui-même ou depuis n'importe quelle machine derrière le firewall, j'obtiens une erreur “operation not permitted”. Comment utiliser nmap avec Shorewall?"

**Réponse** : Retirez temporairement les règles rejNotSyn, dropNotSyn and dropInvalid du fichier `/etc/shorewall/rules` et relancez Shorewall.

## (FAQ 27) Je compile un nouveau noyau (kernel) pour mon firewall. A quoi devrais-je faire attention?

**Réponse** : Commencez par regarder la page de [configuration du noyau pour Shorewall](../reference/kernel.md). Vous souhaiterez sans doute vous assurer que vous avez bien sélectionné “ **NAT of local connections (READ HELP)** ” dans le menu de configuration de Netfilter. Sans cela, les règles DNAT ayant votre firewall comme zone source ne fonctionneraient pas avec votre nouveau noyau.

### (FAQ 27a) Je viens de compiler (ou j'ai téléchargé ou récupéré par n'importe quel autre moyen) et d'installer un nouveau noyau et Shorewall ne démarre plus. Je sais que les options de mon noyau sont correctes.

Les dernières lignes de la [trace de démarrage](../reference/troubleshoot.md) sont les suivantes:

    + run_iptables2 -t nat -A eth0_masq -s 192.168.2.0/24 -d 0.0.0.0/0 -j
    MASQUERADE
    + '[' 'x-t nat -A eth0_masq -s 192.168.2.0/24 -d 0.0.0.0/0 -j
    MASQUERADE' = 'x-t nat -A eth0_masq -s 192.168.2.0/24 -d 0.0.0.
    0/0 -j MASQUERADE' ']'
    + run_iptables -t nat -A eth0_masq -s 192.168.2.0/24 -d 0.0.0.0/0 -j
    MASQUERADE
    + iptables -t nat -A eth0_masq -s 192.168.2.0/24 -d 0.0.0.0/0 -j
    MASQUERADE
    iptables: Invalid argument
    + '[' -z '' ']'
    + stop_firewall
    + set +x

**Réponse:** votre noyau contient des entêtes incompatibles avec celles utilisées pour compiler votre programme `iptables`. Vous devez recompiler `iptables` en utilisant l'arbre de sources de votre nouveau noyau.

## (FAQ 28) Comment utiliser Shorewall en pont filtrant (Bridging Firewall)?

**Réponse** : Le support Shorewall pour les ponts filtrant existe — [voir ici pour les détails](bridge_fr.md).

## (FAQ 39) Comment bloquer les connexion à un domaine particulier?

J'ai essayé de bloquer Adsense de Google. Adsense est un Javascript que les gens ajoutent à leur pages web. J'ai ajouté la règle suivante:

    #ACTION   SOURCE        DEST                                 PROTO
    REJECT    fw            net:pagead2.googlesyndication.com    all

Cependant, ceci bloque parfois les accès à "google.com". Pourquoi? Avec dig, je trouve les adresses IP suivantes pour le domaine googlesyndication.com:

    216.239.37.99
    216.239.39.99

Et celles-ci pour google.com:

    216.239.37.99
    216.239.39.99
    216.239.57.99

Je suppose donc que ce n'est pas le domaine qui est bloqué mais plutôt ses adresses IP. Comment bloquer réellement un nom de domaine?

**Réponse:** Les filtres de paquets basent leurs décisions sur le contenu des différents entêtes de protocole qui se trouvent au début de chaque paquet. Les filtres de paquet à suivi d'états (dont Netfilter est un exemple) utilisent une combinaison du contenu de l'entête et de l'état de la connexion créé lors du traitement de paquets précédents. Netfilter (et l'usage qui en est fait par Shorewall) prend également en compte l'interface réseau sur laquelle chaque paquet est entré ou sur laquelle le paquet va quitter le routeur/firewall.

Lorsque vous spécifiez un [nom de domaine dans une règle Shorewall](../reference/configuration_file_basics.md#dnsnames), le programme iptables résout ce nom en une ou plusieurs adresses IP et les véritables règles qui seront créées sont exprimées avec ces adresses IP. C'est pourquoi la règle que vous avez entrée est équivalente à:

    #ACTION   SOURCE        DEST                 PROTO
    REJECT    fw            net:216.239.37.99    all
    REJECT    fw            net:216.239.39.99    all

Sachant que l'hébergement multiple basé sur le nom d'hôte est une pratique courante (par exemple, lists.shorewall.net et www1.shorewall.net sont hébergés tous les deux sur le même système avec un seule adresse IP), il n'est pas possible de filtrer les connexions vers un nom particulier au seul examen des entêtes de protocole. Alors que certains protocoles tels que [FTP](../features/FTP.md) nécessitent que le firewall examine et éventuellement modifie les données (payload) du paquet, analyser les données de paquets individuellement ne fonctionne pas toujours car le flux de données de niveau application peut être fractionné de manière arbitraire entre les paquets. Ceci est une des faiblesses de l'extension 'string match' de Netfilter que l'on trouve dans le Patch-O-Matic-ng. Le seul moyen sûr pour filtrer sur le contenu des paquets est d'utiliser un proxy pour les connexions concernées -- dans le cas de HTTP, on pourra utiliser une application telle que [Squid](../features/Shorewall_Squid_Usage.md). Lorsqu'on utilise un proxy, celui-ci ré-assemble des messages complets de niveau applicatif qui peuvent alors être analysés de manière précise.

## (FAQ 42) Comment connaître quelles sont les fonctions supportées par mon noyau et ma version d'iptables?

**Réponse**: En tant que root, utilisez la commande `shorewall[-lite] show capabilities`.

    gateway:~# shorewall show capabilities
    Loading /usr/share/shorewall/functions...
    Processing /etc/shorewall/params ...
    Processing /etc/shorewall/shorewall.conf...
    Loading Modules...
    Shorewall has detected the following iptables/netfilter capabilities:
       NAT: Available
       Packet Mangling: Available
       Multi-port Match: Available
       Extended Multi-port Match: Available
       Connection Tracking Match: Available
       Packet Type Match: Available
       Policy Match: Available
       Physdev Match: Available
       IP range Match: Available
       Recent Match: Available
       Owner Match: Available
       Ipset Match: Available
       ROUTE Target: Available
       Extended MARK Target: Available
       CONNMARK Target: Available
       Connmark Match: Available
       Raw Table: Available
    gateway:~#

## (FAQ 19) Comment ouvrir le firewall pour tout le trafic de/vers le LAN?

**Réponse** : Ajoutez ces deux politiques:

    #SOURCE            DESTINATION             POLICY            LOG              LIMIT:BURST
    #                                                            LEVEL
    $FW                loc                     ACCEPT
    loc                $FW                     ACCEPT           

Vous pouvez également supprimer toutes les règles ACCEPT de \$FW-\>loc et loc-\>\$FW car ces règles sont maintenant redondantes avec les deux politiques fixées ci-dessus.
