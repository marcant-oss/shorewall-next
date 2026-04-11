<div class="note">

<u>Notes du traducteur :</u> Si vous trouvez des erreurs ou si vous avez des améliorations à apporter à cette traduction vous pouvez [me contacter](mailto:guy@posteurs.com).

</div>

<div class="caution">

**Cet article s'applique à Shorewall 3.0 et à ses versions ultérieures. Si vous êtes en train d'installer ou de mettre à jour vers une version antérieure à Shorewall 3.0.0, merci de vous référer à la documentation de cette version.**

</div>

<div class="important">

Avant de vous lancer dans l'installation, je vous encourage vivement à lire et à imprimer une copie du guide pratique présenté dans [Shorewall QuickStart](../reference/shorewall_quickstart_guide.md) et décrivant la configuration la plus proche de la votre.

</div>

<div class="important">

Avant toute mise à jour, assurez-vous d'avoir passé en revue [les problèmes de mise à jour](upgrade_issues.md).

</div>

<div class="note">

Les RPM Shorewall sont signés. Pour éviter d'avoir des avertissements tels que le suivant

    warning: shorewall-3.2.1-1.noarch.rpm: V3 DSA signature: NOKEY, key ID 6c562ac4

téléchargez la [clé GPG Shorewall](https://lists.shorewall.net/shorewall.gpg.key) puis exécutez cette commande:

    rpm --import shorewall.gpg.key

</div>

# Installation avec un RPM

Pour installer Shorewall avec un RPM:

1.  **Assurez-vous d'avoir le paquetage RPM adéquat!**

    On sait que le paquetage RPM standard de shorewall.net et des miroirs fonctionne avec **SUSE**, **Power PPC**, **Trustix** et **TurboLinux**. Il existe un paquetage fourni par Simon Matter construit pour **RedHat/Fedora** ainsi qu'un autre paquetage de Jack Coates adapté pour **Mandriva**. Il sont tous disponibles sur la [page de téléchargement](https://shorewall.org/download.htm).

    Si vous tentez d'installer le mauvais paquetage, il ne fonctionnera probablement pas.

    <div class="note">

    Si vous installez Shorewall 4.0.0 ou une version ultérieure, vous aurez besoin d'installer au moins deux paquetages.

    - Soit vous installerez Shorewall-shell (le compilateur de configuration classique basé sur le shell) et/ou Shorewall-perl (Le compilateur écrit en perl, plus récent et plus rapide).

    - Shorewall-common

    Si c'est la première fois que vous installez Shorewall, nous vous recommandons vivement d'installer Shorewall-perl.

    </div>

2.  Installer les RPMs

        rpm -ivh <compiler rpm> ... <shorewall-common rpm>

    <div class="caution">

    Certains utilisateurs ont l'habitude d'utiliser la commande `rpm -U` pour installer et pour mettre à jour leurs paquetages. Si vous utilisez cette commande pour installer le RPM Shorewall vous devrez activer manuellement le lancement de Shorewall au démarrage en utilisant `chkconfig`, `insserv` ou l'utilitaire que vous utilisez pour manipuler les liens symboliques pour init.

    </div>

    <div class="note">

    Certains utilisateurs SUSE ont rencontré un problème dans lequel le rpm signale un conflit avec un noyau de version \<= 2.2 alors qu'un noyau 2.4 est installé. Si ceci se produit, utilisez simplement l'option rpm --nodeps.

        rpm -ivh --nodeps <rpms>

    </div>

    <div class="note">

    Shorewall dépend du paquetage iproute. Malheureusement, certaines distribution nomment ce paquetage iproute2 ce qui provoque un échec de l'installation de Shorewall avec le diagnostic suivant:

        error: failed dependencies:iproute is needed by shorewall-3.2.x-1

    Ce problème ne devrait pas survenir si vous utilisez le bon paquetage RPM (voir 1., ci-dessus), mais il peut être contourné en utilisant l'option --nodeps de rpm.

        rpm -ivh --nodeps <rpms>

    </div>

    Exemple:

        rpm -ivh shorewall-perl-4.0.0-1.noarch.rpm shorewall-common-4.0.0-1.noarch.rpm

    <div class="important">

    Simon Matter nomme 'shorewall' son rpm '*common*' au lieu de '*shorewall-common*'. C'est pourquoi, si vous installez ses RPMs, la commande à utiliser sera:

        rpm -ivh shorewall-perl-4.0.0-1.noarch.rpm shorewall-4.0.0-1.noarch.rpm

    </div>

3.  Éditez les [fichiers de configuration](#Config_Files) pour qu'ils correspondent à votre configuration.

    <div class="warning">

    VOUS NE POUVEZ PAS SIMPLEMENT INSTALLER LE RPM ET LANCER UNE COMMANDE “`shorewall start`”. UN MINIMUM DE CONFIGURATION EST NÉCESSAIRE AVANT QUE VOTRE FIREWALL NE DÉMARRE. SI VOUS EXÉCUTEZ UNE COMMANDE “`start`” ET QUE LE LANCEMENT DU FIREWALL ÉCHOUE, VOTRE SYSTÈME N'ACCEPTERA PLUS AUCUN TRAFIC RÉSEAU. SI CELA SE PRODUIT, EXÉCUTEZ LA COMMANDE “`shorewall clear`” POUR RÉTABLIR LA CONNECTIVITÉ RÉSEAU.

    </div>

4.  Activez le démarrage de shorewall en éditant le fichier /`etc/shorewall/shorewall.conf` et mettez STARTUP_ENABLED à Yes).

5.  Lancez le firewall avec

        shorewall start

# Installer avec le fichier tarball

<div class="note">

Si vous installez Shorewall 4.0.0 ou une version ultérieure, vous aurez besoin d'installer au moins deux paquetages.

- Soit vous installerez Shorewall-shell (le compilateur de configuration classique basé sur le shell) et/ou Shorewall-perl (Le compilateur écrit en perl, plus récent et plus rapide).

- Shorewall-common

Si c'est la première fois que vous installez Shorewall, nous vous recommandons vivement d'installer Shorewall-perl.

</div>

Pour installer Shorewall-perl et Shorewall-common avec le tarball et le script d'installation:

1.  Décompressez les tarballs:

        tar -jxf shorewall-common-4.0.0.tar.bz2
        tar -jxf shorewall-perl-4.0.0.tar.bz2

2.  Allez dans le répertoire shorewall-perl (la version est codée dans le nom de répertoire comme par exemple dans “shorewall-perl-4.0.0”).

3.  Tapez:

        ./install.sh

4.  Allez dans le répertoire shorewall-common (la version est codée dans le nom de répertoire comme par exemple dans “shorewall-common-4.0.0”).

5.  Tapez:

        ./install.sh

6.  Éditez les [fichiers de configuration](#Config_Files) pour qu'ils correspondent à votre configuration.

7.  Activez le démarrage de shorewall en éditant le fichier `/etc/shorewall/shorewall.conf` et en y mettant STARTUP_ENABLED=Yes.

8.  Lancez le firewall avec

        shorewall start

9.  Si le script d'installation n'a pas réussi à configurer Shorewall pour qu'il soit lancé automatiquement au démarrage du système, allez voir [ces instructions](../reference/starting_and_stopping_shorewall.md).

# Installer avec le .deb

<div class="important">

Après avoir installé les paquetages .deb, avant de commencer à configurer Shorewall, vous devriez prendre connaissance de ce conseil de Lorenzo Martignoni, le mainteneur Debian de Shorewall:

“Pour plus d'information quant à l'utilisation de Shorewall sur un système Debian vous devriez aller voir le fichier /usr/share/doc/shorewall/README.Debian distribué avec le paquetage Debian de Shorewall.”

</div>

Le façon la plus simple d'installer Shorewall sur Debian est d'utiliser apt-get:

`apt-get install shorewall`

Pour être certain d'installer la dernière version de Shorewall, vous devriez modifier votre fichier `/etc/apt/preferences`

    Package: shorewall
    Pin: release o=Debian,a=testing
    Pin-Priority: 700

    Package: shorewall-doc
    Pin: release o=Debian,a=testing
    Pin-Priority: 700

***Puis exécutez***

    # apt-get update
    # apt-get install shorewall

**Lorsque vous avez fini de configurer Shorewall, vous pouvez activer son lancement au démarrage du système en positionnant startup=1 dans le fichier `/etc/default/shorewall`.**

# Observations générales sur les mises à jour de Shorewall

La plupart des problèmes de mise à jour ont pour cause:

- L'utilisateur n'a pas lu et suivi les considération de migration présentées dans les notes de mise à jour (*release notes*) (ces notes sont aussi reproduites dans le document [Shorewall Upgrade Issues](upgrade_issues.md)).

- L'utilisateur a mal géré son fichier `/etc/shorewall/shorewall.conf` durant la mise à niveau. Shorewall est conçu pour permettre à son comportement par défaut d'évoluer dans le temps. Pour que ce la soit possible, il est supposé de conception que **vous ne remplacerez pas votre fichier shorewall.conf lors des mises à jour**. Il est donc recommandé de modifier votre fichier `/etc/shorewall/shorewall.conf` après la première installation de shorewall de façon à empêcher votre gestionnaire de paquets de l'écraser lors de mises à jour ultérieures (même pour l'ajout de STARTUP_ENABLED, une telle modification est garantie puisque vous devez changer son paramètrage manuellement). Si vous vous sentez vraiment tenu d'avoir les derniers commentaires et options dans votre fichier `shorewall.conf`, vous devrez procéder très prudemment. Vous devrez déterminer quelles nouvelles options ont été introduites. Vous devrez réinitialiser la valeur de ces nouvelles options (par exemple OPTION=""), sinon, vous obtiendrez un comportement différent de celui auquel vous vous attendez.

# Mise à jour avec un RPM

Si le RPM Shorewall est déjà installé et que vous mettez à jour vers une nouvelle version:

1.  **Assurez-vous d'avoir le bon paquetage RPM!**

    On sait que le paquetage RPM standard de shorewall.net et des miroirs fonctionne avec **SUSE**, **Power PPC**, **Trustix** et **TurboLinux**. Il existe un paquetage fourni par Simon Matter construit pour **RedHat/Fedora** ainsi qu'un autre paquetage de Jack Coates adapté pour **Mandriva**. Si vous tentez d'installer le mauvais paquetage, il ne fonctionnera probablement pas.

    <div class="important">

    Simon Matter nomme 'shorewall' son rpm '*common*' au leu de '*shorewall-common*'.

    </div>

2.  Si vous faites une mise à jour depuis une version 2.x or 3.x vers une version 4.x, vous trouverez des instructions spécifiques pour les [problèmes de mise à jour](upgrade_issues.md).

3.  Procédez à la mise à jour

        rpm -Uvh <compiler rpm file> ... <shorewall-common rpm file> 

    <div class="note">

    Certains utilisateur de SUSE ont rencontré un problème dans lequel rpm signale un conflit avec un noyau de version \<= 2.2 alors qu'un noyau 2.4 est installé. Si ceci vous arrive, vous pouvez simplement utiliser l'option --nodeps de rpm.

        rpm -Uvh --nodeps <shorewall-common rpm> <compiler rpm> ...

    </div>

    <div class="note">

    Shorewall dépend du paquetage iproute. Malheureusement, certaines distributions nomment ce paquetage iproute2 ce qui provoquera un échec de la mise à jour avec le diagnostic suivant:

        error: failed dependencies:iproute is needed by shorewall-3.2.1-1

    Ceci peut être contourné en utilisant l'option --nodeps de rpm.

        rpm -Uvh --nodeps <shorewall rpm> <compiler-rpm> ...

    </div>

4.  Contrôlez si il existe des incompatibilités entre votre configuration et votre nouvelle version de Shorewall et corrigez quand cela est nécessaire.

        shorewall check

5.  Redémarrez le firewall.

        shorewall restart

# Mise à niveau avec le tarball

<div class="important">

Si vous faites une mise à jour depuis une version 2.x or 3.x vers une version 4.x, vous trouverez des instructions spécifiques pour les [problèmes de mise à jour](upgrade_issues.md).

</div>

Si Shorewall est déjà installé et que vous procédez à une mise à jour de version avec le tarball:

1.  Décompressez les tarballs:

        tar -jxf shorewall-common-4.0.0.tar.bz2
        tar -jxf shorewall-perl-4.0.0.tar.bz2
        tar -jxf shorewall-shell-4.0.0.tar.bz2 (if you use this compiler)

2.  Allez dans le répertoire shorewall-perl (la version est codée dans le nom de répertoire comme par exemple dans “shorewall-perl-4.0.0”).

3.  Tapez:

        ./install.sh

4.  Effectuez les deux étapes ci-dessus pour le répertoire shorewall-shell si vous utilisez ce compilateur.

5.  Allez dans le répertoire shorewall-common (la version est codée dans le nom de répertoire comme par exemple dans “shorewall-common-4.0.0”).

6.  Tapez:

        ./install.sh

7.  Contrôlez si il existe des incompatibilités entre votre configuration et votre nouvelle version de Shorewall et corrigez quand cela est nécessaire.

        shorewall check

8.  Lancez le firewall avec

        shorewall start

9.  Si le script d'installation n'a pas réussi à configurer Shorewall pour un démarrage automatique au boot du système, reportez-vous à [ces instructions](../reference/starting_and_stopping_shorewall.md).

# Mettre à jour avec le .deb

<div class="warning">

Lorsque le programme d'installation vous demande sir vous voulez remplacer le fichier de configuration /etc/shorewall/shorewall.conf par la nouvelle version, nous vous recommandons très fortement de refuser. Voir [ci-dessus](#Upgrade).

</div>

# Mettre à jour avec le .lrp

Ceci est une contribution de Charles Steinkuehler postée sur la liste de diffusion Leaf:

> c'est \*TRÈS\* simple... mettez un nouveau CD et redémarrez le système :-) En réalité, je ne plaisante que très peu... c'est exactement de cette manière que je mets à jour mes firewall de production. La fonction de sauvegarde partielle que j'ai ajoutée à Dachstein permet de stocker séparément les données de configuration et le reste du paquetage.
>
> Une fois les données de configuration séparées du reste du paquetage, il devient facile de procéder à la mise à jour du paquetage en conservant votre configuration courante (dans mon cas, il me suffit d'insérer un nouveau CD et de rebooter).
>
> L'idée générale est d'utiliser un backup partiel pour sauvegarder votre configuration, de remplacer le paquetage, puis de restaurer vos anciens fichiers de configuration. Les instructions pas-à-pas données ci-après proposent une manière d'y parvenir (on suppose l'utilisation d'un système LEAF conventionnel sur une seule disquette):
>
> - Faites une copie de sauvegarde de votre disquette firewall ('NEW'). C'est sur cette disquette que vous allez ajouter le(s) paquetage(s) à jour.
>
> - Formattez une disquette que vous utiliserez comme emplacement temporaire pour vos fichiers de configuration ('XFER'). Cette disquette devrait avoir le même format que votre disquette firewall (une autre copie de sauvegarde de votre disquette firewall ferait très bien l'affaire).
>
> - Assurez-vous de disposer d'une copie fonctionnelle de votre firewall existant ('OLD') dans un endroit sûr, et que vous N'UTILISEREZ PAS PENDANT ce processus. De cette façon, si quoi que ce soit se passait mal, vous pourriez simplement rebooter avec cette disquette OLD pour revenir à une configuration fonctionnelle.
>
> - Retirez la disquette firewall courante et remplacez-la par la disquette XFER.
>
> - Utilisez le menu de sauvegarde de `lrcfg` pour réaliser un backup partiel du(des) paquetage(s) que vous voulez mettre à jour en vous assurant de sauvegarder les fichiers sur la disquette XFER. Dans le menu de sauvegarde:
>
>       t e <enter> p <enter>
>       b <package1> <enter>
>       b <package2> <enter>
>       ...
>
> - Téléchargez et copiez le(s) paquetage(s) que vous voulez mettre à jour sur la disquette NEW
>
> - Rebootez votre firewall en utilisant la disquette NEW... à ce point du processus, les paquetages que vous mettez à jour sont avec leur configuration par défaut.
>
> - Montez la disquette XFER (mount -t msdos /dev/fd0u1680 /mnt)
>
> - Allez dans le répertoire racine (cd /)
>
> - Extrayez manuellement les données de configuration de chaque paquetage que vous avez mis à jour:
>
>       tar -xzvf /mnt/package1.lrp
>       tar -xzvf /mnt/package2.lrp
>       ...
>
> - Démontez (umount /mnt) puis retirez la disquette XFER
>
> - En utilisant `lrcfg`, faites une sauvegarde COMPLÈTE de vos paquetages mis à jour.
>
> - Rebootez et vérifiez que le firewall fonctionne comme prévu. Il peut être nécessaire d'ajuster certains fichiers de configuration pour qu'ils fonctionnent convenablement avec les nouveaux binaires.
>
> <div class="important">
>
> On peut utiliser le nouveau fichier de paquetage \<paquetage\>.local pour fixer précisément quels fichiers du backup partiel seront inclus ou pas (pour plus détails se reporter au Dachstein-CD README). Si ce fichier n'existe pas, le script de backup suppose que tous les fichiers de \<paquetage\>.list qui résident dans `/etc` ou dans `/var/lib/lrpkg` font partie de la configuration et sont utilisés pour créer le backup partiel. Si Shorewall installe quoi que ce soit dans `/etc` qui ne soit pas un fichier de configuration modifié par l'utilisateur, un fichier `shorewall.local` approprié devrait être créé avant de faire le backup partiel \[**Remarque de l'éditeur**: Shorewall ne place dans `/etc/` que des fichiers modifiables par l'utilisateur\].
>
> </div>
>
> <div class="note">
>
> Il est évidemment possible de réaliser tout cela 'sur-place', sans utiliser plusieurs disquettes, et même sans faire de backup partiel (c.a.d. copier les fichiers de configuration courants dans `/tmp`, extraire manuellement le nouveau paquetage sur le firewall en cours d'exécution, copier et fusionner les données de configuration depuis `/tmp` et du backup... ou autre), mais quiconque est capable de cette gymnastique en ligne de commande le fait sans doute déjà, sans avoir besoin d'instructions détaillées! :-)
>
> </div>

Pour des informations concernant d'autres outils de mise à jour LEAF/Bering, consultez [cet article de Alex Rhomberg](http://leaf.cvs.sourceforge.net/*checkout*/leaf/devel/alexrh/lck/README.html).

# Configurer Shorewall

Vous devrez éditer certains voire la totalité des fichiers de configuration pour obtenir la configuration que vous souhaitez. Dans la plupart des cas, les [guides de démarrage rapide shorewall](../reference/shorewall_quickstart_guide.md) contiennent toute l'information dont vous aurez besoin.

# Désinstaller / Revenir à la version antérieure

Voir “[Fallback and Uninstall](../features/fallback.md)”.
