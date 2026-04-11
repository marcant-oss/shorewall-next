# Продукты

В состав Shorewall 4.0 входят следующие четыре пакета.

1.  **Shorewall-common**. Этот пакет необходимо установить хотя бы в одной системе в вашей сети. В этой системе также должны быть установлены Shorewall-shell и/или Shorewall-perl.

2.  **Shorewall-shell**. Этот пакет содержит прежний компилятор конфигурации Shorewall, написанный на Bourne Shell. Этот компилятор работает в большинстве систем, но он медленный, и его сопровождение стало затруднительным.

3.  **Shorewall-perl**. Этот компилятор заменяет Shorewall-shell и написан на языке Perl. Он работает на всех платформах Unix, поддерживающих Perl (включая Cygwin), и рекомендуется для всех систем, где Shorewall устанавливается заново.

4.  **Shorewall-lite**. В Shorewall предусмотрена возможность централизованного управления несколькими системами файрволов. Для этого применяется пакет Shorewall lite. Полностью продукт Shorewall, включая Shorewall-shell и/или Shorewall-perl, устанавливается в центральной административной системе, где генерируются сценарии Shorewall. Эти сценарии копируются в системы файрволов, где они выполняются под управлением Shorewall-lite.

# Shorewall-common

Пакет Shorewall-common включает много файлов, которые устанавливаются в каталоги /`sbin`, `/usr/share/shorewall`, `/etc/shorewall`, `/etc/init.d` и `/var/lilb/shorewall/`. Они описаны далее.

## /sbin

Программа `/sbin/shorewall` взаимодействует с Shorewall. См. [shorewall](https://shorewall.org/manpages/shorewall.html)(8).

## /usr/share/shorewall

Здесь устанавливаются основные файлы Shorewall.

- `action.template` - файл шаблонов для создания [действий](../concepts/Actions.md).

- `action.*` - стандартные действия Shorewall.

- `actions.std` - в этом файле перечислены стандартные действия.

- `configfiles` - в этом каталоге содержатся файлы конфигурации, при копировании которых создается [каталог экспорта Shorewall-lite.](CompiledPrograms.md#Lite)

- `configpath` - здесь содержится информация о путях, которая зависит от дистрибутива.

- `firewall` - эта программа обрабатывает команды `add` и `delete` (см. [shorewall](https://shorewall.org/manpages/shorewall.html)(8)). Кроме того, она обрабатывает команды `stop` и `clear`, если в системе нет текущего скомпилированного сценария файрвола.

- `functions` - ссылка на `lib.base`, предусмотренная для совместимости с прежними версиями Shorewall.

- `init` - ссылка на сценарий инициализации (обычно это - `/etc/init.d/shorewall`).

- `lib.*` - библиотеки функций оболочки, используемые другими программами.

- `macro.*` - стандартные [макросы](../concepts/Macros.md) Shorewall.

- `modules` - файл, управляющий загрузкой модулей Netfilter ядра. Его можно переопределить в файле `/etc/shorewall/modules`.

- `version` - файл, в котором указана текущая установленная версия Shorewall.

- `wait4ifup` - программа, которую могут использовать [сценарии расширения](../reference/shorewall_extension_scripts.md) для ожидания готовности сетевого интерфейса.

## /etc/shorewall

В этом каталоге содержатся файлы конфигурации, настраиваемые пользователем.

## /etc/init.d или /etc/rc.d (зависит от дистрибутива)

Здесь устанавливается сценарий инициализации. В зависимости от дистрибутива, он называется `shorewall` или `rc.firewall`.

## /var/lib/shorewall

Shorewall не устанавливает никаких файлов в этот каталог. Он используется для хранения данных во время выполнения. Этот каталог можно перенести командой [shorewall-vardir](https://shorewall.org/manpages/shorewall-vardir.html)(5).

- `chains` - если в [shorewall.conf](https://shorewall.org/manpages/shorewall.conf.html)(5) задан DYNAMIC_ZONES=Yes, то в этом файле содержится информация для команд `add` и `delete` (см. [shorewall](https://shorewall.org/manpages/shorewall.html)(8)).

- `.iptables-restore-input`- этот файл передается программе iptables-restore для инициализации файрвола в ходе выполнения последней команды `start` или `restart` (см. [shorewall](https://shorewall.org/manpages/shorewall.html)(8)).

- `.modules` - содержимое файла модулей, использованного последними командами `start` или `restart` (см. [shorewall](https://shorewall.org/manpages/shorewall.html)(8)).

- `.modulesdir` - параметр MODULESDIR ([shorewall.conf](https://shorewall.org/manpages/shorewall.conf.html)(5)) в ходе выполнения последней команды `start` или `restart.`

- `nat` - в этом файле (с неудачным именем) записаны IP-адреса, добавленные при включенных опциях ADD_SNAT_ALIASES=Yes и ADD_IP_ALIASES=Yes в [shorewall.conf](https://shorewall.org/manpages/shorewall.conf.html)(5).

- `proxyarp` - записи arp, добавленные элементами [shorewall-proxyarp](https://shorewall.org/manpages/shorewall-proxyarp.html)(5).

- `.refresh` - программа, которая выполнила последнюю успешную команду `refresh`.

- `.restart` - программа, которая выполнила последнюю успешную команду `restart`.

- `restore` - программа по умолчанию, выполняющая команды `restore`.

- `.restore` - программа, которая выполнила последнюю успешную команду `refresh, restart` или `start`.

- `save` - файл, созданный командой `save` и используемый для восстановления динамического чёрного списка в ходе выполнения команд `start/restart`.

- `.start` - программа, которая выполнила последнюю успешную команду `start`.

- `state` - здесь записано текущее состояние файрвола.

- `zones` - здесь записано текущее состояние зон.

# Shorewall-shell

Все файлы продукта Shorewall-shell устанавливаются в каталоге /usr/share/`shorewall-shell`.

- `compiler` - компилятор конфигурации (программа shell).

- `lib.*` - библиотеки функций оболочки, используемые компилятором. Для уменьшения объема в встроенных системах могут быть установлены не все библиотеки.

- `prog.*` - фрагменты кода на shell, используемые компилятором.

- `version` - файл, в котором указана текущая установленная версия Shorewall-shell.

# Shorewall-perl

Все файлы продукта Shorewall-perl устанавливаются в каталоге /usr/share/`shorewall-perl`.

- `buildports.pl` - программа на Perl, которая компонует модуль Shorewall/Ports.pm во время установки.

- `compiler` - компилятор конфигурации (программа shell).

- `prog.*` - фрагменты кода на shell, используемые компилятором.

- `Shorewall` - каталог, содержащий модули Shorewall Perl, используемые компилятором.

- `version` - файл, в котором указана текущая установленная версия Shorewall-shell.

# Shorewall-lite

Файлы Shorewall-lite устанавливаются в каталогах /`sbin`, `/usr/share/shorewall-lite`, /etc/`shorewall-lite`, `/etc/init.d` и `/var/lilb/shorewall/`. Они описаны далее.

## /sbin

Программа `/sbin/shorewall-lite` взаимодействует с Shorewall lite. См. [shorewall-lite](https://shorewall.org/manpages/shorewall-lite.html)(8).

## /etc/init.d или /etc/rc.d (зависит от дистрибутива)

Здесь устанавливается сценарий инициализации. В зависимости от дистрибутива, он называется `shorewall-lite` или `rc.firewall`.

## /etc/shorewall-lite

В этом каталоге содержатся файлы конфигурации, настраиваемые пользователем.

## /usr/share/shorewall-lite

Здесь устанавливаются основные файлы Shorewall-lite.

- `configpath` - здесь содержится информация о путях, которая зависит от дистрибутива.

- `functions` - ссылка на `lib.base`, предусмотренная для совместимости с прежними версиями Shorewall.

- `lib.*` - библиотеки функций оболочки, используемые другими программами. Это копии соответствующих библиотек продукта Shorewall.

- `modules` - файл, управляющий загрузкой модулей Netfilter ядра. Его можно переопределить в файле `/etc/shorewall-lite/modules`.

- `shorecap` - программа, которая создает файл capabilities. См. [документацию Shorewall-lite](CompiledPrograms.md#Lite).

- `version` - файл, в котором указана текущая установленная версия Shorewall.

- `wait4ifup` - программа, которую могут использовать [сценарии расширения](../reference/shorewall_extension_scripts.md) для ожидания готовности сетевого интерфейса.

## /var/lib/shorewall-lite

Shorewall-lite не устанавливает никаких файлов в этот каталог. Он используется для хранения данных во время выполнения. Этот каталог можно перенести командой [shorewall-lite-vardir](https://shorewall.org/manpages/shorewall-lite-vardir.html)(5).

- `firewall` - скомпилированный сценарий, который устанавливается командой load или reload, выполняемой в административной системе (см. [shorewall](https://shorewall.org/manpages/shorewall.html)(8)).

- `firewall.conf` - дайджест файла shorewall.conf, использованного для компиляции сценария файрвола в административной системе.

<!-- -->

- `.iptables-restore-input`- этот файл передается программе iptables-restore для инициализации файрвола в ходе выполнения последней команды `start` или `restart` (см. [shorewall-lite](https://shorewall.org/manpages/shorewall-lite.html)(8)).

- `.modules` - содержимое файла модулей, использованного последними командами `start` или `restart` (см. [shorewall-lite](https://shorewall.org/manpages/shorewall-lite.html)(8)).

- `.modulesdir` - параметр MODULESDIR ([shorewall.conf](https://shorewall.org/manpages/shorewall.conf.html)(5)) в ходе выполнения последней команды `start` или `restart.`

- `nat` - в этом файле (с неудачным именем) записаны IP-адреса, добавленные при включенных опциях ADD_SNAT_ALIASES=Yes и ADD_IP_ALIASES=Yes в [shorewall.conf](https://shorewall.org/manpages/shorewall.conf.html)(5).

- `proxyarp` - записи arp, добавленные элементами [shorewall-proxyarp](https://shorewall.org/manpages/shorewall-proxyarp.html)(5).

- `.refresh` - программа, которая выполнила последнюю успешную команду `refresh`.

- `.restart` - программа, которая выполнила последнюю успешную команду `restart`.

- `restore` - программа по умолчанию, выполняющая команды `restore`.

- `.restore` - программа, которая выполнила последнюю успешную команду `refresh, restart` или `start`.

- `save` - файл, созданный командой `save` и используемый для восстановления динамического чёрного списка в ходе выполнения команд `start/restart`.

- `.start` - программа, которая выполнила последнюю успешную команду `start`.

- `state` - здесь записано текущее состояние файрвола.

- `zones` - здесь записано текущее состояние зон.
