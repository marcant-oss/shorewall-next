# HOWTO — Einstiegspunkt nach Problem

Schnellreferenz: welches Unterverzeichnis, welche Datei, welches CLAUDE.md
beim Start einer Arbeitssession.

---

## Nach Paket

| Paket | Verzeichnis | CLAUDE.md |
|-------|-------------|-----------|
| Compiler, Emitter, CLI | `packages/shorewall-nft/` | `packages/shorewall-nft/CLAUDE.md` |
| Daemon (Prometheus, DNS-Sets, HA-Sync) | `packages/shorewalld/` | `packages/shorewalld/CLAUDE.md` |
| Simlab (Packet-Tests, netns) | `packages/shorewall-nft-simlab/` | `packages/shorewall-nft-simlab/CLAUDE.md` |
| Stagelab (Performance, DPDK, Advisor) | `packages/shorewall-nft-stagelab/` | `packages/shorewall-nft-stagelab/CLAUDE.md` |
| Netkit (Shared primitives: tundev, nsstub, packets) | `packages/shorewall-nft-netkit/` | `packages/shorewall-nft-netkit/CLAUDE.md` |
| Monorepo-Überblick, CI, Release | Repo-Root | `CLAUDE.md` |

---

## Nach Problemtyp

### Compiler / Emitter

**Symptom:** Falsches nft-Output, fehlende Regel, NAT-Bug, Optimierer, Flowtable

```
packages/shorewall-nft/
  shorewall_nft/compiler/   ir.py, actions.py, nat.py, tc.py, optimize.py
  shorewall_nft/nft/        emitter.py, sets.py, flowtable.py, dns_sets.py
  tests/test_emitter*.py    Regressionstests für Emitter-Features
```

### Config-Parser

**Symptom:** Datei wird nicht gelesen, Präprozessor-Fehler, Zone/Interface-Problem

```
packages/shorewall-nft/
  shorewall_nft/config/     parser.py, zones.py, importer.py, validate.py
  tests/test_config*.py
```

### CLI / Runtime

**Symptom:** Befehl schlägt fehl, falsches Verhalten von `start`/`debug`/`verify`

```
packages/shorewall-nft/
  shorewall_nft/runtime/    cli.py, sysctl.py, monitor.py
  shorewall_nft/netns/      apply.py, systemd.py
```

### Plugin-System

**Symptom:** Plugin lädt nicht, Netbox-Fehler, ip-info-Mapping falsch

```
packages/shorewall-nft/
  shorewall_nft/plugins/    loader.py, builtin/netbox.py, builtin/ip_info.py
  examples/plugins/
  docs/shorewall-nft/plugins.md
  docs/shorewall-nft/plugin-development.md
```

### Prometheus-Metriken fehlen / falsch

**Symptom:** Metrik-Endpoint liefert nichts, falsche Labels, netns nicht gefunden

```
packages/shorewalld/
  shorewalld/collectors/    Eine Datei pro Metrik-Familie:
                            nft.py, link.py, ct.py, flowtable.py,
                            conntrack.py, qdisc.py, nfsets.py,
                            vrrp.py, snmp.py, worker_router.py, …
  shorewalld/exporter.py    NftScraper, LinkCollector, CtCollector
  shorewalld/discover.py    netns auto-discovery
  shorewalld/core.py        Daemon-Lifecycle
  docs/shorewalld/metrics.md  Vollständige Metrik-Referenz mit PromQL-Beispielen
  tools/man/shorewalld.8      METRICS-Abschnitt
```

### VRRP-State wird nicht gemeldet / D-Bus-Fehler

**Symptom:** `shorewalld_vrrp_state` fehlt, `dbus_unavailable`, falsche Priorität

```
packages/shorewalld/
  shorewalld/collectors/vrrp.py    VrrpCollector (D-Bus via jeepney; SNMP-Augmentation)

Upstream-Referenzen:
  https://github.com/acassen/keepalived/blob/master/keepalived/dbus/org.keepalived.Vrrp1.Instance.xml
  https://github.com/acassen/keepalived/blob/master/doc/mibs/KEEPALIVED-MIB.txt
  Lokal (falls vorhanden): /tmp/keepalived-eval/

  # Triage:
  # AL10: keepalived 2.2.8-6.el10 ist ohne --enable-dbus gebaut → kein D-Bus.
  # Fallback: --vrrp-snmp-enable (benötigt keepalived --enable-snmp-vrrp + snmpd).
  # Caveat: D-Bus liefert nur Name + State; priority/vip_count/master_transitions
  #         kommen ausschließlich via SNMP-Augmentation.
  docs/shorewalld/metrics.md  Abschnitt "VRRP" mit Cardinality + Caveats
```

### nfset-Backend hinzufügen / ändern

**Symptom:** Neuer Provider-Typ, neues Fetch-Protokoll, neues Backend-Keyword

```
packages/shorewall-nft/
  shorewall_nft/nft/nfsets.py     NfSetEntry, NfSetRegistry — Datenmodell

packages/shorewalld/
  shorewalld/nfsets_manager.py    Consumer: routet Einträge nach Backend
  shorewalld/collectors/nfsets.py NfsetsCollector — Prometheus-Metriken

  docs/features/nfsets.md         Operator-Referenz (Backends, Optionen, Beispiele)
```

### Neue Config-Tabelle hinzufügen

**Symptom:** Neue Shorewall-Konfigurationsdatei, neues Schema-Feld

```
packages/shorewall-nft/
  shorewall_nft/config/schema.py  Pydantic-Schema für alle Tabellen
  shorewall_nft/compiler/ir.py    IR-Transformation
  shorewall_nft/nft/emitter.py    nft-Ausgabe

  tools/man/shorewall-nft-<table>.5   Man-Page (neu anlegen)
  # Konvention: Core-first (schema → ir → emit), dann Doku, dann Tests.
```

### Neuen CLI-Unterbefehl hinzufügen

**Symptom:** Neuer `shorewall-nft <subcommand>`, neue CLI-Option

```
packages/shorewall-nft/
  shorewall_nft/runtime/cli.py    @cli.command(…) — Click-Dekorator

  docs/reference/commands.json    Ggf. regenerieren (tooling-Befehl prüfen)
  tools/man/shorewall-nft.8       COMMANDS-Abschnitt ergänzen
```

### DNS-Sets populieren nicht

**Symptom:** `dns:github.com` in rules bleibt leer, dnstap kommt nicht an

```
packages/shorewalld/
  shorewalld/dnstap.py          FrameStream-Leser
  shorewalld/dnstap_bridge.py   Decode → SetWriter-Bridge
  shorewalld/dns_set_tracker.py Proposal/Dedup-Logik
  shorewalld/setwriter.py       Netlink-Schreiber

packages/shorewall-nft/
  shorewall_nft/nft/dns_sets.py qname_to_set_name() — shared mit Daemon

  # Smoke-Test auf 192.0.2.83:
  tools/setup-shorewalld-dnstap-smoke.sh root@192.0.2.83
  # Dann auf dem Host:
  shorewalld tap --socket /run/shorewalld/dnstap.sock
  dig @127.0.0.1 -p 5354 github.com A
  nft list set inet shorewall dns_github_com_v4
```

### HA-Peer-Sync (shorewalld)

**Symptom:** Zweiter Node übernimmt Sets nicht, Heartbeat fehlt

```
packages/shorewalld/
  shorewalld/peer.py          UDP-Protokoll (HMAC, Snapshot, Incremental)
  shorewalld/state.py         Persistenz über Restart
  shorewalld/reload_monitor.py Repopulate nach shorewall-nft reload
```

### Stagelab — Performance / Durchsatz-Tests gegen reale FW-Hardware

**Symptom:** Throughput unter Erwartung, hohe Retransmits, Connection-Storm-Fehler

```
packages/shorewall-nft-stagelab/
  shorewall_nft_stagelab/advisor.py      Regel-basierter Advisor (Tier A/B/C)
  shorewall_nft_stagelab/rule_order.py   nft Rule-Order-Analyser (Tier-C-Hints)
  shorewall_nft_stagelab/scenarios.py    Scenario-Runner (throughput, tuning_sweep, …)
  shorewall_nft_stagelab/controller.py   asyncio Orchestrator
  shorewall_nft_stagelab/config.py       Pydantic-Schema (Host, Endpoint, Scenario, …)
  shorewall_nft_stagelab/report.py       run.json / summary.md / recommendations.yaml
  docs/testing/stagelab.md              Operator-Referenz

  # Für Korrektheits-Smoke (keine Line-Rate-NIC nötig):
  #   endpoint mode: probe → scapy-Frames via TAP
  # Für Kernel-Stack-Durchsatz (10–25 Gbps):
  #   endpoint mode: native → iperf3 / nmap
  # Für DPDK Line-Rate (40–100 Gbps) / 10 M+ Sessions:
  #   endpoint mode: dpdk → TRex STL / ASTF
  #   Bootstrap: tools/setup-remote-test-host.sh root@<host> --role stagelab-agent-dpdk
```

### Line-Rate / 10 M+ concurrent sessions (DPDK / TRex)

```
packages/shorewall-nft-stagelab/
  shorewall_nft_stagelab/topology_dpdk.py    NIC-Binding vfio-pci + Crash-Recovery
  shorewall_nft_stagelab/trafgen_trex.py     TRex STL + ASTF Wrapper
  # Bootstrap: tools/setup-remote-test-host.sh root@<host> --role stagelab-agent-dpdk
  # STAGELAB_HUGEPAGES=512 für 1 GiB Hugepages (default)
```

### Simlab-Testfehler

**Symptom:** POSITIVE fail_drop, RANDOM-Mismatches, Topologie-Fehler

```
packages/shorewall-nft-simlab/
  shorewall_nft_simlab/oracle.py      Erwartete Verdicts
  shorewall_nft_simlab/packets.py     Probe-Generator
  shorewall_nft_simlab/topology.py    netns-Aufbau
  shorewall_nft_simlab/controller.py  Run-Steuerung
  shorewall_nft_simlab/report.py      Ergebnisbericht

  # Triage-Reihenfolge bei Mismatch:
  # 1. Probe-Generator (packets.py) — RPF-Quelle korrekt?
  # 2. Topologie (topology.py) — Interface auf richtiger Seite?
  # 3. Emitter (packages/shorewall-nft) — nft-Output stimmt mit iptables.txt?
  # Niemals Emitter anpassen damit Simlab grün wird — erst iptables.txt prüfen.

  # Letzter bekannter Run: docs/testing/simlab-reports/ (lokal, nicht committed)
```

### Test-Setup / Tooling

**Projekt-Venv liegt im Repo-Root: `.venv/` (Python 3.13).**
Ein einziges Venv für alle drei Pakete — keine Per-Package-Venvs anlegen.

**Tests:** laufen als root via `tools/run-tests.sh` (kein run-netns, kein sudoers).

```
tools/
  run-tests.sh                Tests in isoliertem Namespace (unshare --mount --net)
  setup-remote-test-host.sh   Remote: Repo-Sync + alle 3 Pakete installieren

  # Einmalige Bootstrap-Installation ins Repo-Venv (Reihenfolge wichtig!):
  source .venv/bin/activate
  pip install -e packages/shorewall-nft-netkit[dev] \
              -e packages/shorewall-nft[dev] \
              -e packages/shorewalld[dev] \
              -e packages/shorewall-nft-simlab[dev] \
              -e packages/shorewall-nft-stagelab[dev]

  # Tests (isoliert, kein Crash des Hosts möglich):
  tools/run-tests.sh packages/shorewall-nft/tests/ -q
  pytest packages/shorewalld/tests/ -q
  pytest packages/shorewall-nft-simlab/tests/ -q
  pytest packages/shorewall-nft-stagelab/tests/unit -q
```

### Packaging (.deb / .rpm)

**Symptom:** Build schlägt fehl, fehlende Datei im Paket, falscher Pfad

```
packaging/
  debian/rules                dh_auto_install Override, man pages, completions
  rpm/shorewall-nft.spec      %install, %files — KEINE pyproject-rpm-macros!
  systemd/                    shorewall-nft.service, shorewalld.service

  # RPM-Gotcha: python3-rpm-macros JA, pyproject-rpm-macros NEIN
  # Deb-Gotcha: entry-points landen in usr/local/bin → vor dh_usrlocal nach usr/bin/ verschieben
  # Beide: tools/man/shorewall-nft.8 und shorewalld.8 werden installiert
```

### CI-Fehler (GitHub Actions)

**Symptom:** Lint, Unit-Tests, Integration, deb/rpm-Build schlägt fehl

```
.github/workflows/build.yaml
  # Reihenfolge: Lint → Unit (3.11/3.12/3.13) → Integration+Wheels → .deb → .rpm → Release
  # Release-Job feuert nur auf refs/tags/v*
```

### Dokumentation

**Symptom:** Falsche/fehlende Doku, Links kaputt

```
docs/
  index.md                    Einstieg mit 4-Paket-Übersicht (inkl. Stagelab)
  quick-start.md              Anfänger + Migrations-Pfad
  shorewall-nft/              7 Dateien: merge-config, plugins, debug, optimizer, config-hash, config-dirs, plugin-dev
  shorewalld/index.md         Daemon-Referenz (DNS-Sets, HA, tap)
  shorewalld/metrics.md       Vollständige Prometheus-Metrik-Referenz (nfsets, VRRP, worker, iplist, plainlist)
  features/nfsets.md          Named dynamic nft sets (dnstap/resolver/ip-list/ip-list-plain)
  testing/                    Simlab + Stagelab + Setup, Suite, Debugging, Verification
  testing/stagelab.md         Stagelab-Operator-Referenz
  cli/commands.md             CLI-Referenz aller shorewall-nft-Befehle
  concepts/ features/         Shorewall config-language Referenz
  reference/glossary.md       Terminologie-Glossar (nfset, VRRP, fastaccept, pseudo-zone, …)
  roadmap/nfsets-deferred.md  Backlog offener nfsets-Features + W7b-Audit-Items
```

### Release

**Symptom:** Version bumpen, CHANGELOG schreiben, Tag setzen

```
# Dateien, die synchron gebumpt werden müssen:
packages/shorewall-nft/pyproject.toml
packages/shorewalld/pyproject.toml
packages/shorewall-nft-simlab/pyproject.toml
packages/shorewall-nft/shorewall_nft/__init__.py
packaging/rpm/shorewall-nft.spec      (Version: + %changelog)
packaging/debian/changelog
CHANGELOG.md

# Dann:
git tag -a vX.Y.Z -m "release X.Y.Z"
git push && git push --tags
# → GitHub Actions baut und veröffentlicht wheels + .deb + .rpm
```

---

## Point of truth (Verifikation)

```
/home/avalentin/projects/marcant-fw/old/iptables.txt   ← gewinnt immer
/home/avalentin/projects/marcant-fw/old/ip6tables.txt  ← gewinnt immer
Autoritative Doku: docs/testing/point-of-truth.md
```

Wenn Simlab ≠ iptables.txt → Simlab hat unrecht. Erst probe-generator → topology → emitter prüfen.

---

## Schwester-Projekte (nft-Referenz)

```
/home/avalentin/projects/marcant-fw/shorewall2foomuuri/
  nft_parser.py           nft-Syntax-Referenz
  iptables_parser.py      iptables↔nft Semantik
  verify.py               Verifikations-Framework

/home/avalentin/projects/marcant-fw/netns-routing/
  # 16 Zonen, ~3300 Regeln, HA/VRRP — Produktions-nft-Referenz
```
