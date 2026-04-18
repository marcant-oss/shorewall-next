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
  shorewalld/exporter.py    NftScraper, LinkCollector, CtCollector
  shorewalld/discover.py    netns auto-discovery
  shorewalld/core.py        Daemon-Lifecycle
  docs/shorewalld/index.md  #metrics
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

**Test-Setup:** Tests laufen als root via `tools/run-tests.sh` (kein run-netns, kein sudoers).

```
tools/
  run-tests.sh                Tests in isoliertem Namespace (unshare --mount --net)
  setup-remote-test-host.sh   Remote: Repo-Sync + alle 3 Pakete installieren

  # Venv auf dem Testhost:
  pip install -e packages/shorewall-nft[dev] \
              -e packages/shorewalld[dev] \
              -e packages/shorewall-nft-simlab[dev]

  # Tests (isoliert, kein Crash des Hosts möglich):
  tools/run-tests.sh packages/shorewall-nft/tests/ -q
  pytest packages/shorewalld/tests/ -q
  pytest packages/shorewall-nft-simlab/tests/ -q
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
  index.md                    Einstieg mit 3-Paket-Übersicht
  quick-start.md              Anfänger + Migrations-Pfad
  shorewall-nft/              7 Dateien: merge-config, plugins, debug, optimizer, config-hash, config-dirs, plugin-dev
  shorewalld/index.md         Daemon-Referenz (Metriken, DNS-Sets, HA, tap)
  testing/                    9 Dateien: Setup, Suite, Simlab, Debugging, Verification
  cli/commands.md             36 Befehle (v1.4.0)
  concepts/ features/         Shorewall config-language Referenz
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
