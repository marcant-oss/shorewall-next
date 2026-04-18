# Hardware Offload: TC Flower + eSwitch Auto-Offload

## Überblick

Dieses Dokument beschreibt die geplante Hardware-Offload-Architektur für
shorewall-nft/shorewalld, basierend auf einer ausführlichen Analyse der
Linux-Kernel-Offload-Infrastruktur (TC Flower, nftables Flowtable,
mlx5 eSwitch/switchdev).

Das Ziel ist **Ansatz 2**: stateless HW-ACLs in der NIC, vollständige
stateful nftables-Firewall im Kernel, SW-Flowtable-Fastpath für established
Flows — und optional ein automatischer eSwitch-Offload-Loop für maximalen
Durchsatz ohne OVS.

---

## Architektur-Entscheidungen (Ergebnis der Analyse)

### Was in Hardware geht (NIC-Mode, kein switchdev nötig)

- **TC Flower DROP-Rules** auf dem PF-Interface: VLAN-ID als Match-Kriterium,
  src/dst IP, Proto/Port, Action=drop. Landet direkt in der NIC-Hardware.
  Geeignet für Blacklist, scfilter (Bogon/Spoofing), stateless ACLs.
- **VLAN-Match als Filter-Kriterium**: lesend, kein push/pop als Action.
- **SW-Flowtable**: funktioniert mit VLAN-Subinterfaces ab Kernel 5.13
  stabil und vollständig. Kein `flags offload` nötig — SW-Fastpath ist
  bereits erheblich schneller als normaler Forwarding-Pfad.

### Was switchdev/eSwitch braucht

- **VLAN push/pop als TC-Action**: nur im eSwitch-Mode verfügbar, nie im
  normalen NIC-Mode. Gilt für alle relevanten NICs (mlx5, ice, bnxt).
- **Flow-Offload zwischen VF-Interfaces**: TC-Rules auf VF-Representoren
  landen im eSwitch-FDB → echter Hardware-Bypass ohne CPU.
- **Auto-Offload-Loop** (OffloadManager, siehe unten): beobachtet
  conntrack-Events, installiert TC-Rules im eSwitch wenn ein Flow
  established + offload-eligible ist.

### NIC-Empfehlung

**NVIDIA/Mellanox ConnectX-5 oder ConnectX-6 Lx** (mlx5e-Treiber).
Einzige NIC mit nachgewiesener, co-entwickelter netfilter-Flowtable-HW-
Offload-Unterstützung. ConnectX-5 ab ~100 EUR gebraucht für 10/25G.
ConnectX-6 Lx für 25G-Produktionsbetrieb.

Wichtige Einschränkung mlx5: VLAN-Context-Speicher im NIC ist auf 512
Einträge begrenzt. Bei mehr als ~500 VLANs auf einem physischen Interface
bitte VLAN-Filtering auf dem Interface deaktivieren.

---

## Drei-Schichten-Modell

```
┌─────────────────────────────────────────────────────────────┐
│  Schicht 1: TC Flower HW-ACL (NIC-Mode, immer aktiv)        │
│                                                             │
│  Quellen: blacklist, scfilter aus shorewall-Konfiguration   │
│  Generator: shorewall-nft generate-tc --mode hw-acl         │
│  Activation: ethtool -K <dev> hw-tc-offload on              │
│              tc qdisc add dev <dev> ingress                 │
│  Effekt: Drop vor dem Kernel-Stack, kein CPU-Aufwand        │
│  VLAN: vlan_id als Match-Kriterium ✅                       │
├─────────────────────────────────────────────────────────────┤
│  Schicht 2: nftables Firewall (Kernel, vollständig)         │
│                                                             │
│  Generiert von: shorewall-nft compile / start               │
│  Features: stateful, conntrack, NAT, Sets, DNS-Sets,        │
│            Flowtable (SW-Fastpath), vollständige Semantik   │
│  VLAN: Subinterfaces ab Kernel 5.13 vollständig unterstützt │
├─────────────────────────────────────────────────────────────┤
│  Schicht 3: OffloadManager (shorewalld, optional)           │
│                                                             │
│  Voraussetzung: mlx5 im switchdev-Mode, VFs im Host-NS      │
│  Funktion: conntrack-Events → TC-Rules auf VF-Representoren │
│            → eSwitch-FDB → Flows komplett in Hardware       │
│  VLAN: push/pop im eSwitch verfügbar ✅                     │
│  Fallback: bei fehlendem switchdev läuft SW-Flowtable       │
└─────────────────────────────────────────────────────────────┘
```

---

## Phase 1: TC Flower HW-ACL Generator (shorewall-nft)

**Ziel**: `generate-tc --mode hw-acl` erzeugt ausführbare tc-Befehle
für stateless Drop-Rules aus blacklist + scfilter.

### Neue shorewall.conf-Direktiven

```ini
HW_OFFLOAD_INTERFACES=eth0,eth1   # "auto" = alle FLOWTABLE-Interfaces
HW_OFFLOAD_BLACKLIST=Yes           # blacklist → TC Flower HW drop
HW_OFFLOAD_SCFILTER=Yes            # scfilter → TC Flower HW drop
HW_OFFLOAD_VLAN=Yes                # VLAN-ID in TC-Match einbeziehen
FLOWTABLE=auto
FLOWTABLE_OFFLOAD=No               # für VLAN-Setups: SW-Fastpath
```

### Rule-Klassifikation im IR

Neues Flag `hw_offload_eligible: bool` an `ir.Rule`:

```python
def is_hw_offloadable(rule) -> bool:
    """
    True wenn die Regel als stateless TC-Flower-Drop in HW
    offloadbar ist. Kriterien:
    - Action ist DROP (kein REJECT, kein LOG-only, kein ACCEPT)
    - Nur einfache IP/Port/Proto-Matches (kein ct state, kein mark,
      kein limit, kein connlimit, kein time, kein user)
    - Kein Macro mit mehreren Actions
    - Keine Negation auf komplexen Feldern
    """
    return (
        rule.action in ("DROP",)
        and not rule.has_conntrack_match
        and not rule.has_rate_limit
        and not rule.has_mark_match
        and not rule.has_time_match
        and not rule.has_user_match
        and not rule.is_macro_with_multiple_actions
    )
```

### Neues Modul: `shorewall_nft/nft/tc_offload.py`

```
TcOffloadEmitter
  emit_setup(interfaces, vlan_map) -> str
    # ethtool -K <dev> hw-tc-offload on
    # tc qdisc add dev <dev> ingress
    # pro VLAN-Interface: Zuordnung physisches Interface ↔ VLAN-ID

  emit_blacklist_rules(blacklist_entries, vlan_map) -> str
    # TC Flower drop rules aus blacklist-Datei
    # Bei HW_OFFLOAD_VLAN=Yes: vlan_id als zusätzlicher Match

  emit_scfilter_rules(scfilter_entries, vlan_map) -> str
    # TC Flower drop rules für Source-CIDR-Sanity

  emit_teardown(interfaces) -> str
    # tc qdisc del dev <dev> ingress  (bei stop)

  classify_rule(rule) -> Literal["hw", "sw", "mixed"]
    # Delegiert an is_hw_offloadable()
```

### Integration in `start` / `stop`

`shorewall_nft/runtime/apply.py` führt bereits pyroute2-Calls durch
(proxyarp). Gleiches Muster für TC:

```
start():
  1. TcOffloadEmitter.apply_setup()     # ethtool + qdisc
  2. TcOffloadEmitter.apply_acls()      # blacklist + scfilter
  3. nft -f <ruleset>                   # nftables
  4. nft add flowtable ...              # SW-Fastpath

stop():
  1. nft delete table inet shorewall
  2. TcOffloadEmitter.apply_teardown()  # tc qdisc del
```

### generate-tc Erweiterung

```
shorewall-nft generate-tc [DIR]              # bestehend: TC-Marks
shorewall-nft generate-tc [DIR] --mode hw-acl  # neu: HW-Drop-Rules
```

### Tests

- `tests/test_tc_offload.py`: Unit-Tests für `is_hw_offloadable()`
  mit allen Grenzfällen (ct-Match, rate-limit, Macro, Negation)
- `tests/test_tc_emitter.py`: Ausgabe-Tests für `TcOffloadEmitter`
  gegen Referenz-tc-Befehle
- Simlab: `_flowtable_state()` Erweiterung um TC-ACL-Verifizierung

---

## Phase 2: SW-Flowtable + VLAN (shorewall-nft)

**Status**: Infrastruktur bereits vorhanden (`FLOWTABLE=`, `FLOWTABLE_OFFLOAD=`).

**Offene Punkte**:

- `FLOWTABLE=auto` sollte Interfaces aus `interfaces`-Datei ableiten
  (physische Interfaces, nicht VLAN-Subinterfaces — Kernel entpackt
  VLAN ab 5.13 automatisch)
- `FLOWTABLE_OFFLOAD=Yes` nur aktivieren wenn NIC tatsächlich
  `hw-tc-offload: on` (nicht `[fixed]`) meldet — Capability-Check
  via `ethtool -k` in `apply.py`
- Für VLAN-Setups: `FLOWTABLE_OFFLOAD=No` ist korrekt und stabil,
  da VLAN push/pop in NIC-Mode nicht unterstützt wird

---

## Phase 3: OffloadManager (shorewalld) — eSwitch Auto-Offload

**Voraussetzungen**:
- mlx5 ConnectX-5 oder neuer im switchdev-Mode
- VFs im Host-Namespace (nicht in VMs), mit VLAN-Konfiguration
- `devlink dev eswitch set pci/... mode switchdev`
- VF-Representoren sichtbar im Host (`enp4s0f0_0`, `enp4s0f0_1`, ...)

### Warum VFs im Host statt PF-Subinterfaces

VLAN push/pop ist im eSwitch-Mode verfügbar. Wenn jedes VLAN auf einem
eigenen VF terminiert wird (statt als `eth0.100`), kann der eSwitch
VLAN-Tags in Hardware setzen/entfernen. Zusätzlich ermöglichen
VF-Representoren granulare TC-Rules pro VLAN/Zone.

Konfigurationsbeispiel für 3 VLANs:

```bash
# switchdev aktivieren
echo 3 > /sys/class/net/enp4s0f0/device/sriov_numvfs
devlink dev eswitch set pci/0000:04:00.0 mode switchdev

# VF-MAC-Adressen + VLAN-Konfiguration
ip link set enp4s0f0 vf 0 mac 00:00:00:00:01:00 vlan 100
ip link set enp4s0f0 vf 1 mac 00:00:00:00:02:00 vlan 200
ip link set enp4s0f0 vf 2 mac 00:00:00:00:03:00 vlan 300

# VFs im Host binden
echo 0000:04:00.2 > /sys/bus/pci/drivers/mlx5_core/bind  # VF0 → enp4s0f0v0
echo 0000:04:00.3 > /sys/bus/pci/drivers/mlx5_core/bind  # VF1 → enp4s0f0v1
echo 0000:04:00.4 > /sys/bus/pci/drivers/mlx5_core/bind  # VF2 → enp4s0f0v2

# hw-tc-offload auf PF + Representoren
ethtool -K enp4s0f0 hw-tc-offload on
ethtool -K enp4s0f0_0 hw-tc-offload on
ethtool -K enp4s0f0_1 hw-tc-offload on
ethtool -K enp4s0f0_2 hw-tc-offload on

# nftables läuft auf enp4s0f0v0/v1/v2 (ungetaggte Interfaces)
```

### OffloadManager-Architektur

```
shorewalld/
  offload_manager.py          Hauptklasse, Lifecycle
  conntrack_watcher.py        Netlink ctnetlink Event-Loop
  flow_eligibility.py         Offload-Entscheidungslogik
  tc_rule_installer.py        pyroute2 TC-Rule-Installation auf Representoren
  flow_aging.py               TC-Statistiken-Poll + conntrack-Refresh
  representor_map.py          VF-Index ↔ Representor-Netdev ↔ VLAN-ID Mapping
```

### ConntrackWatcher

Empfängt Kernel-Events via `NFNLGRP_CONNTRACK_NEW` /
`NFNLGRP_CONNTRACK_UPDATE` / `NFNLGRP_CONNTRACK_DESTROY`:

```python
class ConntrackWatcher:
    """
    Abonniert conntrack-Netlink-Events.
    Liefert FlowEvent-Objekte mit:
      - 5-Tuple (src_ip, dst_ip, src_port, dst_port, proto)
      - ct_state (NEW, ESTABLISHED, RELATED, ...)
      - ct_mark, ct_zone
      - orig_iif, reply_iif (Eingangs-Interface-Index)
      - NAT-Info (orig vs. reply Tuple verschieden → NAT aktiv)
    """
```

Implementierung via `pyroute2.conntrack` oder direkt über
`socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER)`.

### FlowEligibility

```python
class FlowEligibility:
    """
    Entscheidet ob ein conntrack-Flow in den eSwitch offloadbar ist.

    Kriterien GEGEN Offload:
    - NAT aktiv UND pedit-NAT-Rewrite nicht implementiert (Phase 3a)
    - ct_mark gesetzt (würde nicht mehr aktualisiert)
    - Flow durch Interface ohne Representor (kein eSwitch-Port)
    - Flow zu/von localhost (Input-Chain, kein Forward)
    - Proto nicht TCP oder UDP (ICMP etc. → im Kernel lassen)
    - shorewall-nft Rule-Klassifikation: "mixed" oder "sw"

    Erweiterung Phase 3b: NAT via pedit-Actions offloaden.
    """
    def __init__(self, rule_classifier: RuleClassifier,
                 representor_map: RepresentorMap):
        ...

    def is_eligible(self, flow: FlowEvent) -> bool:
        ...
```

### TcRuleInstaller

```python
class TcRuleInstaller:
    """
    Installiert / entfernt TC-Flower-Rules auf VF-Representoren.

    Für einen established Flow VF0→VF1:
      tc filter add dev enp4s0f0_0 ingress protocol ip pref <N> flower
        src_ip <X> dst_ip <Y> ip_proto tcp src_port <A> dst_port <B>
        ct_state +trk+est
        action mirred egress redirect dev enp4s0f0_1
        skip_sw

      tc filter add dev enp4s0f0_1 ingress protocol ip pref <N> flower
        src_ip <Y> dst_ip <X> ip_proto tcp src_port <B> dst_port <A>
        ct_state +trk+est
        action mirred egress redirect dev enp4s0f0_0
        skip_sw

    Beide Richtungen werden atomisch installiert.
    Bei Fehler (EOPNOTSUPP o.ä.): Flow bleibt im SW-Pfad, kein Absturz.
    """
    def install(self, flow: FlowEvent) -> bool: ...
    def remove(self, flow_cookie: int) -> None: ...
```

Implementierung via `pyroute2.tc` (IPRoute.tc() API).

### FlowAging

Das kritische Problem: sobald ein Flow im eSwitch ist, aktualisiert der
Kernel conntrack nicht mehr. Nach dem Timeout (TCP: 432000s established,
UDP: 180s) räumt conntrack den Flow auf — nächstes Paket würde wieder
durch den Kernel müssen.

Lösung: periodisches Polling der TC-Statistiken, conntrack-Refresh bei
aktiven Flows:

```python
class FlowAging:
    """
    Pollt alle AGING_INTERVAL Sekunden TC-Flower-Statistiken
    für alle offgeloadeten Flows.

    Bei bytes_delta > 0 seit letztem Poll:
      → Flow ist aktiv → conntrack-Timeout refreshen via
        conntrack -U --src <X> --dst <Y> ... --timeout <DEFAULT_TIMEOUT>

    Bei bytes_delta == 0 für IDLE_TIMEOUT:
      → Flow als inaktiv markieren → TC-Rule entfernen
      → Flow fällt zurück in SW-Pfad, conntrack räumt normal auf

    AGING_INTERVAL: 10s (konfigurierbar via shorewalld.conf)
    IDLE_TIMEOUT: 60s (konfigurierbar)
    """
```

### shorewalld.conf neue Parameter

```ini
# OffloadManager
OFFLOAD_MANAGER=yes               # aktiviert den eSwitch Auto-Offload
OFFLOAD_INTERFACES=enp4s0f0       # PF(s) mit switchdev
OFFLOAD_AGING_INTERVAL=10         # Sekunden zwischen Stats-Polls
OFFLOAD_IDLE_TIMEOUT=60           # Sekunden bis Flow als inaktiv gilt
OFFLOAD_NAT_REWRITE=no            # Phase 3b: pedit-NAT (default: no)

# Metrics
# Neue Prometheus-Metriken (NftCollector-Erweiterung):
# shorewalld_offload_flows_active{interface}
# shorewalld_offload_flows_installed_total{interface}
# shorewalld_offload_flows_removed_total{reason,interface}
# shorewalld_offload_aging_polls_total
# shorewalld_offload_eligibility_rejected_total{reason}
```

---

## Phase 3b: NAT-Rewrite via pedit (Erweiterung)

Wenn NAT aktiv ist (`orig_tuple != reply_tuple` in conntrack), kann der
eSwitch trotzdem offloaden wenn die NAT-Translation explizit als
`pedit`-Action in die TC-Rule eingebaut wird:

```bash
# Beispiel SNAT: src 192.168.1.5 → 203.0.113.1
tc filter add dev enp4s0f0_0 ingress flower \
  src_ip 192.168.1.5 dst_ip 8.8.8.8 ip_proto tcp \
  action pedit ex munge ip src set 203.0.113.1 pipe \
  action csum ip tcp pipe \
  action mirred egress redirect dev enp4s0f0   # PF = Uplink
```

Voraussetzungen:
- `action pedit` + `action csum` müssen im eSwitch offloadbar sein
  (bei mlx5 ab ConnectX-5 verfügbar, aber zu verifizieren)
- Checksum-Update muss korrekt implementiert sein (TCP/UDP-Pseudo-Header)
- Bidirektionale Rules: SNAT auf Egress, DNAT-Reverse auf Ingress

Phase 3b ist **bewusst separiert** von Phase 3a (kein NAT-Offload):
erst wenn Phase 3a stabil und getestet ist, wird NAT-Rewrite angegangen.

---

## Kernel-Anforderungen

| Feature | Kernel-Version | Status |
|---|---|---|
| TC Flower HW-Offload (Basis) | 4.8+ | stabil, mainline |
| VLAN-ID als Match in TC Flower | 4.8+ | stabil |
| nftables Flowtable SW | 4.16+ | stabil |
| VLAN-Device-Erkennung in Flowtable | 5.13+ | stabil |
| nftables Flowtable HW-Offload (mlx5) | 5.13+ | teilweise, VLAN-Routing fragil |
| mlx5 switchdev + TC-Flower eSwitch | 4.8+ | stabil für NIC-Mode-ACLs |
| mlx5 VLAN push/pop im eSwitch | 4.8+ | stabil im switchdev-Mode |
| ct_state Match in TC Flower | 5.3+ | stabil |

Empfohlene Kernel-Mindestversion: **6.1 LTS** (Debian 12 Standard).

---

## Implementierungsreihenfolge

### Phase 1 (TC HW-ACL Generator) — Priorität: hoch

1. `is_hw_offloadable()` in `compiler/ir.py` + Tests
2. `shorewall_nft/nft/tc_offload.py` — `TcOffloadEmitter`
3. `generate-tc --mode hw-acl` CLI-Command
4. Integration in `start`/`stop` via `apply.py`
5. Neue shorewall.conf-Direktiven parsen
6. Tests: `test_tc_offload.py`, `test_tc_emitter.py`

### Phase 2 (SW-Flowtable VLAN-Fix) — Priorität: mittel

1. `FLOWTABLE=auto` korrekt auf physische Interfaces ableiten
2. Capability-Check in `apply.py`: `ethtool -k` vor `FLOWTABLE_OFFLOAD=Yes`
3. Dokumentation: klarer Hinweis wann `FLOWTABLE_OFFLOAD=No` korrekt ist

### Phase 3a (OffloadManager, kein NAT) — Priorität: mittel-niedrig

1. `representor_map.py` — VF↔Representor↔VLAN-Mapping aus sysfs
2. `conntrack_watcher.py` — Netlink-Event-Loop
3. `flow_eligibility.py` — Offload-Entscheidung (kein NAT, nur Forward)
4. `tc_rule_installer.py` — bidirektionale TC-Rules auf Representoren
5. `flow_aging.py` — Statistiken-Poll + conntrack-Refresh
6. Integration in `shorewalld/core.py`
7. shorewalld.conf-Parser-Erweiterung
8. Prometheus-Metriken
9. Tests (ohne echte Hardware: Mock-Representoren, simulierte ct-Events)

### Phase 3b (NAT-Rewrite) — Priorität: niedrig

Nach erfolgreicher Phase 3a-Validierung auf echter mlx5-Hardware.

---

## Bekannte Einschränkungen und Nicht-Ziele

- **Keine nftables-Flowtable-HW für VLAN-Routing**: VLAN push/pop als
  nf_flow_table-Action ist im mainline Kernel noch nicht stabil (Stand
  April 2026, Patches in Diskussion auf netfilter-devel). Nicht anstreben.
- **Kein switchdev ohne SR-IOV**: der eSwitch-Mode setzt SR-IOV voraus.
  Für Setups ohne VFs bleibt Schicht 1+2 (TC-ACL + nftables).
- **Intel E810/i40e**: TC Flower `hw-tc-offload: on` gesetzt, aber
  nftables Flowtable HW-Offload schlägt mit EOPNOTSUPP fehl (Treiber-
  Einschränkung, bestätigt 2024). Nur für Schicht 1 (stateless ACLs)
  nutzbar.
- **OffloadManager ist optional**: ohne switchdev/mlx5 laufen Schicht
  1+2 vollständig. Der OffloadManager ist ein Performance-Feature,
  keine Voraussetzung für korrekte Firewall-Funktion.
- **QinQ (802.1ad)**: nicht unterstützt für HW-Offload in keiner Schicht.
  Bei `encaps >= 2` wird empfohlen, kein HW-Offload zu konfigurieren
  (OpenWrt-Dokumentation).

---

## Einstieg für neue Arbeitssessions

```
# Compiler/IR-Änderungen (Phase 1):
packages/shorewall-nft/
  shorewall_nft/compiler/ir.py          hw_offload_eligible Flag
  shorewall_nft/nft/tc_offload.py       TcOffloadEmitter (neu)
  shorewall_nft/runtime/apply.py        TC-Setup in start/stop
  shorewall_nft/config/parser.py        HW_OFFLOAD_* Direktiven
  tests/test_tc_offload.py              (neu)

# OffloadManager (Phase 3a):
packages/shorewalld/
  shorewalld/offload_manager.py         (neu)
  shorewalld/conntrack_watcher.py       (neu)
  shorewalld/flow_eligibility.py        (neu)
  shorewalld/tc_rule_installer.py       (neu)
  shorewalld/flow_aging.py              (neu)
  shorewalld/representor_map.py         (neu)
  shorewalld/core.py                    Integration OffloadManager
  tests/test_offload_manager.py         (neu)
```

Zugehörige HOWTO-CLAUDE.md Einträge: siehe Abschnitt
"HW-Offload / TC Flower / eSwitch" (nach Merge dieses Dokuments eintragen).
