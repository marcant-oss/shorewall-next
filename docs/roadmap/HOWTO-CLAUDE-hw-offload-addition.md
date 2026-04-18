## HW-Offload / TC Flower / eSwitch

**Symptom:** TC-ACL-Generator, OffloadManager, mlx5-Offload, Flowtable-HW,
VLAN-Offload, VF-Representor, conntrack-Watcher

```
# Architektur-Referenz:
docs/roadmap/hw-offload-eswitch.md    ← HIER ANFANGEN — vollständige Analyse
                                          + Implementierungsplan

# Phase 1 — TC HW-ACL Generator (shorewall-nft):
packages/shorewall-nft/
  shorewall_nft/compiler/ir.py          hw_offload_eligible Flag + is_hw_offloadable()
  shorewall_nft/nft/tc_offload.py       TcOffloadEmitter (neu, noch nicht vorhanden)
  shorewall_nft/runtime/apply.py        TC-Setup in start/stop (pyroute2-Muster: proxyarp)
  shorewall_nft/config/parser.py        HW_OFFLOAD_INTERFACES, HW_OFFLOAD_BLACKLIST,
                                          HW_OFFLOAD_SCFILTER, HW_OFFLOAD_VLAN
  tests/test_tc_offload.py              (neu)

# Phase 3a — OffloadManager (shorewalld):
packages/shorewalld/
  shorewalld/offload_manager.py         Hauptklasse (neu)
  shorewalld/conntrack_watcher.py       Netlink ctnetlink Events (neu)
  shorewalld/flow_eligibility.py        Offload-Entscheidung (neu)
  shorewalld/tc_rule_installer.py       pyroute2 TC-Rules auf Representoren (neu)
  shorewalld/flow_aging.py              Stats-Poll + conntrack-Refresh (neu)
  shorewalld/representor_map.py         VF↔Representor↔VLAN aus sysfs (neu)
  shorewalld/core.py                    Integration: OFFLOAD_MANAGER=yes

# Referenz-Implementierungen im selben Paket (Muster übernehmen):
packages/shorewalld/
  shorewalld/setwriter.py               pyroute2-Netlink-Pattern (für tc_rule_installer)
  shorewalld/dns_set_tracker.py         Event-Loop-Pattern (für conntrack_watcher)
  shorewalld/exporter.py                CtCollector — conntrack via /proc (Basis für Watcher)

# Hardware-Voraussetzungen für Phase 3a:
#   mlx5 ConnectX-5 oder neuer
#   devlink dev eswitch set pci/... mode switchdev
#   VFs im Host-Namespace (nicht in VMs)
#   ethtool -K <pf> hw-tc-offload on
#   ethtool -K <rep> hw-tc-offload on  (pro VF-Representor)

# Kritische Einschränkungen (NICHT vergessen):
#   - VLAN push/pop NUR im eSwitch-Mode, nie im NIC-Mode
#   - Intel E810/i40e: hw-tc-offload:on gesetzt, aber nftables Flowtable
#     HW-Offload schlägt mit EOPNOTSUPP fehl → nur für stateless ACLs nutzbar
#   - nftables Flowtable HW-Offload für VLAN-Routing: noch nicht stabil
#     im mainline Kernel (Stand April 2026) → FLOWTABLE_OFFLOAD=No für VLAN
#   - OffloadManager ist optional — ohne switchdev laufen Schicht 1+2 vollständig
#   - QinQ (encaps >= 2): kein HW-Offload konfigurieren
```
