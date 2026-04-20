"""Smoke test: the stagelab package is importable and exposes a version."""

import shorewall_nft_stagelab
from shorewall_nft_stagelab import (
    agent,
    cli,
    config,
    controller,
    ipc,
    metrics,
    report,
    scenarios,
    topology_bridge,
    topology_native,
    trafgen_iperf3,
    trafgen_nmap,
    trafgen_scapy,
    trafgen_tcpkali,
    tuning,
)


def test_version_attribute():
    assert shorewall_nft_stagelab.__version__ == "1.8.0"


def test_all_submodules_importable():
    # Presence of modules is asserted by the import above; this asserts
    # they are all distinct module objects.
    mods = [agent, cli, config, controller, ipc, metrics, report, scenarios,
            topology_bridge, topology_native, trafgen_iperf3, trafgen_nmap,
            trafgen_scapy, trafgen_tcpkali, tuning]
    assert len({id(m) for m in mods}) == len(mods)
