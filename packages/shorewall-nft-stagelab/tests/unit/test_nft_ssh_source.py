"""Unit tests for NftSSHSource / NftSSHScraper in metrics_ingest."""

from __future__ import annotations

import asyncio
import subprocess
from pathlib import Path
from subprocess import TimeoutExpired
from unittest.mock import MagicMock

import pytest

from shorewall_nft_stagelab.config import NftSSHSourceSpec, load
from shorewall_nft_stagelab.metrics import MetricRow
from shorewall_nft_stagelab.metrics_ingest import (
    NftSSHScraper,
    NftSSHSource,
    build_source,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FIXTURES = Path(__file__).parent.parent / "fixtures"
_NFT_FIXTURE = _FIXTURES / "nft_list_counters.json"

_TS = 1_700_000_000.0


def _run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_parse_counters_emits_three_rows_per_counter(monkeypatch):
    """Loading the fixture via a monkeypatched subprocess.run produces 6*3=18 MetricRows.

    The :counter-tagged rows must carry the packets value.
    """
    fixture_json = _NFT_FIXTURE.read_text()

    def _fake_run(cmd, **kwargs):
        result = MagicMock()
        result.stdout = fixture_json
        return result

    monkeypatch.setattr(subprocess, "run", _fake_run)

    src = NftSSHSource(name="fw-nft", ssh_target="root@10.0.0.1")
    scraper = NftSSHScraper(src)
    rows = _run(scraper.scrape(_TS))

    # 6 counters × 3 rows each
    assert len(rows) == 18
    assert all(isinstance(r, MetricRow) for r in rows)

    # :counter rows carry packets value
    counter_rows = [r for r in rows if r.source == "fw-nft:counter"]
    assert len(counter_rows) == 6

    # ssh-accept row: 900000 packets
    ssh_counter = next(r for r in counter_rows if r.key == "fw-accept-ssh")
    assert ssh_counter.value == 900000.0

    # packets rows and bytes rows exist
    assert len([r for r in rows if r.source == "fw-nft:packets"]) == 6
    assert len([r for r in rows if r.source == "fw-nft:bytes"]) == 6


def test_nft_ssh_source_spec_accepted(tmp_path):
    """A YAML config with kind: nft_ssh is accepted and parsed to NftSSHSourceSpec."""
    import textwrap
    yaml_text = textwrap.dedent("""\
        hosts:
          - name: thx1
            address: root@192.0.2.73

        dut:
          kind: external

        endpoints:
          - name: client-lan
            host: thx1
            mode: native
            nic: enp1s0f0
            vlan: 10
            ipv4: 10.0.10.100/24
            ipv4_gw: 10.0.10.1
          - name: server-wan
            host: thx1
            mode: native
            nic: enp1s0f1
            vlan: 20
            ipv4: 198.51.100.100/30
            ipv4_gw: 198.51.100.99

        scenarios:
          - id: tp1
            kind: throughput
            source: client-lan
            sink: server-wan
            proto: tcp
            duration_s: 10
            parallel: 4
            expect_min_gbps: 1.0

        metrics:
          sources:
            - kind: nft_ssh
              name: fw-nft
              ssh_target: root@192.168.1.1

        report:
          output_dir: /tmp/out
    """)
    p = tmp_path / "cfg.yaml"
    p.write_text(yaml_text)

    cfg = load(p)
    assert len(cfg.metrics.sources) == 1
    spec = cfg.metrics.sources[0]
    assert isinstance(spec, NftSSHSourceSpec)
    assert spec.kind == "nft_ssh"
    assert spec.name == "fw-nft"
    assert spec.ssh_target == "root@192.168.1.1"
    assert spec.timeout_s == 10.0


def test_scrape_timeout_raises(monkeypatch):
    """If subprocess.run raises TimeoutExpired, scrape() propagates it."""

    def _timeout_run(cmd, **kwargs):
        raise TimeoutExpired(cmd, kwargs.get("timeout", 10))

    monkeypatch.setattr(subprocess, "run", _timeout_run)

    src = NftSSHSource(name="fw-nft", ssh_target="root@10.0.0.1", timeout_s=1.0)
    scraper = NftSSHScraper(src)
    with pytest.raises(TimeoutExpired):
        _run(scraper.scrape(_TS))


def test_build_source_dispatches_nft_ssh():
    """build_source(NftSSHSourceSpec(...)) returns an NftSSHScraper instance."""
    spec = NftSSHSourceSpec(kind="nft_ssh", name="fw-nft", ssh_target="root@10.0.0.1")
    scraper = build_source(spec)
    assert isinstance(scraper, NftSSHScraper)
