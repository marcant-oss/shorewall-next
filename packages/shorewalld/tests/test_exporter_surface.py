"""Guard the public surface of shorewalld.exporter against regressions.

If a future change accidentally adds private names to ``__all__`` (e.g.
by re-adding ``_CT_STAT_FIELDS``), this test fails immediately and
makes the regression visible in CI.

Private helpers (_MetricFamily, _fmt_bucket_bound, etc.) are intentionally
absent from __all__ — they remain importable but are not part of the
guaranteed public API.  Import them from shorewalld.collectors.<module>
or from shorewalld.exporter directly if needed in tests.
"""

from __future__ import annotations

EXPECTED_PUBLIC_NAMES: frozenset[str] = frozenset(
    {
        # Core infrastructure (defined in shorewalld.exporter itself)
        "CollectorBase",
        "Histogram",
        "NftScraper",
        "ShorewalldRegistry",
        # Collector classes (re-exported from shorewalld.collectors)
        "AddressCollector",
        "ConntrackStatsCollector",
        "CtCollector",
        "FlowtableCollector",
        "LinkCollector",
        "NeighbourCollector",
        "NetstatCollector",
        "NfsetsCollector",
        "NftCollector",
        "QdiscCollector",
        "SnmpCollector",
        "SockstatCollector",
        "SoftnetCollector",
        "VrrpCollector",
        # Public dataclasses consumed by tests / integrations
        "VrrpInstance",
        "VrrpSnmpConfig",
    }
)


def test_exporter_public_surface_stable():
    """Guard against accidental re-export regression.

    The exporter module's public surface is defined by __all__. If a
    future change adds private names here, this test fails."""
    import shorewalld.exporter as exp

    assert set(exp.__all__) == EXPECTED_PUBLIC_NAMES
