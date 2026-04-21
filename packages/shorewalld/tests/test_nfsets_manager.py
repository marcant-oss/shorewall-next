"""Unit tests for NfSetsManager.

Verifies that the nfsets payload from register-instance is correctly
dispatched to dns_registries(), iplist_configs(), and plain_list_configs().
"""

from __future__ import annotations


from shorewall_nft.nft.nfsets import NfSetEntry, NfSetRegistry, nfset_registry_to_payload


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def _make_payload(*entries: NfSetEntry) -> dict:
    """Build a payload dict from NfSetEntry objects via the core serialiser."""
    reg = NfSetRegistry()
    for e in entries:
        reg.entries.append(e)
        reg.set_names.add(e.name)
    return nfset_registry_to_payload(reg)


def _dnstap(name: str, *hosts: str) -> NfSetEntry:
    return NfSetEntry(name=name, hosts=list(hosts), backend="dnstap")


def _resolver(name: str, *hosts: str, dns_servers: list[str] | None = None) -> NfSetEntry:
    return NfSetEntry(
        name=name,
        hosts=list(hosts),
        backend="resolver",
        dns_servers=dns_servers or [],
    )


def _iplist(
    name: str,
    provider: str,
    filters: list[str] | None = None,
    refresh: int | None = None,
) -> NfSetEntry:
    opts = {}
    if filters:
        opts["filter"] = filters
    return NfSetEntry(
        name=name,
        hosts=[provider],
        backend="ip-list",
        options=opts,
        refresh=refresh,
    )


def _plain(
    name: str,
    source: str,
    refresh: int | None = None,
    inotify: bool = False,
) -> NfSetEntry:
    return NfSetEntry(
        name=name,
        hosts=[source],
        backend="ip-list-plain",
        refresh=refresh,
        inotify=inotify,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestEmptyPayload:
    def test_empty_dict_all_empty(self):
        from shorewalld.nfsets_manager import NfSetsManager
        mgr = NfSetsManager({})
        dns_reg, dnsr_reg = mgr.dns_registries()
        assert list(dns_reg.iter_sorted()) == []
        assert list(dnsr_reg.iter_sorted()) == []
        assert mgr.iplist_configs() == []
        assert mgr.plain_list_configs() == []

    def test_no_entries_key_all_empty(self):
        from shorewalld.nfsets_manager import NfSetsManager
        mgr = NfSetsManager({"entries": []})
        assert mgr.iplist_configs() == []
        assert mgr.plain_list_configs() == []


class TestDnstapOnly:
    def test_dns_registries_populated(self):
        from shorewalld.nfsets_manager import NfSetsManager
        payload = _make_payload(_dnstap("myname", "a.example.com", "b.example.com"))
        mgr = NfSetsManager(payload)

        dns_reg, dnsr_reg = mgr.dns_registries()
        qnames = {s.qname for s in dns_reg.iter_sorted()}
        assert "a.example.com" in qnames
        assert "b.example.com" in qnames

    def test_iplist_and_plain_empty(self):
        from shorewalld.nfsets_manager import NfSetsManager
        payload = _make_payload(_dnstap("myname", "a.example.com"))
        mgr = NfSetsManager(payload)
        assert mgr.iplist_configs() == []
        assert mgr.plain_list_configs() == []

    def test_set_name_override_written(self):
        """DnsSetSpec.set_name is set to an nfset target name, not the default qname-derived name.

        NOTE: DnsSetRegistry stores one spec per qname (not per family).  W2's
        nfset_registry_to_dns_registries calls add_with_target twice (once for v4,
        once for v6) on the same qname, so the second call (v6) overwrites the first
        (v4).  As a result, spec.set_name is the v6 nfset name.  This is a known W2
        design limitation flagged in the Wave 3 report; Wave 4 must address it in the
        worker_router lookup closure.
        """
        from shorewall_nft.nft.nfsets import nfset_to_set_name
        from shorewalld.nfsets_manager import NfSetsManager

        payload = _make_payload(_dnstap("widgets", "api.example.com"))
        mgr = NfSetsManager(payload)
        dns_reg, _ = mgr.dns_registries()
        specs = list(dns_reg.iter_sorted())
        assert len(specs) == 1  # one spec per qname
        spec = specs[0]
        # set_name is non-None (it's been overridden to point at an nfset).
        assert spec.set_name is not None
        # A2 fix: set_name now stores the BASE name (no _v4/_v6 suffix).
        # The worker appends the family suffix at write time.
        expected_v4 = nfset_to_set_name("widgets", "v4")
        expected_base = expected_v4[:-3]  # strip "_v4"
        assert spec.set_name == expected_base, (
            f"set_name={spec.set_name!r} should be base name {expected_base!r}"
        )
        assert not spec.set_name.endswith("_v4"), "base name must not have _v4 suffix"
        assert not spec.set_name.endswith("_v6"), "base name must not have _v6 suffix"


class TestResolverOnly:
    def test_dnsr_registry_populated(self):
        from shorewalld.nfsets_manager import NfSetsManager
        payload = _make_payload(_resolver("rsv", "example.com", "www.example.com"))
        mgr = NfSetsManager(payload)
        _, dnsr_reg = mgr.dns_registries()
        groups = list(dnsr_reg.iter_sorted())
        assert len(groups) > 0

    def test_iplist_and_plain_empty(self):
        from shorewalld.nfsets_manager import NfSetsManager
        payload = _make_payload(_resolver("rsv", "example.com"))
        mgr = NfSetsManager(payload)
        assert mgr.iplist_configs() == []
        assert mgr.plain_list_configs() == []


class TestIpListOnly:
    def test_iplist_configs_populated(self):
        from shorewalld.nfsets_manager import NfSetsManager
        payload = _make_payload(_iplist("blocklist", "aws", refresh=7200))
        mgr = NfSetsManager(payload)
        cfgs = mgr.iplist_configs()
        assert len(cfgs) == 1
        cfg = cfgs[0]
        assert cfg.name == "nfset_blocklist"
        assert cfg.provider == "aws"
        assert cfg.refresh == 7200

    def test_dns_and_plain_empty(self):
        from shorewalld.nfsets_manager import NfSetsManager
        payload = _make_payload(_iplist("bl", "bogon"))
        mgr = NfSetsManager(payload)
        dns_reg, dnsr_reg = mgr.dns_registries()
        assert list(dns_reg.iter_sorted()) == []
        assert mgr.plain_list_configs() == []

    def test_set_v4_v6_derived(self):
        from shorewall_nft.nft.nfsets import nfset_to_set_name
        from shorewalld.nfsets_manager import NfSetsManager

        payload = _make_payload(_iplist("mylist", "azure"))
        mgr = NfSetsManager(payload)
        cfg = mgr.iplist_configs()[0]
        assert cfg.set_v4 == nfset_to_set_name("mylist", "v4")
        assert cfg.set_v6 == nfset_to_set_name("mylist", "v6")

    def test_filter_option_forwarded(self):
        from shorewalld.nfsets_manager import NfSetsManager
        payload = _make_payload(
            _iplist("aws_ec2", "aws", filters=["region=us-east-1", "service=EC2"])
        )
        mgr = NfSetsManager(payload)
        cfg = mgr.iplist_configs()[0]
        assert "region" in cfg.filters
        assert cfg.filters["region"] == ["us-east-1"]
        assert cfg.filters["service"] == ["EC2"]

    def test_default_refresh_when_none(self):
        from shorewalld.nfsets_manager import NfSetsManager, _DEFAULT_REFRESH_IPLIST
        payload = _make_payload(_iplist("bl", "bogon", refresh=None))
        mgr = NfSetsManager(payload)
        cfg = mgr.iplist_configs()[0]
        assert cfg.refresh == _DEFAULT_REFRESH_IPLIST


class TestPlainListOnly:
    def test_plain_configs_populated(self):
        from shorewalld.nfsets_manager import NfSetsManager
        payload = _make_payload(_plain("blocklist", "https://example.org/list.txt"))
        mgr = NfSetsManager(payload)
        cfgs = mgr.plain_list_configs()
        assert len(cfgs) == 1
        cfg = cfgs[0]
        assert cfg.name == "nfset_blocklist"
        assert cfg.source == "https://example.org/list.txt"

    def test_dns_and_iplist_empty(self):
        from shorewalld.nfsets_manager import NfSetsManager
        payload = _make_payload(_plain("bl", "/var/lib/blocklist.txt"))
        mgr = NfSetsManager(payload)
        dns_reg, dnsr_reg = mgr.dns_registries()
        assert list(dns_reg.iter_sorted()) == []
        assert mgr.iplist_configs() == []

    def test_inotify_flag_preserved(self):
        from shorewalld.nfsets_manager import NfSetsManager
        payload = _make_payload(_plain("bl", "/etc/shorewall/blocklist.txt", inotify=True))
        mgr = NfSetsManager(payload)
        cfg = mgr.plain_list_configs()[0]
        assert cfg.inotify is True

    def test_default_refresh_when_none(self):
        from shorewalld.nfsets_manager import NfSetsManager, _DEFAULT_REFRESH_PLAIN
        payload = _make_payload(_plain("bl", "/etc/list.txt", refresh=None))
        mgr = NfSetsManager(payload)
        cfg = mgr.plain_list_configs()[0]
        assert cfg.refresh == _DEFAULT_REFRESH_PLAIN

    def test_set_v4_v6_derived(self):
        from shorewall_nft.nft.nfsets import nfset_to_set_name
        from shorewalld.nfsets_manager import NfSetsManager

        payload = _make_payload(_plain("myplain", "/etc/list.txt"))
        mgr = NfSetsManager(payload)
        cfg = mgr.plain_list_configs()[0]
        assert cfg.set_v4 == nfset_to_set_name("myplain", "v4")
        assert cfg.set_v6 == nfset_to_set_name("myplain", "v6")


class TestMixedPayload:
    def test_all_backends_correct_split(self):
        from shorewalld.nfsets_manager import NfSetsManager
        payload = _make_payload(
            _dnstap("dnsnames", "host.example.com"),
            _resolver("resolv", "svc.example.com"),
            _iplist("ipbl", "aws"),
            _plain("plainbl", "https://example.org/bl.txt"),
        )
        mgr = NfSetsManager(payload)

        dns_reg, dnsr_reg = mgr.dns_registries()
        assert len(list(dns_reg.iter_sorted())) > 0
        assert len(list(dnsr_reg.iter_sorted())) > 0
        assert len(mgr.iplist_configs()) == 1
        assert len(mgr.plain_list_configs()) == 1


class TestN6AdditiveMultiBackend:
    """N6: payload with two entries for the same name, different backends.

    Both entries must be routed to the correct tracker; both must resolve
    to the same nft set name.
    """

    def test_resolver_and_plain_same_name_both_routed(self):
        """resolver + ip-list-plain on 'web' → each tracker gets one entry."""
        from shorewall_nft.nft.nfsets import (
            NfSetRegistry,
            nfset_registry_to_payload,
            nfset_to_set_name,
        )
        from shorewalld.nfsets_manager import NfSetsManager

        # Build the registry with two entries for the same name.
        reg = NfSetRegistry()
        resolver_entry = NfSetEntry(
            name="web",
            hosts=["cdn.example.org", "edge.example.org"],
            backend="resolver",
            refresh=300,
        )
        plain_entry = NfSetEntry(
            name="web",
            hosts=["/etc/shorewall46/web-blocks.txt"],
            backend="ip-list-plain",
            refresh=3600,
        )
        reg.entries.append(resolver_entry)
        reg.entries.append(plain_entry)
        reg.set_names.add("web")
        payload = nfset_registry_to_payload(reg)

        mgr = NfSetsManager(payload)

        # resolver entry → dns_registries (DnsrRegistry).
        _, dnsr_reg = mgr.dns_registries()
        groups = list(dnsr_reg.iter_sorted())
        assert len(groups) > 0, "resolver entry must reach DnsrRegistry"

        # ip-list-plain entry → plain_list_configs.
        plain_cfgs = mgr.plain_list_configs()
        assert len(plain_cfgs) == 1
        cfg = plain_cfgs[0]
        assert cfg.name == "nfset_web"
        assert cfg.source == "/etc/shorewall46/web-blocks.txt"

        # Both entries resolve to the same nft set names.
        expected_v4 = nfset_to_set_name("web", "v4")
        expected_v6 = nfset_to_set_name("web", "v6")
        assert cfg.set_v4 == expected_v4
        assert cfg.set_v6 == expected_v6

    def test_dnstap_and_iplist_same_name_each_goes_to_own_tracker(self):
        """dnstap + ip-list on 'cdn' → dns tracker and iplist tracker, same set name."""
        from shorewall_nft.nft.nfsets import (
            NfSetRegistry,
            nfset_registry_to_payload,
            nfset_to_set_name,
        )
        from shorewalld.nfsets_manager import NfSetsManager

        reg = NfSetRegistry()
        dnstap_entry = NfSetEntry(
            name="cdn",
            hosts=["a.example.com", "b.example.com"],
            backend="dnstap",
        )
        iplist_entry = NfSetEntry(
            name="cdn",
            hosts=["https://example.org/cdn-prefixes.txt"],
            backend="ip-list-plain",
        )
        reg.entries.append(dnstap_entry)
        reg.entries.append(iplist_entry)
        reg.set_names.add("cdn")
        payload = nfset_registry_to_payload(reg)

        mgr = NfSetsManager(payload)

        dns_reg, _ = mgr.dns_registries()
        qnames = {s.qname for s in dns_reg.iter_sorted()}
        assert "a.example.com" in qnames
        assert "b.example.com" in qnames

        plain_cfgs = mgr.plain_list_configs()
        assert len(plain_cfgs) == 1
        cfg = plain_cfgs[0]
        assert cfg.name == "nfset_cdn"
        # Both point to the same nft set names.
        assert cfg.set_v4 == nfset_to_set_name("cdn", "v4")
        assert cfg.set_v6 == nfset_to_set_name("cdn", "v6")
