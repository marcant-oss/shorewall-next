"""End-to-end integration test for the nfsets feature.

No sudo, no netns, no kernel calls.

Tests:
1. Compiler emits correct nft set declarations for dnstap / resolver /
   ip-list-plain backends.
2. Rules referencing ``nfset:name`` and ``nfset:set1,set2`` emit
   ``@nfset_<name>_v4`` match expressions.
3. Full payload round-trip: nfset_registry_to_payload →
   payload_to_nfset_registry → NfSetsManager → correct backend splits.

All hostnames: example.com / example.org (RFC 2606).
All addresses: RFC 5737 (198.51.100.x, 203.0.113.x) or RFC 1918.
"""

from __future__ import annotations

from pathlib import Path


from shorewall_nft.compiler.ir import build_ir
from shorewall_nft.config.parser import ConfigLine, ShorewalConfig, load_config
from shorewall_nft.nft.emitter import emit_nft
from shorewall_nft.nft.nfsets import (
    NfSetEntry,
    NfSetRegistry,
    nfset_registry_to_payload,
    nfset_to_set_name,
    payload_to_nfset_registry,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_MINIMAL_DIR = Path(__file__).parent / "configs" / "minimal"


def _line(*cols: str, file: str = "test", lineno: int = 1) -> ConfigLine:
    """Build a ConfigLine for use in synthetic config."""
    return ConfigLine(columns=list(cols), file=file, lineno=lineno)


def _lines(*rows: tuple) -> list[ConfigLine]:
    return [_line(*row) for row in rows]


def _minimal_config(
    extra_rules: list[tuple] | None = None,
    nfset_rows: list[tuple] | None = None,
) -> ShorewalConfig:
    """Load the minimal test config and optionally inject nfsets + extra rules."""
    cfg = load_config(_MINIMAL_DIR)

    # Append extra rules after the already-loaded ones.
    if extra_rules:
        cfg.rules.extend(_lines(*extra_rules))

    # Inject nfsets lines.
    if nfset_rows:
        cfg.nfsets = _lines(*nfset_rows)

    return cfg


# ---------------------------------------------------------------------------
# Part 1: Compiler emits correct set declarations
# ---------------------------------------------------------------------------


class TestNfsetSetDeclarations:
    def test_dnstap_set_declarations(self):
        """dnstap backend → flags timeout set declarations."""
        cfg = _minimal_config(
            nfset_rows=[
                ("web", "cdn.example.com", "dnstap"),
            ]
        )
        ir = build_ir(cfg)
        out = emit_nft(ir)

        v4_name = nfset_to_set_name("web", "v4")
        v6_name = nfset_to_set_name("web", "v6")
        assert f"set {v4_name}" in out, f"missing {v4_name} in output"
        assert f"set {v6_name}" in out, f"missing {v6_name} in output"
        # DNS backend → flags timeout
        assert "flags timeout" in out

    def test_resolver_set_declarations(self):
        """resolver backend → flags timeout set declarations."""
        cfg = _minimal_config(
            nfset_rows=[
                ("cdn", "api.example.org", "resolver"),
            ]
        )
        ir = build_ir(cfg)
        out = emit_nft(ir)

        v4_name = nfset_to_set_name("cdn", "v4")
        v6_name = nfset_to_set_name("cdn", "v6")
        assert f"set {v4_name}" in out
        assert f"set {v6_name}" in out
        assert "flags timeout" in out

    def test_ip_list_plain_set_declarations(self):
        """ip-list-plain backend → flags interval set declarations."""
        cfg = _minimal_config(
            nfset_rows=[
                ("edge", "/var/lib/lists/edge.txt", "ip-list-plain"),
            ]
        )
        ir = build_ir(cfg)
        out = emit_nft(ir)

        v4_name = nfset_to_set_name("edge", "v4")
        v6_name = nfset_to_set_name("edge", "v6")
        assert f"set {v4_name}" in out
        assert f"set {v6_name}" in out
        # ip-list-plain backend → flags interval
        assert "flags interval" in out

    def test_set_type_ipv4(self):
        """v4 sets have type ipv4_addr."""
        cfg = _minimal_config(
            nfset_rows=[("web", "cdn.example.com", "dnstap")]
        )
        out = emit_nft(build_ir(cfg))
        v4_name = nfset_to_set_name("web", "v4")
        # Find the set block and confirm type
        assert "type ipv4_addr" in out

    def test_set_type_ipv6(self):
        """v6 sets have type ipv6_addr."""
        cfg = _minimal_config(
            nfset_rows=[("web", "cdn.example.com", "dnstap")]
        )
        out = emit_nft(build_ir(cfg))
        assert "type ipv6_addr" in out


# ---------------------------------------------------------------------------
# Part 2: Rule matches reference @nfset_<name>_v4
# ---------------------------------------------------------------------------


class TestNfsetRuleMatches:
    def test_nfset_source_match(self):
        """nfset: in SOURCE → @nfset_<name>_v4 in emitted rules."""
        cfg = _minimal_config(
            nfset_rows=[("web", "cdn.example.com", "dnstap")],
            extra_rules=[
                ("ACCEPT", "net:nfset:web", "loc"),
            ],
        )
        ir = build_ir(cfg)
        out = emit_nft(ir)
        v4_name = nfset_to_set_name("web", "v4")
        assert f"@{v4_name}" in out, (
            f"Expected @{v4_name} in emitted rules. Rule output:\n{out[:2000]}")

    def test_nfset_dest_match(self):
        """nfset: in DEST → @nfset_<name>_v4 in emitted rules."""
        cfg = _minimal_config(
            nfset_rows=[("web", "cdn.example.com", "dnstap")],
            extra_rules=[
                ("ACCEPT", "loc", "net:nfset:web"),
            ],
        )
        ir = build_ir(cfg)
        out = emit_nft(ir)
        v4_name = nfset_to_set_name("web", "v4")
        assert f"@{v4_name}" in out

    def test_multi_set_comma_syntax(self):
        """nfset:cdn,edge → two rules (one per set) or one rule matching both."""
        cfg = _minimal_config(
            nfset_rows=[
                ("cdn", "cdn.example.com", "dnstap"),
                ("edge", "edge.example.org", "dnstap"),
            ],
            extra_rules=[
                ("ACCEPT", "net:nfset:cdn,edge", "loc"),
            ],
        )
        ir = build_ir(cfg)
        out = emit_nft(ir)
        cdn_v4 = nfset_to_set_name("cdn", "v4")
        edge_v4 = nfset_to_set_name("edge", "v4")
        # Both set names must appear somewhere in the output
        assert f"@{cdn_v4}" in out, f"missing @{cdn_v4}"
        assert f"@{edge_v4}" in out, f"missing @{edge_v4}"


# ---------------------------------------------------------------------------
# Part 3: Payload round-trip + NfSetsManager split
# ---------------------------------------------------------------------------


class TestPayloadRoundTrip:
    def _build_registry(self) -> NfSetRegistry:
        """Build a registry with all four backends."""
        reg = NfSetRegistry()
        entries = [
            NfSetEntry(
                name="web",
                hosts=["cdn.example.com", "static.example.org"],
                backend="dnstap",
            ),
            NfSetEntry(
                name="cdn",
                hosts=["api.example.com"],
                backend="resolver",
                dns_servers=["198.51.100.53"],
                refresh=300,
            ),
            NfSetEntry(
                name="edge",
                hosts=["/var/lib/lists/edge.txt"],
                backend="ip-list-plain",
                inotify=True,
            ),
            NfSetEntry(
                name="blocklist",
                hosts=["https://example.org/prefixes.txt"],
                backend="ip-list",
            ),
        ]
        for e in entries:
            reg.entries.append(e)
            reg.set_names.add(e.name)
        return reg

    def test_payload_round_trip_lossless(self):
        """nfset_registry_to_payload → payload_to_nfset_registry is lossless."""
        reg = self._build_registry()
        payload = nfset_registry_to_payload(reg)
        reg2 = payload_to_nfset_registry(payload)

        assert len(reg2.entries) == len(reg.entries)
        for orig, restored in zip(reg.entries, reg2.entries):
            assert restored.name == orig.name
            assert restored.hosts == orig.hosts
            assert restored.backend == orig.backend
            assert restored.refresh == orig.refresh
            assert restored.inotify == orig.inotify
            assert restored.dns_servers == orig.dns_servers

    def test_nfsets_manager_dns_registries_split(self):
        """NfSetsManager splits dnstap entries into DnsSetRegistry."""
        from shorewalld.nfsets_manager import NfSetsManager

        reg = self._build_registry()
        payload = nfset_registry_to_payload(reg)
        mgr = NfSetsManager(payload)

        dns_reg, dnsr_reg = mgr.dns_registries()
        # dnstap hosts → dns_reg
        assert "cdn.example.com" in dns_reg.specs
        assert "static.example.org" in dns_reg.specs
        # resolver host → dnsr_reg
        assert "api.example.com" in dnsr_reg.groups

    def test_nfsets_manager_dns_set_name_is_base(self):
        """DnsSetSpec.set_name in NfSetsManager output is a base name (no _v4/_v6)."""
        from shorewalld.nfsets_manager import NfSetsManager

        reg = NfSetRegistry()
        reg.entries.append(NfSetEntry(
            name="web",
            hosts=["cdn.example.com"],
            backend="dnstap",
        ))
        reg.set_names.add("web")
        payload = nfset_registry_to_payload(reg)
        mgr = NfSetsManager(payload)
        dns_reg, _ = mgr.dns_registries()

        spec = dns_reg.specs.get("cdn.example.com")
        assert spec is not None
        assert spec.set_name is not None
        assert not spec.set_name.endswith("_v4"), "base name must not have _v4"
        assert not spec.set_name.endswith("_v6"), "base name must not have _v6"

    def test_nfsets_manager_iplist_configs_split(self):
        """NfSetsManager splits ip-list entries into IpListConfig objects."""
        from shorewalld.nfsets_manager import NfSetsManager

        reg = self._build_registry()
        payload = nfset_registry_to_payload(reg)
        mgr = NfSetsManager(payload)

        iplist_cfgs = mgr.iplist_configs()
        assert len(iplist_cfgs) == 1
        cfg = iplist_cfgs[0]
        assert cfg.name == "nfset_blocklist"
        assert cfg.set_v4 == nfset_to_set_name("blocklist", "v4")
        assert cfg.set_v6 == nfset_to_set_name("blocklist", "v6")

    def test_nfsets_manager_plain_list_configs_split(self):
        """NfSetsManager splits ip-list-plain entries into PlainListConfig objects."""
        from shorewalld.nfsets_manager import NfSetsManager

        reg = self._build_registry()
        payload = nfset_registry_to_payload(reg)
        mgr = NfSetsManager(payload)

        plain_cfgs = mgr.plain_list_configs()
        assert len(plain_cfgs) == 1
        cfg = plain_cfgs[0]
        assert cfg.name == "nfset_edge"
        assert cfg.source == "/var/lib/lists/edge.txt"
        assert cfg.inotify is True
        assert cfg.set_v4 == nfset_to_set_name("edge", "v4")
        assert cfg.set_v6 == nfset_to_set_name("edge", "v6")

    def test_full_wire_end_to_end(self):
        """Compiler output → payload → NfSetsManager → correct backend splits."""
        from shorewalld.nfsets_manager import NfSetsManager

        cfg = _minimal_config(
            nfset_rows=[
                ("web", "cdn.example.com", "dnstap"),
                ("cdn", "api.example.org", "resolver"),
                ("edge", "/var/lib/lists/edge.txt", "ip-list-plain"),
            ]
        )
        ir = build_ir(cfg)
        # Simulate payload serialization as done by shorewall-nft runtime/cli.py
        payload = nfset_registry_to_payload(ir.nfset_registry)
        mgr = NfSetsManager(payload)

        dns_reg, dnsr_reg = mgr.dns_registries()
        plain_cfgs = mgr.plain_list_configs()

        # dnstap host landed in dns_reg
        assert "cdn.example.com" in dns_reg.specs
        # resolver host landed in dnsr_reg
        assert "api.example.org" in dnsr_reg.groups
        # plain list config for edge
        assert len(plain_cfgs) == 1
        assert plain_cfgs[0].source == "/var/lib/lists/edge.txt"
