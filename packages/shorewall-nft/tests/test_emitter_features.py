"""Emitter feature tests — the four nft-native knobs shipped in 1.1.

All four features are opt-in via shorewall.conf settings, so each test
loads the minimal fixture, patches the settings dict on the parsed
config, builds the IR, and asserts the emitted nft script has the
expected stanzas. No kernel calls here — this is a string-level
regression suite that runs in unit-test time.
"""

from __future__ import annotations

from pathlib import Path

from shorewall_nft.compiler.ir import build_ir
from shorewall_nft.config.parser import load_config
from shorewall_nft.nft.emitter import emit_nft

MINIMAL_DIR = Path(__file__).parent / "configs" / "minimal"


def _emit(**settings: str) -> str:
    """Load minimal config, apply settings overrides, emit nft script."""
    config = load_config(MINIMAL_DIR)
    config.settings.update(settings)
    ir = build_ir(config)
    return emit_nft(ir)


# ──────────────────────────────────────────────────────────────────────
# FLOWTABLE
# ──────────────────────────────────────────────────────────────────────


class TestFlowtable:
    def test_disabled_by_default(self):
        out = _emit()
        assert "flowtable ft" not in out
        assert "flow add @ft" not in out

    def test_device_list(self):
        out = _emit(FLOWTABLE="eth0,eth1")
        assert "flowtable ft {" in out
        assert '"eth0"' in out
        assert '"eth1"' in out
        # and the forward chain picks up the flow add
        assert "meta l4proto { tcp, udp } flow add @ft" in out

    def test_device_whitespace(self):
        out = _emit(FLOWTABLE="eth0 eth1")
        assert '"eth0"' in out
        assert '"eth1"' in out

    def test_auto_picks_all_interfaces(self):
        out = _emit(FLOWTABLE="auto")
        assert '"eth0"' in out
        assert '"eth1"' in out

    def test_disabled_explicit(self):
        for val in ("", "No", "no", "0", "false"):
            out = _emit(FLOWTABLE=val)
            assert "flowtable ft" not in out, f"{val!r} should disable flowtable"

    def test_priority_keyword(self):
        out = _emit(FLOWTABLE="eth0", FLOWTABLE_PRIORITY="mangle")
        assert "hook ingress priority -150" in out

    def test_priority_integer(self):
        out = _emit(FLOWTABLE="eth0", FLOWTABLE_PRIORITY="-300")
        assert "hook ingress priority -300" in out

    def test_priority_default_filter(self):
        out = _emit(FLOWTABLE="eth0")
        assert "hook ingress priority 0" in out

    def test_flags_offload(self):
        out = _emit(FLOWTABLE="eth0", FLOWTABLE_FLAGS="offload")
        assert "flags offload;" in out
        assert "hw-tc-offload" in out

    def test_legacy_offload_boolean(self):
        out = _emit(FLOWTABLE="eth0", FLOWTABLE_OFFLOAD="Yes")
        assert "flags offload;" in out
        assert "hw-tc-offload" in out

    def test_counter_stanza(self):
        out = _emit(FLOWTABLE="eth0", FLOWTABLE_COUNTER="Yes")
        assert "\t\tcounter" in out

    def test_offload_dropped_when_probe_fails(self):
        """Capability probe says no offload → flag is stripped + warning."""
        from shorewall_nft.nft.capabilities import NftCapabilities
        caps = NftCapabilities()
        caps.has_flowtable = True
        caps.has_flowtable_offload = False

        config = load_config(MINIMAL_DIR)
        config.settings.update({"FLOWTABLE": "eth0", "FLOWTABLE_FLAGS": "offload"})
        ir = build_ir(config)
        out = emit_nft(ir, capabilities=caps)
        assert "flags offload" not in out
        assert "hw-tc-offload" not in out
        assert "FLOWTABLE_FLAGS=offload dropped" in out


# ──────────────────────────────────────────────────────────────────────
# OPTIMIZE_VMAP — vmap dispatch
# ──────────────────────────────────────────────────────────────────────


class TestVmapDispatch:
    def test_disabled_by_default(self):
        out = _emit()
        # Default is the cascade: explicit iifname + oifname per pair.
        assert "iifname . oifname vmap" not in out
        assert 'iifname "eth0"' in out  # cascade still present

    def test_enabled_forward(self):
        out = _emit(OPTIMIZE_VMAP="Yes")
        # Forward chain should use a concat-key vmap
        assert "iifname . oifname vmap" in out

    def test_enabled_input_vmap(self):
        out = _emit(OPTIMIZE_VMAP="Yes")
        # Input chain should use iifname vmap (single key, not concat)
        assert "iifname vmap {" in out

    def test_vmap_has_jump_entries(self):
        out = _emit(OPTIMIZE_VMAP="Yes")
        # Net-to-loc pair and loc-to-net pair should appear as vmap entries
        assert 'jump net-loc' in out or 'jump loc-net' in out


# ──────────────────────────────────────────────────────────────────────
# CT_ZONE_TAG — ct mark zone tagging
# ──────────────────────────────────────────────────────────────────────


class TestCtZoneTag:
    def test_disabled_by_default(self):
        out = _emit()
        assert "sw_zone_tag" not in out

    def test_enabled_emits_prerouting_chain(self):
        out = _emit(CT_ZONE_TAG="Yes")
        assert "chain sw_zone_tag {" in out
        assert "type filter hook prerouting priority mangle" in out
        # With the default 0xff mask nft rejects `ct mark and X or MAP`
        # (rhs of `or` must be a constant), so we emit one rule per
        # iface with a per-iface constant instead.
        assert 'iifname "eth0" ct mark set ct mark and 0xffffff00 or ' in out
        assert 'iifname "eth1" ct mark set ct mark and 0xffffff00 or ' in out

    def test_zone_marks_per_interface(self):
        out = _emit(CT_ZONE_TAG="Yes")
        # Both interfaces from the minimal config should get a mark
        assert '"eth0"' in out
        assert '"eth1"' in out

    def test_firewall_zone_excluded(self):
        """The firewall zone has no incoming interface, so no mark."""
        out = _emit(CT_ZONE_TAG="Yes")
        # There's no interface named "fw" that would get tagged
        lines_in_tag_chain = [
            ln for ln in out.splitlines()
            if "sw_zone_tag" in out and ":" in ln and "0x" in ln
        ]
        # Every emitted entry must be for a real iifname, not "fw"
        for ln in lines_in_tag_chain:
            assert '"fw"' not in ln

    def test_mask_default_is_0xff(self):
        out = _emit(CT_ZONE_TAG="Yes")
        # Default mask 0xff keeps the upper 24 bits of ct mark untouched
        assert "ct mark and 0xffffff00 or " in out

    def test_mask_custom_16bit(self):
        out = _emit(CT_ZONE_TAG="Yes", CT_ZONE_TAG_MASK="0xffff")
        # Custom 16-bit mask — upper 16 bits preserved
        assert "ct mark and 0xffff0000 or " in out

    def test_mask_full_no_bitwise(self):
        """A 32-bit-wide mask means we overwrite ct mark entirely."""
        out = _emit(CT_ZONE_TAG="Yes", CT_ZONE_TAG_MASK="0xffffffff")
        # No bitwise clamp, just a direct set
        assert "ct state new ct mark set iifname map" in out
        assert "ct mark and" not in out.split("sw_zone_tag")[1].split("}")[0]

    def test_mask_invalid_falls_back_with_warning(self):
        out = _emit(CT_ZONE_TAG="Yes", CT_ZONE_TAG_MASK="garbage")
        assert "CT_ZONE_TAG_MASK" in out and "0xff" in out
        # Warning comment present
        assert "WARNING: CT_ZONE_TAG_MASK" in out


# ──────────────────────────────────────────────────────────────────────
# conntrackd fragment generator
# ──────────────────────────────────────────────────────────────────────


class TestConntrackdFragment:
    def _config(self, **settings: str):
        config = load_config(MINIMAL_DIR)
        config.settings.update(settings)
        return config

    def test_default_renders(self):
        from shorewall_nft.runtime.conntrackd import generate_conntrackd_fragment
        out = generate_conntrackd_fragment(self._config())
        assert "Sync {" in out
        assert "Mode FTFW" in out
        assert "Multicast Default" in out
        assert "General {" in out

    def test_sync_iface_override(self):
        from shorewall_nft.runtime.conntrackd import generate_conntrackd_fragment
        out = generate_conntrackd_fragment(
            self._config(), sync_iface="bond9")
        assert "Interface bond9" in out

    def test_ct_zone_tag_emits_mark_filter(self):
        """When CT_ZONE_TAG is on, the sync filter narrows to the mask."""
        from shorewall_nft.runtime.conntrackd import generate_conntrackd_fragment
        out = generate_conntrackd_fragment(
            self._config(CT_ZONE_TAG="Yes", CT_ZONE_TAG_MASK="0x0f"))
        assert "Mark {" in out
        assert "Value 0x0000000f" in out
        assert "Mask 0x0000000f" in out

    def test_no_mark_filter_without_ct_tag(self):
        from shorewall_nft.runtime.conntrackd import generate_conntrackd_fragment
        out = generate_conntrackd_fragment(self._config())
        # Filter block exists but no Mark stanza
        assert "Protocol Accept" in out
        assert "Mark {" not in out


# ──────────────────────────────────────────────────────────────────────
# OPTIMIZE_DNAT_MAP — concat-map DNAT
# ──────────────────────────────────────────────────────────────────────


class TestDnatConcatMap:
    """DNAT rules are typically sparse in the minimal fixture, so these
    tests synthesise a prerouting NAT chain in-memory and re-run the
    emitter on it.
    """

    def _ir_with_dnat_rules(self):
        from shorewall_nft.compiler.ir import (
            Chain,
            ChainType,
            Hook,
            Match,
            Rule,
            Verdict,
        )

        config = load_config(MINIMAL_DIR)
        ir = build_ir(config)

        # Build a synthetic NAT prerouting chain with 3 DNAT rules
        pre = Chain(
            name="prerouting",
            chain_type=ChainType.NAT,
            hook=Hook.PREROUTING,
            priority=-100,
        )
        for daddr, dport, tip, tport in [
            ("203.0.113.10", "80",  "192.0.2.10", "80"),
            ("203.0.113.10", "443", "192.0.2.10", "443"),
            ("203.0.113.20", "25",  "192.0.2.20", "25"),
        ]:
            pre.rules.append(Rule(
                matches=[
                    Match(field="ip daddr", value=daddr),
                    Match(field="meta l4proto", value="tcp"),
                    Match(field="tcp dport", value=dport),
                ],
                verdict=Verdict.JUMP,
                verdict_args=f"dnat:{tip}:{tport}",
            ))
        ir.chains["prerouting"] = pre
        return ir

    def test_disabled_by_default(self):
        ir = self._ir_with_dnat_rules()
        out = emit_nft(ir)
        assert "dnat ip to ip daddr . tcp dport map" not in out
        # Individual dnat lines instead
        assert "dnat to 192.0.2.10:80" in out

    def test_enabled_collapses_rules(self):
        ir = self._ir_with_dnat_rules()
        ir.settings["OPTIMIZE_DNAT_MAP"] = "Yes"
        out = emit_nft(ir)
        assert "DNAT concat-map" in out
        assert "dnat ip to ip daddr . tcp dport map {" in out
        # All three rules collapsed
        assert "203.0.113.10 . 80 : 192.0.2.10 . 80" in out
        assert "203.0.113.10 . 443 : 192.0.2.10 . 443" in out
        assert "203.0.113.20 . 25 : 192.0.2.20 . 25" in out

    def test_singleton_bucket_not_collapsed(self):
        """A saddr+proto bucket with exactly one rule is passed through."""
        from shorewall_nft.compiler.ir import (
            Chain,
            ChainType,
            Hook,
            Match,
            Rule,
            Verdict,
        )

        config = load_config(MINIMAL_DIR)
        ir = build_ir(config)
        ir.settings["OPTIMIZE_DNAT_MAP"] = "Yes"

        pre = Chain(
            name="prerouting",
            chain_type=ChainType.NAT,
            hook=Hook.PREROUTING,
            priority=-100,
        )
        pre.rules.append(Rule(
            matches=[
                Match(field="ip daddr", value="203.0.113.30"),
                Match(field="meta l4proto", value="udp"),
                Match(field="udp dport", value="53"),
            ],
            verdict=Verdict.JUMP,
            verdict_args="dnat:192.0.2.30:53",
        ))
        ir.chains["prerouting"] = pre
        out = emit_nft(ir)
        # Single rule should NOT be wrapped in a map
        assert "dnat ip to ip daddr" not in out


# ──────────────────────────────────────────────────────────────────────
# Combined — all four features at once
# ──────────────────────────────────────────────────────────────────────


class TestSimulateHelpers:
    """Unit tests for simulate helpers that don't need netns privileges."""

    def test_slave_ns_naming(self):
        from shorewall_nft.verify.simulate import slave_ns
        assert slave_ns("net") == "sw-z-net"
        assert slave_ns("host") == "sw-z-host"

    def test_slave_ns_caps_zone_name(self):
        from shorewall_nft.verify.simulate import slave_ns
        # netns names cap at IFNAMSIZ; long zone names get truncated
        # so the full ns name fits.
        assert len(slave_ns("averyverylongzonename")) <= 16

    def test_split_chain_zones_basic(self):
        from shorewall_nft.verify.simulate import _split_chain_zones
        assert _split_chain_zones("net2host") == ("net", "host")
        assert _split_chain_zones("adm2fw") == ("adm", "fw")

    def test_split_chain_zones_base_chains_none(self):
        from shorewall_nft.verify.simulate import _split_chain_zones
        assert _split_chain_zones("INPUT") == (None, None)
        assert _split_chain_zones("FORWARD") == (None, None)
        assert _split_chain_zones("PREROUTING") == (None, None)

    def test_split_chain_zones_helper_suffix(self):
        from shorewall_nft.verify.simulate import _split_chain_zones
        # Shorewall emits names like "net2adm_frwd" for helper chains;
        # the suffix gets stripped.
        assert _split_chain_zones("net2adm_frwd") == ("net", "adm")
        assert _split_chain_zones("net2adm_dnat") == ("net", "adm")
        assert _split_chain_zones("adm2host_input") == ("adm", "host")

    def test_zone_subnet_deterministic(self):
        from shorewall_nft.verify.simulate import SimTopology
        # SimTopology() constructor requires no root for in-memory cache
        topo = SimTopology.__new__(SimTopology)
        topo.zones = {"net": "bond1"}
        topo._zone_subnets = {}
        a = topo._zone_subnet("net", "src")
        b = topo._zone_subnet("net", "src")
        assert a == b
        # Different side gets different /30
        c = topo._zone_subnet("net", "dst")
        assert a != c
        assert a[0].startswith("10.201.") or a[1].startswith("10.201.")
        assert c[0].startswith("10.202.") or c[1].startswith("10.202.")

    def test_zone_subnet_different_zones_different_slots(self):
        from shorewall_nft.verify.simulate import SimTopology
        topo = SimTopology.__new__(SimTopology)
        topo.zones = {}
        topo._zone_subnets = {}
        net_subnet = topo._zone_subnet("net", "src")
        host_subnet = topo._zone_subnet("host", "src")
        adm_subnet = topo._zone_subnet("adm", "src")
        assert len({net_subnet, host_subnet, adm_subnet}) == 3


class TestDeriveTestsAllZones:
    """derive_tests_all_zones should annotate with src_zone/dst_zone."""

    def test_walks_zone_pair_chains(self, tmp_path):
        from shorewall_nft.verify.simulate import derive_tests_all_zones
        dump = tmp_path / "ipt.txt"
        dump.write_text(
            "*filter\n"
            ":INPUT ACCEPT [0:0]\n"
            ":FORWARD ACCEPT [0:0]\n"
            ":OUTPUT ACCEPT [0:0]\n"
            ":net2host - [0:0]\n"
            ":adm2host - [0:0]\n"
            "-A net2host -s 10.0.0.0/24 -d 203.0.113.5/32 -p tcp -m tcp --dport 80 -j ACCEPT\n"
            "-A net2host -d 203.0.113.5/32 -p tcp -m tcp --dport 443 -j DROP\n"
            "-A adm2host -s 10.1.0.5/32 -d 203.0.113.6/32 -p udp -m udp --dport 53 -j ACCEPT\n"
            "COMMIT\n"
        )
        cases = derive_tests_all_zones(
            dump, zones={"net", "host", "adm"},
            max_tests=10, family=4)
        assert len(cases) == 3
        by_chain = {(c.src_zone, c.dst_zone, c.proto, c.port): c for c in cases}
        assert ("net", "host", "tcp", 80) in by_chain
        assert ("net", "host", "tcp", 443) in by_chain
        assert ("adm", "host", "udp", 53) in by_chain

    def test_skips_unknown_zones(self, tmp_path):
        """Chains whose zones aren't in the supplied set are skipped."""
        from shorewall_nft.verify.simulate import derive_tests_all_zones
        dump = tmp_path / "ipt.txt"
        dump.write_text(
            "*filter\n"
            ":INPUT ACCEPT [0:0]\n"
            ":FORWARD ACCEPT [0:0]\n"
            ":OUTPUT ACCEPT [0:0]\n"
            ":secret2host - [0:0]\n"
            "-A secret2host -d 203.0.113.5/32 -p tcp -m tcp --dport 80 -j ACCEPT\n"
            "COMMIT\n"
        )
        cases = derive_tests_all_zones(
            dump, zones={"net", "host"},
            max_tests=10, family=4)
        # secret isn't in the zones set → rule is filtered out
        assert len(cases) == 0


class TestAllFeaturesTogether:
    def test_all_four_enabled(self):
        out = _emit(
            FLOWTABLE="eth0,eth1",
            FLOWTABLE_COUNTER="Yes",
            OPTIMIZE_VMAP="Yes",
            CT_ZONE_TAG="Yes",
            OPTIMIZE_DNAT_MAP="Yes",
        )
        assert "flowtable ft {" in out
        assert "flow add @ft" in out
        assert "iifname . oifname vmap" in out
        assert "chain sw_zone_tag {" in out
        # DNAT map only fires if there are DNAT rules — minimal config
        # has none, so the absence here is expected.


# ──────────────────────────────────────────────────────────────────────
# routestopped → standalone shorewall_stopped table
# ──────────────────────────────────────────────────────────────────────


class TestRoutestopped:
    def _build_ir_with_routestopped(self, columns_list):
        from shorewall_nft.config.parser import ConfigLine, load_config
        config = load_config(MINIMAL_DIR)
        config.routestopped = [
            ConfigLine(columns=cols, file="routestopped", lineno=i)
            for i, cols in enumerate(columns_list)
        ]
        return build_ir(config)

    def test_no_routestopped_emits_nothing(self):
        from shorewall_nft.nft.emitter import emit_stopped_nft
        config = load_config(MINIMAL_DIR)
        ir = build_ir(config)
        assert emit_stopped_nft(ir) == ""
        # Main emitter must not leak stopped chains either.
        out = emit_nft(ir)
        assert "stopped-input" not in out
        assert "shorewall_stopped" not in out

    def test_emits_standalone_table(self):
        from shorewall_nft.nft.emitter import emit_stopped_nft
        ir = self._build_ir_with_routestopped([
            ["eth0", "192.168.1.0/24", "-", "tcp", "22"],
            ["eth1", "-", "-", "-", "-"],
        ])
        out = emit_stopped_nft(ir)
        assert "table inet shorewall_stopped {" in out
        assert "chain stopped-input {" in out
        assert "chain stopped-output {" in out
        assert "chain stopped-forward {" in out
        assert "type filter hook input priority 0; policy drop;" in out
        assert "type filter hook forward priority 0; policy drop;" in out
        assert "iifname lo accept" in out
        assert "ct state { established, related } accept" in out
        assert "iifname eth0 ip saddr 192.168.1.0/24" in out
        assert "iifname eth1 accept" in out

    def test_main_table_excludes_stopped_chains(self):
        ir = self._build_ir_with_routestopped([
            ["eth0", "-", "-", "-", "-"],
        ])
        out = emit_nft(ir)
        assert "stopped-input" not in out
        assert "stopped-output" not in out
        assert "stopped-forward" not in out
        assert "shorewall_stopped" not in out

    def test_option_source_only_emits_input(self):
        from shorewall_nft.nft.emitter import emit_stopped_nft
        ir = self._build_ir_with_routestopped([
            ["eth0", "10.0.0.1", "source", "tcp", "22"],
        ])
        out = emit_stopped_nft(ir)
        # input rule present
        assert "iifname eth0 ip saddr 10.0.0.1" in out
        # but no matching output rule for that host
        assert "oifname eth0 ip daddr 10.0.0.1" not in out

    def test_option_dest_only_emits_output(self):
        from shorewall_nft.nft.emitter import emit_stopped_nft
        ir = self._build_ir_with_routestopped([
            ["eth0", "10.0.0.1", "dest", "tcp", "22"],
        ])
        out = emit_stopped_nft(ir)
        assert "oifname eth0 ip daddr 10.0.0.1" in out
        assert "iifname eth0 ip saddr 10.0.0.1" not in out

    def test_option_routeback_adds_forward_rule(self):
        from shorewall_nft.nft.emitter import emit_stopped_nft
        ir = self._build_ir_with_routestopped([
            ["eth0", "10.0.0.1", "routeback", "-", "-"],
        ])
        out = emit_stopped_nft(ir)
        assert "iifname eth0 oifname eth0" in out

    def test_option_notrack_creates_raw_chain(self):
        from shorewall_nft.nft.emitter import emit_stopped_nft
        ir = self._build_ir_with_routestopped([
            ["eth0", "10.0.0.1", "notrack", "tcp", "22"],
        ])
        out = emit_stopped_nft(ir)
        assert "chain stopped-raw-prerouting {" in out
        assert "type filter hook prerouting priority -300;" in out
        assert " notrack" in out

    def test_routestopped_open_setting_collapses_to_wildcard(self):
        from shorewall_nft.config.parser import ConfigLine, load_config
        from shorewall_nft.nft.emitter import emit_stopped_nft
        config = load_config(MINIMAL_DIR)
        config.settings["ROUTESTOPPED_OPEN"] = "Yes"
        config.routestopped = [
            ConfigLine(columns=["eth0", "10.0.0.1", "-", "tcp", "22"],
                       file="routestopped", lineno=0),
        ]
        ir = build_ir(config)
        out = emit_stopped_nft(ir)
        # Wildcard rule replaces host/proto filtering on this iface.
        lines = [l for l in out.splitlines()
                 if "iifname eth0" in l and "accept" in l]
        # The single open rule must not carry the host or port match.
        assert any("ip saddr" not in l and "tcp dport" not in l
                   for l in lines), out

    def test_ipv6_host_uses_ip6_match(self):
        from shorewall_nft.nft.emitter import emit_stopped_nft
        ir = self._build_ir_with_routestopped([
            ["eth0", "2001:db8::1", "-", "tcp", "22"],
        ])
        out = emit_stopped_nft(ir)
        assert "ip6 saddr 2001:db8::1" in out
        assert "ip6 daddr 2001:db8::1" in out

    def test_sport_column_emitted(self):
        from shorewall_nft.nft.emitter import emit_stopped_nft
        ir = self._build_ir_with_routestopped([
            ["eth0", "10.0.0.1", "-", "tcp", "22", "1024"],
        ])
        out = emit_stopped_nft(ir)
        assert "tcp dport 22" in out
        assert "tcp sport 1024" in out

    def test_critical_option_accepted_silently(self):
        from shorewall_nft.nft.emitter import emit_stopped_nft
        # Should not raise even though `critical` is currently a no-op.
        ir = self._build_ir_with_routestopped([
            ["eth0", "10.0.0.1", "critical", "-", "-"],
        ])
        out = emit_stopped_nft(ir)
        assert "iifname eth0 ip saddr 10.0.0.1" in out


# ──────────────────────────────────────────────────────────────────────
# stoppedrules — modern routestopped successor
# ──────────────────────────────────────────────────────────────────────


class TestStoppedrules:
    def _build_ir_with_stoppedrules(self, columns_list):
        from shorewall_nft.config.parser import ConfigLine, load_config
        config = load_config(MINIMAL_DIR)
        config.stoppedrules = [
            ConfigLine(columns=cols, file="stoppedrules", lineno=i)
            for i, cols in enumerate(columns_list)
        ]
        return build_ir(config)

    def test_accept_to_fw_lands_in_input(self):
        from shorewall_nft.nft.emitter import emit_stopped_nft
        ir = self._build_ir_with_stoppedrules([
            ["ACCEPT", "net:10.0.0.5", "$FW", "tcp", "22"],
        ])
        out = emit_stopped_nft(ir)
        assert "chain stopped-input {" in out
        assert "ip saddr 10.0.0.5" in out
        assert "tcp dport 22 accept" in out

    def test_accept_from_fw_lands_in_output(self):
        from shorewall_nft.nft.emitter import emit_stopped_nft
        ir = self._build_ir_with_stoppedrules([
            ["ACCEPT", "$FW", "net:10.0.0.5", "udp", "53"],
        ])
        out = emit_stopped_nft(ir)
        assert "chain stopped-output {" in out
        assert "ip daddr 10.0.0.5" in out
        assert "udp dport 53 accept" in out

    def test_accept_transit_lands_in_forward(self):
        from shorewall_nft.nft.emitter import emit_stopped_nft
        ir = self._build_ir_with_stoppedrules([
            ["ACCEPT", "net", "loc:10.1.1.10", "tcp", "443"],
        ])
        out = emit_stopped_nft(ir)
        assert "chain stopped-forward {" in out
        assert "ip daddr 10.1.1.10" in out

    def test_notrack_target_routes_to_raw_chain(self):
        from shorewall_nft.nft.emitter import emit_stopped_nft
        ir = self._build_ir_with_stoppedrules([
            ["NOTRACK", "net:10.0.0.5", "$FW", "udp", "500"],
        ])
        out = emit_stopped_nft(ir)
        assert "chain stopped-raw-prerouting {" in out
        assert " notrack" in out

    def test_drop_explicit(self):
        from shorewall_nft.nft.emitter import emit_stopped_nft
        ir = self._build_ir_with_stoppedrules([
            ["DROP", "net:1.2.3.4", "$FW", "tcp", "23"],
        ])
        out = emit_stopped_nft(ir)
        assert "ip saddr 1.2.3.4" in out
        assert "tcp dport 23 drop" in out

    def test_unknown_target_warns_and_skips(self):
        import warnings

        from shorewall_nft.nft.emitter import emit_stopped_nft
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            ir = self._build_ir_with_stoppedrules([
                ["DNAT", "net", "loc:10.0.0.5", "tcp", "80"],
            ])
            assert any("unsupported target" in str(x.message) for x in w)
        out = emit_stopped_nft(ir)
        assert "ip daddr 10.0.0.5" not in out


# ──────────────────────────────────────────────────────────────────────
# rawnat — raw-table actions, runs pre-conntrack
# ──────────────────────────────────────────────────────────────────────


class TestRawnat:
    def _ir(self, columns_list):
        from shorewall_nft.config.parser import ConfigLine, load_config
        config = load_config(MINIMAL_DIR)
        config.rawnat = [
            ConfigLine(columns=cols, file="rawnat", lineno=i)
            for i, cols in enumerate(columns_list)
        ]
        return build_ir(config)

    def test_notrack_action_lands_in_raw_prerouting(self):
        ir = self._ir([["NOTRACK", "net", "loc", "udp", "500"]])
        out = emit_nft(ir)
        assert "chain raw-prerouting {" in out
        assert "type filter hook prerouting priority -300;" in out
        # nftables emits "notrack" as the verdict, no jump form
        assert "udp dport 500" in out
        assert " notrack" in out

    def test_accept_action(self):
        ir = self._ir([["ACCEPT", "net:1.2.3.4", "all", "tcp", "22"]])
        out = emit_nft(ir)
        assert "ip saddr 1.2.3.4" in out
        assert "tcp dport 22 accept" in out

    def test_drop_action(self):
        ir = self._ir([["DROP", "net:1.2.3.4", "all", "udp", "53"]])
        out = emit_nft(ir)
        assert "ip saddr 1.2.3.4" in out
        assert "udp dport 53 drop" in out

    def test_fw_source_routes_to_raw_output(self):
        # $FW source → raw-output, not raw-prerouting
        ir = self._ir([["NOTRACK", "$FW", "net:1.2.3.4", "udp", "53"]])
        out = emit_nft(ir)
        assert "chain raw-output {" in out
        assert "type filter hook output priority -300;" in out

    def test_unknown_action_warns(self):
        import warnings
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            ir = self._ir([["DNAT", "net:1.2.3.4", "all", "tcp", "80"]])
            assert any("unsupported action" in str(x.message) for x in w)
        out = emit_nft(ir)
        assert "dnat ip to" not in out


# ──────────────────────────────────────────────────────────────────────
# arprules — separate arp filter table
# ──────────────────────────────────────────────────────────────────────


class TestArprules:
    def _ir(self, columns_list):
        from shorewall_nft.config.parser import ConfigLine, load_config
        config = load_config(MINIMAL_DIR)
        config.arprules = [
            ConfigLine(columns=cols, file="arprules", lineno=i)
            for i, cols in enumerate(columns_list)
        ]
        return build_ir(config)

    def test_emits_arp_table(self):
        ir = self._ir([["DROP", "10.0.0.5", "-", "eth0", "-"]])
        out = emit_nft(ir)
        assert "table arp filter {" in out
        assert "chain arp-input {" in out
        assert "type filter hook input priority 0; policy accept;" in out
        assert "arp saddr ip 10.0.0.5" in out
        assert "drop" in out

    def test_no_arp_table_when_no_arprules(self):
        from shorewall_nft.config.parser import load_config
        config = load_config(MINIMAL_DIR)
        ir = build_ir(config)
        out = emit_nft(ir)
        assert "table arp filter" not in out

    def test_mac_match(self):
        ir = self._ir([["DROP", "-", "-", "eth0", "00-11-22-33-44-55"]])
        out = emit_nft(ir)
        assert "arp saddr ether 00:11:22:33:44:55" in out

    def test_dest_target_match(self):
        ir = self._ir([["ACCEPT", "-", "10.0.0.1", "eth0", "-"]])
        out = emit_nft(ir)
        assert "arp daddr ip 10.0.0.1" in out
        assert "accept" in out

    def test_unknown_action_warns(self):
        import warnings
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            self._ir([["FOO", "10.0.0.5", "-", "eth0", "-"]])
            assert any("unsupported action" in str(x.message) for x in w)


# ──────────────────────────────────────────────────────────────────────
# nfacct — named counter declarations
# ──────────────────────────────────────────────────────────────────────


class TestNfacct:
    def _ir(self, columns_list):
        from shorewall_nft.config.parser import ConfigLine, load_config
        config = load_config(MINIMAL_DIR)
        config.nfacct = [
            ConfigLine(columns=cols, file="nfacct", lineno=i)
            for i, cols in enumerate(columns_list)
        ]
        return build_ir(config)

    def test_emits_named_counter(self):
        ir = self._ir([["http_in"]])
        out = emit_nft(ir)
        assert "counter http_in {" in out

    def test_initial_packet_byte_values(self):
        ir = self._ir([["seeded", "100", "5000"]])
        out = emit_nft(ir)
        assert "counter seeded { packets 100 bytes 5000 }" in out

    def test_no_counter_block_when_no_nfacct(self):
        from shorewall_nft.config.parser import load_config
        config = load_config(MINIMAL_DIR)
        ir = build_ir(config)
        out = emit_nft(ir)
        # The "Named accounting counters" comment is the marker for
        # the nfacct block; absence proves nothing was emitted.
        assert "Named accounting counters" not in out


# ──────────────────────────────────────────────────────────────────────
# scfilter — source CIDR sanity filter
# ──────────────────────────────────────────────────────────────────────


class TestScfilter:
    def _ir(self, columns_list):
        from shorewall_nft.config.parser import ConfigLine, load_config
        config = load_config(MINIMAL_DIR)
        config.scfilter = [
            ConfigLine(columns=cols, file="scfilter", lineno=i)
            for i, cols in enumerate(columns_list)
        ]
        return build_ir(config)

    def test_v4_negated_set_drop(self):
        ir = self._ir([["eth0", "10.0.0.0/8,192.168.0.0/16"]])
        out = emit_nft(ir)
        assert ("iifname eth0 ip saddr != "
                "{ 10.0.0.0/8, 192.168.0.0/16 } drop") in out

    def test_v6_negated_set_drop(self):
        ir = self._ir([["eth0", "2001:db8::/32"]])
        out = emit_nft(ir)
        assert "iifname eth0 ip6 saddr != { 2001:db8::/32 } drop" in out


# ──────────────────────────────────────────────────────────────────────
# ecn — clear ECN bits per iface/host
# ──────────────────────────────────────────────────────────────────────


class TestEcn:
    def _ir(self, columns_list):
        from shorewall_nft.config.parser import ConfigLine, load_config
        config = load_config(MINIMAL_DIR)
        config.ecn = [
            ConfigLine(columns=cols, file="ecn", lineno=i)
            for i, cols in enumerate(columns_list)
        ]
        return build_ir(config)

    def test_iface_only(self):
        ir = self._ir([["eth0"]])
        out = emit_nft(ir)
        assert "chain mangle-postrouting {" in out
        assert "oifname eth0 meta l4proto tcp ip ecn set not-ect" in out

    def test_iface_and_host(self):
        ir = self._ir([["eth0", "10.0.0.5"]])
        out = emit_nft(ir)
        assert ("oifname eth0 meta l4proto tcp ip daddr 10.0.0.5 "
                "ip ecn set not-ect") in out
