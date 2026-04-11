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

    def test_legacy_offload_boolean(self):
        out = _emit(FLOWTABLE="eth0", FLOWTABLE_OFFLOAD="Yes")
        assert "flags offload;" in out

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
        assert "ct state new ct mark set iifname map" in out

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
        assert "dnat ip to" not in out
