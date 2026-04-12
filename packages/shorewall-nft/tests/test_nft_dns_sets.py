"""Unit tests for shorewall_nft.nft.dns_sets — the shared helper
that compiler and daemon both import for DNS-backed nft sets.
"""

from __future__ import annotations

from pathlib import Path

from shorewall_nft.nft.dns_sets import (
    DEFAULT_SET_SIZE,
    DEFAULT_TTL_CEIL,
    DEFAULT_TTL_FLOOR,
    MAX_SET_NAME_LEN,
    DnsSetRegistry,
    DnsSetSpec,
    canonical_qname,
    emit_dns_set_declarations,
    is_dns_token,
    is_valid_hostname,
    parse_dnsnames_file,
    qname_to_set_name,
    read_compiled_allowlist,
    write_compiled_allowlist,
)


class TestCanonicalQname:
    def test_lowercases_and_strips_trailing_dot(self):
        assert canonical_qname("Github.Com.") == "github.com"

    def test_no_op_on_already_canonical(self):
        assert canonical_qname("github.com") == "github.com"

    def test_trims_whitespace(self):
        assert canonical_qname("  github.com  ") == "github.com"


class TestIsDnsToken:
    def test_detects_dns_prefix(self):
        assert is_dns_token("dns:github.com") is True

    def test_rejects_other_prefixes(self):
        assert is_dns_token("net:github.com") is False
        assert is_dns_token("github.com") is False

    def test_rejects_empty_body(self):
        assert is_dns_token("dns:") is False


class TestIsValidHostname:
    def test_accepts_normal_domain(self):
        assert is_valid_hostname("github.com")
        assert is_valid_hostname("api.stripe.com")
        assert is_valid_hostname("a.b.c.d.e.f")

    def test_rejects_ipv4_literal(self):
        assert not is_valid_hostname("1.2.3.4")

    def test_rejects_ipv6_literal(self):
        assert not is_valid_hostname("2001:db8::1")

    def test_rejects_single_label(self):
        assert not is_valid_hostname("localhost")

    def test_rejects_empty_or_too_long(self):
        assert not is_valid_hostname("")
        assert not is_valid_hostname("a" * 254)

    def test_rejects_label_with_invalid_chars(self):
        assert not is_valid_hostname("foo!bar.com")
        assert not is_valid_hostname("foo bar.com")

    def test_rejects_label_starting_with_hyphen(self):
        assert not is_valid_hostname("-foo.com")

    def test_accepts_trailing_dot(self):
        assert is_valid_hostname("github.com.")


class TestQnameToSetName:
    def test_basic_dualstack_pair(self):
        assert qname_to_set_name("github.com", "v4") == "dns_github_com_v4"
        assert qname_to_set_name("github.com", "v6") == "dns_github_com_v6"

    def test_canonicalisation_is_applied(self):
        assert (qname_to_set_name("Github.Com.", "v4")
                == qname_to_set_name("github.com", "v4"))

    def test_hyphens_become_underscores(self):
        assert qname_to_set_name("api-cdn.example.net", "v4").startswith(
            "dns_api_cdn_example_net")

    def test_length_cap_with_hash_tail(self):
        long = "really.long.subdomain.example.com.test.cloud"
        name = qname_to_set_name(long, "v4")
        assert len(name) <= MAX_SET_NAME_LEN
        assert name.startswith("dns_")
        assert name.endswith("_v4")

    def test_long_names_stay_unique(self):
        a = qname_to_set_name("alpha." * 10 + "example.com", "v4")
        b = qname_to_set_name("beta." * 10 + "example.com", "v4")
        assert a != b
        assert len(a) <= MAX_SET_NAME_LEN
        assert len(b) <= MAX_SET_NAME_LEN

    def test_deterministic_across_calls(self):
        for _ in range(3):
            assert (qname_to_set_name("foo.example.org", "v4")
                    == "dns_foo_example_org_v4")

    def test_collapses_consecutive_separators(self):
        # Weird input that could happen from a wildcard
        name = qname_to_set_name("x..y..z.com", "v4")
        assert "__" not in name


class TestDnsSetRegistry:
    def test_add_from_rule_creates_default_spec(self):
        reg = DnsSetRegistry()
        spec = reg.add_from_rule("github.com")
        assert spec.qname == "github.com"
        assert spec.ttl_floor == DEFAULT_TTL_FLOOR
        assert spec.ttl_ceil == DEFAULT_TTL_CEIL
        assert spec.size == DEFAULT_SET_SIZE

    def test_add_from_rule_idempotent(self):
        reg = DnsSetRegistry()
        a = reg.add_from_rule("github.com")
        b = reg.add_from_rule("github.com")
        assert a is b
        assert len(reg.specs) == 1

    def test_explicit_spec_survives_rule_discovery(self):
        reg = DnsSetRegistry()
        reg.add_spec(DnsSetSpec(
            qname="github.com", ttl_floor=60, ttl_ceil=3600, size=64))
        reg.add_from_rule("github.com")
        assert reg.specs["github.com"].ttl_floor == 60
        assert reg.specs["github.com"].size == 64

    def test_case_normalisation(self):
        reg = DnsSetRegistry()
        reg.add_from_rule("Github.Com")
        reg.add_from_rule("github.com")
        assert len(reg.specs) == 1

    def test_iter_sorted_is_stable(self):
        reg = DnsSetRegistry()
        reg.add_from_rule("z.example")
        reg.add_from_rule("a.example")
        reg.add_from_rule("m.example")
        names = [s.qname for s in reg.iter_sorted()]
        assert names == ["a.example", "m.example", "z.example"]

    def test_set_names_pair(self):
        reg = DnsSetRegistry()
        v4, v6 = reg.set_names("github.com")
        assert v4 == "dns_github_com_v4"
        assert v6 == "dns_github_com_v6"


class TestEmitDnsSetDeclarations:
    def test_empty_registry_yields_no_lines(self):
        assert emit_dns_set_declarations(DnsSetRegistry()) == []

    def test_emits_both_families_with_timeout_flag(self):
        reg = DnsSetRegistry()
        reg.add_from_rule("github.com")
        lines = emit_dns_set_declarations(reg)
        text = "\n".join(lines)
        assert "set dns_github_com_v4 {" in text
        assert "set dns_github_com_v6 {" in text
        assert "type ipv4_addr;" in text
        assert "type ipv6_addr;" in text
        # Timeout flag is mandatory — daemon adds elements with TTL
        assert "flags timeout;" in text
        assert f"size {DEFAULT_SET_SIZE};" in text

    def test_per_spec_comment_appears(self):
        reg = DnsSetRegistry()
        reg.add_spec(DnsSetSpec(
            qname="api.stripe.com",
            ttl_floor=60, ttl_ceil=3600, size=32,
            comment="Payment webhooks",
        ))
        lines = emit_dns_set_declarations(reg)
        text = "\n".join(lines)
        assert "# api.stripe.com: Payment webhooks" in text
        assert "size 32;" in text

    def test_sorted_output_for_reproducibility(self):
        reg = DnsSetRegistry()
        reg.add_from_rule("z.example.com")
        reg.add_from_rule("a.example.com")
        lines = emit_dns_set_declarations(reg)
        text = "\n".join(lines)
        a_pos = text.index("dns_a_example_com_v4")
        z_pos = text.index("dns_z_example_com_v4")
        assert a_pos < z_pos


class TestCompiledAllowlistRoundTrip:
    def test_write_and_read_back(self, tmp_path: Path):
        reg = DnsSetRegistry()
        reg.add_spec(DnsSetSpec(
            qname="github.com", ttl_floor=300, ttl_ceil=86400,
            size=256, comment="API+web"))
        reg.add_spec(DnsSetSpec(
            qname="api.stripe.com", ttl_floor=60, ttl_ceil=3600,
            size=64, comment="Payment webhooks"))
        path = tmp_path / "dnsnames.compiled"
        write_compiled_allowlist(reg, path)

        assert path.exists()
        content = path.read_text()
        assert content.startswith("# shorewall-nft")
        assert "github.com" in content
        assert "Payment webhooks" in content

        reloaded = read_compiled_allowlist(path)
        assert set(reloaded.specs.keys()) == {"github.com", "api.stripe.com"}
        assert reloaded.specs["github.com"].size == 256
        assert reloaded.specs["api.stripe.com"].comment == "Payment webhooks"

    def test_read_missing_file_yields_empty(self, tmp_path: Path):
        reloaded = read_compiled_allowlist(tmp_path / "nope")
        assert reloaded.specs == {}

    def test_atomic_write_no_partial_file(self, tmp_path: Path):
        reg = DnsSetRegistry()
        reg.add_from_rule("github.com")
        path = tmp_path / "allowlist"
        # Pre-create with stale content to verify replacement
        path.write_text("STALE\n")
        write_compiled_allowlist(reg, path)
        content = path.read_text()
        assert "STALE" not in content
        assert "github.com" in content

    def test_ignores_malformed_lines(self, tmp_path: Path):
        path = tmp_path / "broken"
        path.write_text(
            "# header\n"
            "github.com\t300\t86400\t256\tok\n"
            "malformed line\n"
            "bad\tnotanint\tbad\tbad\n"
            "api.stripe.com\t60\t3600\t64\tpayments\n"
        )
        reg = read_compiled_allowlist(path)
        assert set(reg.specs.keys()) == {"github.com", "api.stripe.com"}


class TestParseDnsnamesFile:
    def test_parses_default_columns(self):
        specs = parse_dnsnames_file([
            "github.com 300 86400 256 GitHub API+web",
            "api.stripe.com 60 3600 64 Payment webhooks",
        ])
        assert len(specs) == 2
        assert specs[0].qname == "github.com"
        assert specs[0].ttl_floor == 300
        assert specs[0].comment == "GitHub API+web"
        assert specs[1].size == 64

    def test_dash_means_default(self):
        specs = parse_dnsnames_file(
            ["github.com - - - uses defaults"],
            default_ttl_floor=111,
            default_ttl_ceil=222,
            default_size=333,
        )
        assert specs[0].ttl_floor == 111
        assert specs[0].ttl_ceil == 222
        assert specs[0].size == 333

    def test_skips_comments_and_blank_lines(self):
        specs = parse_dnsnames_file([
            "# this is a comment",
            "",
            "github.com 300 86400 256 good",
        ])
        assert len(specs) == 1

    def test_rejects_invalid_hostnames(self):
        specs = parse_dnsnames_file([
            "1.2.3.4 300 86400 256 literal",
            "github.com 300 86400 256 good",
        ])
        assert len(specs) == 1
        assert specs[0].qname == "github.com"

    def test_accepts_config_line_objects(self):
        class Fake:
            def __init__(self, cols):
                self.columns = cols
        specs = parse_dnsnames_file([
            Fake(["github.com", "300", "86400", "256", "good"]),
        ])
        assert len(specs) == 1
        assert specs[0].qname == "github.com"


class TestDnsSetSpecSerialisation:
    """Ensure the compiled allowlist survives non-ASCII comments and
    preserves byte identity for the fast loader."""

    def test_unicode_comment_round_trips(self, tmp_path: Path):
        reg = DnsSetRegistry()
        reg.add_spec(DnsSetSpec(
            qname="example.com", ttl_floor=300, ttl_ceil=86400,
            size=128, comment="Kunde Müller – Q2 ticket"))
        path = tmp_path / "allowlist"
        write_compiled_allowlist(reg, path)
        reloaded = read_compiled_allowlist(path)
        assert "Müller" in reloaded.specs["example.com"].comment
