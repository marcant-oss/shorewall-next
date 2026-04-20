"""Unit tests for trafgen_trex_profiles — template builders."""

from __future__ import annotations

from shorewall_nft_stagelab.trafgen_trex_profiles import (
    build_dns_query_profile,
    build_half_open_profile,
    build_syn_flood_profile,
    build_udp_flood_profile,
)

# ---------------------------------------------------------------------------
# 1. syn_flood template compiles
# ---------------------------------------------------------------------------

def test_syn_flood_template_compiles():
    text = build_syn_flood_profile(
        src_cidr="10.0.0.0/16",
        dst_ips=("192.168.1.1",),
        dst_ports=(80, 443),
        rate_pps=100_000,
    )
    compile(text, "<profile>", "exec")  # must not raise


# ---------------------------------------------------------------------------
# 2. syn_flood template carries rate_pps
# ---------------------------------------------------------------------------

def test_syn_flood_template_carries_rate_pps():
    rate = 75_000
    text = build_syn_flood_profile(
        src_cidr="10.0.0.0/8",
        dst_ips=("10.1.2.3",),
        dst_ports=(22,),
        rate_pps=rate,
    )
    assert str(rate) in text


# ---------------------------------------------------------------------------
# 3. udp_flood template includes exact payload size
# ---------------------------------------------------------------------------

def test_udp_flood_template_payload_size():
    size = 1400
    text = build_udp_flood_profile(
        src_cidr="172.16.0.0/12",
        dst_ips=("192.0.2.1",),
        dst_ports=(5000,),
        payload_size_b=size,
        rate_pps=50_000,
    )
    assert str(size) in text
    # Also verify it compiles
    compile(text, "<profile>", "exec")


# ---------------------------------------------------------------------------
# 4. dns_query template contains each qname
# ---------------------------------------------------------------------------

def test_dns_query_template_contains_qnames():
    qnames = ("example.com", "test.local", "victim.org")
    text = build_dns_query_profile(
        src_cidr="10.0.0.0/24",
        resolver_ip="8.8.8.8",
        qnames=qnames,
        qps=10_000,
    )
    for qname in qnames:
        assert qname in text
    compile(text, "<profile>", "exec")


# ---------------------------------------------------------------------------
# 5. half_open template is ASTF-shaped
# ---------------------------------------------------------------------------

def test_half_open_template_is_astf_shape():
    target_conns = 65536
    text = build_half_open_profile(
        src_cidr="10.0.0.0/16",
        dst_ip="192.168.100.1",
        dst_port=443,
        target_conns=target_conns,
        open_rate_per_s=500,
    )
    assert "ASTFProfile" in text
    assert "def get_profile" in text
    assert str(target_conns) in text
    compile(text, "<profile>", "exec")
