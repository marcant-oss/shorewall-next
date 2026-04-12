#!/bin/sh
# setup-shorewalld-dnstap-smoke.sh — dnstap end-to-end smoke on a RAM-only VM.
#
# Extends tools/setup-remote-test-host.sh with everything needed to
# manually verify the shorewalld dnstap ingress path:
#
#   1. Same repo rsync + venv + apt deps as the base deployment script
#      (installs pdns-recursor + dnsutils on top).
#   2. Writes a minimal /etc/shorewall/shorewalld.conf and a compiled
#      DNS allowlist containing three example hostnames.
#   3. Compiles + loads a tiny stub shorewall-nft ruleset containing
#      the three dns_<name>_{v4,v6} sets so shorewalld has something
#      to populate (no zones, no filters — just the sets).
#   4. Drops packaging/pdns-recursor/shorewalld.lua.template into
#      /etc/powerdns/recursor.d/shorewalld.lua and writes a matching
#      minimal recursor.conf bound to 127.0.0.1:5354 (keeps it out of
#      the way of any host resolver at :53).
#   5. Starts shorewalld via `systemd-run --unit shorewalld-smoke`
#      and pdns-recursor via systemd. Both use --collect so a clean
#      stop removes them.
#
# After the script finishes, verify from the remote shell:
#
#     # inspect a live dnstap frame stream (uses the tap subcommand):
#     /root/shorewall-nft/.venv/bin/shorewalld tap \
#         --socket /run/shorewalld/dnstap.sock
#
#     # trigger a resolve:
#     dig @127.0.0.1 -p 5354 github.com A
#     dig @127.0.0.1 -p 5354 github.com AAAA
#
#     # verify the nft set was populated:
#     nft list set inet shorewall dns_github_com_v4
#     nft list set inet shorewall dns_github_com_v6
#
# Usage:
#     tools/setup-shorewalld-dnstap-smoke.sh root@192.0.2.83
#
# The host must already accept passwordless SSH. Idempotent: safe to
# re-run; the script tears down any previous shorewalld-smoke unit
# before starting a new one.

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REMOTE=""

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)
            sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            if [ -z "$REMOTE" ]; then
                REMOTE="$1"
                shift
            else
                echo "unexpected argument: $1" >&2
                exit 1
            fi
            ;;
    esac
done

[ -n "$REMOTE" ] || {
    echo "usage: $0 user@host" >&2
    exit 1
}

info() { printf 'shorewalld-dnstap-smoke: %s\n' "$1"; }

# ──────────────────────────────────────────────────────────────────
# 1. Repo sync + venv + base deps. Mirrors setup-remote-test-host.sh
#    but adds pdns-recursor and dig.
# ──────────────────────────────────────────────────────────────────

info "rsync repo → $REMOTE:/root/shorewall-nft"
ssh "$REMOTE" 'mkdir -p /root/shorewall-nft'
rsync -a --delete \
    --exclude='.git' \
    --exclude='__pycache__' \
    --exclude='.pytest_cache' \
    --exclude='.ruff_cache' \
    --exclude='dist' \
    --exclude='*.egg-info' \
    --exclude='.venv' \
    --exclude='tools/deploy.json' \
    "$REPO_DIR/" "$REMOTE:/root/shorewall-nft/"

info "apt install base deps + pdns-recursor + dnsutils"
ssh "$REMOTE" 'DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1 || true; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        python3 python3-venv python3-pip \
        python3-click python3-pyroute2 \
        iproute2 nftables conntrack \
        pdns-recursor dnsutils \
        2>&1 | tail -10 || true'

info "create venv + editable install (compiler + daemon sub-packages)"
ssh "$REMOTE" 'cd /root/shorewall-nft && \
    python3 -m venv --system-site-packages .venv && \
    .venv/bin/pip install -q \
        -e "packages/shorewall-nft" \
        -e "packages/shorewalld[daemon]" 2>&1 | tail -5 && \
    .venv/bin/shorewall-nft --version && \
    .venv/bin/shorewalld --version'

# ──────────────────────────────────────────────────────────────────
# 2. Stub shorewall-nft config with three dns:<name> rules so the
#    compiler emits the dns_<name>_{v4,v6} sets. Keeps the ruleset
#    otherwise empty — this is a functionality probe, not a security
#    exercise.
# ──────────────────────────────────────────────────────────────────

info "build stub /etc/shorewall46 config for the smoke test"
ssh "$REMOTE" 'bash -s' <<'REMOTE_EOF'
set -eu
# Wipe any previous deployment so the stub below is the only thing
# the compiler sees. Important on re-run where a full merged config
# from setup-remote-test-host.sh may be sitting in /etc/shorewall46.
rm -rf /etc/shorewall46
mkdir -p /etc/shorewall46

cat >/etc/shorewall46/shorewall.conf <<'CONF'
STARTUP_ENABLED=Yes
LOGFORMAT="Shorewall:%s:%s:"
IP_FORWARDING=On
FASTACCEPT=Yes
OPTIMIZE=8
CONF

cat >/etc/shorewall46/zones <<'CONF'
fw          firewall
net         ipv4,ipv6
CONF

cat >/etc/shorewall46/interfaces <<'CONF'
net    lo                 routeback
CONF

cat >/etc/shorewall46/policy <<'CONF'
fw     all     ACCEPT
net    all     ACCEPT
all    all     REJECT
CONF

# dns:<name> tokens drive the compiler's DnsSetRegistry to emit the
# dns_<name>_v4 / _v6 sets. SOURCE side uses the synthetic tokens,
# PROTO is tcp so the emitted rule is syntactically valid (an empty
# or "all" proto column expands to "meta l4proto all" which nft
# rejects); the exact match doesn't matter — we only care that
# the sets get declared.
cat >/etc/shorewall46/rules <<'CONF'
ACCEPT   net:dns:github.com        fw    tcp    443
ACCEPT   net:dns:example.com       fw    tcp    443
ACCEPT   net:dns:cloudflare.com    fw    tcp    443
CONF

# Empty params file keeps the compiler happy.
: >/etc/shorewall46/params
REMOTE_EOF

info "compile + load the stub ruleset"
ssh "$REMOTE" 'set -e
cd /root/shorewall-nft
.venv/bin/shorewall-nft compile /etc/shorewall46 -o /tmp/smoke.nft
nft flush ruleset 2>/dev/null || true
nft -f /tmp/smoke.nft
nft list table inet shorewall | grep -E "^\s*set dns_" | head -6'

# ──────────────────────────────────────────────────────────────────
# 3. Allowlist + shorewalld.conf.
# ──────────────────────────────────────────────────────────────────

info "write compiled DNS allowlist + shorewalld.conf"
ssh "$REMOTE" 'bash -s' <<'REMOTE_EOF'
set -eu
mkdir -p /var/lib/shorewalld /etc/shorewall /run/shorewalld

cat >/var/lib/shorewalld/dns-allowlist.tsv <<'ALLOW'
# shorewalld compiled allowlist — smoke test
github.com	300	3600	1024	smoke test
example.com	300	3600	1024	smoke test
cloudflare.com	300	3600	1024	smoke test
ALLOW

cat >/etc/shorewall/shorewalld.conf <<'CONF'
# shorewalld.conf — dnstap smoke test configuration.
#
# shorewalld accepts DNS answers through two ingestion paths:
#
#   * dnstap (this smoke test, preferred) — standard fstrm
#     FrameStream transport, supports both unix sockets and TCP,
#     works with pdns_recursor, unbound, dnsdist, and every other
#     DNS server that speaks fstrm. The recursor ships raw DNS
#     wire bytes in a dnstap.Dnstap protobuf envelope; shorewalld
#     parses them via dnspython (~100 µs per frame at typical
#     loads).
#
#   * PBDNSMessage — pdns-recursor's native protobuf logger.
#     Pre-decomposed DNSRR records mean no DNS wire parse on the
#     shorewalld side (~20 µs faster per frame), but pdns refuses
#     to speak it over a unix socket (TCP only), which adds a
#     loopback hop and a port to manage. PBDNSMessage is also
#     pdns-specific; no other recursor supports it.
#
# Default recommendation: dnstap. The efficiency delta is well
# within shorewalld's latency budget at realistic DNS QPS
# (<20 k/s), while the ecosystem reach, transport flexibility,
# and unix-socket support of dnstap outweigh the marginal
# per-frame saving of PBDNSMessage. The PbdnsServer code path
# in shorewall_nft/daemon/pbdns.py remains available for
# deployments that already have a pdns protobuf stream in
# place — enable it by uncommenting PBDNS_TCP below.
LISTEN_PROM=127.0.0.1:9748
LISTEN_API=/run/shorewalld/dnstap.sock

# Unix socket ownership/mode applied to every daemon-owned
# unix socket (dnstap + pbdns). The smoke test runs everything
# as root so the defaults are fine; in production you typically
# want ``SOCKET_GROUP=pdns`` + ``SOCKET_MODE=0660`` so the
# recursor can connect as its usual non-root user without
# shorewalld itself needing to drop privileges.
SOCKET_MODE=0660
# SOCKET_OWNER=root
# SOCKET_GROUP=pdns

# Alternative ingest path (opt-in):
# PBDNS_TCP=127.0.0.1:9999
# PBDNS_SOCKET=/run/shorewalld/pbdns.sock    # for non-pdns producers

ALLOWLIST_FILE=/var/lib/shorewalld/dns-allowlist.tsv
STATE_DIR=/var/lib/shorewalld
RELOAD_POLL_INTERVAL=2
LOG_LEVEL=debug
LOG_TARGET=stderr
LOG_FORMAT=human
CONF
REMOTE_EOF

# ──────────────────────────────────────────────────────────────────
# 4. pdns-recursor configuration + shorewalld Lua fragment.
# ──────────────────────────────────────────────────────────────────

info "configure pdns-recursor for dnstap → /run/shorewalld/dnstap.sock"
# pdns-recursor supports two ways to register a dnstap FrameStream
# exporter:
#
#   1. legacy Lua: ``dnstapFrameStreamServer({...}, {...})`` inside
#      a file loaded via ``lua_config_file``. This is how pdns 4.x
#      shipped the feature and how
#      packaging/pdns-recursor/shorewalld.lua.template has always
#      wired it. Still works under 5.x.
#
#   2. native YAML: ``logging.dnstap_framestream_servers: [...]``
#      added in pdns 5.x as part of the YAML config migration.
#
# Running BOTH at the same time is explicitly unsupported:
# pdns-recursor 5.x refuses to start with the message
#   "YAML settings include values originally in Lua but also
#    sets `recursor.lua_config_file`. This is unsupported"
# so you must pick exactly one path. The smoke test uses the Lua
# path (the one shipped with shorewalld's packaging/ template);
# the YAML block below is kept for documentation and as a
# drop-in alternative if you prefer the native pdns 5.x
# mechanism — comment out ``lua_config_file`` and uncomment the
# YAML block, then restart pdns-recursor.
#
# Both paths produce identical dnstap frames on the wire (same
# fstrm + protobuf encoding), so shorewalld's decoder can't tell
# them apart. Use ``shorewalld tap`` to inspect the stream under
# whichever mode is active.
rsync "$REPO_DIR/packaging/pdns-recursor/shorewalld.lua.template" \
    "$REMOTE:/etc/powerdns/recursor.d/shorewalld.lua"

ssh "$REMOTE" 'bash -s' <<'REMOTE_EOF'
set -eu
mkdir -p /etc/powerdns/recursor.d /etc/systemd/system/pdns-recursor.service.d

# The shorewalld.lua.template already wires dnstapFrameStreamServer()
# as the sole producer. PBDNSMessage (protobufServer) is NOT added
# by default — see the preamble in /etc/shorewall/shorewalld.conf
# for the rationale. To enable it, append the following block
# manually and uncomment PBDNS_TCP in shorewalld.conf:
#
#   cat >>/etc/powerdns/recursor.d/shorewalld.lua <<'LUA'
#   -- Alternative ingest path: PBDNSMessage over TCP.
#   -- pdns-recursor's protobufServer() only accepts TCP (not
#   -- unix sockets) so this listens on a loopback port that
#   -- shorewalld's PbdnsServer picks up via PBDNS_TCP.
#   protobufServer("127.0.0.1:9999", {
#       logQueries = false,
#       logResponses = true,
#   })
#   LUA

# Stale .conf wins over .yml silently — wipe both and write YAML fresh.
rm -f /etc/powerdns/recursor.conf
cat >/etc/powerdns/recursor.yml <<'CONF'
incoming:
  listen:
    - '127.0.0.1:5354'
recursor:
  # Active dnstap path: legacy Lua mechanism. The vendored
  # shorewalld.lua.template calls dnstapFrameStreamServer().
  lua_config_file: /etc/powerdns/recursor.d/shorewalld.lua
logging:
  loglevel: 7
  structured_logging: true

  # Alternative dnstap path: native YAML (pdns 5.x). Commented
  # out because pdns 5.x refuses to start with both
  # lua_config_file AND dnstap_framestream_servers set. To
  # switch to the native YAML route: uncomment the block below,
  # comment out the `lua_config_file:` line above, then
  # `systemctl restart pdns-recursor`.
  #
  # dnstap_framestream_servers:
  #   - servers:
  #       - '/run/shorewalld/dnstap.sock'
  #     logQueries: false
  #     logResponses: true
  #     flushTimeout: 1
  #     queueNotifyThreshold: 1
CONF

# Drop-in: pdns-recursor runs as 'pdns' but needs to write to
# /run/shorewalld/dnstap.sock which shorewalld creates 0660
# root:root. Simplest resolution for a disposable smoke: run the
# recursor as root. This is EXPLICITLY a test-only arrangement.
cat >/etc/systemd/system/pdns-recursor.service.d/smoke.conf <<'UNIT'
[Service]
User=root
Group=root
# The socket lives in /run/shorewalld/ — make sure that directory
# is reachable from the recursor's mount namespace.
PrivateMounts=no
UNIT

systemctl daemon-reload
REMOTE_EOF

# ──────────────────────────────────────────────────────────────────
# 5. Start shorewalld first (creates the socket), then
#    pdns-recursor (connects to it).
# ──────────────────────────────────────────────────────────────────

info "restart any previous smoke runs cleanly"
ssh "$REMOTE" '
systemctl stop pdns-recursor 2>/dev/null || true
systemctl stop shorewalld-smoke 2>/dev/null || true
rm -f /run/shorewalld/dnstap.sock
'

info "start shorewalld via systemd-run (unit=shorewalld-smoke)"
ssh "$REMOTE" '
systemd-run --unit=shorewalld-smoke --collect \
    --property=StandardOutput=append:/tmp/shorewalld.log \
    --property=StandardError=append:/tmp/shorewalld.log \
    /root/shorewall-nft/.venv/bin/shorewalld \
        --config-file /etc/shorewall/shorewalld.conf
sleep 1
# Confirm the socket is there.
ls -l /run/shorewalld/dnstap.sock
'

info "start pdns-recursor"
ssh "$REMOTE" '
systemctl start pdns-recursor
sleep 1
systemctl is-active pdns-recursor
'

# ──────────────────────────────────────────────────────────────────
# Done.
# ──────────────────────────────────────────────────────────────────

info "done. next steps on the remote:"
info ""
info "  # live tap of the dnstap stream (second window):"
info "  /root/shorewall-nft/.venv/bin/shorewalld tap --socket /run/shorewalld/dnstap.sock"
info ""
info "  # trigger three resolves — each should populate the matching set:"
info "  dig @127.0.0.1 -p 5354 github.com A"
info "  dig @127.0.0.1 -p 5354 example.com AAAA"
info "  dig @127.0.0.1 -p 5354 cloudflare.com A"
info ""
info "  # verify the nft sets got populated:"
info "  nft list set inet shorewall dns_github_com_v4"
info "  nft list set inet shorewall dns_example_com_v6"
info "  nft list set inet shorewall dns_cloudflare_com_v4"
info ""
info "  # shorewalld logs live here:"
info "  tail -f /tmp/shorewalld.log"
info ""
info "  # stop everything (removes the shorewalld-smoke unit):"
info "  systemctl stop pdns-recursor"
info "  systemctl stop shorewalld-smoke"
