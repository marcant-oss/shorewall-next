#!/bin/sh
# setup-remote-test-host.sh — deploy shorewall-nft to a RAM-only test box.
#
# Bootstraps a disposable test host over SSH:
#   1. rsyncs the working copy to /root/shorewall-nft (excluding .venv, caches)
#   2. creates a venv and installs all three sub-packages (packages/*)
#   3. runs tools/install-test-tooling.sh for the run-netns wrapper + sudoers
#   4. copies the marcant-fw iptables-save dump + matching shorewall config
#      to /root/simulate-data, so `shorewall-nft simulate` has ground truth
#
# Usage:
#   tools/setup-remote-test-host.sh root@192.0.2.83
#   tools/setup-remote-test-host.sh root@host --simulate-src /path/to/old
#
# The host must already accept passwordless SSH for the given user.
# Idempotent: safe to re-run after the box is re-imaged.

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SIMULATE_SRC_DEFAULT="$REPO_DIR/../old"
SIMULATE_SRC="$SIMULATE_SRC_DEFAULT"
DEPLOY_JSON_DEFAULT="$SCRIPT_DIR/deploy.json"
DEPLOY_JSON="$DEPLOY_JSON_DEFAULT"
REMOTE=""

while [ $# -gt 0 ]; do
    case "$1" in
        --simulate-src) SIMULATE_SRC="$2"; shift 2 ;;
        --deploy-json)  DEPLOY_JSON="$2"; shift 2 ;;
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

[ -n "$REMOTE" ] || { echo "usage: $0 user@host [--simulate-src DIR]" >&2; exit 1; }

info() { printf 'setup-remote-test-host: %s\n' "$1"; }

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

info "install apt deps (idempotent)"
ssh "$REMOTE" 'DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1 || true; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    python3 python3-venv python3-pip python3.12-venv \
    python3-pytest python3-pytest-xdist python3-click python3-pyroute2 \
    iproute2 sudo nftables conntrack ipset 2>&1 | tail -5 || true'

info "create venv + editable install (all three sub-packages)"
ssh "$REMOTE" 'cd /root/shorewall-nft && \
    python3 -m venv --system-site-packages .venv && \
    .venv/bin/pip install -q \
        -e "packages/shorewall-nft[dev]" \
        -e "packages/shorewalld[dev]" \
        -e "packages/shorewall-nft-simlab[dev]" && \
    .venv/bin/shorewall-nft --version && \
    .venv/bin/shorewalld --version'

info "run install-test-tooling.sh on remote"
ssh "$REMOTE" 'sh /root/shorewall-nft/tools/install-test-tooling.sh'

if [ -f "$SIMULATE_SRC/iptables.txt" ] && [ -d "$SIMULATE_SRC/etc/shorewall" ]; then
    info "copy simulate ground truth from $SIMULATE_SRC"
    ssh "$REMOTE" 'mkdir -p /root/simulate-data/etc'
    rsync -a "$SIMULATE_SRC/etc/shorewall/" "$REMOTE:/root/simulate-data/etc/shorewall/"
    if [ -d "$SIMULATE_SRC/etc/shorewall6" ]; then
        rsync -a "$SIMULATE_SRC/etc/shorewall6/" "$REMOTE:/root/simulate-data/etc/shorewall6/"
    fi
    rsync "$SIMULATE_SRC/iptables.txt" "$REMOTE:/root/simulate-data/iptables.txt"
    # fw-state dumps used by simlab
    for f in ip4add ip4routes ip6add ip6routes; do
        if [ -f "$SIMULATE_SRC/$f" ]; then
            rsync "$SIMULATE_SRC/$f" "$REMOTE:/root/simulate-data/$f"
        fi
    done
    info "simulate data in /root/simulate-data/ (config + iptables.txt + fw-state dumps)"
else
    info "WARNING: no simulate ground truth at $SIMULATE_SRC — skipping"
    info "         (expected: $SIMULATE_SRC/iptables.txt + $SIMULATE_SRC/etc/shorewall/)"
fi

if [ -f "$DEPLOY_JSON" ]; then
    info "deploy $DEPLOY_JSON → /etc/shorewall46 via structured config import"
    # Rsync the deploy JSON to a tmp path on the remote (never into
    # /root/shorewall-nft/tools — that dir is .gitignored and
    # excluded from the repo sync anyway). Then let the importer
    # write plugins.conf, plugins/netbox.toml (TOML-rendered from
    # the nested dict), and plugins/netbox.token (raw, mode 0600)
    # via write_config_dir.
    rsync "$DEPLOY_JSON" "$REMOTE:/tmp/deploy.json"
    ssh "$REMOTE" '
set -e
mkdir -p /etc/shorewall46
/root/shorewall-nft/.venv/bin/shorewall-nft config import \
    /tmp/deploy.json --to /etc/shorewall46 --force
rm -f /tmp/deploy.json
# Mirror into /root/simulate-data/etc/shorewall/ so a fresh simlab
# bootstrap from that source tree picks them up too. Guarded against
# the (common) case where /etc/shorewall46 is already a symlink
# into /root/simulate-data/etc/shorewall (cp -u would complain).
if [ "$(readlink -f /etc/shorewall46)" != "$(readlink -f /root/simulate-data/etc/shorewall)" ]; then
    mkdir -p /root/simulate-data/etc/shorewall/plugins
    cp /etc/shorewall46/plugins.conf /root/simulate-data/etc/shorewall/plugins.conf 2>/dev/null || true
    cp /etc/shorewall46/plugins/netbox.toml /root/simulate-data/etc/shorewall/plugins/netbox.toml 2>/dev/null || true
    cp /etc/shorewall46/plugins/netbox.token /root/simulate-data/etc/shorewall/plugins/netbox.token 2>/dev/null || true
    chmod 600 /root/simulate-data/etc/shorewall/plugins/netbox.token 2>/dev/null || true
fi
'
    info "plugin deploy done"
else
    info "no deploy overlay at $DEPLOY_JSON — skipping plugin deploy"
    info "  (copy tools/deploy.json.example → tools/deploy.json and fill in the real API token)"
fi

# ──────────────────────────────────────────────────────────────────
# Produce /etc/shorewall46 by merging v4 + v6 sources through the
# plugin pipeline. This is the step that actually runs the netbox
# plugin (for IPv4↔IPv6 pairing / translation-rule enrichment).
# ──────────────────────────────────────────────────────────────────
info "merge-config: /root/simulate-data/etc/shorewall{,6} → /etc/shorewall46 (plugin-aware)"
ssh "$REMOTE" '
set -e
if [ -d /etc/shorewall46 ] && [ ! -L /etc/shorewall46 ]; then
    rm -rf /etc/shorewall46
fi
if [ -L /etc/shorewall46 ]; then
    rm -f /etc/shorewall46
fi
if [ -d /root/simulate-data/etc/shorewall6 ]; then
    /root/shorewall-nft/.venv/bin/shorewall-nft merge-config \
        /root/simulate-data/etc/shorewall \
        /root/simulate-data/etc/shorewall6 \
        -o /etc/shorewall46
else
    /root/shorewall-nft/.venv/bin/shorewall-nft merge-config \
        /root/simulate-data/etc/shorewall \
        -o /etc/shorewall46
fi
# Re-apply plugin files into the merged output (merge-config may
# not carry plugins.conf + plugins/ forward from either source).
mkdir -p /etc/shorewall46/plugins
if [ -f /root/simulate-data/etc/shorewall/plugins.conf ]; then
    cp /root/simulate-data/etc/shorewall/plugins.conf /etc/shorewall46/plugins.conf
fi
if [ -d /root/simulate-data/etc/shorewall/plugins ]; then
    cp -a /root/simulate-data/etc/shorewall/plugins/. /etc/shorewall46/plugins/
    chmod 600 /etc/shorewall46/plugins/netbox.token 2>/dev/null || true
fi
echo "merged: $(find /etc/shorewall46 -maxdepth 1 -type f | wc -l) files"
'

info "done. next steps on the remote:"
info "  systemd-run --unit=shorewall-pytest --collect --working-directory=/root/shorewall-nft \\"
info "    --property=StandardOutput=file:/tmp/pytest.log \\"
info "    --property=StandardError=file:/tmp/pytest.log \\"
info "    /root/shorewall-nft/.venv/bin/python -m pytest \\"
info "        packages/shorewall-nft/tests/ \\"
info "        packages/shorewalld/tests/ \\"
info "        packages/shorewall-nft-simlab/tests/ -v"
info "  /root/shorewall-nft/.venv/bin/shorewall-nft simulate /root/simulate-data/etc/shorewall \\"
info "    --iptables /root/simulate-data/iptables.txt -n 60"
