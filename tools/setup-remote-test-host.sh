#!/bin/sh
# setup-remote-test-host.sh — deploy shorewall-nft to a RAM-only test box.
#
# Bootstraps a disposable test host over SSH:
#   1. rsyncs the working copy to /root/shorewall-nft (excluding .venv, caches)
#   2. creates a venv and `pip install -e .`
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
REMOTE=""

while [ $# -gt 0 ]; do
    case "$1" in
        --simulate-src) SIMULATE_SRC="$2"; shift 2 ;;
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
    "$REPO_DIR/" "$REMOTE:/root/shorewall-nft/"

info "install apt deps (idempotent)"
ssh "$REMOTE" 'DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    python3 python3-venv python3-pip \
    python3-pytest python3-pytest-xdist python3-click python3-pyroute2 \
    iproute2 sudo nftables conntrack ipset >/dev/null 2>&1 || true'

info "create venv + editable install"
ssh "$REMOTE" 'cd /root/shorewall-nft && \
    python3 -m venv --system-site-packages .venv && \
    .venv/bin/pip install -q -e . && \
    .venv/bin/shorewall-nft --version'

info "run install-test-tooling.sh on remote"
ssh "$REMOTE" 'sh /root/shorewall-nft/tools/install-test-tooling.sh'

if [ -f "$SIMULATE_SRC/iptables.txt" ] && [ -d "$SIMULATE_SRC/etc/shorewall" ]; then
    info "copy simulate ground truth from $SIMULATE_SRC"
    ssh "$REMOTE" 'mkdir -p /root/simulate-data/etc'
    rsync -a "$SIMULATE_SRC/etc/shorewall/" "$REMOTE:/root/simulate-data/etc/shorewall/"
    rsync "$SIMULATE_SRC/iptables.txt" "$REMOTE:/root/simulate-data/iptables.txt"
    info "simulate data in /root/simulate-data/ (config + iptables.txt)"
else
    info "WARNING: no simulate ground truth at $SIMULATE_SRC — skipping"
    info "         (expected: $SIMULATE_SRC/iptables.txt + $SIMULATE_SRC/etc/shorewall/)"
fi

info "done. next steps on the remote:"
info "  systemd-run --unit=shorewall-pytest --collect --working-directory=/root/shorewall-nft \\"
info "    --property=StandardOutput=file:/tmp/pytest.log \\"
info "    --property=StandardError=file:/tmp/pytest.log \\"
info "    /root/shorewall-nft/.venv/bin/python -m pytest tests/ -v"
info "  /root/shorewall-nft/.venv/bin/shorewall-nft simulate /root/simulate-data/etc/shorewall \\"
info "    --iptables /root/simulate-data/iptables.txt -n 60"
