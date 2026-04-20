#!/bin/sh
# setup-remote-test-host.sh — deploy shorewall-nft to a RAM-only test box.
#
# Bootstraps a disposable test host over SSH:
#   1. rsyncs the working copy to /root/shorewall-nft (excluding .venv, caches)
#   2. creates a venv and installs all three sub-packages (packages/*)
#   3. copies the marcant-fw iptables-save dump + matching shorewall config
#      to /root/simulate-data, so `shorewall-nft simulate` has ground truth
#
# No extra tooling (run-netns, sudoers) is installed — tests run as root
# inside a fully isolated private namespace via tools/run-tests.sh.
#
# Usage:
#   tools/setup-remote-test-host.sh root@192.0.2.83
#   tools/setup-remote-test-host.sh root@host --simulate-src /path/to/old
#   tools/setup-remote-test-host.sh root@host --role stagelab-agent
#   tools/setup-remote-test-host.sh root@host --role stagelab-agent-dpdk
#
# --role ROLE   choose bootstrap role:
#               "default"              existing behaviour (simlab/simulate)
#               "stagelab-agent"       adds iperf3/nmap/ethtool + high-pps sysctls
#               "stagelab-agent-dpdk"  stagelab-agent PLUS DPDK + TRex bootstrap
#               Default: "default".
#
# Environment variables (stagelab-agent-dpdk only):
#   STAGELAB_HUGEPAGES   2 MiB hugepages to allocate (default: 512 = 1 GiB)
#   STAGELAB_SKIP_SHA    set to 1 to skip TRex tarball SHA-256 check (dev/CI only)
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
ROLE="default"

# TRex bundle constants (stagelab-agent-dpdk only).
# SHA is a placeholder — after downloading the tarball manually the first
# time, record `sha256sum /tmp/trex.tar.gz` here and remove this comment.
# Use STAGELAB_SKIP_SHA=1 in CI / integration tests to bypass the check.
TREX_VERSION="v3.04"
TREX_SHA256="0000000000000000000000000000000000000000000000000000000000000000"
TREX_URL="https://trex-tgn.cisco.com/trex/release/${TREX_VERSION}.tar.gz"
TREX_DEST="/opt/trex/${TREX_VERSION}"

while [ $# -gt 0 ]; do
    case "$1" in
        --simulate-src) SIMULATE_SRC="$2"; shift 2 ;;
        --deploy-json)  DEPLOY_JSON="$2"; shift 2 ;;
        --role)         ROLE="$2"; shift 2 ;;
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

[ -n "$REMOTE" ] || { echo "usage: $0 user@host [--simulate-src DIR] [--role default|stagelab-agent|stagelab-agent-dpdk]" >&2; exit 1; }

case "$ROLE" in
    default|stagelab-agent|stagelab-agent-dpdk) ;;
    *) echo "unknown role: $ROLE (expected: default, stagelab-agent, or stagelab-agent-dpdk)" >&2; exit 1 ;;
esac

# stagelab-agent-dpdk implies stagelab-agent
IS_DPDK=0
if [ "$ROLE" = "stagelab-agent-dpdk" ]; then
    IS_DPDK=1
fi

info() { printf 'setup-remote-test-host: %s\n' "$1"; }

# probe_nics: enumerate non-loopback NICs and print ethtool offload info.
# Informational only — never fails the bootstrap.
probe_nics() {
    _ifaces=$(ssh "$REMOTE" \
        'ip -o link show | awk -F: '"'"'{print $2}'"'"' | tr -d '"'"' '"'"' | grep -v "^lo$\|@"' \
        2>/dev/null || true)
    if [ -z "$_ifaces" ]; then
        info "probe_nics: no non-loopback interfaces found"
        return
    fi
    for _iface in $_ifaces; do
        info "NIC $_iface — queue depths:"
        ssh "$REMOTE" "ethtool -l '$_iface' 2>/dev/null | head -20 || true" | \
            while IFS= read -r _line; do info "  $_line"; done
        info "NIC $_iface — offload flags:"
        ssh "$REMOTE" "ethtool -k '$_iface' 2>/dev/null \
            | grep -E '^(tcp-segmentation-offload|generic-segmentation-offload|rx-vlan-filter|rx-vlan-hw-parse)' \
            || true" | \
            while IFS= read -r _line; do info "  $_line"; done
    done
}

info "rsync repo → $REMOTE:/root/shorewall-nft (role=$ROLE)"
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

# Detect package manager on remote. grml/Debian → apt, AlmaLinux/Fedora → dnf.
PKG_MGR=$(ssh "$REMOTE" '
if command -v apt-get >/dev/null 2>&1; then
    echo apt
elif command -v dnf >/dev/null 2>&1; then
    echo dnf
elif command -v yum >/dev/null 2>&1; then
    echo yum
else
    echo unknown
fi
')
info "package manager on remote: $PKG_MGR"
case "$PKG_MGR" in
    apt|dnf|yum) ;;
    *) echo "unsupported remote: no apt/dnf/yum found" >&2; exit 1 ;;
esac

info "install base deps (idempotent)"
if [ "$PKG_MGR" = "apt" ]; then
    ssh "$REMOTE" 'DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1 || true; \
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        python3 python3-venv python3-pip python3.12-venv \
        python3-pytest python3-pytest-xdist python3-click python3-pyroute2 \
        python3-nftables \
        iproute2 sudo nftables conntrack ipset 2>&1 | tail -5 || true'
else
    # AlmaLinux 10 / Fedora: install via dnf. EPEL + CRB needed for several
    # Python deps (python3-pyroute2, python3-pytest-xdist). Best-effort — if
    # EPEL/CRB cannot be enabled, fall back to pip inside the venv.
    ssh "$REMOTE" '
set -e
dnf install -y -q epel-release 2>/dev/null || true
dnf config-manager --set-enabled crb 2>/dev/null || true
dnf install -y -q \
    python3 python3-pip \
    python3-click python3-pyroute2 python3-nftables \
    iproute nftables conntrack-tools ipset sudo 2>&1 | tail -5 || true
# python3-pytest may live in CRB; try, ignore if not found
dnf install -y -q python3-pytest python3-pytest-xdist 2>/dev/null || true
'
fi

# ── stagelab-agent: extra tooling ─────────────────────────────────
if [ "$ROLE" = "stagelab-agent" ] || [ "$IS_DPDK" = "1" ]; then
    info "stagelab-agent: installing perf-test tooling"
    if [ "$PKG_MGR" = "apt" ]; then
        ssh "$REMOTE" '
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    iperf3 nmap ethtool bridge-utils jq tcpdump 2>&1 | tail -5 || true
# TODO: tcpkali — add source-build step when needed (T8d)
if DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        linux-perf >/dev/null 2>&1; then
    echo "linux-perf installed"
else
    echo "WARNING: linux-perf not available on this distro — skipping"
fi
' || true
    else
        # dnf: iperf3 is in EPEL on EL10. bridge commands come from iproute
        # (no separate bridge-utils package on EL). perf = "perf" package.
        ssh "$REMOTE" '
dnf install -y -q iperf3 nmap ethtool jq tcpdump 2>&1 | tail -5 || true
# TODO: tcpkali — add source-build step when needed (T8d)
if dnf install -y -q perf >/dev/null 2>&1; then
    echo "perf installed"
else
    echo "WARNING: perf not available on this distro — skipping"
fi
' || true
    fi

    info "stagelab-agent: applying ephemeral sysctls (grml is RAM-only — not persistent across reboot)"
    ssh "$REMOTE" 'sysctl -w net.netfilter.nf_conntrack_max=4194304' && \
        info "  net.netfilter.nf_conntrack_max=4194304" || \
        info "  WARNING: could not set nf_conntrack_max"
    ssh "$REMOTE" 'sysctl -w net.core.rmem_max=134217728' && \
        info "  net.core.rmem_max=134217728" || \
        info "  WARNING: could not set rmem_max"
    ssh "$REMOTE" 'sysctl -w net.core.wmem_max=134217728' && \
        info "  net.core.wmem_max=134217728" || \
        info "  WARNING: could not set wmem_max"

    info "stagelab-agent: probing NIC offload capabilities"
    probe_nics

    info "stagelab role: grml is RAM-only; for persistent isolcpus/nohz_full pin, edit boot cmdline manually (note: rebooting wipes everything on grml)."
fi
# ──────────────────────────────────────────────────────────────────

# ── stagelab-agent-dpdk: DPDK + TRex bootstrap ────────────────────
if [ "$IS_DPDK" = "1" ]; then
    # ── 1. DPDK tooling install ──────────────────────────────────
    info "stagelab-agent-dpdk: installing DPDK tooling"
    if [ "$PKG_MGR" = "apt" ]; then
        ssh "$REMOTE" '
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    dpdk python3-pyelftools 2>&1 | tail -5 || true
# dpdk-kmods-dkms may fail on kernels without matching headers — log and continue
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    dpdk-kmods-dkms 2>&1 | tail -5 || echo "WARNING: dpdk-kmods-dkms not available — skipping"
' || true
    else
        ssh "$REMOTE" '
dnf install -y -q dpdk dpdk-tools python3-pyelftools 2>&1 | tail -5 || true
' || true
    fi
    # Fall-back: if dpdk-devbind.py was not provided by the distro package,
    # use a vendored copy if present (we do not create it here — placeholder only).
    ssh "$REMOTE" '
if ! command -v dpdk-devbind.py >/dev/null 2>&1 && \
   ! test -f /usr/share/dpdk/usertools/dpdk-devbind.py && \
   ! test -f /usr/sbin/dpdk-devbind.py; then
    if test -f /root/shorewall-nft/tools/dpdk-devbind.py; then
        cp /root/shorewall-nft/tools/dpdk-devbind.py /usr/local/sbin/dpdk-devbind.py
        chmod +x /usr/local/sbin/dpdk-devbind.py
        echo "dpdk-devbind.py: installed from vendored copy"
    else
        echo "WARNING: dpdk-devbind.py not found — DPDK NIC binding will not work"
    fi
fi
' || true

    # ── 2. Load vfio-pci kernel module ───────────────────────────
    info "stagelab-agent-dpdk: loading vfio-pci module"
    ssh "$REMOTE" '
modprobe vfio-pci || echo "WARNING: failed to modprobe vfio-pci (kernel may lack CONFIG_VFIO_PCI)"
# Enable unsafe NOIOMMU on hosts/VMs without an IOMMU (typical in test VMs)
if [ ! -d /sys/class/iommu ] || [ -z "$(ls -A /sys/class/iommu 2>/dev/null)" ]; then
    echo "no IOMMU detected — enabling vfio unsafe_noiommu_mode"
    echo 1 > /sys/module/vfio/parameters/enable_unsafe_noiommu_mode 2>/dev/null || true
fi
' || true

    # ── 3. Hugepages allocation ───────────────────────────────────
    info "stagelab-agent-dpdk: allocating 2 MiB hugepages"
    _hp="${STAGELAB_HUGEPAGES:-512}"
    ssh "$REMOTE" "
DPDK_HUGEPAGES_2M='${_hp}'
echo \"\$DPDK_HUGEPAGES_2M\" > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
mkdir -p /dev/hugepages
mountpoint -q /dev/hugepages || mount -t hugetlbfs nodev /dev/hugepages
got=\$(cat /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages)
echo \"hugepages: requested=\$DPDK_HUGEPAGES_2M got=\$got\"
if [ \"\$got\" -lt \"\$DPDK_HUGEPAGES_2M\" ]; then
    echo \"WARNING: only \$got of \$DPDK_HUGEPAGES_2M hugepages allocated — low RAM?\"
fi
" || true

    # ── 4. NIC DPDK-compatibility survey ─────────────────────────
    info "stagelab-agent-dpdk: surveying NIC DPDK compatibility"
    ssh "$REMOTE" '
for _iface in $(ip -o link show | awk -F: '"'"'{print $2}'"'"' | tr -d '"'"' '"'"' | grep -v "^lo$\|@"); do
    _driver=$(ethtool -i "$_iface" 2>/dev/null | awk '"'"'/^driver:/{print $2}'"'"')
    _pci=$(ethtool -i "$_iface" 2>/dev/null | awk '"'"'/^bus-info:/{print $2}'"'"')
    case "$_driver" in
        i40e|ice|mlx5_core) _status="compatible" ;;
        virtio_net)          _status="virtio-user dev only" ;;
        r8169|r8125)         _status="not compatible (Realtek)" ;;
        "")                  _status="unknown (ethtool unavailable?)" ;;
        *)                   _status="unknown/unsupported" ;;
    esac
    echo "DPDK: $_iface (pci=$_pci driver=$_driver) -- $_status"
done
' 2>/dev/null | while IFS= read -r _line; do info "  $_line"; done || true

    # ── 5. TRex bundle staging ────────────────────────────────────
    info "stagelab-agent-dpdk: staging TRex $TREX_VERSION"
    # Pass vars and the skip-SHA flag to the remote function
    _skip_sha="${STAGELAB_SKIP_SHA:-}"
    ssh "$REMOTE" "
TREX_VERSION='${TREX_VERSION}'
TREX_SHA256='${TREX_SHA256}'
TREX_URL='${TREX_URL}'
TREX_DEST='${TREX_DEST}'
STAGELAB_SKIP_SHA='${_skip_sha}'

stage_trex() {
    if [ -d \"\$TREX_DEST\" ] && [ -x \"\$TREX_DEST/t-rex-64\" ]; then
        echo \"TRex \$TREX_VERSION already staged at \$TREX_DEST — skipping\"
        return
    fi
    echo \"downloading TRex \$TREX_VERSION to /tmp/trex.tar.gz\"
    _exit_block=''
    curl -fsSL \"\$TREX_URL\" -o /tmp/trex.tar.gz || {
        echo \"WARNING: failed to download TRex — leaving /opt/trex absent\"
        _exit_block=1
    }
    if [ -z \"\${STAGELAB_SKIP_SHA:-}\" ] && [ -z \"\$_exit_block\" ]; then
        _actual=\$(sha256sum /tmp/trex.tar.gz | awk '{print \$1}')
        if [ \"\$_actual\" != \"\$TREX_SHA256\" ]; then
            echo \"WARNING: TRex SHA mismatch (actual=\$_actual expected=\$TREX_SHA256)\"
            echo \"         Set STAGELAB_SKIP_SHA=1 to bypass (dev only) or update the pinned SHA.\"
            _exit_block=1
        fi
    fi
    if [ -z \"\$_exit_block\" ]; then
        mkdir -p \"\$TREX_DEST\"
        tar -xzf /tmp/trex.tar.gz -C \"\$TREX_DEST\" --strip-components=1
        echo \"TRex staged at \$TREX_DEST\"
    fi
    rm -f /tmp/trex.tar.gz
}

stage_trex
" || true

    # ── 6. Recovery-file parent dir ───────────────────────────────
    info "stagelab-agent-dpdk: ensuring /var/lib/stagelab exists"
    ssh "$REMOTE" '
mkdir -p /var/lib/stagelab
# If a dpdk-bindings.json recovery file exists from a prior crashed run,
# leave it — the agent will replay bindings and clear it on next start.
' || true

fi
# ── end stagelab-agent-dpdk ───────────────────────────────────────

info "create venv + editable install (netkit first, then dependent packages)"
# Install order is load-bearing: netkit must be installed before simlab
# (which depends on shorewall-nft-netkit>=1.8.0). pip with -e does not
# resolve local-path editables transitively — they must be installed in
# dependency order.
STAGELAB_EXTRA=""
if [ "$ROLE" = "stagelab-agent" ] || [ "$IS_DPDK" = "1" ]; then
    STAGELAB_EXTRA=" -e packages/shorewall-nft-stagelab[dev]"
fi
ssh "$REMOTE" "cd /root/shorewall-nft && \
    python3 -m venv --system-site-packages .venv && \
    .venv/bin/pip install -q --upgrade pip && \
    .venv/bin/pip install -q \
        -e packages/shorewall-nft-netkit[dev] \
        -e 'packages/shorewall-nft[dev]' \
        -e 'packages/shorewalld[dev]' \
        -e 'packages/shorewall-nft-simlab[dev]'$STAGELAB_EXTRA && \
    .venv/bin/shorewall-nft --version"

info "verify libnftables Python bindings (required for production setns path)"
ssh "$REMOTE" 'python3 -c "
import sys
try:
    import nftables
    n = nftables.Nftables()
    print(\"libnft OK — production setns path available\")
except Exception as e:
    print(\"WARNING: python3-nftables not importable:\", e, file=sys.stderr)
    print(\"  CLI will fall back to ip netns exec for namespace operations\", file=sys.stderr)
    print(\"  Install python3-nftables for the full production code path\", file=sys.stderr)
    sys.exit(1)
" || true'


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
info "  # run full test suite (fully isolated — cannot crash the host network):"
info "  systemd-run --unit=shorewall-pytest --collect \\"
info "    --property=StandardOutput=file:/tmp/pytest.log \\"
info "    --property=StandardError=file:/tmp/pytest.log \\"
info "    /root/shorewall-nft/tools/run-tests.sh \\"
info "        packages/shorewall-nft/tests/ \\"
info "        packages/shorewalld/tests/ \\"
info "        packages/shorewall-nft-simlab/tests/ -v"
info "  # Follow: systemctl is-active shorewall-pytest; tail -f /tmp/pytest.log"
info ""
info "  # smoke the production path:"
info "  /root/shorewall-nft/.venv/bin/shorewall-nft start /etc/shorewall46"
info "  /root/shorewall-nft/.venv/bin/shorewall-nft status"
info "  /root/shorewall-nft/.venv/bin/shorewall-nft stop"
info ""
info "  # simulate against ground truth:"
info "  /root/shorewall-nft/.venv/bin/shorewall-nft simulate /root/simulate-data/etc/shorewall \\"
info "    --iptables /root/simulate-data/iptables.txt -n 60"
