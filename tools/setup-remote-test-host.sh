#!/bin/sh
# setup-remote-test-host.sh — deploy shorewall-nft to a remote test host.
#
# Supported targets:
#   AlmaLinux/RHEL/Rocky 10 with persistent storage (primary, stagelab)
#   Debian/grml (legacy, simlab only)
#
# Bootstraps a test host over SSH:
#   1. rsyncs the working copy to /root/shorewall-nft (excluding .venv, caches)
#   2. creates a venv and installs all three sub-packages (packages/*)
#   3. copies the iptables-save dump + matching shorewall config
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
#   tools/setup-remote-test-host.sh root@host --check-trex-updates
#
# --role ROLE   choose bootstrap role:
#               "default"              simlab/simulate (AlmaLinux 10 or Debian/grml)
#               "stagelab-agent"       adds iperf3/nmap/ethtool + high-pps sysctls
#                                      (AlmaLinux 10 primary target)
#               "stagelab-agent-dpdk"  stagelab-agent PLUS DPDK + TRex bootstrap
#                                      (AlmaLinux 10 only — Debian supported but not primary)
#               Default: "default".
#
# --check-trex-updates
#               Query remote /opt/trex/, the pinned version in this script,
#               and (best-effort) the cisco CDN for the latest release.
#               Never mutates remote state. Exits after printing the report.
#
# Environment variables (stagelab-agent-dpdk only):
#   STAGELAB_HUGEPAGES            2 MiB hugepages to allocate (default: 512 = 1 GiB)
#   STAGELAB_TREX_VERSION         override TRex version without editing this file
#   STAGELAB_TREX_MIRROR_URL      base URL of an internal mirror (no trailing slash)
#                                 curl downloads <URL>/<version>.tar.gz; CA-verified when https
#   STAGELAB_TREX_LOCAL_TARBALL   path to a pre-downloaded local tarball; skips network entirely
#
# The host must already accept passwordless SSH for the given user.
# Idempotent: safe to re-run on persistent-storage hosts.

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SIMULATE_SRC_DEFAULT="$REPO_DIR/../old"
SIMULATE_SRC="$SIMULATE_SRC_DEFAULT"
DEPLOY_JSON_DEFAULT="$SCRIPT_DIR/deploy.json"
DEPLOY_JSON="$DEPLOY_JSON_DEFAULT"
REMOTE=""
ROLE="default"
CHECK_TREX_UPDATES=0

# TRex installation pin. Update TREX_VERSION_LATEST_KNOWN when a newer
# release is verified to work. Set STAGELAB_TREX_VERSION in the env to
# install a specific version without editing this file.
TREX_VERSION_LATEST_KNOWN="v3.08"
TREX_VERSION="${STAGELAB_TREX_VERSION:-$TREX_VERSION_LATEST_KNOWN}"
TREX_CDN_BASE="https://trex-tgn.cisco.com/trex/release"
TREX_CA_PEM="$SCRIPT_DIR/trex-ca.pem"

info() { printf 'setup-remote-test-host: %s\n' "$1"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --simulate-src)      SIMULATE_SRC="$2"; shift 2 ;;
        --deploy-json)       DEPLOY_JSON="$2"; shift 2 ;;
        --role)              ROLE="$2"; shift 2 ;;
        --check-trex-updates) CHECK_TREX_UPDATES=1; shift ;;
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

[ -n "$REMOTE" ] || { echo "usage: $0 user@host [--simulate-src DIR] [--role default|stagelab-agent|stagelab-agent-dpdk] [--check-trex-updates]" >&2; exit 1; }

if [ "${CHECK_TREX_UPDATES}" = "1" ]; then
    # shellcheck source=tools/lib/trex-install.sh
    . "$SCRIPT_DIR/lib/trex-install.sh"
    trex_install_check_updates "$REMOTE"
    exit 0
fi

case "$ROLE" in
    default|stagelab-agent|stagelab-agent-dpdk) ;;
    *) echo "unknown role: $ROLE (expected: default, stagelab-agent, or stagelab-agent-dpdk)" >&2; exit 1 ;;
esac

# stagelab-agent-dpdk implies stagelab-agent
IS_DPDK=0
if [ "$ROLE" = "stagelab-agent-dpdk" ]; then
    IS_DPDK=1
fi

# ── Required binary sets (for post-install verification) ──────────────────────
# role=default
REQUIRED_BINS_DEFAULT="python3 ip ss nft conntrack ipset sudo rsync"
# role=stagelab-agent adds:
REQUIRED_BINS_STAGELAB="iperf3 nmap ethtool tcpdump jq"
# role=stagelab-agent-dpdk adds:
REQUIRED_BINS_DPDK="python3-pyelftools"   # checked as package; dpdk-devbind.py checked separately

# ── Verification helpers ──────────────────────────────────────────────────────

# verify_binaries: check that each binary is findable via command -v on remote.
# Usage: verify_binaries "description" bin1 bin2 ...
verify_binaries() {
    _vb_desc="$1"; shift
    _vb_missing=""
    for _vb_bin in "$@"; do
        ssh "$REMOTE" "command -v '$_vb_bin' >/dev/null 2>&1" || _vb_missing="$_vb_missing $_vb_bin"
    done
    if [ -n "$_vb_missing" ]; then
        echo "ERROR: binary verification failed for $_vb_desc on remote:" >&2
        echo "  missing binaries:$_vb_missing" >&2
        echo "  (on AlmaLinux this is usually EPEL/CRB not enabled. Check 'dnf repolist' on the remote.)" >&2
        exit 1
    fi
    info "verified binaries present for $_vb_desc:$(printf ' %s' "$@")"
}

# verify_pkg_rpm: check that each rpm package is installed on remote.
# Usage: verify_pkg_rpm "description" pkg1 pkg2 ...
verify_pkg_rpm() {
    _vp_desc="$1"; shift
    _vp_missing=""
    for _vp_pkg in "$@"; do
        ssh "$REMOTE" "rpm -q '$_vp_pkg' >/dev/null 2>&1" || _vp_missing="$_vp_missing $_vp_pkg"
    done
    if [ -n "$_vp_missing" ]; then
        echo "ERROR: RPM package verification failed for $_vp_desc:" >&2
        echo "  missing packages:$_vp_missing" >&2
        echo "  (on AlmaLinux this is usually EPEL/CRB not enabled. Check 'dnf repolist' on the remote.)" >&2
        exit 1
    fi
    info "verified RPM packages present for $_vp_desc:$(printf ' %s' "$@")"
}

# verify_sysctl: assert that a sysctl value on remote is >= minimum.
# Usage: verify_sysctl key minimum_value
verify_sysctl() {
    _vs_key="$1" _vs_min="$2"
    _vs_actual=$(ssh "$REMOTE" "sysctl -n '$_vs_key' 2>/dev/null || echo 0")
    if [ "$_vs_actual" -lt "$_vs_min" ]; then
        echo "ERROR: sysctl $_vs_key=$_vs_actual < required $_vs_min" >&2
        exit 1
    fi
    info "sysctl $_vs_key=$_vs_actual (>= required $_vs_min) OK"
}

# ─────────────────────────────────────────────────────────────────────────────

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

# ── Detect remote OS and choose install path ─────────────────────────────────
OS_ID=$(ssh "$REMOTE" '. /etc/os-release && echo "$ID:$VERSION_ID"')
info "remote OS: $OS_ID"
case "$OS_ID" in
    almalinux:10.*|almalinux:10|rhel:10.*|rocky:10.*)
        TARGET_FAMILY=rhel10 ;;
    debian:*|ubuntu:*)
        TARGET_FAMILY=debian ;;
    *)
        echo "ERROR: unsupported remote OS: $OS_ID (supported: AlmaLinux/RHEL/Rocky 10, Debian/Ubuntu)" >&2
        exit 1 ;;
esac
info "target family: $TARGET_FAMILY"

info "install base deps (idempotent)"
# Legacy: grml/Debian codepath, used for simlab-only test hosts. stagelab targets AlmaLinux 10.
if [ "$TARGET_FAMILY" = "debian" ]; then
    ssh "$REMOTE" 'DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1 || true
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        python3 python3-venv python3-pip python3.12-venv \
        python3-pytest python3-pytest-xdist python3-click python3-pyroute2 \
        python3-nftables \
        iproute2 sudo nftables conntrack ipset rsync 2>&1 | tail -10'
    verify_binaries "role=default (Debian)" python3 ip ss nft conntrack ipset sudo rsync
else
    # AlmaLinux 10 / RHEL 10: EPEL and CRB are required for python3-pyroute2,
    # python3-pytest-xdist, and several stagelab tools (iperf3, nmap).
    # Fail fast if either repo cannot be enabled — silently missing repos is
    # what caused iperf3 to vanish without error in previous bootstraps.
    ssh "$REMOTE" '
set -e
# EPEL may already be provided by a local overlay (e.g. marcant-config-repo).
# Only install epel-release if no enabled repo id matches /epel/.
if ! dnf repolist enabled 2>/dev/null | grep -qi "epel"; then
    echo "enabling EPEL (installing epel-release)..."
    dnf install -y epel-release
else
    echo "EPEL already enabled via existing repo — skipping epel-release install"
fi
echo "enabling CRB..."
dnf config-manager --set-enabled crb 2>/dev/null || \
    dnf config-manager --set-enabled powertools 2>/dev/null || \
    { echo "ERROR: could not enable crb/powertools" >&2; exit 1; }
echo "refreshing dnf metadata..."
dnf makecache -y
'
    # Verify EPEL and CRB are actually enabled (dnf config-manager is sometimes a no-op
    # when the repo id differs by distro variant).
    _repolist=$(ssh "$REMOTE" "dnf repolist enabled 2>/dev/null")
    echo "$_repolist" | grep -qi "epel" || {
        echo "ERROR: EPEL repo not enabled after dnf install epel-release." >&2
        echo "  Check 'dnf repolist' on the remote." >&2
        exit 1
    }
    echo "$_repolist" | grep -qiE "crb|powertools" || {
        echo "ERROR: CRB/powertools repo not enabled after dnf config-manager --set-enabled crb." >&2
        echo "  Check 'dnf repolist' on the remote." >&2
        exit 1
    }
    info "EPEL and CRB repos confirmed enabled"

    # Single transaction — atomic rollback on any partial failure.
    ssh "$REMOTE" '
set -e
dnf install -y \
    python3 python3-pip \
    python3-click python3-pyroute2 python3-nftables \
    python3-pytest python3-pytest-xdist \
    iproute nftables conntrack-tools ipset sudo rsync
'
    verify_binaries "role=default (AlmaLinux)" python3 ip ss nft conntrack ipset sudo rsync
fi

# ── stagelab-agent: extra tooling ─────────────────────────────────
if [ "$ROLE" = "stagelab-agent" ] || [ "$IS_DPDK" = "1" ]; then
    info "stagelab-agent: installing perf-test tooling (primary target: AlmaLinux 10)"
    # Legacy: grml/Debian codepath, used for simlab-only test hosts. stagelab targets AlmaLinux 10.
    if [ "$TARGET_FAMILY" = "debian" ]; then
        ssh "$REMOTE" '
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    iperf3 nmap ethtool bridge-utils jq tcpdump curl vsftpd snmp 2>&1 | tail -10
# TODO: tcpkali — add source-build step when needed (T8d)
if DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        linux-perf >/dev/null 2>&1; then
    echo "linux-perf installed"
else
    echo "WARNING: linux-perf not available on this distro — skipping"
fi
'
        verify_binaries "role=stagelab-agent (Debian)" iperf3 nmap ethtool tcpdump jq curl snmpget
        ssh "$REMOTE" 'mkdir -p /etc/snmp && grep -q "^mibs +ALL" /etc/snmp/snmp.conf 2>/dev/null || echo "mibs +ALL" >> /etc/snmp/snmp.conf'
    else
        # AlmaLinux 10: iperf3 is in EPEL. bridge commands come from iproute
        # (no separate bridge-utils on EL). perf = "perf" package.
        # net-snmp-utils provides snmpwalk/snmpget for operator debugging.
        # Single transaction for atomic rollback on partial failure.
        ssh "$REMOTE" '
set -e
dnf install -y iperf3 nmap ethtool jq tcpdump curl vsftpd net-snmp-utils
# TODO: tcpkali — add source-build step when needed (T8d)
'
        # perf is optional — warn but do not fail
        ssh "$REMOTE" 'dnf install -y perf >/dev/null 2>&1 && echo "perf installed" || echo "WARNING: perf not available — skipping"' || true
        verify_binaries "role=stagelab-agent (AlmaLinux)" iperf3 nmap ethtool tcpdump jq curl snmpget
    fi
    # Enable KEEPALIVED-MIB symbolic names without requiring -m +ALL on every command.
    # Without this, snmpwalk returns raw OIDs (SNMPv2-SMI::enterprises.9586...) instead of
    # KEEPALIVED-MIB::vrrpInstanceState etc. — unusable for operator debugging.
    ssh "$REMOTE" 'mkdir -p /etc/snmp && grep -q "^mibs +ALL" /etc/snmp/snmp.conf 2>/dev/null || echo "mibs +ALL" >> /etc/snmp/snmp.conf'
    info "stagelab-agent: vsftpd installed but NOT enabled."
    info "  For stateful_helper_ftp scenarios:"
    info "    systemctl start vsftpd    # on the sink tester"
    info "    useradd ftpuser; echo 'ftpuser:ftpuser' | chpasswd"

    info "stagelab-agent: applying sysctls (persistent on AlmaLinux 10)"
    # nf_conntrack module must be loaded before /proc/sys/net/netfilter/nf_conntrack_max exists.
    ssh "$REMOTE" 'modprobe nf_conntrack 2>/dev/null || true'
    ssh "$REMOTE" 'sysctl -w net.netfilter.nf_conntrack_max=4194304' || \
        { echo "ERROR: could not set nf_conntrack_max" >&2; exit 1; }
    ssh "$REMOTE" 'sysctl -w net.core.rmem_max=134217728' || \
        { echo "ERROR: could not set rmem_max" >&2; exit 1; }
    ssh "$REMOTE" 'sysctl -w net.core.wmem_max=134217728' || \
        { echo "ERROR: could not set wmem_max" >&2; exit 1; }
    verify_sysctl net.netfilter.nf_conntrack_max 4194304
    verify_sysctl net.core.rmem_max 134217728
    verify_sysctl net.core.wmem_max 134217728

    info "stagelab-agent: probing NIC offload capabilities"
    probe_nics
fi
# ──────────────────────────────────────────────────────────────────

# ── stagelab-agent-dpdk: DPDK + TRex bootstrap ────────────────────
if [ "$IS_DPDK" = "1" ]; then
    # ── 0. Detach DPDK-candidate NICs from NetworkManager ───────
    # Any NIC we will later bind to vfio-pci MUST be marked unmanaged in NM,
    # otherwise NM will re-claim it on carrier change and fight the agent's
    # DPDK setup/teardown. Idempotent: if the interface is already unmanaged
    # (via netns-routing's pre-existing conf, via this script's own conf,
    # or via no NM at all), we skip delete + reload.
    _DPDK_IFACES="${STAGELAB_DPDK_IFACES:-eth1 eth2}"
    info "stagelab-agent-dpdk: ensuring NM treats DPDK NICs as unmanaged ($_DPDK_IFACES)"
    # shellcheck disable=SC2029
    ssh "$REMOTE" "
set -e
DPDK_IFACES='$_DPDK_IFACES'
if ! systemctl is-active --quiet NetworkManager; then
    echo 'NetworkManager not active — nothing to do'
    exit 0
fi

_changed=0
for _if in \$DPDK_IFACES; do
    # Only act on interfaces that actually exist
    ip link show \"\$_if\" >/dev/null 2>&1 || { echo \"skip \$_if (not present)\"; continue; }

    _state=\$(nmcli -t -f DEVICE,STATE device status 2>/dev/null | awk -F: -v d=\"\$_if\" '\$1==d{print \$2}')
    if [ \"\$_state\" = 'unmanaged' ]; then
        echo \"\$_if: already unmanaged\"
        continue
    fi

    # Delete any NM connection profiles bound to this device (ifcfg or nmconnection)
    nmcli -t -f NAME,DEVICE connection show 2>/dev/null \\
        | awk -F: -v d=\"\$_if\" '\$2==d{print \$1}' \\
        | while IFS= read -r _conn; do
            [ -n \"\$_conn\" ] || continue
            echo \"deleting NM connection \$_conn (device \$_if)\"
            nmcli connection delete \"\$_conn\" || true
        done
    _changed=1
done

# Write our own keyfile so unmanaged persists across reboots.
# Separate filename (stagelab-unmanaged.conf) so we don't collide with
# pre-existing unmanaged-devices lists (e.g. netns-routing's
# 10-netns-unmanaged.conf). NM merges all *.conf additively.
mkdir -p /etc/NetworkManager/conf.d
cat > /etc/NetworkManager/conf.d/20-stagelab-unmanaged.conf <<EOF
# Written by tools/setup-remote-test-host.sh --role stagelab-agent-dpdk
# Keeps DPDK-candidate NICs out of NetworkManager so vfio-pci binding
# in topology_dpdk is not racing against NM autoconnect.
[keyfile]
unmanaged-devices=\$(echo \$DPDK_IFACES | tr ' ' ';' | sed 's/^/interface-name:/;s/;/;interface-name:/g')
EOF

if [ \"\$_changed\" -eq 1 ] || ! grep -q '20-stagelab-unmanaged' /proc/\$(pidof NetworkManager)/cmdline 2>/dev/null; then
    echo 'reloading NetworkManager config'
    systemctl reload NetworkManager || nmcli general reload 2>/dev/null || true
fi

# Final verify: every requested iface must now be unmanaged.
for _if in \$DPDK_IFACES; do
    ip link show \"\$_if\" >/dev/null 2>&1 || continue
    _st=\$(nmcli -t -f DEVICE,STATE device status 2>/dev/null | awk -F: -v d=\"\$_if\" '\$1==d{print \$2}')
    if [ \"\$_st\" != 'unmanaged' ]; then
        echo \"ERROR: \$_if still not unmanaged after NM reload (state=\$_st)\" >&2
        exit 1
    fi
    echo \"\$_if: unmanaged OK\"
done
"

    # ── 1. DPDK tooling install ──────────────────────────────────
    info "stagelab-agent-dpdk: installing DPDK tooling (primary target: AlmaLinux 10)"
    # Legacy: grml/Debian codepath, used for simlab-only test hosts. stagelab targets AlmaLinux 10.
    if [ "$TARGET_FAMILY" = "debian" ]; then
        ssh "$REMOTE" '
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    dpdk python3-pyelftools 2>&1 | tail -10
# dpdk-kmods-dkms may fail on kernels without matching headers — log and continue
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    dpdk-kmods-dkms 2>&1 | tail -5 || echo "WARNING: dpdk-kmods-dkms not available — skipping"
'
        # dpkg-based: verify pyelftools via python3 import (no rpm -q available)
        ssh "$REMOTE" "python3 -c 'import elftools' >/dev/null 2>&1" || {
            echo "ERROR: python3-pyelftools not importable after apt install" >&2; exit 1
        }
    else
        # AlmaLinux 10: single transaction for atomic rollback.
        ssh "$REMOTE" '
set -e
dnf install -y dpdk dpdk-tools python3-pyelftools
'
        verify_pkg_rpm "role=stagelab-agent-dpdk (AlmaLinux)" python3-pyelftools
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
'
    # Verify dpdk-devbind.py is reachable via PATH or known paths
    ssh "$REMOTE" '
command -v dpdk-devbind.py >/dev/null 2>&1 || \
test -f /usr/share/dpdk/usertools/dpdk-devbind.py || \
test -f /usr/sbin/dpdk-devbind.py || \
test -f /usr/local/sbin/dpdk-devbind.py || {
    echo "ERROR: dpdk-devbind.py not found after install — DPDK NIC binding unavailable" >&2
    exit 1
}
echo "dpdk-devbind.py: present"
' || exit 1
    info "dpdk-devbind.py verified present"

    # ── 2. Load vfio-pci kernel module ───────────────────────────
    info "stagelab-agent-dpdk: loading vfio-pci module"
    ssh "$REMOTE" '
modprobe vfio-pci || echo "WARNING: failed to modprobe vfio-pci (kernel may lack CONFIG_VFIO_PCI)"
# Enable unsafe NOIOMMU on hosts/VMs without an IOMMU (typical in test VMs)
if [ ! -d /sys/class/iommu ] || [ -z "$(ls -A /sys/class/iommu 2>/dev/null)" ]; then
    echo "no IOMMU detected — enabling vfio unsafe_noiommu_mode"
    echo 1 > /sys/module/vfio/parameters/enable_unsafe_noiommu_mode 2>/dev/null || true
fi
'
    # Verify vfio-pci module is live
    _vfio_state=$(ssh "$REMOTE" "cat /sys/module/vfio_pci/initstate 2>/dev/null || echo absent")
    if [ "$_vfio_state" != "live" ]; then
        echo "ERROR: vfio-pci module not live after modprobe (initstate=$_vfio_state)." >&2
        echo "  The kernel may lack CONFIG_VFIO_PCI. Check 'modinfo vfio-pci' on the remote." >&2
        exit 1
    fi
    info "vfio-pci module: live"

    # ── 3. Hugepages allocation ───────────────────────────────────
    info "stagelab-agent-dpdk: allocating 2 MiB hugepages"
    _hp="${STAGELAB_HUGEPAGES:-512}"
    ssh "$REMOTE" "
DPDK_HUGEPAGES_2M='${_hp}'
_cur=\$(cat /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages 2>/dev/null || echo 0)
if [ \"\$_cur\" -lt \"\$DPDK_HUGEPAGES_2M\" ]; then
    echo \"\$DPDK_HUGEPAGES_2M\" > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
fi
mkdir -p /dev/hugepages
mountpoint -q /dev/hugepages || mount -t hugetlbfs nodev /dev/hugepages
got=\$(cat /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages)
echo \"hugepages: requested=\$DPDK_HUGEPAGES_2M got=\$got\"
if [ \"\$got\" -lt \"\$DPDK_HUGEPAGES_2M\" ]; then
    echo \"WARNING: only \$got of \$DPDK_HUGEPAGES_2M hugepages allocated — low RAM?\"
fi
"
    # Verify hugepages count and /dev/hugepages mount
    _hp_actual=$(ssh "$REMOTE" "cat /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages 2>/dev/null || echo 0")
    if [ "$_hp_actual" -lt "$_hp" ]; then
        echo "ERROR: hugepages allocated=$_hp_actual < requested=$_hp — insufficient RAM?" >&2
        exit 1
    fi
    info "hugepages: $_hp_actual x 2 MiB allocated (requested $_hp)"
    ssh "$REMOTE" "mountpoint -q /dev/hugepages" || {
        echo "ERROR: /dev/hugepages is not mounted after mount attempt" >&2
        exit 1
    }
    info "/dev/hugepages: mounted"

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
    # shellcheck source=tools/lib/trex-install.sh
    . "$SCRIPT_DIR/lib/trex-install.sh"
    info "stagelab-agent-dpdk: staging TRex $TREX_VERSION"
    trex_install_stage "$REMOTE" "$TREX_VERSION"
    trex_install_verify "$REMOTE" "$TREX_VERSION"

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
# Idempotent: if venv already exists and shorewall_nft is importable, skip
# venv recreation and only upgrade deps as needed.
STAGELAB_EXTRA=""
if [ "$ROLE" = "stagelab-agent" ] || [ "$IS_DPDK" = "1" ]; then
    STAGELAB_EXTRA=" -e 'packages/shorewall-nft-stagelab[dev,snmp]'"
fi
ssh "$REMOTE" "
cd /root/shorewall-nft
_venv_ok=0
if [ -x .venv/bin/python ] && .venv/bin/python -c 'import shorewall_nft' >/dev/null 2>&1; then
    echo 'venv exists and shorewall_nft importable — upgrading deps only'
    _venv_ok=1
fi
if [ \"\$_venv_ok\" = '0' ]; then
    python3 -m venv --system-site-packages .venv
    .venv/bin/pip install -q --upgrade pip
fi
.venv/bin/pip install -q --upgrade-strategy only-if-needed \
    -e packages/shorewall-nft-netkit[dev] \
    -e 'packages/shorewall-nft[dev]' \
    -e 'packages/shorewalld[dev]' \
    -e 'packages/shorewall-nft-simlab[dev]'${STAGELAB_EXTRA}
.venv/bin/shorewall-nft --version
"

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
