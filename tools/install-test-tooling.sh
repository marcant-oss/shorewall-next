#!/bin/sh
#
# install-test-tooling.sh — one-shot installer for shorewall-nft test tooling
#
# Installs:
#   /usr/local/bin/run-netns           — ip netns wrapper (root:root 0755)
#   /etc/sudoers.d/shorewall-nft-tests — NOPASSWD rule for the netns-test group
#
# Also ensures the `netns-test` group exists and (by default) adds the
# current user to it, so the shorewall-nft test suite can run without
# further configuration.
#
# Usage:
#   sudo tools/install-test-tooling.sh
#   sudo tools/install-test-tooling.sh --user alice
#   sudo tools/install-test-tooling.sh --uninstall
#
# Safe to re-run: everything is idempotent. visudo -c is used to validate
# the sudoers snippet before installing it.
#
# REQUIREMENTS: root, /sbin/ip (iproute2), visudo, groupadd/usermod.

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WRAPPER_SRC="$SCRIPT_DIR/run-netns"
WRAPPER_DST="/usr/local/bin/run-netns"
SUDOERS_SRC="$SCRIPT_DIR/sudoers.d-shorewall-nft"
SUDOERS_DST="/etc/sudoers.d/shorewall-nft-tests"
GROUP="netns-test"
TARGET_USER="${SUDO_USER:-${USER:-root}}"
UNINSTALL=0

die() {
    printf >&2 "install-test-tooling: %s\n" "$1"
    exit 1
}

info() {
    printf "install-test-tooling: %s\n" "$1"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --user)       TARGET_USER="$2"; shift 2 ;;
        --no-user)    TARGET_USER=""; shift ;;
        --uninstall)  UNINSTALL=1; shift ;;
        -h|--help)
            sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) die "unknown argument: $1" ;;
    esac
done

[ "$(id -u)" -eq 0 ] || die "must run as root (try: sudo $0)"

if [ "$UNINSTALL" -eq 1 ]; then
    info "removing $WRAPPER_DST and $SUDOERS_DST"
    rm -f "$WRAPPER_DST" "$SUDOERS_DST"
    info "NOTE: the '$GROUP' group and its members are left untouched."
    info "done."
    exit 0
fi

# Sanity checks
[ -x /sbin/ip ] || [ -x /usr/bin/ip ] || [ -x /usr/sbin/ip ] || \
    die "ip binary not found — install iproute2"
command -v visudo >/dev/null 2>&1 || die "visudo not found — install sudo"
[ -f "$WRAPPER_SRC" ] || die "missing $WRAPPER_SRC"
[ -f "$SUDOERS_SRC" ] || die "missing $SUDOERS_SRC"

# 1. Install the wrapper
install -o root -g root -m 0755 "$WRAPPER_SRC" "$WRAPPER_DST"
info "installed $WRAPPER_DST"

# 2. Ensure the group exists
if ! getent group "$GROUP" >/dev/null; then
    groupadd --system "$GROUP"
    info "created group '$GROUP'"
else
    info "group '$GROUP' already exists"
fi

# 3. Install the sudoers snippet (validated with visudo -c)
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT
cp "$SUDOERS_SRC" "$TMP"
chmod 0440 "$TMP"
if ! visudo -cf "$TMP" >/dev/null; then
    die "sudoers snippet failed visudo validation ($SUDOERS_SRC)"
fi
install -o root -g root -m 0440 "$SUDOERS_SRC" "$SUDOERS_DST"
info "installed $SUDOERS_DST"

# 4. Optionally add the current user to the group
if [ -n "$TARGET_USER" ]; then
    if id "$TARGET_USER" >/dev/null 2>&1; then
        if id -nG "$TARGET_USER" | tr ' ' '\n' | grep -qx "$GROUP"; then
            info "user '$TARGET_USER' is already in '$GROUP'"
        else
            usermod -aG "$GROUP" "$TARGET_USER"
            info "added '$TARGET_USER' to '$GROUP' — log out/in for this to take effect"
        fi
    else
        info "WARNING: user '$TARGET_USER' does not exist; skipping group add"
    fi
fi

# 5. Quick smoke test (runs as root, should always work)
if /usr/local/bin/run-netns list >/dev/null 2>&1; then
    info "smoke test OK: run-netns list succeeded as root"
else
    info "WARNING: smoke test failed — check /usr/local/bin/run-netns manually"
fi

info "done. To verify as the test user:"
info "  sudo /usr/local/bin/run-netns list"
info "  pytest tests/test_cli_integration.py -v"
