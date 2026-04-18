#!/usr/bin/env bash
# run-tests.sh — run pytest inside a fully isolated network + mount namespace.
#
# Prevents tests from affecting the test host's network stack:
#   - private network namespace: nft rules / sysctl changes cannot escape
#   - private mount namespace:   ip netns add/delete write to a private tmpfs
#                                (/run/netns) invisible to the host
#   - loopback brought up:       shorewalld UDP peer tests need 127.0.0.1
#
# Usage (must run as root):
#   tools/run-tests.sh [pytest-args...]
#   tools/run-tests.sh packages/shorewall-nft/tests/ -v -k netns
#
# Via systemd-run (recommended for remote hosts — survives disconnect):
#   systemd-run --unit=shorewall-pytest --collect \
#     --working-directory=/root/shorewall-nft \
#     --property=StandardOutput=file:/tmp/pytest.log \
#     --property=StandardError=file:/tmp/pytest.log \
#     /root/shorewall-nft/tools/run-tests.sh \
#       packages/shorewall-nft/tests/ \
#       packages/shorewalld/tests/ \
#       packages/shorewall-nft-simlab/tests/ -v
#
#   # Follow: systemctl is-active shorewall-pytest; tail -f /tmp/pytest.log
#   # Stop:   systemctl stop shorewall-pytest && systemctl reset-failed shorewall-pytest
#
# No extra tooling needed: just iproute2 + util-linux (unshare).
# The old run-netns wrapper and its sudoers entry are no longer required.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── namespace bootstrap ───────────────────────────────────────────────────────
# On first invocation: re-exec ourselves inside a private network + mount
# namespace.  The env var prevents infinite re-exec.
if [[ "${_SWNFT_ISOLATED:-0}" != "1" ]]; then
    exec unshare --mount --net -- env _SWNFT_ISOLATED=1 "$0" "$@"
fi

# ── inside the isolated namespace ────────────────────────────────────────────

# Loopback starts DOWN in a fresh netns — bring it up.
ip link set lo up

# Make all current mounts private so nothing propagates back to the host.
mount --make-rprivate / 2>/dev/null || mount --make-private / 2>/dev/null || true

# Overlay /run/netns with a private tmpfs.  ip netns add writes bind-mounts
# here; they stay inside this namespace and don't touch the host.
mkdir -p /run/netns
mount -t tmpfs tmpfs /run/netns

# ── run pytest ───────────────────────────────────────────────────────────────
cd "$REPO"
# Use venv python if present (local dev), otherwise fall back to system python.
if [[ -x "$REPO/.venv/bin/python" ]]; then
    exec "$REPO/.venv/bin/python" -m pytest "$@"
else
    exec python3 -m pytest "$@"
fi
