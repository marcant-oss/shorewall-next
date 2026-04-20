#!/bin/bash
set -eu
SCRIPT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
LIB="$SCRIPT_DIR/tools/lib/trex-install.sh"

# Fake ssh/rsync/curl binaries that record argv and return canned results.
TMPD="$(mktemp -d)"
trap 'rm -rf "$TMPD"' EXIT
TMPD_LOG="$TMPD"
mkdir -p "$TMPD_LOG"

cat > "$TMPD/ssh" <<'FAKESSH'
#!/bin/bash
echo "ssh $*" >> "$TMPD_LOG/ssh.log"
# For `test -x /opt/trex/.../t-rex-64`: return non-zero so install proceeds.
# For subsequent commands: 0.
case "$*" in *"test -x /opt/trex/"*) exit 1 ;; esac
exit 0
FAKESSH

cat > "$TMPD/rsync" <<'FAKERSYNC'
#!/bin/bash
echo "rsync $*" >> "$TMPD_LOG/rsync.log"
FAKERSYNC

cat > "$TMPD/curl" <<'FAKECURL'
#!/bin/bash
echo "curl $*" >> "$TMPD_LOG/curl.log"
# If output file (-o) given, create it.
while [ $# -gt 0 ]; do
    case "$1" in
        -o) touch "$2"; shift 2 ;;
        --cacert) shift 2 ;;
        *) shift ;;
    esac
done
FAKECURL

chmod +x "$TMPD/ssh" "$TMPD/rsync" "$TMPD/curl"
export TMPD_LOG
export PATH="$TMPD:$PATH"

# Provide the variables and info() that the library expects from the caller.
TREX_CDN_BASE="https://trex-tgn.cisco.com/trex/release"
TREX_VERSION_LATEST_KNOWN="v3.04"
TREX_CA_PEM="/tmp/fake-ca.pem"
info() { echo "[info] $*"; }

# Source the library under test.
# shellcheck source=tools/lib/trex-install.sh
. "$LIB"

_failures=0

test_local_tarball_bypasses_curl() {
    export STAGELAB_TREX_LOCAL_TARBALL="/tmp/fake.tar.gz"
    unset STAGELAB_TREX_MIRROR_URL 2>/dev/null || true
    > "$TMPD/curl.log"
    trex_install_stage root@host v3.04
    if grep -q "curl" "$TMPD/curl.log"; then
        echo "FAIL: local tarball path invoked curl"
        _failures=$((_failures + 1))
        unset STAGELAB_TREX_LOCAL_TARBALL
        return
    fi
    unset STAGELAB_TREX_LOCAL_TARBALL
    echo "PASS: local tarball bypasses curl"
}

test_no_ca_no_mirror_fails() {
    unset STAGELAB_TREX_LOCAL_TARBALL 2>/dev/null || true
    unset STAGELAB_TREX_MIRROR_URL 2>/dev/null || true
    TREX_CA_PEM="/nonexistent/ca.pem"
    if trex_install_stage root@host v3.04 2>/dev/null; then
        echo "FAIL: expected install to fail without CA/mirror/tarball"
        _failures=$((_failures + 1))
        TREX_CA_PEM="/tmp/fake-ca.pem"
        return
    fi
    TREX_CA_PEM="/tmp/fake-ca.pem"
    echo "PASS: refuses install without CA"
}

test_mirror_url_used() {
    unset STAGELAB_TREX_LOCAL_TARBALL 2>/dev/null || true
    export STAGELAB_TREX_MIRROR_URL="https://mirror.example/trex"
    > "$TMPD/ssh.log"
    trex_install_stage root@host v3.04 || true
    if ! grep -q "mirror.example" "$TMPD/ssh.log"; then
        echo "FAIL: mirror URL not used"
        _failures=$((_failures + 1))
        unset STAGELAB_TREX_MIRROR_URL
        return
    fi
    unset STAGELAB_TREX_MIRROR_URL
    echo "PASS: mirror URL used when set"
}

test_local_tarball_bypasses_curl
test_no_ca_no_mirror_fails
test_mirror_url_used

if [ "$_failures" -eq 0 ]; then
    echo "all tests passed"
else
    echo "$_failures test(s) failed" >&2
    exit 1
fi
