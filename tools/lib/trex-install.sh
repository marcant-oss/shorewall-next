#!/bin/bash
# trex-install.sh — TRex installation helpers for setup-remote-test-host.sh.
# Sourced (not executed) by the main script.  All functions expect the caller
# to have exported: TREX_CDN_BASE, TREX_VERSION_LATEST_KNOWN, TREX_CA_PEM,
# and the info() shell function.
set -eu

# trex_install_check_updates REMOTE
#   List /opt/trex/ versions on remote, print the pinned TREX_VERSION_LATEST_KNOWN,
#   and (best-effort) HTTP-HEAD cisco CDN for the latest tagged release listing.
#   Never mutates remote state.
trex_install_check_updates() {
    _r="$1"
    info "installed on $_r:"
    ssh "$_r" 'ls -1 /opt/trex/ 2>/dev/null || echo "(none)"' | sed 's/^/  /'
    info "pinned in this script: $TREX_VERSION_LATEST_KNOWN"
    _cdn_latest=$(
        curl -sS --max-time 8 --cacert "$TREX_CA_PEM" \
            "$TREX_CDN_BASE/" 2>/dev/null \
          | grep -oE 'v[0-9]+\.[0-9]+' | sort -V | tail -1 || echo ""
    )
    if [ -n "$_cdn_latest" ]; then
        info "cisco CDN latest: $_cdn_latest"
        if [ "$_cdn_latest" != "$TREX_VERSION_LATEST_KNOWN" ]; then
            info "  -> newer release available; update TREX_VERSION_LATEST_KNOWN after testing"
        fi
    else
        info "cisco CDN latest: (could not query — CDN unreachable or CA issue)"
    fi
}

# trex_install_stage REMOTE VERSION
#   Idempotent. Skips if /opt/trex/VERSION/t-rex-64 is already executable.
#   Source priority:
#     1. STAGELAB_TREX_LOCAL_TARBALL (rsync the local file to remote /tmp)
#     2. STAGELAB_TREX_MIRROR_URL     (curl from internal mirror; CA-verified when https)
#     3. TREX_CDN_BASE                 (curl with --cacert trex-ca.pem)
#   Non-zero exit on any install failure.
trex_install_stage() {
    _r="$1"; _v="$2"
    if ssh "$_r" "test -x /opt/trex/$_v/t-rex-64" 2>/dev/null; then
        info "TRex $_v already staged on $_r — skipping"
        return 0
    fi
    _tarball="/tmp/trex-$_v.tar.gz"

    if [ -n "${STAGELAB_TREX_LOCAL_TARBALL:-}" ]; then
        info "TRex $_v: rsync local $STAGELAB_TREX_LOCAL_TARBALL -> $_r:$_tarball"
        rsync -q "$STAGELAB_TREX_LOCAL_TARBALL" "$_r:$_tarball"
    elif [ -n "${STAGELAB_TREX_MIRROR_URL:-}" ]; then
        _url="$STAGELAB_TREX_MIRROR_URL/$_v.tar.gz"
        info "TRex $_v: downloading from mirror $_url"
        ssh "$_r" "curl -fsSL -o '$_tarball' '$_url'" || {
            echo "ERROR: mirror download failed ($_url)" >&2
            return 1
        }
    else
        if [ ! -f "$TREX_CA_PEM" ]; then
            cat >&2 <<EOF
ERROR: cannot download TRex from $TREX_CDN_BASE — no CA pem at:
    $TREX_CA_PEM
Either:
  - commit a valid tools/trex-ca.pem (extract via openssl s_client), or
  - set STAGELAB_TREX_MIRROR_URL to an internal mirror, or
  - set STAGELAB_TREX_LOCAL_TARBALL to a local tarball path.
EOF
            return 1
        fi
        # Copy CA pem to remote so curl-on-remote can use it.
        rsync -q "$TREX_CA_PEM" "$_r:/tmp/trex-ca.pem"
        _url="$TREX_CDN_BASE/$_v.tar.gz"
        info "TRex $_v: downloading from cisco CDN"
        ssh "$_r" "curl -fsSL --cacert /tmp/trex-ca.pem -o '$_tarball' '$_url'" || {
            echo "ERROR: cisco CDN download failed ($_url). Check tools/trex-ca.pem is up-to-date." >&2
            return 1
        }
    fi

    info "TRex $_v: extracting to /opt/trex/$_v/"
    ssh "$_r" "
        set -e
        mkdir -p /opt/trex/$_v
        tar -xzf '$_tarball' -C /opt/trex/$_v --strip-components=1
        rm -f '$_tarball'
    " || {
        echo "ERROR: tar extraction failed" >&2
        return 1
    }
    info "TRex $_v: staged"
}

# trex_install_verify REMOTE VERSION
#   Sanity-check the binary is present + runnable.
trex_install_verify() {
    _r="$1"; _v="$2"
    if ssh "$_r" "test -x /opt/trex/$_v/t-rex-64"; then
        info "TRex $_v: t-rex-64 binary verified on $_r"
    else
        echo "ERROR: /opt/trex/$_v/t-rex-64 not executable after install" >&2
        return 1
    fi
}
