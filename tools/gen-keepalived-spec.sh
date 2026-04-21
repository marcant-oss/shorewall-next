#!/usr/bin/env bash
# Generate packaging/rpm/keepalived-marcant.spec from the .spec.in template.
#
# Keepalived version is PINNED to a specific upstream release.  Bumping the
# version is a deliberate manual decision — see the TODO comment in the spec.
#
# TODO: periodically check https://github.com/acassen/keepalived/releases for
#       a newer version and update KEEPALIVED_VERSION below.
KEEPALIVED_VERSION="2.3.4"
#
# Release scheme (mirrors gen-rpm-spec.sh convention for dev builds):
#   - HEAD is exactly on a v* tag → Release=1%{?dist}
#   - HEAD is after the last v* tag → Release=0.<commits_since>.g<sha>%{?dist}
#   - No v* tag in history → Release=0.0.g<sha>%{?dist}
#
# Usage: tools/gen-keepalived-spec.sh [--out PATH] [--template PATH]

set -euo pipefail

OUT="packaging/rpm/keepalived-marcant.spec"
TEMPLATE="packaging/rpm/keepalived-marcant.spec.in"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --out)      OUT="$2";      shift 2 ;;
        --template) TEMPLATE="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,20p' "$0"
            exit 0
            ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

[[ -f "$TEMPLATE" ]] || { echo "error: template not found: $TEMPLATE" >&2; exit 1; }

# ---- release derivation from git (same logic as gen-rpm-spec.sh) ----
SHA=$(git rev-parse --short=7 HEAD 2>/dev/null || echo "unknown")
LAST_TAG=$(git describe --tags --match 'v*' --abbrev=0 2>/dev/null || true)

if git describe --tags --exact-match --match 'v*' HEAD >/dev/null 2>&1; then
    RELEASE="1"
elif [[ -n "$LAST_TAG" ]]; then
    COMMITS_SINCE=$(git rev-list --count "${LAST_TAG}..HEAD")
    RELEASE="0.${COMMITS_SINCE}.g${SHA}"
else
    RELEASE="0.0.g${SHA}"
fi

# ---- build and runtime dependencies (AL10 only for now) ----
# AL10 ships libnftnl + libnftables from BaseOS, libipset from BaseOS,
# net-snmp-devel from BaseOS/AppStream, glib2-devel from BaseOS.
# NOTE: libbpf-devel is intentionally absent — keepalived v2.3.4 has no
# eBPF/XDP support (no --enable-ebpf configure flag, zero BPF source files).
# See docs/testing/keepalived-features-roadmap.md for the deferral rationale.
BUILD_REQUIRES='BuildRequires:  gcc make autoconf automake libtool
BuildRequires:  libnl3-devel
BuildRequires:  libnftnl-devel
BuildRequires:  libnftables-devel
BuildRequires:  libipset-devel
BuildRequires:  net-snmp-devel
BuildRequires:  glib2-devel
BuildRequires:  dbus-devel
BuildRequires:  openssl-devel
BuildRequires:  libpcre2-devel
BuildRequires:  systemd-devel
BuildRequires:  systemd-rpm-macros
BuildRequires:  pkgconf-pkg-config'

# Runtime Requires for AL10: distro packages that ship the shared libs.
# EPEL is required on the target host for some of these.
DISTRO_REQUIRES='Requires:       net-snmp
Requires:       libnftnl
Requires:       libnftables
Requires:       libipset
Requires:       iproute-tc
Requires:       systemd
Recommends:     python3-dbus'

# ---- changelog entry ----
TODAY=$(date -u +"%a %b %d %Y")
MAINTAINER="André Valentin <avalentin@marcant.net>"
HEAD_SHA=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
if [[ "$RELEASE" == "1" ]]; then
    ENTRY_BODY="- keepalived-marcant ${KEEPALIVED_VERSION} release build."
else
    ENTRY_BODY="- keepalived-marcant ${KEEPALIVED_VERSION} development build from ${HEAD_SHA}."
fi
CHANGELOG_ENTRY="* ${TODAY} ${MAINTAINER} - ${KEEPALIVED_VERSION}-${RELEASE}
${ENTRY_BODY}"

# ---- substitute into template ----
export KEEPALIVED_VERSION RELEASE BUILD_REQUIRES DISTRO_REQUIRES CHANGELOG_ENTRY

perl -pe '
    BEGIN {
        $kv = $ENV{KEEPALIVED_VERSION};
        $r  = $ENV{RELEASE};
        $b  = $ENV{BUILD_REQUIRES};
        $d  = $ENV{DISTRO_REQUIRES};
        $c  = $ENV{CHANGELOG_ENTRY};
    }
    s/\@\@KEEPALIVED_VERSION\@\@/$kv/g;
    s/\@\@RELEASE\@\@/$r/g;
    s/\@\@BUILD_REQUIRES\@\@/$b/g;
    s/\@\@DISTRO_REQUIRES\@\@/$d/g;
    s/\@\@CHANGELOG_ENTRY\@\@/$c/g;
' "$TEMPLATE" > "$OUT"

echo "generated $OUT  keepalived_version=${KEEPALIVED_VERSION}  release=${RELEASE}"
