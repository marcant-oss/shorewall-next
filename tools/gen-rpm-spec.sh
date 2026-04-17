#!/usr/bin/env bash
# Generate packaging/rpm/shorewall-nft.spec from the .spec.in template.
#
# Version/Release scheme:
#   - HEAD is exactly on a v* tag → Version=<tag>,  Release=1%{?dist}
#   - HEAD is after the last v* tag → Version=<last-tag>,
#                                     Release=0.<commits_since>.g<sha>%{?dist}
#     (the leading "0." keeps dev builds sorted under numbered releases.)
#   - No v* tag in history → fall back to pyproject version + 0.0.g<sha>.
#
# Usage: tools/gen-rpm-spec.sh --distro {fedora|almalinux10} [--out PATH] [--template PATH]

set -euo pipefail

DISTRO=""
OUT="packaging/rpm/shorewall-nft.spec"
TEMPLATE="packaging/rpm/shorewall-nft.spec.in"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --distro)   DISTRO="$2";   shift 2 ;;
        --out)      OUT="$2";      shift 2 ;;
        --template) TEMPLATE="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,13p' "$0"
            exit 0
            ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

[[ -n "$DISTRO"   ]] || { echo "error: --distro is required (fedora|almalinux10)" >&2; exit 2; }
[[ -f "$TEMPLATE" ]] || { echo "error: template not found: $TEMPLATE" >&2; exit 1; }

# ---- version / release from git ----
SHA=$(git rev-parse --short=7 HEAD 2>/dev/null || echo "unknown")
LAST_TAG=$(git describe --tags --match 'v*' --abbrev=0 2>/dev/null || true)

if git describe --tags --exact-match --match 'v*' HEAD >/dev/null 2>&1; then
    VERSION="${LAST_TAG#v}"
    RELEASE="1"
elif [[ -n "$LAST_TAG" ]]; then
    COMMITS_SINCE=$(git rev-list --count "${LAST_TAG}..HEAD")
    VERSION="${LAST_TAG#v}"
    RELEASE="0.${COMMITS_SINCE}.g${SHA}"
else
    VERSION=$(python3 - <<'PY'
import tomllib
print(tomllib.load(open("packages/shorewall-nft/pyproject.toml","rb"))["project"]["version"])
PY
)
    RELEASE="0.0.g${SHA}"
fi

# ---- distro-specific BuildRequires + Requires ----
case "$DISTRO" in
    fedora)
        BUILD_REQUIRES='BuildRequires:  python3 >= 3.11
BuildRequires:  python3-setuptools >= 68.0
BuildRequires:  python3-pip'

        DISTRO_REQUIRES='Requires:       python3 >= 3.11
Requires:       python3-click >= 8.0
Requires:       python3-pyroute2 >= 0.7
Requires:       nftables
Requires:       iproute
Recommends:     python3-nftables
Recommends:     ipset
# shorewalld deps
Requires:       python3-protobuf >= 4.25
Requires:       python3-prometheus_client >= 0.20
Requires:       python3-dns >= 2.4
# simlab optional
Suggests:       python3-scapy'

        TESTS_PYTEST_REQ='Requires:       python3-pytest >= 8.0'
        ;;

    almalinux10)
        # Versions reflect what AlmaLinux 10 actually ships:
        # - python3 3.12, python3-setuptools 69, python3-dns 2.6, python3-scapy 2.6 (AppStream/BaseOS)
        # - python3-protobuf 3.19.6 (AppStream — no newer version available)
        # - python3-click, python3-pyroute2, python3-prometheus_client, python3-pytest (EPEL 10 / CRB)
        BUILD_REQUIRES='BuildRequires:  python3 >= 3.12
BuildRequires:  python3-setuptools >= 69.0
BuildRequires:  python3-pip'

        DISTRO_REQUIRES='Requires:       python3 >= 3.12
Requires:       python3-click >= 8.1
Requires:       python3-pyroute2 >= 0.7
Requires:       nftables
Requires:       iproute
Recommends:     python3-nftables
Recommends:     ipset
# shorewalld deps — AL10 AppStream ships python3-protobuf 3.19.6 (no newer version).
Requires:       python3-protobuf >= 3.19
Requires:       python3-prometheus_client >= 0.20
Requires:       python3-dns >= 2.6
# simlab optional
Suggests:       python3-scapy'

        TESTS_PYTEST_REQ='Requires:       python3-pytest >= 7.4'
        ;;

    *)
        echo "error: unknown --distro: $DISTRO (expected: fedora|almalinux10)" >&2
        exit 2
        ;;
esac

# ---- changelog entry for this build ----
TODAY=$(date -u +"%a %b %d %Y")
MAINTAINER="shorewall-nft maintainers <shorewall-nft@example.com>"
HEAD_SHA=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
if [[ "$RELEASE" == "1" ]]; then
    ENTRY_BODY="- Release ${VERSION} — see CHANGELOG.md for details."
else
    ENTRY_BODY="- Development build from ${HEAD_SHA} (${DISTRO} profile)."
fi
CHANGELOG_ENTRY="* ${TODAY} ${MAINTAINER} - ${VERSION}-${RELEASE}
${ENTRY_BODY}"

# ---- substitute into template ----
export VERSION RELEASE BUILD_REQUIRES DISTRO_REQUIRES TESTS_PYTEST_REQ CHANGELOG_ENTRY

perl -pe '
    BEGIN {
        $v = $ENV{VERSION};
        $r = $ENV{RELEASE};
        $b = $ENV{BUILD_REQUIRES};
        $d = $ENV{DISTRO_REQUIRES};
        $t = $ENV{TESTS_PYTEST_REQ};
        $c = $ENV{CHANGELOG_ENTRY};
    }
    s/\@\@VERSION\@\@/$v/g;
    s/\@\@RELEASE\@\@/$r/g;
    s/\@\@BUILD_REQUIRES\@\@/$b/g;
    s/\@\@DISTRO_REQUIRES\@\@/$d/g;
    s/\@\@TESTS_PYTEST_REQ\@\@/$t/g;
    s/\@\@CHANGELOG_ENTRY\@\@/$c/g;
' "$TEMPLATE" > "$OUT"

echo "generated $OUT  distro=$DISTRO  version=$VERSION  release=$RELEASE"
