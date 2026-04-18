#!/usr/bin/env bash
# release.sh — bump version, update changelogs, commit, tag.
#
# One command creates the release commit and annotated tag.
# Pushing the tag triggers CI, which builds wheels + .deb + .rpm
# and publishes a GitHub Release automatically.
#
# Usage:
#   tools/release.sh vX.Y.Z "Short release summary"
#
#   tools/release.sh --dry-run vX.Y.Z "Short summary"   # preview only
#   tools/release.sh --push    vX.Y.Z "Short summary"   # commit, tag, and push
#
# Examples:
#   tools/release.sh v1.5.0 "in-process netns + CLI unification"
#   tools/release.sh --push v1.5.0 "in-process netns + CLI unification"

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── argument parsing ─────────────────────────────────────────────────────────

DRY_RUN=0
PUSH=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=1; shift ;;
        --push)    PUSH=1;    shift ;;
        -h|--help)
            sed -n '3,15p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        v[0-9]*) VERSION="$1"; shift ;;
        *) SUMMARY="$1"; shift ;;
    esac
done

[[ -n "${VERSION:-}" ]] || { echo "error: version required (e.g. v1.5.0)" >&2; exit 1; }
[[ -n "${SUMMARY:-}" ]] || { echo "error: summary required (e.g. \"in-process netns + CLI unification\")" >&2; exit 1; }

# Strip leading v for bare numeric version
BARE="${VERSION#v}"
if ! [[ "$BARE" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "error: version must be vX.Y.Z (got '$VERSION')" >&2
    exit 1
fi

# ── pre-flight checks ────────────────────────────────────────────────────────

cd "$REPO"

# Working tree must be clean
if [[ -n "$(git status --porcelain)" ]]; then
    echo "error: working tree is not clean — commit or stash changes first" >&2
    git status --short >&2
    exit 1
fi

# Tag must not already exist
if git rev-parse "$VERSION" >/dev/null 2>&1; then
    echo "error: tag $VERSION already exists" >&2
    exit 1
fi

# Collect commits since last tag for the changelog
LAST_TAG="$(git describe --tags --match 'v*' --abbrev=0 2>/dev/null || true)"
if [[ -n "$LAST_TAG" ]]; then
    COMMITS="$(git log --oneline "${LAST_TAG}..HEAD" 2>/dev/null || true)"
else
    COMMITS="$(git log --oneline HEAD 2>/dev/null | head -20)"
fi

DATE_ISO="$(date -u '+%Y-%m-%d')"
DATE_RFC="$(date -u '+%a, %d %b %Y %H:%M:%S +0000')"

# ── preview ──────────────────────────────────────────────────────────────────

echo "release: $VERSION — $SUMMARY"
echo "date:    $DATE_ISO"
echo "since:   ${LAST_TAG:-<beginning>}"
echo ""
if [[ -n "$COMMITS" ]]; then
    echo "commits since last release:"
    while IFS= read -r line; do echo "  $line"; done <<< "$COMMITS"
    echo ""
fi

if [[ $DRY_RUN -eq 1 ]]; then
    echo "(dry run — no files changed)"
    exit 0
fi

# ── update version in all pyproject.toml files ──────────────────────────────

for f in \
    packages/shorewall-nft/pyproject.toml \
    packages/shorewalld/pyproject.toml \
    packages/shorewall-nft-simlab/pyproject.toml
do
    sed -i "s/^version = \"[0-9]*\.[0-9]*\.[0-9]*\"/version = \"$BARE\"/" "$f"
done

# ── update __version__ in __init__.py ────────────────────────────────────────

sed -i "s/^__version__ = \"[0-9]*\.[0-9]*\.[0-9]*\"/__version__ = \"$BARE\"/" \
    packages/shorewall-nft/shorewall_nft/__init__.py

# ── update CHANGELOG.md ──────────────────────────────────────────────────────

# Build the new section
CHANGELOG_SECTION="## [$BARE] — $DATE_ISO — $SUMMARY"$'\n'
if [[ -n "$COMMITS" ]]; then
    CHANGELOG_SECTION+=$'\n### Changes\n\n'
    while IFS= read -r line; do
        # Strip leading commit hash (first word)
        msg="${line#* }"
        CHANGELOG_SECTION+="- $msg"$'\n'
    done <<< "$COMMITS"
fi
CHANGELOG_SECTION+=$'\n'

# Insert after the "## [Unreleased]" line
python3 - "$CHANGELOG_SECTION" <<'PY'
import sys, pathlib

section = sys.argv[1]
p = pathlib.Path("CHANGELOG.md")
text = p.read_text()

marker = "## [Unreleased]"
idx = text.find(marker)
if idx == -1:
    # no Unreleased section — insert after the first blank line after the header
    idx = text.find("\n\n") + 2
else:
    idx = text.find("\n", idx) + 1  # position right after the Unreleased line

p.write_text(text[:idx] + "\n" + section + text[idx:])
print("CHANGELOG.md updated")
PY

# ── update debian/changelog ──────────────────────────────────────────────────

DEB_ENTRY="shorewall-nft ($BARE-1) unstable; urgency=medium

  * Release $BARE: $SUMMARY.
  * See CHANGELOG.md for full details.

 -- André Valentin <avalentin@marcant.net>  $DATE_RFC

"

# Prepend to debian/changelog
{ echo "$DEB_ENTRY"; cat packaging/debian/changelog; } > /tmp/deb-changelog.tmp
mv /tmp/deb-changelog.tmp packaging/debian/changelog

# ── stage and commit ─────────────────────────────────────────────────────────

git add \
    packages/shorewall-nft/pyproject.toml \
    packages/shorewalld/pyproject.toml \
    packages/shorewall-nft-simlab/pyproject.toml \
    packages/shorewall-nft/shorewall_nft/__init__.py \
    packaging/debian/changelog \
    CHANGELOG.md

git commit -m "$(cat <<EOF
release: $VERSION — $SUMMARY

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"

# ── create annotated tag ─────────────────────────────────────────────────────

git tag -a "$VERSION" -m "Release $BARE — $SUMMARY"

echo ""
echo "created commit: $(git log -1 --format='%h %s')"
echo "created tag:    $VERSION"
echo ""

if [[ $PUSH -eq 1 ]]; then
    REMOTE="${PUSH_REMOTE:-origin}"
    BRANCH="$(git rev-parse --abbrev-ref HEAD)"
    echo "pushing branch $BRANCH and tag $VERSION to $REMOTE …"
    git push "$REMOTE" "$BRANCH"
    git push "$REMOTE" "$VERSION"
    echo ""
    echo "CI triggered. GitHub Actions will build and publish the release."
else
    echo "next step — push to trigger CI and GitHub Release:"
    echo "  git push origin HEAD"
    echo "  git push origin $VERSION"
fi
