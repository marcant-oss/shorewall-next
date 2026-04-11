#!/bin/sh
# simulate-all-zones.sh — iterate `shorewall-nft simulate` across every
# (src_zone, dst_zone) pair that has at least one interface on each side,
# aggregating per-zone-pair pass/fail counts.
#
# The default simulate topology only exercises net→host. This wrapper
# overrides --src-iface and --dst-iface for each run so every zone
# gets at least one probe through it. Half the default parallelism
# (--parallel 2) so the box stays responsive while iterating.
#
# Usage on the remote test host:
#   tools/simulate-all-zones.sh /etc/shorewall46 \
#       /root/simulate-data/iptables.txt \
#       /root/simulate-data/ip6tables.txt \
#       /tmp/simulate-all-zones.log \
#       [TARGETS_PER_ZONE]
#
# TARGETS_PER_ZONE defaults to 5.

set -eu

CFG_DIR="${1:-/etc/shorewall46}"
DUMP="${2:-/root/simulate-data/iptables.txt}"
DUMP6="${3:-/root/simulate-data/ip6tables.txt}"
LOG="${4:-/tmp/simulate-all-zones.log}"
TOP_N="${5:-5}"
SWNFT="${SWNFT:-/root/shorewall-nft/.venv/bin/shorewall-nft}"
PARALLEL="${PARALLEL:-2}"

[ -f "$DUMP" ] || { echo "dump missing: $DUMP" >&2; exit 1; }
[ -d "$CFG_DIR" ] || { echo "config missing: $CFG_DIR" >&2; exit 1; }
[ -x "$SWNFT" ] || { echo "shorewall-nft missing: $SWNFT" >&2; exit 1; }

: > "$LOG"
log() { printf '%s\n' "$*" | tee -a "$LOG"; }

log "=== simulate-all-zones: start $(date -Iseconds) ==="
log "config   : $CFG_DIR"
log "dump v4  : $DUMP"
log "dump v6  : $DUMP6"
log "parallel : $PARALLEL"
log "top-N    : $TOP_N per (src_zone, dst_zone) pair"
log ""

# Extract zone → primary interface mapping from the merged interfaces file.
# Format: "zone iface options"; skip comments and blank lines.
mapfile_tmp=$(mktemp)
awk '!/^(#|$)/ { if (!seen[$1]++) print $1 " " $2 }' \
    "$CFG_DIR/interfaces" > "$mapfile_tmp"

ZONES=$(awk '{ print $1 }' "$mapfile_tmp")
TOTAL_PAIRS=0
PASS_SUM=0
FAIL_SUM=0

for src_zone in $ZONES; do
    src_iface=$(awk -v z="$src_zone" '$1==z { print $2; exit }' "$mapfile_tmp")
    [ -n "$src_iface" ] || continue

    for dst_zone in $ZONES; do
        [ "$src_zone" = "$dst_zone" ] && continue
        dst_iface=$(awk -v z="$dst_zone" '$1==z { print $2; exit }' "$mapfile_tmp")
        [ -n "$dst_iface" ] || continue

        # Pick top-N destination IPs in the dst zone. Filter the ipt dump
        # rules targeting the ${src_zone}2${dst_zone} chain and rank by
        # ACCEPT frequency. Fallback: any -d IPs referenced in that chain.
        targets=$(awk -v chain="-A ${src_zone}2${dst_zone}" '
            $0 ~ chain && /-d [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/ \
                && /-j (ACCEPT|DROP|REJECT)/ {
                for (i=1;i<=NF;i++) if ($i=="-d") { print $(i+1); next }
            }' "$DUMP" | sed 's,/32,,' | sort | uniq -c | sort -rn \
            | head -n "$TOP_N" | awk '{ print $2 }' | tr '\n' ',' | sed 's/,$//')

        if [ -z "$targets" ]; then
            log "[skip] $src_zone → $dst_zone (no target IPs in ${src_zone}2${dst_zone})"
            continue
        fi

        TOTAL_PAIRS=$((TOTAL_PAIRS + 1))
        log "[$TOTAL_PAIRS] $src_zone($src_iface) → $dst_zone($dst_iface) :: $targets"

        # Clean leftover netns from a prior crash
        ip netns list 2>/dev/null | awk '{print $1}' \
            | grep '^shorewall-next-sim' \
            | xargs -r -n1 ip netns delete 2>/dev/null || true

        out=$("$SWNFT" simulate "$CFG_DIR" \
                --iptables "$DUMP" \
                --targets "$targets" \
                --src-iface "$src_iface" \
                --dst-iface "$dst_iface" \
                -n 10 \
                --parallel "$PARALLEL" \
                --no-trace 2>&1 | tail -50)
        res=$(printf '%s\n' "$out" | grep -E '^Results:' | tail -1)
        if [ -n "$res" ]; then
            log "  $res"
            p=$(printf '%s\n' "$res" | awk '{print $2}')
            f=$(printf '%s\n' "$res" | awk '{print $4}')
            case "$p" in ''|*[!0-9]*) p=0 ;; esac
            case "$f" in ''|*[!0-9]*) f=0 ;; esac
            PASS_SUM=$((PASS_SUM + p))
            FAIL_SUM=$((FAIL_SUM + f))
        else
            log "  [no results — likely 0 derived cases]"
        fi
    done
done

rm -f "$mapfile_tmp"

log ""
log "=== simulate-all-zones: done $(date -Iseconds) ==="
log "(src,dst) pairs iterated : $TOTAL_PAIRS"
log "  passed                 : $PASS_SUM"
log "  failed                 : $FAIL_SUM"
