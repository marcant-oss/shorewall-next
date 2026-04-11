#!/bin/sh
# simulate-all.sh — iterate `shorewall-nft simulate` across every target IP
# that has ACCEPT/DROP/REJECT rules in the supplied iptables-save dump.
#
# Aggregates per-target pass/fail counts into a single summary log.
#
# Usage on the test host:
#   tools/simulate-all.sh /etc/shorewall46 /root/simulate-data/iptables.txt \
#                         /tmp/simulate-all.log [TOP_N]
#
# TOP_N defaults to 30 (most-referenced targets in the dump).

set -eu

CFG_DIR="${1:-/etc/shorewall46}"
DUMP="${2:-/root/simulate-data/iptables.txt}"
LOG="${3:-/tmp/simulate-all.log}"
TOP_N="${4:-30}"
SWNFT="${SWNFT:-/root/shorewall-nft/.venv/bin/shorewall-nft}"

[ -f "$DUMP" ] || { echo "dump missing: $DUMP" >&2; exit 1; }
[ -d "$CFG_DIR" ] || { echo "config missing: $CFG_DIR" >&2; exit 1; }
[ -x "$SWNFT" ] || { echo "shorewall-nft missing: $SWNFT" >&2; exit 1; }

: > "$LOG"
log() { printf '%s\n' "$*" | tee -a "$LOG"; }

log "=== simulate-all: start $(date -Iseconds) ==="
log "config: $CFG_DIR"
log "dump  : $DUMP"
log "top-N : $TOP_N"
log ""

TARGETS=$(awk '/^-A/ && /-d [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/ && /-j (ACCEPT|DROP|REJECT)/' "$DUMP" \
          | grep -oE '\-d [0-9.]+/32' | awk '{gsub("/32",""); print $2}' \
          | sort | uniq -c | sort -rn | head -n "$TOP_N" | awk '{print $2}')

TOTAL=0; PASS_SUM=0; FAIL_SUM=0
i=0

for t in $TARGETS; do
    i=$((i+1))
    log "[${i}/${TOP_N}] $t"
    # Clean up any leftovers from an earlier crashing run
    ip netns list 2>/dev/null | awk '{print $1}' | grep '^shorewall-next-sim' \
        | xargs -r -n1 ip netns delete 2>/dev/null || true

    out=$("$SWNFT" simulate "$CFG_DIR" \
            --iptables "$DUMP" \
            --target "$t" \
            -n 40 \
            --parallel 1 \
            2>&1 | tail -30)
    # Last line of output: "Results: X passed, Y failed (Z total)"
    res=$(printf '%s\n' "$out" | grep -E '^Results:' | tail -1)
    log "  $res"
    # Extract counts
    p=$(printf '%s\n' "$res" | awk '{print $2}')
    f=$(printf '%s\n' "$res" | awk '{print $4}')
    tot=$(printf '%s\n' "$res" | awk '{gsub("[()]","",$6); print $6}')
    case "$p" in ''|*[!0-9]*) p=0 ;; esac
    case "$f" in ''|*[!0-9]*) f=0 ;; esac
    case "$tot" in ''|*[!0-9]*) tot=0 ;; esac
    PASS_SUM=$((PASS_SUM + p))
    FAIL_SUM=$((FAIL_SUM + f))
    TOTAL=$((TOTAL + tot))
done

log ""
log "=== simulate-all: done $(date -Iseconds) ==="
log "targets iterated : $i"
log "test cases total : $TOTAL"
log "  passed         : $PASS_SUM"
log "  failed         : $FAIL_SUM"
