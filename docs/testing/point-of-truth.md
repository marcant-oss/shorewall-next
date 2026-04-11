# Point of Truth — what the tests verify against

This document pins down **what counts as "correct"** when a
verification tool (simlab, simulate, triangle) reports a
discrepancy. If two sources disagree, this is the tiebreaker.

## Authoritative sources

| artifact                                              | role                                        |
|-------------------------------------------------------|---------------------------------------------|
| `/home/avalentin/projects/marcant-fw/old/iptables.txt`  | **IPv4 ground truth** — `iptables-save` from the *running* marcant-fw primary |
| `/home/avalentin/projects/marcant-fw/old/ip6tables.txt` | **IPv6 ground truth** — `ip6tables-save` from the same host |
| `/home/avalentin/projects/marcant-fw/old/etc/shorewall/`  | **IPv4 source** — the Shorewall config directory that, when compiled by *classic* Shorewall, produces `iptables.txt` |
| `/home/avalentin/projects/marcant-fw/old/etc/shorewall6/` | **IPv6 source** — ditto for `ip6tables.txt`                 |
| `/home/avalentin/projects/marcant-fw/old/ip4add` / `ip4routes` / `ip6add` / `ip6routes` | **topology + routing ground truth** — what simlab reproduces in its namespace |

Dump captured **2026-04-07 18:56 UTC** by `iptables-save v1.4.21`
from the running marcant-fw primary node. v4 dump: 12 132 lines,
v6 dump: 5 321 lines.

## Conflict resolution ranking

When a verification tool finds a mismatch between its prediction
and the compiled output, resolve in this order:

1. **`iptables.txt` / `ip6tables.txt` wins.** These describe what
   the production firewall is actually doing *right now*. If our
   compiled nft script disagrees with them, the compiled script is
   wrong — unless the difference is explicitly introduced by a
   shorewall-nft 1.1 feature (flowtable, vmap dispatch, CT zone
   tag, concat-map DNAT, plugin enrichment). Every new feature
   that changes the emit deliberately has to carry a paragraph
   in its docs explaining *which* iptables.txt lines it replaces
   and why.
2. **Parsed `etc/shorewall{,6}`** is next — if the dump disagrees
   with the source, the dump is stale (re-capture it, see §4).
3. **The triangle verifier** agrees with #1 and #2 by construction
   because it compares rule fingerprints. If triangle reports a
   coverage gap, the emitter is missing something the iptables
   source has.
4. **simlab packet probes** are the weakest signal: they can fail
   due to topology (rp_filter, missing routes), probe generator
   bugs (e.g. the placeholder-src issue), or real emit bugs. When
   simlab disagrees with #1, *simlab is wrong by default* and
   needs diagnosis — in that order: probe generator → topology →
   finally emit. Never tune the emit to make simlab green without
   first checking the iptables dump says the same thing.

## What "autorepair" means in a scan

`simlab full` is growing an autorepair semantic distinct from the
earlier "pre-fix known bugs" reading:

1. Run the scan normally, collecting per-probe `(expected,
   observed)` verdicts.
2. For every mismatch, **verify against the point of truth**:
   - Look up the same (src_zone, dst_zone, src_ip, dst_ip,
     proto, dport) tuple in `iptables.txt`.
   - If iptables.txt says ACCEPT but simlab observed DROP → real
     regression in the emit OR a topology issue. Log with the
     matching iptables rule number so a human can triage.
   - If iptables.txt says DROP but simlab observed ACCEPT → same.
   - If iptables.txt also says the observed verdict → the
     *oracle* was wrong (e.g. a shorewall-nft 1.1 feature
     legitimately changed behaviour). Auto-correct the oracle for
     that probe and log it under `oracle_corrections`.
   - If iptables.txt *has no matching rule at all* for the probe
     tuple → the probe is asking something iptables-save doesn't
     cover. Log under `unverifiable` and do not count as failure.
3. Rewrite the mismatches.txt to only list the *real* mismatches
   (category 1+2), and dump the oracle corrections + unverifiable
   probes as separate artifacts so a later run can re-classify
   without the noise.

This is **not yet implemented** — it's the semantic the current
scan-report plumbing is being rebuilt to support. The scan
currently finishes then grep'd by hand; the autorepair pass lands
as a follow-up to the simlab four-way report split.

## Refreshing the dump

When the production firewall's config is updated, re-capture:

```bash
# On the marcant-fw primary
iptables-save  > /tmp/iptables.txt
ip6tables-save > /tmp/ip6tables.txt
ip -4 addr show  > /tmp/ip4add
ip -4 route show > /tmp/ip4routes
ip -6 addr show  > /tmp/ip6add
ip -6 route show table all > /tmp/ip6routes

# Copy all four to the host
rsync /tmp/{iptables,ip6tables}.txt /tmp/ip{4,6}{add,routes} \
      host:/home/avalentin/projects/marcant-fw/old/
```

Bump the `2026-04-07` date at the top of this file and commit
both.

## See also

- `docs/testing/simlab.md` — the packet-level verifier
- `shorewall_nft/verify/triangle.py` — the static rule-coverage checker
- `shorewall_nft/verify/iptables_parser.py` — the parser that
  turns `iptables.txt` into a structured dict the oracle walks
- `memory/reference_point_of_truth.md` — the auto-memory entry
  summarising this file (kept in sync)
