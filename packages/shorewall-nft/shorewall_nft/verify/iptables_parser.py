"""
iptables-save parser — turn an iptables-save / ip6tables-save dump into a
structured form that the verifiers can query.

The parser is intentionally minimal: each rule is represented as a dict
with the parsed key/value pairs from the iptables match-and-target syntax,
plus the original line for diagnostic output. We do NOT try to normalize
semantically (e.g. coalesce repeated -m flags) — that's the verifier's
job, since the right normalization depends on what is being compared.

Output shape:

    Dump = {
        "filter": {
            "chains": {"INPUT": {"policy": "ACCEPT", "counters": "..."}},
            "rules":  {"INPUT": [Rule, ...], ...},
        },
        "nat":    { ... },
        "mangle": { ... },
        "raw":    { ... },
    }

Each Rule is a dict like:

    {
        "raw": "-A bond1_masq -s 192.0.2.35/32 -d 198.51.100.34/32 ...",
        "chain": "bond1_masq",
        "saddr": "192.0.2.35/32",
        "daddr": "198.51.100.34/32",
        "iif":   None,
        "oif":   None,
        "proto": "tcp" | None,
        "dport": "443" | None,
        "sport": None,
        "target": "SNAT",
        "target_args": {"to-source": "198.51.100.34"},
        "comment": "tag" | None,
    }

This covers the constructs that the production config corpus actually uses:
SNAT, DNAT, NOTRACK (`-j CT --notrack`), CT helper, plus the basic
filter ACCEPT/DROP/REJECT/jump-to-chain rules.
"""
from __future__ import annotations

import shlex
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Rule:
    raw: str
    chain: str
    matches: dict[str, str] = field(default_factory=dict)
    target: str | None = None
    target_args: dict[str, str] = field(default_factory=dict)

    @property
    def saddr(self) -> str | None:
        return self.matches.get("saddr")

    @property
    def daddr(self) -> str | None:
        return self.matches.get("daddr")

    @property
    def iif(self) -> str | None:
        return self.matches.get("iif")

    @property
    def oif(self) -> str | None:
        return self.matches.get("oif")

    @property
    def proto(self) -> str | None:
        return self.matches.get("proto")

    @property
    def dport(self) -> str | None:
        return self.matches.get("dport")

    @property
    def sport(self) -> str | None:
        return self.matches.get("sport")

    @property
    def comment(self) -> str | None:
        return self.matches.get("comment")


@dataclass
class Table:
    name: str
    chains: dict[str, dict] = field(default_factory=dict)
    rules: dict[str, list[Rule]] = field(default_factory=dict)


def parse_iptables_save(path: Path) -> dict[str, Table]:
    """Parse an iptables-save dump file."""
    if not path.exists():
        raise FileNotFoundError(f"iptables file not found: {path}")

    tables: dict[str, Table] = {}
    current: Table | None = None

    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.rstrip()
        if not line or line.startswith("#"):
            continue

        if line.startswith("*"):
            name = line[1:].strip()
            current = Table(name=name)
            tables[name] = current
            continue

        if line == "COMMIT":
            current = None
            continue

        if current is None:
            continue

        if line.startswith(":"):
            # Chain declaration: ":CHAIN POLICY [counters]"
            head, _, rest = line[1:].partition(" ")
            policy, _, counters = rest.partition(" ")
            current.chains[head] = {
                "policy": policy.strip(),
                "counters": counters.strip(),
            }
            current.rules.setdefault(head, [])
            continue

        if line.startswith("-A "):
            rule = _parse_rule_line(line)
            current.rules.setdefault(rule.chain, []).append(rule)
            continue

    return tables


# A minimal flag-to-key mapping for the iptables tokens we care about.
# Flags marked with `*_pair` consume the NEXT token as their value.
_FLAG_TO_KEY = {
    "-s": "saddr",
    "--source": "saddr",
    "-d": "daddr",
    "--destination": "daddr",
    "-i": "iif",
    "--in-interface": "iif",
    "-o": "oif",
    "--out-interface": "oif",
    "-p": "proto",
    "--protocol": "proto",
    "--dport": "dport",
    "--sport": "sport",
    "--dports": "dport",
    "--sports": "sport",
    "--icmpv6-type": "dport",
}


def _parse_rule_line(line: str) -> Rule:
    """
    Parse a single `-A CHAIN ... -j TARGET ...` line.

    Uses shlex so quoted comments survive intact. Iterates over tokens
    and recognises the flags listed in _FLAG_TO_KEY plus -m/-j logic.
    """
    tokens = shlex.split(line)
    assert tokens[0] == "-A", f"unexpected rule line: {line!r}"
    chain = tokens[1]
    matches: dict[str, str] = {}
    target: str | None = None
    target_args: dict[str, str] = {}
    in_target_args = False

    i = 2
    while i < len(tokens):
        tok = tokens[i]

        if tok in _FLAG_TO_KEY:
            key = _FLAG_TO_KEY[tok]
            i += 1
            if i < len(tokens):
                # Strip iptables negation prefix `!`
                val = tokens[i]
                if val == "!":
                    i += 1
                    val = "!" + tokens[i] if i < len(tokens) else "!"
                matches[key] = val
            i += 1
            continue

        if tok == "-m":
            # `-m MODULE [args]` — we mostly care about `-m comment --comment "tag"`
            i += 1
            module = tokens[i] if i < len(tokens) else ""
            i += 1
            # Match-module-specific args follow until the next -m, -j or
            # known flag. We just track the comment text here.
            if module == "comment":
                # next must be --comment
                if i < len(tokens) and tokens[i] == "--comment":
                    i += 1
                    if i < len(tokens):
                        matches["comment"] = tokens[i]
                        i += 1
            elif module == "iprange":
                # `-m iprange --src-range A-B` / `--dst-range A-B`. Used
                # by Shorewall when a host:* expansion produces a true
                # IP range (e.g. `203.0.113.220-203.0.113.254`). The
                # iptables/iprange match doesn't store the range under
                # `-s`/`-d`, so we copy it into `saddr`/`daddr` here so
                # the verifier can compare it against foomuuri's range
                # iplist entries.
                while i < len(tokens) and tokens[i] in (
                    "--src-range", "--dst-range"
                ):
                    flag = tokens[i]
                    i += 1
                    if i < len(tokens):
                        key = "saddr" if flag == "--src-range" else "daddr"
                        matches[key] = tokens[i]
                        i += 1
            # other -m modules are not consumed; their args are picked up
            # by the regular flag loop or ignored.
            continue

        if tok in ("-j", "-g"):
            # `-j TARGET` is a jump (return-able), `-g TARGET` is a
            # goto (terminal). Both name a target chain; for action
            # classification they're equivalent. Shorewall's
            # rate-limited logger lives behind `-g ~logN`.
            i += 1
            target = tokens[i] if i < len(tokens) else None
            i += 1
            in_target_args = True
            continue

        if in_target_args and tok.startswith("--"):
            key = tok[2:]
            i += 1
            if i < len(tokens) and not tokens[i].startswith("-"):
                target_args[key] = tokens[i]
                i += 1
            else:
                target_args[key] = ""
            continue

        # Unknown token, skip.
        i += 1

    return Rule(
        raw=line,
        chain=chain,
        matches=matches,
        target=target,
        target_args=target_args,
    )
