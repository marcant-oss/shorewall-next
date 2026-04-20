# Project principles

Load-bearing design rules for this monorepo. Adherence is non-negotiable;
deviations require explicit justification in the PR description.

## P1 — AI-discoverable tooling

**Any AI agent (Claude, Copilot, Cursor, etc.) must be able to determine
from the docs alone:**

1. **What the tool can be used for** — the capability set (what scenarios
   it runs, what reports it produces, what standards it covers).
2. **How to instruct it** — the invocation surface (CLI flags, required
   config fields, environment variables, prerequisites).
3. **What the tool CANNOT do** — the out-of-scope boundary, so the AI
   doesn't hallucinate features that don't exist.
4. **How to verify it worked** — the expected outputs, log lines, exit
   codes, and how to read the audit report.

Corollary rules:

- Every new CLI must ship with a top-of-file docstring / `--help` block
  that answers the four points above in ≤50 lines.
- Every new YAML schema field must land with one-line purpose + expected
  value shape (type, enum, example).
- Any non-obvious dependency chain (load order, env vars, file paths)
  goes in a `docs/testing/*.md` or the relevant package `CLAUDE.md`.
- Pointer from the root CLAUDE.md or a package CLAUDE.md is mandatory;
  orphan docs are drift.
- If a concept takes > 2 reads for a competent engineer to grok, the
  doc is wrong, not the engineer.

**The test**: an AI agent handed only the docs should be able to write
a correct `stagelab run …` or `tools/run-security-test-plan.sh …` invocation
for a new standard without reading source code. If they have to `grep` or
`Read` a Python file to figure out flags, the docs are incomplete.

### Practical checks on every PR

- [ ] New CLI / subcommand has `--help` that describes purpose + required
      flags + an example.
- [ ] New YAML field has a sentence or example in `docs/testing/*.md`.
- [ ] New scenario kind appears in `docs/testing/security-test-plan.md`
      with its acceptance-criteria shape.
- [ ] New dependency (pip extra, system package, external binary) is
      listed in `tools/setup-remote-test-host.sh` AND the relevant
      package `CLAUDE.md`.
- [ ] `README.md` or `CLAUDE.md` of the touched package links to the new
      feature so it's discoverable from the top of the tree.

## P2 — No secrets in git

- Community strings, API keys, passwords: ONLY via `${ENV_VAR}`
  placeholders in YAML. Never a literal value, even in an example file.
- Exceptions: well-known public defaults (`public` SNMP community on a
  lab-only network) may appear in docs but NEVER in a production config.
- If you catch a secret in a diff, halt and rotate.

## P3 — Deployment names are scoped

- Commit messages, `CHANGELOG.md`, and release notes refer to the
  **reference HA firewall** / **reference config** — never the real
  deployment name (fw-primary, fw-secondary, etc.).
- Internal files (repo-local `CLAUDE.md`, operator runbooks, `tools/`,
  `nodes/<name>/`) may use the real name.
- Published history is public; keep it generic.

## P4 — Point of truth for verification

Ranking when signals disagree (from `docs/testing/point-of-truth.md`):

1. **`/home/avalentin/projects/marcant-fw/old/iptables.txt` + `ip6tables.txt`** — live dumps from the reference firewall primary. The authoritative "what is the firewall actually doing" signal.
2. **`/home/avalentin/projects/marcant-fw/old/etc/shorewall{,6}/`** — the Shorewall config that produces (1). Use when (1) looks stale.
3. **simlab output** is the WEAKEST signal. When simlab disagrees with (1), assume simlab is wrong and investigate: probe generator → topology → emit.

## P5 — Test reports split false-drop vs false-accept

- Never just "N mismatches". Always split into:
  - `fail_drop_count` (expected ACCEPT, got DROP) — *unnecessary restriction*
  - `fail_accept_count` (expected DROP, got ACCEPT) — *security hole*
- Include the oracle reason (which rule fired, which chain matched).
- Random-probe mismatches need full provenance so they can be triaged
  vs. dismissed as known noise.

## P6 — Two-scope edits

When a change touches both a **core package** and a **consumer package**:

- Core first: ship + release + test-in-isolation.
- Consumer next: bump dep floor + update, referencing the core release.

Resists the temptation to edit both at once — atomic cross-cutting changes
are painful to revert if the core turns out to need revisions.

## P7 — Versions stay in sync

Every `pyproject.toml` + `__init__.py` + RPM spec + Debian changelog +
`CHANGELOG.md` moves together in a single commit. Never a divergent
version floor across the monorepo. See `CLAUDE.md` release-state
section for the full list of files.
