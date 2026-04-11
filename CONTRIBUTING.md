# Contributing to shorewall-nft

Thank you for your interest in contributing. shorewall-nft is a
Python rewrite of the Shorewall firewall compiler that targets
nftables directly. We welcome bug reports, feature requests, and
patches from anyone.

This document describes the workflow for getting your changes
merged. For setup instructions, see
[`docs/testing/setup.md`](docs/testing/setup.md).

## Quick start

```bash
# 1. Fork and clone
git clone https://github.com/<you>/shorewall-nft.git
cd shorewall-nft

# 2. Set up your dev environment
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,simulate]"
sudo tools/install-test-tooling.sh

# 3. Create a branch
git checkout -b fix/my-bug

# 4. Make changes, run tests
pytest tests/ -v

# 5. Commit with a descriptive message
git commit -m "parser: handle empty columns in tcrules

The columnar parser previously raised IndexError when a tcrules
line had fewer than 3 columns. Fix by padding with '-' like the
other columnar formats do."

# 6. Push and open a pull request
git push origin fix/my-bug
```

## Reporting bugs

Before filing a bug:

1. Check that it reproduces against the latest `shorewall-next` branch
2. Search existing issues for duplicates
3. Try to reduce the failing config to a minimal example

Your bug report should include:

- **Version**: output of `shorewall-nft --version`
- **Environment**: Python version, kernel version, distro
- **Command**: the exact invocation that fails
- **Expected vs actual**: what you thought would happen, what did
- **Minimal reproducer**: smallest config that triggers the bug

A template is in
[`docs/testing/troubleshooting.md`](docs/testing/troubleshooting.md#reporting-a-bug).

## Running tests

```bash
# Full suite (requires netns tooling)
pytest tests/ -v

# Fast unit tests only (works without root or netns)
pytest tests/ -v --ignore=tests/test_cli_integration.py

# A single test by name
pytest tests/test_plugins.py::TestIpInfo::test_v4_to_v6_basic -v

# With coverage
pytest tests/ --cov=shorewall_nft --cov-report=term-missing
```

See [`docs/testing/test-suite.md`](docs/testing/test-suite.md) for
the full test catalog and patterns for writing new tests.

## Code style

- **Python**: PEP 8, four-space indents, `snake_case` for functions,
  `PascalCase` for classes. Line length max ~100 chars but don't
  obsess.
- **Docstrings**: every public function and class should have a
  one-line docstring. Complex internals get a triple-quoted
  explanation with Args/Returns when helpful.
- **Comments**: explain *why*, not *what*. The code already says
  what it does.
- **Type hints**: use them on public APIs and helpers. Internal
  helpers can skip annotations if it hurts readability.
- **Shell scripts**: POSIX `sh`, not bash-isms. Use `set -eu` and
  validate with `sh -n` + `shellcheck` if available.

We do not currently enforce a strict formatter, but a
`.pre-commit-config.yaml` with `ruff` and `shellcheck` is available
— see [Pre-commit](#pre-commit-optional) below.

## Adding a new feature

1. **Open an issue first** for anything non-trivial — we want to
   agree on scope before you invest time.
2. **Add tests** covering both the happy path and at least one
   failure mode. See `tests/test_plugins.py` for examples.
3. **Update the docs**:
   - User-facing: `docs/shorewall-nft/<feature>.md`
   - Changelog: add an entry under `## [Unreleased]` in
     [`CHANGELOG.md`](CHANGELOG.md)
4. **Regenerate the machine-readable catalogs** if you added CLI
   options or explain features:
   ```bash
   # commands.json is generated from click introspection
   .venv/bin/python scripts/regenerate-docs.py   # or inline in your PR
   ```

## Pull requests

- **One PR per concern.** A bugfix + a feature = two PRs.
- **Rebase, don't merge.** Keep history linear.
- **Green CI.** PRs with failing tests won't be merged until they
  pass.
- **Sign-off** your commits with `git commit -s` (Developer
  Certificate of Origin).
- **Descriptive commit messages.** First line is a 50-char summary,
  then a blank line, then a longer explanation of *why*. Reference
  issues with `Fixes #123`.

Good commit message example:

```
parser: accept Unicode characters in ?COMMENT tags

The regex for ?COMMENT was [^A-Za-z0-9], rejecting mandant tags
with umlauts or accents (e.g. "?COMMENT Hüppmeier"). Relax to
\S+ so any non-whitespace identifier works.

Fixes #142
```

## Pre-commit (optional)

```bash
pip install pre-commit
pre-commit install
```

Runs `ruff`, `shellcheck`, and basic hygiene checks on every commit.
See [`.pre-commit-config.yaml`](.pre-commit-config.yaml).

## Documentation

Docs live under [`docs/`](docs/) as Markdown, compatible with
MkDocs Material. Preview locally:

```bash
pip install mkdocs-material
mkdocs serve
```

Writing guidelines:

- **Examples matter more than prose.** Put a code block in the
  first third of every page.
- **Link liberally** between pages — readers arrive from search
  and need to navigate.
- **Machine-readable** where possible. JSON catalogs in
  `docs/reference/` are consumed by agents and scripts.
- **No emoji** unless specifically asked for.

## Release process

Maintainers:

1. Update `pyproject.toml` and `shorewall_nft/__init__.py` with the
   new version.
2. Fill in the new version in `CHANGELOG.md`, moving `[Unreleased]`
   items to the new section.
3. Commit: `git commit -am "Release X.Y.Z: <headline>"`
4. Tag: `git tag -a vX.Y.Z -m "Release X.Y.Z"`
5. Push: `git push && git push --tags`
6. Build: `python -m build`
7. (Optional) Upload to PyPI: `twine upload dist/*`

## Code of conduct

Be kind. Assume good intent. Review code, not people. If a
discussion gets heated, step away for 24 hours before responding.

## Security issues

**Do not file security bugs in the public issue tracker.** See
[`SECURITY.md`](SECURITY.md) for the disclosure process.

## License

By contributing, you agree that your contributions will be licensed
under the [GNU General Public License v2.0](LICENSE) matching the
rest of the project.
