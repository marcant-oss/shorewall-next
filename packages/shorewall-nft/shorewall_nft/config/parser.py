"""Shorewall configuration file parser.

Parses the column-based Shorewall config format including:
- params (KEY=VALUE with variable expansion)
- shorewall.conf (KEY=VALUE settings)
- zones, interfaces, hosts, policy, rules (column-based)
- Preprocessor directives: ?FORMAT, ?SECTION, ?COMMENT, ?IF/?ELSE/?ENDIF, ?SET, ?INCLUDE
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ConfigLine:
    """A parsed line from a config file."""
    columns: list[str]
    file: str
    lineno: int
    comment_tag: str | None = None
    section: str | None = None
    raw: str = ""
    format_version: int = 1  # ?FORMAT version active when line was parsed


@dataclass
class ShorewalConfig:
    """Complete parsed Shorewall configuration."""
    config_dir: Path
    settings: dict[str, str] = field(default_factory=dict)
    params: dict[str, str] = field(default_factory=dict)
    zones: list[ConfigLine] = field(default_factory=list)
    interfaces: list[ConfigLine] = field(default_factory=list)
    hosts: list[ConfigLine] = field(default_factory=list)
    policy: list[ConfigLine] = field(default_factory=list)
    rules: list[ConfigLine] = field(default_factory=list)
    masq: list[ConfigLine] = field(default_factory=list)
    conntrack: list[ConfigLine] = field(default_factory=list)
    notrack: list[ConfigLine] = field(default_factory=list)
    blrules: list[ConfigLine] = field(default_factory=list)
    routestopped: list[ConfigLine] = field(default_factory=list)
    stoppedrules: list[ConfigLine] = field(default_factory=list)
    tcrules: list[ConfigLine] = field(default_factory=list)
    tcdevices: list[ConfigLine] = field(default_factory=list)
    tcinterfaces: list[ConfigLine] = field(default_factory=list)
    tcclasses: list[ConfigLine] = field(default_factory=list)
    tcfilters: list[ConfigLine] = field(default_factory=list)
    tcpri: list[ConfigLine] = field(default_factory=list)
    mangle: list[ConfigLine] = field(default_factory=list)
    providers: list[ConfigLine] = field(default_factory=list)
    routes: list[ConfigLine] = field(default_factory=list)
    rtrules: list[ConfigLine] = field(default_factory=list)
    tunnels: list[ConfigLine] = field(default_factory=list)
    accounting: list[ConfigLine] = field(default_factory=list)
    secmarks: list[ConfigLine] = field(default_factory=list)
    maclist: list[ConfigLine] = field(default_factory=list)
    netmap: list[ConfigLine] = field(default_factory=list)
    # Files added as part of the structured-io groundwork
    arprules: list[ConfigLine] = field(default_factory=list)
    proxyarp: list[ConfigLine] = field(default_factory=list)
    proxyndp: list[ConfigLine] = field(default_factory=list)
    ecn: list[ConfigLine] = field(default_factory=list)
    nfacct: list[ConfigLine] = field(default_factory=list)
    rawnat: list[ConfigLine] = field(default_factory=list)
    scfilter: list[ConfigLine] = field(default_factory=list)
    # Legacy static blacklist (CIDR + optional proto/port).
    # Distinct from blrules (full rule grammar) — blacklist is
    # the simple "drop these sources outright" list.
    blacklist: list[ConfigLine] = field(default_factory=list)
    # DNS-backed nft sets — hostnames that the compiler declares as
    # empty timeout sets and shorewalld populates at runtime from
    # dnstap/pbdns frames. See docs/roadmap/shorewalld.md.
    dnsnames: list[ConfigLine] = field(default_factory=list)
    # Named dynamic nft sets backed by various providers (dnstap,
    # resolver, ip-list, ip-list-plain). Declared once here and
    # referenced in rules as ``nfset:name``.
    nfsets: list[ConfigLine] = field(default_factory=list)
    macros: dict[str, list[ConfigLine]] = field(default_factory=dict)
    # Line-based extension scripts — raw line lists so the structured
    # blob can round-trip them without pretending they have columns.
    scripts: dict[str, list[str]] = field(default_factory=dict)
    # Plugin config files — plugins.conf (TOML) and plugins/*.toml /
    # plugins/*.token (raw string for secrets). Keys are file paths
    # relative to the shorewall config dir; values are dicts for TOML
    # files and strings for raw files. The structured importer
    # writes these to disk when config import --to DIR runs.
    plugin_files: dict[str, "str | dict"] = field(default_factory=dict)


class ParseError(Exception):
    """Error during config parsing."""
    def __init__(self, message: str, file: str = "", lineno: int = 0):
        self.file = file
        self.lineno = lineno
        super().__init__(f"{file}:{lineno}: {message}" if file else message)


class ConfigParser:
    """Parser for Shorewall configuration files."""

    # Internal Shorewall variables that are always defined
    _BUILTIN_VARS: dict[str, str] = {
        "__CT_TARGET": "1",
        "__CONNTRACK": "1",
        "__PKTTYPE": "1",
        "__ADDRTYPE": "1",
        "__AUDIT_TARGET": "1",
        "__IPV6": "1",
    }

    def __init__(self, config_dir: Path):
        self.config_dir = config_dir
        self.params: dict[str, str] = dict(self._BUILTIN_VARS)
        self.settings: dict[str, str] = {}
        self._if_stack: list[bool] = []
        self._comment_tag: str | None = None
        self._format_version: int = 1
        self._in_perl_block: bool = False
        # Family scope set by ?FAMILY directive. None = auto-detect,
        # "ipv4"/"ipv6" forces subsequent lines' origin. Used by merge-config
        # to mark v6-origin rules within a unified merged file.
        self._family_scope: str | None = None

    def parse(self) -> ShorewalConfig:
        """Parse all config files and return a ShorewalConfig."""
        config = ShorewalConfig(config_dir=self.config_dir)

        # 1. Parse params first (variable definitions)
        self._parse_params(self.config_dir / "params")
        config.params = dict(self.params)

        # 2. Parse shorewall.conf (settings)
        self._parse_conf(self.config_dir / "shorewall.conf")
        config.settings = dict(self.settings)

        # 3. Parse column-based config files
        for name in ("zones", "interfaces", "hosts", "policy", "rules",
                     "masq", "conntrack", "notrack", "blrules", "routestopped",
                     "stoppedrules",
                     "tcrules", "tcdevices", "tcinterfaces", "tcclasses",
                     "tcfilters", "tcpri", "mangle",
                     "providers", "routes", "rtrules", "tunnels",
                     "accounting", "secmarks",
                     "maclist", "netmap",
                     # Structured-io groundwork additions. These are
                     # now parsed + exported, but the compiler/emitter
                     # does not yet consume them. TODO per file:
                     # - arprules:   ARP anti-spoof rules (arp table)
                     # - proxyarp:   proxy-arp address table
                     # - proxyndp:   proxy-ndp address table
                     # - ecn:        ECN disable per iface/host pair
                     # - nfacct:     named conntrack accounting objects
                     # - rawnat:     raw-table NAT rules (early DNAT)
                     # - stoppedrules: rules that stay when FW is stopped
                     # - scfilter:   source CIDR filter
                     "arprules", "proxyarp", "proxyndp", "ecn",
                     "nfacct", "rawnat", "scfilter",
                     "blacklist", "dnsnames", "nfsets"):
            path = self.config_dir / name
            if path.exists():
                lines = self._parse_columnar(path)
                setattr(config, name, lines)
            # Also check for .d/ directory with includes
            dpath = self.config_dir / f"{name}.d"
            if dpath.is_dir():
                for sub in sorted(dpath.iterdir()):
                    if (sub.is_file()
                            and not sub.name.startswith(".")
                            and not sub.name.endswith(".txt")
                            and not sub.name.endswith(".bak")
                            and not sub.name.endswith(".orig")):
                        lines = self._parse_columnar(sub)
                        getattr(config, name).extend(lines)

        # 4. Line-based extension scripts — stored as raw line lists
        # so structured export/import can round-trip them. The files
        # themselves stay shell (or perl for ``compile``); we don't
        # try to parse or validate them here.
        from shorewall_nft.config.schema import all_script_files
        for script_name in all_script_files():
            path = self.config_dir / script_name
            if path.is_file():
                try:
                    text = path.read_text()
                except (OSError, UnicodeDecodeError):
                    continue
                config.scripts[script_name] = text.splitlines()

        # 5. Parse custom macros from macros/ directory
        macros_dir = self.config_dir / "macros"
        if macros_dir.is_dir():
            for macro_file in sorted(macros_dir.iterdir()):
                if macro_file.is_file() and macro_file.name.startswith("macro."):
                    macro_name = macro_file.name[6:]  # Strip "macro." prefix
                    lines = self._parse_columnar(macro_file)
                    config.macros[macro_name] = lines

        # 6. Plugin config files — plugins.conf (TOML) and the
        # plugins/ directory (TOML files + .token files for
        # secrets). Loaded into ``config.plugin_files`` so a
        # round-trip via ``write_config_dir`` preserves them
        # byte-for-byte. Without this load step the structured-io
        # importer/exporter only saw plugin files when they came
        # via a JSON overlay.
        try:
            import tomllib  # type: ignore[import-not-found]
        except ImportError:
            tomllib = None  # type: ignore[assignment]
        plugins_conf = self.config_dir / "plugins.conf"
        if plugins_conf.is_file() and tomllib is not None:
            try:
                with plugins_conf.open("rb") as f:
                    config.plugin_files["plugins.conf"] = tomllib.load(f)
            except (OSError, Exception):
                pass
        plugins_dir = self.config_dir / "plugins"
        if plugins_dir.is_dir():
            for sub in sorted(plugins_dir.iterdir()):
                if not sub.is_file():
                    continue
                rel = f"plugins/{sub.name}"
                if sub.suffix == ".toml" and tomllib is not None:
                    try:
                        with sub.open("rb") as f:
                            config.plugin_files[rel] = tomllib.load(f)
                    except (OSError, Exception):
                        pass
                elif sub.suffix == ".token" or sub.name.endswith(".secret"):
                    try:
                        config.plugin_files[rel] = sub.read_text().rstrip("\n")
                    except (OSError, UnicodeDecodeError):
                        pass

        return config

    def _parse_params(self, path: Path) -> None:
        """Parse a params file: KEY=VALUE with variable expansion and appending."""
        if not path.exists():
            return

        for lineno, line in self._read_lines(path):
            line = self._strip_comment(line)
            if not line:
                continue

            m = re.match(r'^([A-Za-z_]\w*)\s*=\s*(.*?)\s*$', line)
            if not m:
                continue

            name, value = m.group(1), m.group(2)
            # Strip quotes
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
                value = value[1:-1]
            # Expand variables in value (resolves $VAR references including self-references)
            value = self._expand_vars(value)
            self.params[name] = value

    def _parse_conf(self, path: Path) -> None:
        """Parse shorewall.conf: KEY=VALUE settings.

        The ``--override-json`` / ``--override`` global CLI overlay is
        applied in :func:`shorewall_nft.runtime.cli._compile` via
        :func:`shorewall_nft.config.importer.apply_overlay` **after**
        ``Parser.parse()`` returns, so per-file parse methods don't
        need to know about it — returning early when the file is
        absent is fine, the overlay still runs.
        """
        if not path.exists():
            return

        for lineno, line in self._read_lines(path):
            line = self._strip_comment(line)
            if not line:
                continue

            m = re.match(r'^([A-Za-z_]\w*)\s*=\s*(.*?)\s*$', line)
            if not m:
                continue

            name, value = m.group(1), m.group(2)
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
                value = value[1:-1]
            value = self._expand_vars(value)
            self.settings[name] = value

    def _parse_columnar(self, path: Path) -> list[ConfigLine]:
        """Parse a column-based config file with preprocessor support."""
        result: list[ConfigLine] = []
        section: str | None = None
        fname = str(path)
        self._format_version = 1  # Reset format for each file

        self._in_perl_block = False

        for lineno, line in self._read_lines(path):
            raw = line
            line = self._strip_comment(line)
            if not line:
                continue

            # Skip ?BEGIN PERL ... ?END PERL blocks
            if re.match(r'^\?BEGIN\s+PERL', line, re.IGNORECASE):
                self._in_perl_block = True
                continue
            if re.match(r'^\?END\s+PERL', line, re.IGNORECASE):
                self._in_perl_block = False
                continue
            if self._in_perl_block:
                continue

            # Preprocessor directives
            if line.startswith("?") or line.startswith("INCLUDE"):
                directive_result = self._handle_directive(line, path, lineno)
                if directive_result is not None:
                    if isinstance(directive_result, str):
                        section = directive_result
                    elif isinstance(directive_result, list):
                        for cl in directive_result:
                            cl.section = section
                            cl.comment_tag = self._comment_tag
                        result.extend(directive_result)
                continue

            # Skip if inside a false ?IF block
            if self._if_stack and not self._if_stack[-1]:
                continue

            # Expand variables
            line = self._expand_vars(line)

            # Split into columns
            columns = self._split_columns(line)
            if not columns:
                continue

            # Strip trailing defaults
            while columns and columns[-1] == "-":
                columns.pop()

            if columns:
                # When ?FAMILY ipv6 is active, mark the file path as
                # shorewall6-origin so the compiler emits meta nfproto ipv6.
                effective_file = fname
                if self._family_scope == "ipv6" and "shorewall6" not in fname:
                    effective_file = fname + "#shorewall6-scope"
                result.append(ConfigLine(
                    columns=columns,
                    file=effective_file,
                    lineno=lineno,
                    comment_tag=self._comment_tag,
                    section=section,
                    raw=raw,
                    format_version=self._format_version,
                ))

        return result

    def _handle_directive(self, line: str, path: Path, lineno: int) -> str | list[ConfigLine] | None:
        """Process a preprocessor directive. Returns section name, included lines, or None."""
        # ?SECTION name
        m = re.match(r'^\?SECTION\s+(\S+)', line, re.IGNORECASE)
        if m:
            return m.group(1).upper()

        # ?FORMAT n
        m = re.match(r'^\?FORMAT\s+(\d+)', line, re.IGNORECASE)
        if m:
            self._format_version = int(m.group(1))
            return None

        # ?COMMENT [text]
        m = re.match(r'^\?COMMENT\s*(.*)', line, re.IGNORECASE)
        if m:
            tag = m.group(1).strip()
            self._comment_tag = tag if tag else None
            return None

        # ?FAMILY ipv4 | ipv6 | any — shorewall-nft extension
        # Scopes subsequent rule lines to a specific address family.
        # Used by merge-config to mark v6-origin rules in the unified rules
        # file. Without this, rules in a single-directory config default to
        # the family inferred from addresses / file path.
        m = re.match(r'^\?FAMILY\s+(\S+)', line, re.IGNORECASE)
        if m:
            fam = m.group(1).strip().lower()
            if fam in ("ipv4", "inet"):
                self._family_scope = "ipv4"
            elif fam in ("ipv6",):
                self._family_scope = "ipv6"
            else:
                # "any" or unknown → clear scope
                self._family_scope = None
            return None

        # ?SET $var value
        m = re.match(r'^\?SET\s+\$(\w+)\s+(.*)', line, re.IGNORECASE)
        if m:
            self.params[m.group(1)] = self._expand_vars(m.group(2).strip())
            return None

        # ?IF expression
        m = re.match(r'^\?IF\s+(.*)', line, re.IGNORECASE)
        if m:
            expr = m.group(1).strip()
            result = self._eval_condition(expr)
            self._if_stack.append(result)
            return None

        # ?ELSIF expression
        m = re.match(r'^\?ELSIF\s+(.*)', line, re.IGNORECASE)
        if m:
            if not self._if_stack:
                raise ParseError("?ELSIF without ?IF", str(path), lineno)
            if self._if_stack[-1]:
                # Previous branch was true, skip this one
                self._if_stack[-1] = False
            else:
                expr = m.group(1).strip()
                self._if_stack[-1] = self._eval_condition(expr)
            return None

        # ?ELSE
        if re.match(r'^\?ELSE\b', line, re.IGNORECASE):
            if not self._if_stack:
                raise ParseError("?ELSE without ?IF", str(path), lineno)
            self._if_stack[-1] = not self._if_stack[-1]
            return None

        # ?ENDIF
        if re.match(r'^\?ENDIF\b', line, re.IGNORECASE):
            if not self._if_stack:
                raise ParseError("?ENDIF without ?IF", str(path), lineno)
            self._if_stack.pop()
            return None

        # ?REQUIRE capability — silently accept (capabilities always available in nft)
        if re.match(r'^\?REQUIRE\b', line, re.IGNORECASE):
            return None

        # ?BEGIN perl / ?END perl — skip embedded Perl blocks
        if re.match(r'^\?BEGIN\s+PERL', line, re.IGNORECASE):
            # Set flag to skip until ?END PERL
            return None

        # ?RESET — reset format to default
        if re.match(r'^\?RESET\b', line, re.IGNORECASE):
            self._format_version = 1
            return None

        # DEFAULTS — action defaults declaration
        if line.startswith("DEFAULTS"):
            return None  # Handled by action system

        # ?INCLUDE filename / INCLUDE filename
        m = re.match(r'^(?:\?)?INCLUDE\s+(\S+)', line, re.IGNORECASE)
        if m:
            include_path = self._resolve_include(m.group(1), path)
            if include_path and include_path.exists():
                return self._parse_columnar(include_path)
            return None

        return None

    def _eval_condition(self, expr: str) -> bool:
        """Evaluate a preprocessor condition.

        Supports:
        - $variable (true if defined and non-empty)
        - !$variable (true if undefined or empty)
        - $variable eq 'value'
        - $variable ne 'value'
        """
        expr = expr.strip()

        # Negation
        if expr.startswith("!"):
            return not self._eval_condition(expr[1:].strip())

        # Comparison: $var eq/ne 'value' or $var eq/ne value
        m = re.match(r'^\$(\w+)\s+(eq|ne)\s+[\'"]?([^\'"]*)[\'"]?\s*$', expr)
        if m:
            var_val = self.params.get(m.group(1), "")
            if m.group(2) == "eq":
                return var_val == m.group(3)
            else:
                return var_val != m.group(3)

        # Simple variable check (with or without $)
        m = re.match(r'^\$?(\w+)$', expr)
        if m:
            return bool(self.params.get(m.group(1), ""))

        # Literal true/false
        if expr.lower() in ("1", "true", "yes"):
            return True
        if expr.lower() in ("0", "false", "no", ""):
            return False

        return False

    def _expand_vars(self, text: str) -> str:
        """Expand $variable and ${variable} references."""
        def replace(m: re.Match) -> str:
            name = m.group(2) or m.group(1)
            return self.params.get(name, self.settings.get(name, m.group(0)))

        # Match ${name} and $name patterns
        # Up to 100 iterations to handle transitive references
        for _ in range(100):
            new_text = re.sub(r'\$\{(\w+)\}|\$([A-Za-z_]\w*)', replace, text)
            if new_text == text:
                break
            text = new_text

        return text

    @staticmethod
    def _split_columns(line: str) -> list[str]:
        """Split a line into columns, respecting parenthesized groups and quotes.

        Handles:
        - Parenthesized groups: Proto(tcp,udp) stays as one column
        - Quoted strings: "value with spaces" stays as one column
        - Semicolons: ; separates main columns from key=value pairs
        - Double semicolons: ;; marks inline iptables (stored as-is)
        """
        # Handle ;; inline iptables passthrough
        if ";;" in line:
            main_part, inline_part = line.split(";;", 1)
            columns = ConfigParser._split_columns(main_part)
            if inline_part.strip():
                columns.append(";;" + inline_part.strip())
            return columns

        # Handle ; key=value pairs
        if ";" in line:
            main_part, pairs_part = line.split(";", 1)
            columns = ConfigParser._split_columns(main_part)
            # Parse key=value pairs and append as additional columns
            for pair in pairs_part.split(","):
                pair = pair.strip()
                if pair:
                    columns.append(pair)
            return columns

        columns: list[str] = []
        current = ""
        depth = 0
        in_quote = False
        quote_char = ""

        for char in line:
            if char in ('"', "'") and not in_quote:
                in_quote = True
                quote_char = char
                current += char
            elif char == quote_char and in_quote:
                in_quote = False
                current += char
            elif char == '(' and not in_quote:
                depth += 1
                current += char
            elif char == ')' and not in_quote:
                depth -= 1
                current += char
            elif char in (' ', '\t') and depth == 0 and not in_quote:
                if current:
                    columns.append(current)
                    current = ""
            else:
                current += char

        if current:
            columns.append(current)

        return columns

    @staticmethod
    def _strip_comment(line: str) -> str:
        """Strip trailing comments and whitespace from a line."""
        line = line.strip()
        if not line or line.startswith("#"):
            return ""

        # Find # that's not inside quotes
        in_quote = False
        quote_char = ""
        for i, char in enumerate(line):
            if char in ('"', "'") and not in_quote:
                in_quote = True
                quote_char = char
            elif char == quote_char and in_quote:
                in_quote = False
            elif char == '#' and not in_quote:
                line = line[:i]
                break

        return line.strip()

    def _resolve_include(self, filename: str, current_file: Path) -> Path | None:
        """Resolve an include path relative to current file or config dir."""
        filename = self._expand_vars(filename)
        p = Path(filename)
        if p.is_absolute():
            return p
        # Try relative to current file
        rel = current_file.parent / filename
        if rel.exists():
            return rel
        # Try relative to config dir
        rel = self.config_dir / filename
        if rel.exists():
            return rel
        return None

    @staticmethod
    def _read_lines(path: Path) -> list[tuple[int, str]]:
        """Read a file and return (lineno, line) tuples, handling continuation lines."""
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            text = path.read_text(encoding="latin-1")

        raw_lines = text.splitlines()
        result: list[tuple[int, str]] = []
        continued = ""
        start_lineno = 1

        for i, line in enumerate(raw_lines, 1):
            if line.endswith("\\"):
                if not continued:
                    start_lineno = i
                continued += line[:-1] + " "
            else:
                if continued:
                    result.append((start_lineno, continued + line))
                    continued = ""
                else:
                    result.append((i, line))

        if continued:
            result.append((start_lineno, continued))

        return result


def load_config(config_dir: Path, config6_dir: Path | None = None,
                skip_sibling_merge: bool = False) -> ShorewalConfig:
    """Load and parse a Shorewall configuration directory.

    If config6_dir is provided, also loads the Shorewall6 config
    and merges both into a single unified config (dual-stack).
    """
    config_dir = Path(config_dir)
    if not config_dir.is_dir():
        raise ParseError(f"Not a directory: {config_dir}")

    parser = ConfigParser(config_dir)
    config = parser.parse()

    # Load Shorewall6 config if provided or auto-detected.
    # NOTE: When loading a pre-merged directory (ending in "46"), we skip
    # auto-detection — the config is already dual-stack, and there is no
    # sibling "466" directory. Only the legacy "shorewall" layout triggers
    # an auto-merge with its sibling "shorewall6". The auto-detect can
    # also be explicitly disabled via skip_sibling_merge (e.g. for
    # --no-auto-v6 CLI mode).
    if (config6_dir is None
            and not config_dir.name.endswith("46")
            and not skip_sibling_merge):
        # Auto-detect: /etc/shorewall6 next to /etc/shorewall
        candidate = config_dir.parent / (config_dir.name + "6")
        if candidate.is_dir():
            config6_dir = candidate

    if config6_dir and config6_dir.is_dir():
        parser6 = ConfigParser(config6_dir)
        config6 = parser6.parse()
        _merge_configs(config, config6)

    return config


def _merge_configs(config: ShorewalConfig, config6: ShorewalConfig) -> None:
    """Merge Shorewall6 config into the main config (dual-stack).

    Zones with the same name get their IPv6 rules added.
    New IPv6-only zones are added.
    Rules from both configs are combined.
    """
    # Merge params (v6 params override v4 if same name — usually different)
    # We prefix v6 params to avoid collisions
    for key, value in config6.params.items():
        if key not in config.params:
            config.params[key] = value
        # If same key exists in both, the v6 value might be different
        # (e.g. ORG_PFX is v4 in shorewall, v6 in shorewall6)
        # Keep both — the rules reference the right one via their config

    # Merge zones (same zone name = dual-stack)
    for line in config6.zones:
        # Check if zone already exists in v4
        zone_name = line.columns[0] if line.columns else ""
        existing = [z for z in config.zones if z.columns and z.columns[0] == zone_name]
        if not existing:
            config.zones.append(line)
        else:
            # Zone exists in both v4 and v6 → dual-stack.  Change its
            # type from the single-family "ipv4" to generic "ip" so the
            # emitter does NOT add a meta nfproto qualifier and the
            # dispatch rules match both address families.
            v4_line = existing[0]
            if len(v4_line.columns) > 1 and v4_line.columns[1] in ("ipv4", "ipv6"):
                v4_line.columns[1] = "ip"

    # Merge interfaces (v6 interfaces are typically the same physical interfaces)
    for line in config6.interfaces:
        iface_name = line.columns[1] if len(line.columns) > 1 else ""
        existing = [i for i in config.interfaces
                    if len(i.columns) > 1 and i.columns[1] == iface_name]
        if not existing:
            config.interfaces.append(line)

    # Merge policies
    config.policy.extend(config6.policy)

    # Merge rules
    config.rules.extend(config6.rules)

    # Merge other config files
    config.masq.extend(config6.masq)
    config.conntrack.extend(config6.conntrack)
    config.notrack.extend(config6.notrack)
    config.blrules.extend(config6.blrules)

    # Merge macros — v6 entries extend v4 entries in same macro.
    # The compiler filters by address family during expansion.
    for name, lines in config6.macros.items():
        if name in config.macros:
            # Append v6 entries — they have IPv6 addresses and will
            # only match in IPv6 context
            config.macros[name].extend(lines)
        else:
            config.macros[name] = lines
