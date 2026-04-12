"""Tests for the Shorewall config parser."""

from pathlib import Path

from shorewall_nft.config.parser import ConfigParser, load_config

MINIMAL_DIR = Path(__file__).parent / "configs" / "minimal"


class TestStripComment:
    def test_empty(self):
        assert ConfigParser._strip_comment("") == ""

    def test_full_comment(self):
        assert ConfigParser._strip_comment("# comment") == ""

    def test_trailing_comment(self):
        assert ConfigParser._strip_comment("value # comment") == "value"

    def test_no_comment(self):
        assert ConfigParser._strip_comment("value") == "value"

    def test_hash_in_quotes(self):
        assert ConfigParser._strip_comment('key="val#ue"') == 'key="val#ue"'

    def test_whitespace(self):
        assert ConfigParser._strip_comment("  value  ") == "value"


class TestSplitColumns:
    def test_simple(self):
        assert ConfigParser._split_columns("a b c") == ["a", "b", "c"]

    def test_tabs(self):
        assert ConfigParser._split_columns("a\tb\tc") == ["a", "b", "c"]

    def test_parentheses(self):
        assert ConfigParser._split_columns("SSH(ACCEPT) net $FW") == ["SSH(ACCEPT)", "net", "$FW"]

    def test_multiple_spaces(self):
        assert ConfigParser._split_columns("a   b   c") == ["a", "b", "c"]

    def test_empty(self):
        assert ConfigParser._split_columns("") == []


class TestVariableExpansion:
    def test_simple(self):
        parser = ConfigParser(Path("."))
        parser.params["FOO"] = "bar"
        assert parser._expand_vars("$FOO") == "bar"

    def test_braces(self):
        parser = ConfigParser(Path("."))
        parser.params["FOO"] = "bar"
        assert parser._expand_vars("${FOO}") == "bar"

    def test_transitive(self):
        parser = ConfigParser(Path("."))
        parser.params["A"] = "$B"
        parser.params["B"] = "value"
        assert parser._expand_vars("$A") == "value"

    def test_undefined(self):
        parser = ConfigParser(Path("."))
        assert parser._expand_vars("$UNDEFINED") == "$UNDEFINED"

    def test_inline(self):
        parser = ConfigParser(Path("."))
        parser.params["HOST"] = "10.0.0.1"
        assert parser._expand_vars("net:$HOST") == "net:10.0.0.1"

    def test_append_pattern(self, tmp_path):
        """Test append pattern as it works in real params files."""
        f = tmp_path / "params"
        f.write_text("LIST=a,b\nLIST=$LIST,c\n")
        parser = ConfigParser(tmp_path)
        parser._parse_params(f)
        assert parser.params["LIST"] == "a,b,c"


class TestConditions:
    def test_defined_var(self):
        parser = ConfigParser(Path("."))
        parser.params["FOO"] = "yes"
        assert parser._eval_condition("$FOO") is True

    def test_undefined_var(self):
        parser = ConfigParser(Path("."))
        assert parser._eval_condition("$FOO") is False

    def test_negation(self):
        parser = ConfigParser(Path("."))
        assert parser._eval_condition("!$FOO") is True

    def test_eq(self):
        parser = ConfigParser(Path("."))
        parser.params["FOO"] = "bar"
        assert parser._eval_condition("$FOO eq 'bar'") is True
        assert parser._eval_condition("$FOO eq 'baz'") is False

    def test_ne(self):
        parser = ConfigParser(Path("."))
        parser.params["FOO"] = "bar"
        assert parser._eval_condition("$FOO ne 'baz'") is True


class TestReadLines:
    def test_continuation(self, tmp_path):
        f = tmp_path / "test"
        f.write_text("line1 \\\ncontinued\nline2\n")
        result = ConfigParser._read_lines(f)
        assert len(result) == 2
        # Backslash is replaced by space, so there may be double space
        assert result[0][0] == 1
        assert "line1" in result[0][1]
        assert "continued" in result[0][1]
        assert result[1] == (3, "line2")


class TestLoadConfig:
    def test_minimal(self):
        config = load_config(MINIMAL_DIR)

        # Params
        assert config.params["LOG"] == "info"
        assert config.params["ADMIN"] == "192.168.1.100"
        assert config.params["DNS_SERVERS"] == "8.8.8.8,8.8.4.4"

        # Settings
        assert config.settings["STARTUP_ENABLED"] == "Yes"

        # Zones
        assert len(config.zones) == 3
        assert config.zones[0].columns[0] == "fw"
        assert config.zones[1].columns[0] == "net"
        assert config.zones[2].columns[0] == "loc"

        # Interfaces
        assert len(config.interfaces) == 2

        # Policy
        assert len(config.policy) == 4

        # Rules
        assert len(config.rules) >= 4
