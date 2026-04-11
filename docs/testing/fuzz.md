---
title: Fuzz testing
description: Random config generator for finding edge cases in the parser, compiler, and emitter.
---

# Fuzz testing

`tests/test_config_gen.py` runs a random-config generator against
the compiler + kernel loader. Each fuzz iteration:

1. Generates a random but syntactically valid Shorewall config
2. Compiles it with `shorewall-nft compile`
3. Loads it into a netns via `nft -f`
4. Verifies the kernel accepted it

The generator lives in `shorewall_nft/tools/config_gen.py`. It's
seeded so failing iterations are reproducible by seed number.

## Running

```bash
# All fuzz tests (37 iterations by default)
pytest tests/test_config_gen.py -v

# A specific iteration
pytest tests/test_config_gen.py -v -k "test_generated_config[5]"

# More iterations (set via env or modify the parametrize)
FUZZ_ITERATIONS=100 pytest tests/test_config_gen.py -v
```

Each iteration uses a different seed. On failure, the seed is
printed — re-run with that seed to reproduce:

```bash
pytest tests/test_config_gen.py::test_generated_config -v \
    --seed-override=12345
```

## Generator parameters

`ConfigGenerator` accepts these knobs:

| Parameter | Range | Default |
|-----------|-------|---------|
| `num_zones` | 2-30 | random 2-10 |
| `num_rules` | 0-500 | random 10-100 |
| `dual_stack` | bool | 30% chance |
| `features` | subset of `{nat, macros, rfc1918, rates, ipsets}` | random |

Features covered by the generator:

- All zone types (`ipv4`, `ipv6`, `firewall`, `bport4`, `bport6`)
- Multi-interface zones
- Zone options (`routeback`, `routefilter`, `tcpflags`, `nosmurfs`)
- DHCP-enabled interfaces
- NAT (masq, DNAT, netmap, symmetric)
- All 149 standard macros + custom macros
- Rate limits (`s:name:rate/unit:burst`)
- Rfc1918 blocks
- GeoIP set references
- IPv6 dual-stack
- Conntrack/Notrack rules
- Accounting
- Dynamic blacklist

## Using the generator standalone

```bash
# Generate a random config and inspect it
.venv/bin/python -m shorewall_nft.tools.config_gen \
    --seed 42 \
    --zones 5 \
    --rules 50 \
    --dual-stack \
    -o /tmp/random-fw

ls /tmp/random-fw/
# zones, interfaces, policy, rules, params, shorewall.conf

# Compile and check
.venv/bin/shorewall-nft compile /tmp/random-fw -o /tmp/random.nft
.venv/bin/shorewall-nft check /tmp/random-fw --skip-caps
```

Or from Python:

```python
from pathlib import Path
from shorewall_nft.tools.config_gen import ConfigGenerator

gen = ConfigGenerator(seed=42)
gen.generate(
    output_dir=Path("/tmp/random-fw"),
    num_zones=5,
    num_rules=50,
    dual_stack=True,
    features={"nat", "macros", "rfc1918"},
)
```

## Interpreting failures

When a fuzz test fails, you get:

1. **The seed** — reproducible
2. **The generated config** on disk (left behind in a `pytest` tmpdir)
3. **The compile error** (if any) or nft load error

Typical failure modes:

- **Parser bug**: rare edge case in column handling. Fix the parser,
  add the minimal repro to `tests/test_parser.py`.
- **Compiler bug**: IR build crashes or produces invalid nft.
  Fix the compiler, add minimal repro to `tests/test_compiler.py`.
- **Emitter bug**: nft refuses the generated script. Fix the emitter,
  add minimal repro to `tests/test_emitter.py`.

Always **minimize** the failing config before committing the repro
test — keep only the zones / rules that are necessary to reproduce.

## Extending the generator

To cover a new feature class, add a generator method to
`ConfigGenerator` and include it in the top-level `generate()`:

```python
def _gen_my_feature(self, config_dir):
    lines = ["?SECTION NEW"]
    for _ in range(self.rng.randint(1, 10)):
        lines.append(self._gen_my_rule())
    (config_dir / "my_feature_rules").write_text("\n".join(lines))

def generate(self, output_dir, **kwargs):
    ...
    if "my_feature" in features:
        self._gen_my_feature(output_dir)
```

Then add a test case that exercises it:

```python
@pytest.mark.parametrize("seed", range(10))
def test_my_feature_fuzz(seed, swnft_cli_netns):
    gen = ConfigGenerator(seed=seed)
    gen.generate(tmp_path, features={"my_feature"})
    r = subprocess.run([SWNFT, "compile", str(tmp_path)])
    assert r.returncode == 0
```

## Scale

On a modern dev machine, the 37-iteration fuzz test runs in about
**30-45 seconds**. Running 1000 iterations locally overnight is
practical (`FUZZ_ITERATIONS=1000 pytest ...`) and has historically
caught the remaining edge cases that unit tests missed.

## See also

- [Test suite](test-suite.md) — where fuzz tests fit in the pytest layout
- [Testing index](index.md) — full testing overview
