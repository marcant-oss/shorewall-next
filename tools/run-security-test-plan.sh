#!/usr/bin/env bash
# run-security-test-plan.sh — execute the security test plan end-to-end.
#
# Reads per-standard catalogue fragments, merges them with a base stagelab
# config (hosts/endpoints/DUT/report), calls stagelab validate + run per
# standard, and finally calls stagelab audit to produce audit.html + audit.json.
#
# Usage:
#   run-security-test-plan.sh --config base-config.yaml [options]
#
# See --help for full option list.

set -euo pipefail

# ---------------------------------------------------------------------------
# Locate repo root and venv
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [[ -x "${REPO}/.venv/bin/python" ]]; then
    PYTHON="${REPO}/.venv/bin/python"
    STAGELAB="${REPO}/.venv/bin/shorewall-nft-stagelab"
elif command -v python3 > /dev/null 2>&1; then
    echo "WARNING: repo venv not found at ${REPO}/.venv; falling back to system python3" >&2
    PYTHON="python3"
    STAGELAB="shorewall-nft-stagelab"
else
    echo "ERROR: neither ${REPO}/.venv/bin/python nor system python3 found" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

ALL_STANDARDS="cc,nist,bsi,cis,owasp,iso27001,ipv6-perf"
STANDARDS_ARG="all"
BASE_CONFIG=""
OUT_DIR=""
CATALOGUE_DIR="${REPO}/docs/testing"
DO_SIMLAB=0
SIMLAB_HOST=""
DRY_RUN=0

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------

usage() {
    cat <<'USAGE'
usage: run-security-test-plan.sh [options]

  --standards LIST      Comma-separated standards to run:
                        cc,nist,bsi,cis,owasp,iso27001,ipv6-perf
                        or "all" (default: all).
  --config PATH         Base stagelab YAML with hosts/endpoints/DUT/report.
                        REQUIRED. Scenarios from this file are IGNORED;
                        the catalogue provides them.
  --out DIR             Output directory (default: /tmp/sec-plan-<timestamp>).
  --catalogue-dir DIR   Directory containing security-test-plan.<std>.yaml
                        fragments (default: docs/testing/).
  --simlab              Also run shorewall-nft-simlab smoke and embed report.
  --simlab-host HOST    SSH target for simlab (if running from a workstation
                        that lacks the /root/simulate-data reference dumps).
                        Example: --simlab-host root@192.0.2.93.
                        Requires --simlab.
  --dry-run             Print planned invocations without executing.
  -h, --help            Show this help and exit 0.
USAGE
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

while [[ $# -gt 0 ]]; do
    case "$1" in
        --standards)
            STANDARDS_ARG="$2"
            shift 2
            ;;
        --config)
            BASE_CONFIG="$2"
            shift 2
            ;;
        --out)
            OUT_DIR="$2"
            shift 2
            ;;
        --catalogue-dir)
            CATALOGUE_DIR="$2"
            shift 2
            ;;
        --simlab)
            DO_SIMLAB=1
            shift
            ;;
        --simlab-host)
            SIMLAB_HOST="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "ERROR: unknown option: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Validate required args
# ---------------------------------------------------------------------------

if [[ -z "${BASE_CONFIG}" ]]; then
    echo "ERROR: --config is required" >&2
    usage >&2
    exit 1
fi

if [[ -n "${SIMLAB_HOST}" && "${DO_SIMLAB}" -eq 0 ]]; then
    echo "ERROR: --simlab-host requires --simlab" >&2
    usage >&2
    exit 1
fi

# Expand the base config path to absolute (needed when we cd away).
BASE_CONFIG="$(cd "$(dirname "${BASE_CONFIG}")" && pwd)/$(basename "${BASE_CONFIG}")"

# ---------------------------------------------------------------------------
# Resolve standards list
# ---------------------------------------------------------------------------

if [[ "${STANDARDS_ARG}" == "all" ]]; then
    STANDARDS_LIST="${ALL_STANDARDS}"
else
    STANDARDS_LIST="${STANDARDS_ARG}"
fi

# Split comma-separated list into array.
IFS=',' read -ra STANDARDS <<< "${STANDARDS_LIST}"

# Validate each standard name against known list.
for std in "${STANDARDS[@]}"; do
    # Trim any leading/trailing whitespace produced by spaces around commas.
    std="${std# }"
    std="${std% }"
    case "${std}" in
        cc|nist|bsi|cis|owasp|iso27001|ipv6-perf)
            ;;
        *)
            echo "ERROR: unknown standard '${std}'. Valid values: ${ALL_STANDARDS}" >&2
            exit 1
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Output directory
# ---------------------------------------------------------------------------

if [[ -z "${OUT_DIR}" ]]; then
    TS="$(date +%Y%m%dT%H%M%S)"
    OUT_DIR="/tmp/sec-plan-${TS}"
fi

echo "Output directory: ${OUT_DIR}"

if [[ "${DRY_RUN}" -eq 0 ]]; then
    mkdir -p "${OUT_DIR}/runs" "${OUT_DIR}/logs" "${OUT_DIR}/configs"
fi

# ---------------------------------------------------------------------------
# Helper: merge base config + catalogue fragment into a per-standard config.
# Uses .venv/bin/python with pyyaml (hard dep of stagelab).
# ---------------------------------------------------------------------------

merge_config() {
    local std="$1"
    local fragment="$2"
    local out_config="$3"
    local run_dir="$4"

    "${PYTHON}" - "${BASE_CONFIG}" "${fragment}" "${out_config}" "${run_dir}" <<'PYEOF'
import sys, yaml
from pathlib import Path

base_path, fragment_path, out_path, run_dir = sys.argv[1:]

try:
    base = yaml.safe_load(Path(base_path).read_text())
except Exception as exc:
    print(f"ERROR: cannot parse base config {base_path}: {exc}", file=sys.stderr)
    sys.exit(1)

try:
    fragment = yaml.safe_load(Path(fragment_path).read_text())
except Exception as exc:
    print(f"ERROR: cannot parse catalogue fragment {fragment_path}: {exc}", file=sys.stderr)
    sys.exit(1)

if not isinstance(base, dict):
    print(f"ERROR: base config is not a YAML mapping: {base_path}", file=sys.stderr)
    sys.exit(1)

if not isinstance(fragment, dict):
    print(f"ERROR: catalogue fragment is not a YAML mapping: {fragment_path}", file=sys.stderr)
    sys.exit(1)

# Build merged config: take hosts/endpoints/dut/metrics from base;
# override report.output_dir; take scenarios from catalogue (covered only).
merged = {}

for key in ("hosts", "endpoints", "dut", "metrics"):
    if key in base:
        merged[key] = base[key]

# Override report.output_dir.
report = dict(base.get("report", {}))
report["output_dir"] = run_dir
merged["report"] = report

# Build endpoint role -> name index from base config.
role_index: dict = {}
for ep in base.get("endpoints", []):
    r = ep.get("role")
    if r:
        if r in role_index:
            print(
                f"WARNING: duplicate endpoint role {r!r} — ignoring subsequent",
                file=sys.stderr,
            )
            continue
        role_index[r] = ep["name"]

def _resolve(key_role, key_name, scenario):
    """If scenario has `<kind>_role: X`, replace it with `<kind>: <endpoint-name>`."""
    if key_role not in scenario:
        return
    role = scenario.pop(key_role)
    if key_name in scenario:
        # Explicit name takes precedence; warn and discard the role key.
        print(
            f"WARNING: scenario test_id={scenario.get('test_id')!r} has both "
            f"{key_name!r} and {key_role!r}; using explicit {key_name!r} — "
            f"remove {key_role!r} from catalogue entry",
            file=sys.stderr,
        )
        return
    if role not in role_index:
        print(
            f"WARNING: role {role!r} referenced in test_id={scenario.get('test_id')!r} "
            f"but not defined by any endpoint — scenario will be skipped",
            file=sys.stderr,
        )
        scenario["_skip_reason"] = f"role-unresolved:{role}"
        return
    scenario[key_name] = role_index[role]

# Extract covered scenarios from fragment.
raw_tests = fragment.get("tests", [])
scenarios = []
skipped_scenarios = []
seen_ids = set()

for entry in raw_tests:
    status = entry.get("status", "covered")
    if status != "covered":
        continue

    scenario = dict(entry.get("maps_to_scenario", {}))
    if not scenario:
        continue

    # Use test_id as scenario id; prefix with std shortname if collision.
    test_id = entry.get("test_id", "")
    scenario_id = scenario.get("id", test_id)
    if scenario_id in seen_ids:
        scenario_id = f"{test_id}-{scenario_id}"
    seen_ids.add(scenario_id)

    scenario["id"] = scenario_id

    # Carry through test_id and standard_refs if not already in scenario.
    if test_id and "test_id" not in scenario:
        scenario["test_id"] = test_id
    if "standard_refs" not in scenario and "standard_refs" in entry:
        scenario["standard_refs"] = entry["standard_refs"]
    if "acceptance_criteria" not in scenario and "acceptance_criteria" in entry:
        scenario["acceptance_criteria"] = entry["acceptance_criteria"]

    # Role-based endpoint resolution: replace source_role/sink_role with names.
    _resolve("source_role", "source", scenario)
    _resolve("sink_role", "sink", scenario)

    if "_skip_reason" in scenario:
        skipped_scenarios.append(scenario)
        continue

    scenarios.append(scenario)

if skipped_scenarios:
    skip_ids = [s.get("test_id", s.get("id", "?")) for s in skipped_scenarios]
    print(
        f"INFO: {len(skipped_scenarios)} scenario(s) skipped (role-unresolved): "
        f"{', '.join(skip_ids)}",
        file=sys.stderr,
    )

merged["scenarios"] = scenarios

Path(out_path).parent.mkdir(parents=True, exist_ok=True)
Path(out_path).write_text(yaml.safe_dump(merged, default_flow_style=False, sort_keys=False))
print(f"merged {len(scenarios)} covered scenario(s) into {out_path}", file=sys.stderr)
PYEOF
}

# ---------------------------------------------------------------------------
# Per-standard loop
# ---------------------------------------------------------------------------

FIRST_FAIL_EXIT=0
RUN_DIRS=()

for std in "${STANDARDS[@]}"; do
    # Trim whitespace.
    std="${std# }"
    std="${std% }"

    FRAGMENT="${CATALOGUE_DIR}/security-test-plan.${std}.yaml"
    MERGED_CONFIG="${OUT_DIR}/configs/${std}.yaml"
    RUN_DIR="${OUT_DIR}/runs/${std}"
    LOG_FILE="${OUT_DIR}/logs/${std}.log"

    echo ""
    echo "=== Standard: ${std} ==="

    if [[ ! -f "${FRAGMENT}" ]]; then
        echo "WARNING: catalogue fragment not found: ${FRAGMENT} — skipping ${std}" >&2
        continue
    fi

    if [[ "${DRY_RUN}" -eq 1 ]]; then
        echo "[dry-run] would merge: ${FRAGMENT} + ${BASE_CONFIG} -> ${MERGED_CONFIG}"
        echo "[dry-run] stagelab validate ${MERGED_CONFIG}"
        echo "[dry-run] stagelab run ${MERGED_CONFIG} --output-dir ${RUN_DIR}"
        continue
    fi

    # Merge configs.
    merge_config "${std}" "${FRAGMENT}" "${MERGED_CONFIG}" "${RUN_DIR}"

    # Validate merged config.
    echo "  validating ${MERGED_CONFIG} ..."
    if ! "${STAGELAB}" validate "${MERGED_CONFIG}"; then
        echo "ERROR: validation failed for standard '${std}'" >&2
        if [[ "${FIRST_FAIL_EXIT}" -eq 0 ]]; then
            FIRST_FAIL_EXIT=2
        fi
        continue
    fi

    # Run scenarios.
    echo "  running scenarios (log: ${LOG_FILE}) ..."
    mkdir -p "$(dirname "${LOG_FILE}")"
    if ! "${STAGELAB}" run "${MERGED_CONFIG}" --output-dir "${RUN_DIR}" \
            > "${LOG_FILE}" 2>&1; then
        echo "ERROR: stagelab run failed for standard '${std}' (see ${LOG_FILE})" >&2
        if [[ "${FIRST_FAIL_EXIT}" -eq 0 ]]; then
            FIRST_FAIL_EXIT=3
        fi
    else
        echo "  run complete: ${RUN_DIR}"
        RUN_DIRS+=("${RUN_DIR}")
    fi
done

# ---------------------------------------------------------------------------
# Simlab (optional)
# ---------------------------------------------------------------------------

SIMLAB_JSON="${OUT_DIR}/simlab.json"
SIMLAB_FLAG=""

if [[ "${DO_SIMLAB}" -eq 1 ]]; then
    echo ""
    echo "=== simlab smoke ==="
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        if [[ -n "${SIMLAB_HOST}" ]]; then
            echo "[dry-run] ssh ${SIMLAB_HOST} cd /root/shorewall-nft && .venv/bin/python -m shorewall_nft_simlab.smoketest smoke --output-json <remote-tmp>"
            echo "[dry-run] scp ${SIMLAB_HOST}:<remote-tmp> ${SIMLAB_JSON}"
        else
            echo "[dry-run] python -m shorewall_nft_simlab.smoketest smoke --output-json ${SIMLAB_JSON}"
        fi
    else
        if [[ -n "${SIMLAB_HOST}" ]]; then
            echo "  running simlab on remote: ${SIMLAB_HOST}"
            REMOTE_TMP="$(ssh "${SIMLAB_HOST}" 'mktemp /tmp/simlab-XXXXXX.json')"
            if ssh "${SIMLAB_HOST}" "cd /root/shorewall-nft && \
                    .venv/bin/python -m shorewall_nft_simlab.smoketest smoke \
                        --output-json ${REMOTE_TMP}"; then
                scp "${SIMLAB_HOST}:${REMOTE_TMP}" "${SIMLAB_JSON}"
                ssh "${SIMLAB_HOST}" "rm -f ${REMOTE_TMP}"
                SIMLAB_FLAG="--simlab-report ${SIMLAB_JSON}"
                echo "  simlab.json fetched -> ${SIMLAB_JSON}"
            else
                echo "WARNING: simlab smoke failed on ${SIMLAB_HOST}; embedding skipped" >&2
            fi
        else
            if "${PYTHON}" -m shorewall_nft_simlab.smoketest smoke \
                    --output-json "${SIMLAB_JSON}" > "${OUT_DIR}/logs/simlab.log" 2>&1; then
                echo "  simlab smoke passed: ${SIMLAB_JSON}"
                SIMLAB_FLAG="--simlab-report ${SIMLAB_JSON}"
            else
                echo "WARNING: simlab smoke failed; embedding skipped" >&2
            fi
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Audit report
# ---------------------------------------------------------------------------

echo ""
echo "=== audit report ==="

if [[ "${DRY_RUN}" -eq 1 ]]; then
    echo "[dry-run] stagelab audit <run-dirs...> --output ${OUT_DIR} --format html ${SIMLAB_FLAG}"
    echo ""
    echo "Dry-run complete. No files written."
    exit 0
fi

if [[ "${#RUN_DIRS[@]}" -eq 0 ]]; then
    echo "ERROR: no successful runs to audit" >&2
    exit "${FIRST_FAIL_EXIT:-4}"
fi

# Build stagelab audit command.
AUDIT_ARGS=()
for rd in "${RUN_DIRS[@]}"; do
    AUDIT_ARGS+=("${rd}")
done
AUDIT_ARGS+=(--output "${OUT_DIR}" --format html)
# Pass simlab flag if set (word-splitting intentional — flag is either empty or
# two words, but we use an array to avoid SC2086).
if [[ -n "${SIMLAB_FLAG}" ]]; then
    # shellcheck disable=SC2206
    AUDIT_ARGS+=(${SIMLAB_FLAG})
fi

if ! "${STAGELAB}" audit "${AUDIT_ARGS[@]}"; then
    echo "ERROR: stagelab audit failed" >&2
    if [[ "${FIRST_FAIL_EXIT}" -eq 0 ]]; then
        FIRST_FAIL_EXIT=5
    fi
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo ""
echo "=== results ==="
if [[ -f "${OUT_DIR}/audit.html" ]]; then
    echo "  audit.html : ${OUT_DIR}/audit.html"
fi
if [[ -f "${OUT_DIR}/audit.json" ]]; then
    echo "  audit.json : ${OUT_DIR}/audit.json"
fi
if [[ -f "${SIMLAB_JSON}" ]]; then
    echo "  simlab.json: ${SIMLAB_JSON}"
fi
echo "  run dirs   : ${OUT_DIR}/runs/"
echo "  logs       : ${OUT_DIR}/logs/"

if [[ "${FIRST_FAIL_EXIT}" -ne 0 ]]; then
    echo ""
    echo "WARNING: one or more runs or the audit step encountered errors." >&2
    exit "${FIRST_FAIL_EXIT}"
fi

if [[ ! -f "${OUT_DIR}/audit.html" ]]; then
    echo "ERROR: audit.html was not produced" >&2
    exit 6
fi

exit 0
