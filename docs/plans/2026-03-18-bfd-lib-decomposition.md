# BFD Library Decomposition — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Decompose `bfd.lib.sh` (4,911 lines) and slim `bfd` (1,634 lines) into 8 functionally-organized sub-libraries, preserving all function signatures and passing all tests without modification.

**Spec:** `docs/superpowers/specs/2026-03-18-bfd-lib-decomposition-design.md`

**Architecture:** Bottom-up extraction in 9 phases following the dependency chain. Each phase creates one sub-library (or modifies an existing one), moves functions from `bfd.lib.sh` and/or `bfd`, adds a source statement, and verifies. Final state: `bfd.lib.sh` becomes a ~200-line sourcing hub; `bfd` becomes a ~280-line CLI wrapper. Net ~800-line reduction from dedup and dead scaffolding removal.

**Tech Stack:** Bash 4.1+, mawk-compatible AWK, BATS testing (batsman)

**Status:** NOT STARTED

---

## Constraints

- **Zero test modifications** — all 1,604 unit/integration + 86 UAT tests pass as-is
- **Function signatures unchanged** — internal reorganization only
- **One commit per phase** — format: `2.0.2 | Description`
- **Bash 4.1+ floor** — no `${var,,}`, `declare -n`, `$EPOCHSECONDS`
- **mawk-compatible AWK** — no `gensub()`, `strftime()`, `length(array)`
- **`command cp/mv/rm`** in source code (not `/usr/bin/` or bare)
- **No reordering** of existing source chain (bfd_alert.sh, bfd_report.sh stay in current positions)
- **CHANGELOG + CHANGELOG.RELEASE** updated every phase
- **Spec drift notes:**
  - The spec lists 6 functions removed in commit 6b313b5 (dead code cleanup): `record_and_score`, `pressure_effective_weight`, `_apool_service_summary_awk`, `_apool_service_summary`, `_apool_service_summary_json`, `_apool_service_summary_csv`. These no longer exist and are correctly omitted from this plan.
  - The spec says "Delete `_apool_ban_status()` entirely" (Dedup Finding #1). This plan retains it because 3 single-IP callers (`search_ip`, `events_list_ip_json`, `events_list_ip_csv`) and 7 tests depend on it — deleting would violate the zero-test-modification constraint. Only the batch-loop callers are converted.

---

## Conventions

### Sub-Library Template

Every new sub-library uses this boilerplate (replace placeholders):

```bash
#!/bin/bash
#
# Brute Force Detection 2.0.2 - MODULE_DESCRIPTION
###
# Copyright (C) 1999-2026, R-fx Networks <proj@rfxn.com>
# Copyright (C) 2026, Ryan MacDonald <ryan@rfxn.com>
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
###
#
# SOURCE_DESCRIPTION

# Source guard — prevent double-sourcing
[[ -n "${_GUARD_VAR:-}" ]] && return 0 2>/dev/null
_GUARD_VAR=1

# shellcheck disable=SC2034
VERSION_VAR="1.0.0"
```

### Source Statement Pattern

Each statement appended to `bfd.lib.sh` after the existing chain:

```bash
# Source DESCRIPTION
if [ -f "$_internals_dir/FILENAME" ]; then
	# shellcheck disable=SC1091
	. "$_internals_dir/FILENAME"
fi
```

### Verification Block

Run after every phase — referenced as "standard verification" in tasks:

```bash
# Syntax
bash -n files/bfd files/internals/bfd.lib.sh files/internals/bfd_*.sh \
       files/tlog files/internals/tlog_lib.sh files/internals/elog_lib.sh \
       files/internals/alert_lib.sh files/internals/geoip_lib.sh

# Lint
shellcheck -S warning files/bfd files/internals/bfd.lib.sh files/internals/bfd_*.sh

# Standard greps (all must be clean or justified with inline comments)
grep -rn '/usr/bin/\(rm\|mv\|cp\)' files/
grep -rn '^\s*cp \|^\s*mv \|^\s*rm ' files/
grep -rn 'local [a-z_]*=\$(' files/internals/bfd_*.sh
grep -rn '^\s*cd ' files/internals/bfd_*.sh
```

### Test Command

```bash
make -C tests test 2>&1 | tee /tmp/test-bfd-P{N}-debian12.log | tail -30
grep "not ok" /tmp/test-bfd-P{N}-debian12.log
```

Replace `{N}` with the phase number. All tests must pass, same count as baseline.

### Baseline

Before starting Phase 1, record:

```bash
grep -rc '@test' tests/*.bats | awk -F: '{s+=$2}END{print s}'
```

Every phase must match this count.

### bfd_load_function Behavior After Decomposition

Many tests use `bfd_load_function func_name` (default source: `files/bfd`) or
`bfd_load_function func_name "$PROJECT_ROOT/files/bfd"` to extract a single
function via AWK. After functions move to sub-libraries:

1. The AWK extraction from the old file returns empty → `eval ""` is a no-op
2. The function is STILL available because `bfd_common_setup` sources `bfd.lib.sh`
   which sources all sub-libraries (including the new file where the function lives)
3. Tests pass because the source-chain version takes precedence

**Do NOT update these `bfd_load_function` calls** — that would violate the
zero-test-modification constraint. The silent fallthrough is safe and intentional.

Verify before each phase that no test extracts a function by path from
`bfd.lib.sh` specifically (this would be a real risk):

```bash
grep -rn 'bfd_load_function.*bfd\.lib\.sh' tests/
```

Currently no matches (only `bfd_alert.sh` is referenced by explicit path).

---

## Task 1: Infrastructure + bfd_validate.sh

**Status:** NOT STARTED

**Summary:** Remove `unset _internals_dir` barrier. Extract input/config validation to the first BFD sub-library.

**Files:**
- Create: `files/internals/bfd_validate.sh`
- Modify: `files/internals/bfd.lib.sh`

**Functions (14, from bfd.lib.sh):**
- IP validation: `validate_ip`, `validate_ip6`, `validate_ip_any`, `validate_cidr`, `ip_to_subnet`
- Sanitization: `sanitize_mod`, `sanitize_ports`
- File safety: `_check_file_safety`, `safe_source`
- Email: `validate_email`
- Template: `extract_command_template`, `expand_command_template`
- Config: `validate_config` (~230 lines)
- Log paths: `detect_log_paths`

**Note:** `validate_config` references `EXIT_CONFIG_ERROR` defined later in bfd.lib.sh (line 114). Safe — not called at source time.

- [ ] **Step 1: Remove `unset _internals_dir`**

Delete line 64 of `bfd.lib.sh`:
```bash
unset _internals_dir
```

- [ ] **Step 2: Create bfd_validate.sh**

Create `files/internals/bfd_validate.sh` with sub-library template:
- `MODULE_DESCRIPTION`: `"Input and Config Validation"`
- `SOURCE_DESCRIPTION`: `"Sourced by bfd.lib.sh. Provides input validation, config validation, file safety checks, and log path detection."`
- `_GUARD_VAR`: `_BFD_VALIDATE_LOADED`
- `VERSION_VAR`: `BFD_VALIDATE_VERSION`

- [ ] **Step 3: Move functions**

Cut all 14 functions from `bfd.lib.sh` into `bfd_validate.sh`, preserving order. Clean up orphan blank lines or dangling comments in bfd.lib.sh.

- [ ] **Step 4: Add source statement**

In `bfd.lib.sh`, after the `bfd_report.sh` source block (~line 63), add:

```bash
# Source BFD input and config validation
if [ -f "$_internals_dir/bfd_validate.sh" ]; then
	# shellcheck disable=SC1091
	. "$_internals_dir/bfd_validate.sh"
fi
```

- [ ] **Step 5: Run standard verification**

- [ ] **Step 6: Run test suite**

- [ ] **Step 7: Update CHANGELOG + CHANGELOG.RELEASE**

- [ ] **Step 8: Commit**

```bash
git add files/internals/bfd_validate.sh files/internals/bfd.lib.sh CHANGELOG CHANGELOG.RELEASE
git commit -m "$(cat <<'EOF'
2.0.2 | Extract bfd_validate.sh from bfd.lib.sh

[Change] Move 14 validation functions (validate_ip/ip6/cidr, sanitize_mod/ports,
validate_config, detect_log_paths, etc.) to new bfd_validate.sh sub-library
[Change] Remove unset _internals_dir to support expanded source chain
EOF
)"
```

---

## Task 2: bfd_fw.sh

**Status:** NOT STARTED

**Summary:** Extract firewall backend abstraction — detection, 8 backends, dispatch layer, retry logic.

**Files:**
- Create: `files/internals/bfd_fw.sh`
- Modify: `files/internals/bfd.lib.sh`

**Functions (~40, from bfd.lib.sh):**
- Detection: `detect_firewall`
- Backends: `_fw_{apf,csf,firewalld,ufw,nftables,iptables,route,custom}_{setup,ban,unban,status}` (32)
- Helper: `_fw_nftables_count_elements`
- Dispatch: `fw_resolve_backend`, `fw_setup`, `fw_ban`, `fw_unban`, `fw_status`
- Retry: `_execute_fw_with_retry`

**Note:** Cleanest extraction — contiguous block with clear boundaries.

- [ ] **Step 1: Create bfd_fw.sh**

Template: `"Firewall Backend Abstraction"` / `_BFD_FW_LOADED` / `BFD_FW_VERSION`

Source desc: `"Sourced by bfd.lib.sh. Provides firewall detection, backend dispatch (apf/csf/firewalld/ufw/nftables/iptables/route/custom), ban/unban operations, and retry logic."`

- [ ] **Step 2: Move functions**

Cut entire firewall block from `bfd.lib.sh` — `detect_firewall` through `_execute_fw_with_retry` and all `_fw_*` functions between.

- [ ] **Step 3: Add source statement after bfd_validate.sh block**

```bash
# Source BFD firewall backend abstraction
if [ -f "$_internals_dir/bfd_fw.sh" ]; then
	# shellcheck disable=SC1091
	. "$_internals_dir/bfd_fw.sh"
fi
```

- [ ] **Step 4: Run standard verification + test suite**

- [ ] **Step 5: Commit**

```bash
git add files/internals/bfd_fw.sh files/internals/bfd.lib.sh CHANGELOG CHANGELOG.RELEASE
git commit -m "$(cat <<'EOF'
2.0.2 | Extract bfd_fw.sh from bfd.lib.sh

[Change] Move ~40 firewall backend functions (detect_firewall, 8 backends,
dispatch layer, retry logic) to new bfd_fw.sh sub-library
EOF
)"
```

---

## Task 3: bfd_state.sh

**Status:** NOT STARTED

**Summary:** Extract state I/O (attack pool, bans, pressure), ban execution/lifecycle, and ban management operations.

**Files:**
- Create: `files/internals/bfd_state.sh`
- Modify: `files/internals/bfd.lib.sh`

**Functions (24, from bfd.lib.sh):**
- State init: `state_init`
- Pool: `state_pool_append`, `state_pool_prune`
- Active bans: `state_bans_active_append`, `_remove`, `_check`, `_expired`
- History: `state_bans_history_append`, `state_bans_count_recent`
- Pressure: `state_pressure_append`, `state_pressure_prune`
- Execution: `execute_ban`, `execute_unban`, `process_unbans`
- Lifecycle: `record_ban`, `compute_ban_duration`, `check_recidivism`
- Management: `manual_ban`, `manual_unban`, `list_bans`, `_list_bans_data`, `list_bans_json`, `list_bans_csv`, `flush_bans`

**Note:** `list_bans_json`/`list_bans_csv` use `_json_escape` (stays in bfd.lib.sh) — available via global namespace.

- [ ] **Step 1: Create bfd_state.sh**

Template: `"State I/O and Ban Execution"` / `_BFD_STATE_LOADED` / `BFD_STATE_VERSION`

Source desc: `"Sourced by bfd.lib.sh. Provides state file operations (attack pool, active bans, ban history, pressure), ban execution/lifecycle, and ban management CLI operations."`

- [ ] **Step 2: Move functions**

Cut all `state_*` functions, then `execute_ban` through `check_recidivism`, then `_list_bans_data` through `flush_bans`, from `bfd.lib.sh`.

- [ ] **Step 3: Add source statement after bfd_fw.sh block**

```bash
# Source BFD state I/O and ban execution
if [ -f "$_internals_dir/bfd_state.sh" ]; then
	# shellcheck disable=SC1091
	. "$_internals_dir/bfd_state.sh"
fi
```

- [ ] **Step 4: Run standard verification + test suite**

- [ ] **Step 5: Commit**

```bash
git add files/internals/bfd_state.sh files/internals/bfd.lib.sh CHANGELOG CHANGELOG.RELEASE
git commit -m "$(cat <<'EOF'
2.0.2 | Extract bfd_state.sh from bfd.lib.sh

[Change] Move 24 state I/O and ban execution functions (state_*, execute_ban,
record_ban, manual_ban/unban, list/flush_bans) to new bfd_state.sh sub-library
EOF
)"
```

---

## Task 4: bfd_pressure.sh

**Status:** NOT STARTED

**Summary:** Extract pressure model, rule infrastructure, geolocation, and batch optimization.

**Files:**
- Create: `files/internals/bfd_pressure.sh`
- Modify: `files/internals/bfd.lib.sh`

**Functions (20, from bfd.lib.sh):**
- Rule vars: `_save_rule_vars`, `_restore_rule_vars`, `_clear_rule_vars`, `_compat_rule_vars`
- Config: `_load_pressure_conf`, `_apply_pressure`
- Deprecated: `_load_thresholds`, `_apply_thresholds`
- Activation: `_rule_is_active`, `validate_rule`
- Scoring: `pressure_compute`, `pressure_format`, `_resolve_trip`, `_resolve_min_trip`, `_pressure_aggregate_all`
- Geo: `ip_to_country`, `_resolve_cidr_cc`, `country_weight`
- Batch: `_batch_pressure_compute`, `_batch_ip_to_country`

**Note:** Retain deprecated `_load_thresholds`/`_apply_thresholds` with comment: `# DEPRECATED: retained for pre-2.0 upgrade compatibility. Remove in v3.0.`

- [ ] **Step 1: Create bfd_pressure.sh**

Template: `"Pressure Model and Rule Infrastructure"` / `_BFD_PRESSURE_LOADED` / `BFD_PRESSURE_VERSION`

Source desc: `"Sourced by bfd.lib.sh. Provides the pressure scoring model, rule variable management, rule activation/validation, geolocation lookups, and batch optimization helpers."`

- [ ] **Step 2: Move functions**

Cut all 20 functions from `bfd.lib.sh`, preserving logical grouping.

- [ ] **Step 3: Add source statement after bfd_state.sh block**

```bash
# Source BFD pressure model and rule infrastructure
if [ -f "$_internals_dir/bfd_pressure.sh" ]; then
	# shellcheck disable=SC1091
	. "$_internals_dir/bfd_pressure.sh"
fi
```

- [ ] **Step 4: Run standard verification + test suite**

- [ ] **Step 5: Commit**

```bash
git add files/internals/bfd_pressure.sh files/internals/bfd.lib.sh CHANGELOG CHANGELOG.RELEASE
git commit -m "$(cat <<'EOF'
2.0.2 | Extract bfd_pressure.sh from bfd.lib.sh

[Change] Move 20 pressure model and rule infrastructure functions (pressure_compute,
ip_to_country, rule var management, validate_rule, batch helpers) to new
bfd_pressure.sh sub-library
EOF
)"
```

---

## Task 5: bfd_detect.sh

**Status:** NOT STARTED

**Summary:** Extract detection pipeline — IP extraction, ignore-list filtering, tlog wrapper, subnet analysis.

**Files:**
- Create: `files/internals/bfd_detect.sh`
- Modify: `files/internals/bfd.lib.sh`

**Functions (6, from bfd.lib.sh):**
- `extract_hosts`, `filter_host`, `_build_ignore_cache`
- `_rule_tlog`
- `count_subnet_attackers`, `check_distributed`

**Note:** Smallest extraction. `_rule_tlog` references globals (`_TLOG_PASSTHROUGH`, `_SCAN_MODE`) set at runtime — safe.

- [ ] **Step 1: Create bfd_detect.sh**

Template: `"Detection Pipeline"` / `_BFD_DETECT_LOADED` / `BFD_DETECT_VERSION`

Source desc: `"Sourced by bfd.lib.sh. Provides IP extraction from log lines, ignore-list filtering, tlog wrapper for incremental log reading, and subnet/CIDR attack detection."`

- [ ] **Step 2: Move functions**

Cut all 6 functions from `bfd.lib.sh`.

- [ ] **Step 3: Add source statement after bfd_pressure.sh block**

```bash
# Source BFD detection pipeline
if [ -f "$_internals_dir/bfd_detect.sh" ]; then
	# shellcheck disable=SC1091
	. "$_internals_dir/bfd_detect.sh"
fi
```

- [ ] **Step 4: Run standard verification + test suite**

- [ ] **Step 5: Commit**

```bash
git add files/internals/bfd_detect.sh files/internals/bfd.lib.sh CHANGELOG CHANGELOG.RELEASE
git commit -m "$(cat <<'EOF'
2.0.2 | Extract bfd_detect.sh from bfd.lib.sh

[Change] Move 6 detection pipeline functions (extract_hosts, filter_host,
_rule_tlog, count_subnet_attackers, check_distributed) to new bfd_detect.sh
EOF
)"
```

---

## Task 6: bfd_events.sh (Merge + Dedup)

**Status:** NOT STARTED

**Summary:** Merge event query functions (from bfd.lib.sh) with attack pool reporting (from bfd). Replace per-IP `_apool_ban_status()` with batch pattern in loop callers (retain for single-IP callers).

**Files:**
- Create: `files/internals/bfd_events.sh`
- Modify: `files/internals/bfd.lib.sh`
- Modify: `files/bfd`

**Functions from bfd.lib.sh (18):**
- Event list: `events_list`, `events_list_json`, `events_list_csv`
- Event IP: `events_list_ip`, `events_list_ip_json`, `events_list_ip_csv`
- Event CIDR: `events_list_cidr`, `events_list_cidr_json`, `events_list_cidr_csv`
- IP search: `search_ip`, `search_ip_json`, `search_ip_csv`, `_search_ip_data`
- Helpers: `_events_ip_awk`, `_events_list_ip_pool_awk`, `_events_rule_log_file`, `_events_rule_patterns`, `_resolve_log_source_label`

**Functions from bfd (19 moved):**
- Batch status: `_batch_ban_status_init`, `_batch_ban_status_lookup`, `_batch_ban_status_cleanup`
- Single-IP status: `_apool_ban_status` (retained for single-IP callers — see dedup note)
- Apool AWK: `_apool_awk`, `_apool_summary_awk`, `_apool_service_dual_awk`
- Apool text: `_apool_report`, `_apool_summary`, `_apool_service_dual`
- Apool JSON: `_apool_report_json`, `_apool_summary_json`, `_apool_service_dual_json`
- Apool CSV: `_apool_report_csv`, `_apool_summary_csv`, `_apool_service_dual_csv`
- Apool CLI: `apool_list`, `apool_list_json`, `apool_list_csv`

**Dedup detail:** In `_apool_report()`, `_apool_report_json()`, and `_apool_report_csv()`,
the current code calls `_apool_ban_status "$ip"` per IP in a loop (2-3 AWK spawns each).
Replace with:

1. Before the per-IP loop: add `_batch_ban_status_init`
2. Inside the loop: replace `_apool_ban_status "$ip"` with `_batch_ban_status_lookup "$ip"`
3. After the loop: add `_batch_ban_status_cleanup`

**Do NOT delete `_apool_ban_status()`** — it has 3 additional single-IP callers
(`search_ip`, `events_list_ip_json`, `events_list_ip_csv`) and 7 tests that call
it directly. The batch pattern only benefits loop contexts; single-IP calls have
the same cost either way. Retaining `_apool_ban_status` satisfies the zero-test-
modification constraint.

Eliminates ~50-75 AWK subprocess spawns per `--attackpool` invocation.

- [ ] **Step 1: Create bfd_events.sh**

Template: `"Event Queries and Attack Pool"` / `_BFD_EVENTS_LOADED` / `BFD_EVENTS_VERSION`

Source desc: `"Sourced by bfd.lib.sh. Provides event list/search/CIDR queries, attack pool aggregation and reporting (text/JSON/CSV), and batch ban status optimization."`

- [ ] **Step 2: Move functions from bfd.lib.sh**

Cut all 18 event/search functions into `bfd_events.sh`.

- [ ] **Step 3: Move functions from bfd**

Cut all 19 apool/batch functions from `files/bfd` into `bfd_events.sh`.

- [ ] **Step 4: Apply dedup**

In `bfd_events.sh`, update `_apool_report()`, `_apool_report_json()`, and `_apool_report_csv()` to use the batch pattern (see Dedup detail above). Do NOT delete `_apool_ban_status()` — it is retained for single-IP callers and tests.

- [ ] **Step 5: Add source statement after bfd_detect.sh block**

```bash
# Source BFD event queries and attack pool
if [ -f "$_internals_dir/bfd_events.sh" ]; then
	# shellcheck disable=SC1091
	. "$_internals_dir/bfd_events.sh"
fi
```

- [ ] **Step 6: Run standard verification + test suite**

Pay extra attention to `--attackpool` output — the dedup changes the code path.

- [ ] **Step 7: Commit**

```bash
git add files/internals/bfd_events.sh files/internals/bfd.lib.sh files/bfd \
        CHANGELOG CHANGELOG.RELEASE
git commit -m "$(cat <<'EOF'
2.0.2 | Extract bfd_events.sh from bfd.lib.sh and bfd

[Change] Merge event query functions (from bfd.lib.sh) and attack pool reporting
functions (from bfd) into new bfd_events.sh sub-library (~37 functions)
[Change] Replace per-IP _apool_ban_status with batch pattern in _apool_report,
_apool_report_json, _apool_report_csv — eliminates ~50-75 AWK spawns per invocation
EOF
)"
```

---

## Task 7: bfd_diag.sh

**Status:** NOT STARTED

**Summary:** Extract read-only inspection and testing — health check, status, config display, rule inspection, alert testing.

**Files:**
- Create: `files/internals/bfd_diag.sh`
- Modify: `files/internals/bfd.lib.sh`

**Functions (17, from bfd.lib.sh):**
- Health: `health_check`, `_hc_config`, `_hc_binaries`, `_hc_rules`, `_hc_state`, `_hc_alerts`
- Status: `detect_run_mode`, `show_status`, `show_service_status`
- Config: `show_config` (includes `_mask_secret` local helper)
- Rules: `list_rules`, `show_rule`
- Testing: `test_rule`, `test_pattern`, `test_alert`, `test_alert_email`, `test_alert_messaging`

**Note:** ~1,050 lines — above the ~1,000-line ceiling, justified by functional coherence (all read-only inspection). `test_alert_email` calls `send_alerts()` still in bfd.lib.sh (moves Phase 8) — available via global namespace.

- [ ] **Step 1: Create bfd_diag.sh**

Template: `"Health Check, Status, and Diagnostics"` / `_BFD_DIAG_LOADED` / `BFD_DIAG_VERSION`

Source desc: `"Sourced by bfd.lib.sh. Provides health check, system status, config display, rule inspection, and alert testing operations."`

- [ ] **Step 2: Move functions**

Cut all 17 functions from `bfd.lib.sh`.

- [ ] **Step 3: Add source statement after bfd_events.sh block**

```bash
# Source BFD health check, status, and diagnostics
if [ -f "$_internals_dir/bfd_diag.sh" ]; then
	# shellcheck disable=SC1091
	. "$_internals_dir/bfd_diag.sh"
fi
```

- [ ] **Step 4: Run standard verification + test suite**

- [ ] **Step 5: Commit**

```bash
git add files/internals/bfd_diag.sh files/internals/bfd.lib.sh CHANGELOG CHANGELOG.RELEASE
git commit -m "$(cat <<'EOF'
2.0.2 | Extract bfd_diag.sh from bfd.lib.sh

[Change] Move 17 diagnostic functions (health_check, show_status, show_config,
list_rules, test_alert, etc.) to new bfd_diag.sh sub-library
EOF
)"
```

---

## Task 8: send_alerts → bfd_alert.sh

**Status:** NOT STARTED

**Summary:** Move `send_alerts()` from `bfd.lib.sh` to `bfd_alert.sh` where all its callees already reside.

**Files:**
- Modify: `files/internals/bfd.lib.sh` — remove `send_alerts`
- Modify: `files/internals/bfd_alert.sh` — add `send_alerts`

**Functions:** 1 (`send_alerts`, ~110 lines)

**Note:** bfd_alert.sh grows from ~983 to ~1,093 lines. No new file created.

- [ ] **Step 1: Move send_alerts()**

Cut `send_alerts()` from `bfd.lib.sh` and append to end of `bfd_alert.sh`.

- [ ] **Step 2: Run standard verification + test suite**

- [ ] **Step 3: Commit**

```bash
git add files/internals/bfd_alert.sh files/internals/bfd.lib.sh CHANGELOG CHANGELOG.RELEASE
git commit -m "$(cat <<'EOF'
2.0.2 | Move send_alerts() to bfd_alert.sh

[Change] Move send_alerts() (~110 lines) from bfd.lib.sh to bfd_alert.sh where
all its callees already reside (alert rendering, email delivery, messaging dispatch)
EOF
)"
```

---

## Task 9: bfd_core.sh + Slim bfd

**Status:** NOT STARTED

**Summary:** Create `bfd_core.sh` with orchestration (config_init, check, run, watch, cleanup). Move `_bfd_journal_register_all` definition. Slim `bfd` to CLI wrapper. Update CI.

**Files:**
- Create: `files/internals/bfd_core.sh`
- Modify: `files/bfd`
- Modify: `files/internals/bfd.lib.sh`
- Modify: `.github/workflows/ci.yml`

**Functions from bfd (10):**
- `config_init` (~180 lines), `pre`, `get_state`
- `check` (~300 lines), `run`
- `watch`, `reload_watch`, `cleanup_watch`
- `_cleanup_common`, `cleanup`

**Function from bfd.lib.sh (1):**
- `_bfd_journal_register_all` (definition only — lines 66-107)

**`_bfd_journal_register_all` handling:**

Move the **definition** (bfd.lib.sh lines 68-107) to `bfd_core.sh`. **Keep the call** in bfd.lib.sh (line 109) — it must come AFTER the `bfd_core.sh` source statement:

```bash
# Register journal filters at module load (definition in bfd_core.sh)
_bfd_journal_register_all
```

This preserves source-time behavior for tests that source bfd.lib.sh without calling config_init.

**What STAYS in bfd (~280 lines):**
- Shebang, GPL header, version/path globals (`V`, `APPN`, `INSTALL_PATH`, `UTIME`)
- `source` of bfd.lib.sh with ownership/permission safety check
- `vhead()`, `usage_short()`, `usage()`
- Pre-parse modifier loop
- Main `case` dispatcher
- Trap registration

**What STAYS in bfd.lib.sh (~200 lines):**
- Header, source guard, `_internals_dir`
- 14 source statements (6 upstream + 8 BFD)
- `_bfd_journal_register_all` call (2 lines)
- Exit codes: `EXIT_OK`, `EXIT_CONFIG_ERROR`, `EXIT_LOCK_ERROR`, `EXIT_PREREQ_ERROR`
- 8 shared utilities: `format_table`, `_fmt_ts`, `_fmt_ts_iso`, `eout`, `vout`, `_json_escape`, `_json_array_from_csv`, `format_duration`

- [ ] **Step 1: Create bfd_core.sh**

Template: `"Core Orchestration"` / `_BFD_CORE_LOADED` / `BFD_CORE_VERSION`

Source desc: `"Sourced by bfd.lib.sh. Provides config initialization, the main detection cycle, run/watch mode orchestration, journal registration, and cleanup handlers."`

- [ ] **Step 2: Move _bfd_journal_register_all definition**

Cut the function definition (bfd.lib.sh lines 66-107, including comment) into `bfd_core.sh`. Update the remaining call in bfd.lib.sh to be positioned AFTER the `bfd_core.sh` source statement.

- [ ] **Step 3: Move functions from bfd**

Cut `config_init`, `pre`, `get_state`, `check`, `run`, `cleanup_watch`, `reload_watch`, `watch`, `_cleanup_common`, `cleanup` from `files/bfd` into `bfd_core.sh`.

**Do NOT move:** `vhead`, `usage_short`, `usage` — these stay in `bfd`.

- [ ] **Step 4: Add source statement**

Must be the **last BFD module** before the `_bfd_journal_register_all` call:

```bash
# Source BFD core orchestration
if [ -f "$_internals_dir/bfd_core.sh" ]; then
	# shellcheck disable=SC1091
	. "$_internals_dir/bfd_core.sh"
fi

# Register journal filters at module load (definition in bfd_core.sh)
_bfd_journal_register_all
```

- [ ] **Step 5: Verify bfd is thin**

```bash
wc -l files/bfd                                   # expect ~280 (±30)
grep -c '^[a-z_]*()' files/bfd                     # expect 3 (vhead, usage_short, usage)
```

- [ ] **Step 6: Verify bfd.lib.sh is hub**

```bash
wc -l files/internals/bfd.lib.sh                   # expect ~200 (±30)
grep -c '^[a-z_]*()' files/internals/bfd.lib.sh    # expect 8 (shared utilities)
```

- [ ] **Step 7: Update ci.yml**

In `.github/workflows/ci.yml`, update lint targets to include new files. Use the glob `files/internals/bfd_*.sh` or list all 10 explicitly.

- [ ] **Step 8: Run standard verification**

- [ ] **Step 9: Run full test matrix**

```bash
make -C tests test 2>&1 | tee /tmp/test-bfd-P9-debian12.log | tail -30
grep "not ok" /tmp/test-bfd-P9-debian12.log

make -C tests test-rocky9 2>&1 | tee /tmp/test-bfd-P9-rocky9.log | tail -30
grep "not ok" /tmp/test-bfd-P9-rocky9.log
```

Both must match baseline count.

- [ ] **Step 10: Run UAT**

```bash
make -C tests uat 2>&1 | tee /tmp/test-bfd-P9-uat.log | tail -30
grep "not ok" /tmp/test-bfd-P9-uat.log
```

Expected: 86/86 pass.

- [ ] **Step 11: Commit**

```bash
git add files/internals/bfd_core.sh files/internals/bfd.lib.sh files/bfd \
        .github/workflows/ci.yml CHANGELOG CHANGELOG.RELEASE
git commit -m "$(cat <<'EOF'
2.0.2 | Extract bfd_core.sh and slim bfd to CLI wrapper

[Change] Move 11 orchestration functions (config_init, check, run, watch mode,
cleanup, _bfd_journal_register_all) to new bfd_core.sh sub-library
[Change] Slim bfd from ~1,634 to ~280 lines — thin CLI wrapper with args
parsing, case dispatch, and help text only
[Change] bfd.lib.sh reduced to ~200-line sourcing hub with 14 source statements
and 8 shared utilities
[Change] Update ci.yml lint targets for new sub-library files
EOF
)"
```

---

## Quality Gates

After all 9 phases:

### File Inventory

```bash
ls files/internals/bfd_*.sh | wc -l
```

Expected: 10 (8 new + 2 existing: bfd_alert.sh, bfd_report.sh).

### Line Counts

```bash
wc -l files/bfd files/internals/bfd.lib.sh files/internals/bfd_*.sh
```

Expected: `bfd` ~280, `bfd.lib.sh` ~200, no file exceeds ~1,200.

### Function Distribution

```bash
for f in files/bfd files/internals/bfd.lib.sh files/internals/bfd_*.sh; do
    printf "%3d %s\n" "$(grep -c '^[a-z_]*()' "$f")" "$f"
done | sort -rn
```

Verify: `bfd` = 3, `bfd.lib.sh` = 8, rest distributed.

### Full Test Matrix

```bash
make -C tests test 2>&1 | tee /tmp/test-bfd-final-debian12.log | tail -30
make -C tests test-rocky9 2>&1 | tee /tmp/test-bfd-final-rocky9.log | tail -30
make -C tests uat 2>&1 | tee /tmp/test-bfd-final-uat.log | tail -30
```

All must match baseline counts.

### Install Path Safety

```bash
grep -rn 'INSTALL_PATH\|/usr/local/bfd' files/internals/bfd_*.sh | grep -v '^\S*:\s*#'
```

If any new sub-library hardcodes paths that `pkg_sed_replace` should transform, add it to the sed list in `install.sh`. Expected: none — sub-libraries use `$INSTALL_PATH` variable.

### Source Guard Verification

```bash
for f in files/internals/bfd_*.sh; do
    basename "$f": $(grep -c '_LOADED' "$f")
done
```

Every file should have exactly 2 `_LOADED` references (guard check + guard set).
