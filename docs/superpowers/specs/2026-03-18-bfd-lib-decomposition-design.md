# BFD Library Decomposition — Design Spec

> **Date:** 2026-03-18
> **Project:** BFD (Brute Force Detection)
> **Branch:** `2.0.2`
> **Scope:** Decompose `bfd.lib.sh` (4,932 lines) and slim `bfd` executable (1,707 lines) into functionally-organized sub-libraries

---

## Problem Statement

`bfd.lib.sh` is a 4,932-line monolith containing 139 functions across 28 functional
domains. The `bfd` executable adds another 37 functions (1,707 lines) that belong in
libraries. This makes the codebase difficult to navigate, review, and maintain.

Two sub-libraries have already been successfully extracted (`bfd_alert.sh` at 970 lines,
`bfd_report.sh` at 693 lines), establishing the pattern. This spec extends that pattern
to decompose the remaining code.

## Goals

1. No file exceeds ~1,000 lines (flexible ceiling when functional coherence demands it)
2. `bfd` becomes a thin CLI wrapper (args + case dispatch only)
3. All critical functionality lives in sub-libraries under `files/internals/`
4. Function signatures and behavior are unchanged — internal reorganization only
5. Eliminate identified duplication (~1,100 line net reduction)
6. All 1,651 tests + 86 UAT tests pass without modification

## Non-Goals

- Refactoring function internals or changing APIs
- Adding new features or capabilities
- Modifying test files
- Changing the CLI interface

---

## Architecture

### File Map

```
files/bfd                    (~280 lines)  CLI wrapper: args + case dispatch
files/internals/
  bfd.lib.sh                 (~200 lines)  Sourcing hub + shared utilities
  bfd_validate.sh            (~500 lines)  Input + config validation
  bfd_fw.sh                  (~400 lines)  Firewall backend abstraction
  bfd_state.sh               (~550 lines)  State I/O + ban execution
  bfd_pressure.sh            (~550 lines)  Pressure model + geo + rule infra
  bfd_detect.sh              (~300 lines)  Detection pipeline (extract/filter)
  bfd_core.sh                (~800 lines)  Orchestration + init + watch mode
  bfd_events.sh            (~1100 lines)   Event queries + attack pool (merged)
  bfd_diag.sh                (~750 lines)  Health check + status + inspection
  bfd_alert.sh             (~1080 lines)   Alert rendering + delivery (existing)
  bfd_report.sh              (~693 lines)  Periodic reports (unchanged)
```

### Size Comparison

| Metric | Before | After |
|--------|--------|-------|
| Files | 4 | 12 |
| Total lines | ~8,300 | ~7,200 |
| Largest file | 4,932 | ~1,100 |
| Net reduction | — | ~1,100 lines |

### Sourcing Order

`bfd` sources `bfd.lib.sh`, which sources all sub-libraries in dependency order:

```
bfd
 └─ bfd.lib.sh (hub + shared utilities)
     ├── tlog_lib.sh            (upstream — log reading)
     ├── elog_lib.sh            (upstream — structured logging)
     ├── alert_lib.sh           (upstream — alert primitives)
     ├── geoip_lib.sh           (upstream — geolocation metadata)
     ├── bfd_validate.sh        (no BFD deps)
     ├── bfd_fw.sh              (depends: validate)
     ├── bfd_state.sh           (depends: validate, fw)
     ├── bfd_pressure.sh        (depends: validate, state)
     ├── bfd_alert.sh           (depends: pressure, state)
     ├── bfd_report.sh          (depends: alert, pressure)
     ├── bfd_detect.sh          (depends: validate, state, pressure)
     ├── bfd_core.sh            (depends: all above)
     ├── bfd_events.sh          (depends: state, pressure, validate)
     └── bfd_diag.sh            (depends: all above)
```

No circular dependencies exist in this order.

### Dependency Rules

- Upstream libraries (tlog, elog, alert, geoip) are never modified
- Each sub-library uses the established source guard pattern:
  `[[ -n "${_MODULE_LOADED:-}" ]] && return 0 2>/dev/null; _MODULE_LOADED=1`
- Each sub-library has a version variable: `MODULE_VERSION="1.0.0"`
- Private functions use `_prefix_` naming scoped to their module
- All sub-libraries resolve paths via `$_internals_dir` (set by bfd.lib.sh)

---

## File Contents

### `bfd` — Thin CLI Wrapper (~280 lines)

**Retains:**
- Shebang, header, version/path globals (`V`, `APPN`, `INSTALL_PATH`, `UTIME`)
- Source `bfd.lib.sh` with ownership/permission safety check
- Top-level `config_init` call with error handling
- Pre-parse modifier loop (`--json`, `--csv`, `--sort=`, `--limit=`, `--24h/7d/30d`,
  `--active`, `--verbose`, `--max-lines=`, `--scan-timeout=`)
- Main `case` dispatcher (all CLI flags → library function calls)
- `EXIT`/`INT`/`TERM` trap registration
- `vhead()` — version header
- `usage_short()`, `usage()` — help text (documents the CLI they live next to)

**Moves out:** All 33 non-CLI functions (config_init, check, run, watch, pre,
get_state, all `_apool_*`, `_batch_ban_status_*`, cleanup handlers).

### `bfd.lib.sh` — Sourcing Hub + Shared Utilities (~200 lines)

**Retains:**
- Source guard, `_internals_dir` resolution via `BASH_SOURCE[0]`
- Sources all upstream + BFD sub-libraries in dependency order (14 files)
- Exit code constants (`EXIT_OK`, `EXIT_CONFIG_ERROR`, `EXIT_LOCK_ERROR`,
  `EXIT_PREREQ_ERROR`)
- Shared micro-utilities used by 3+ sub-libraries:
  - `format_table()` — pipe-to-column alignment
  - `_fmt_ts()` — epoch → `mm/dd/yy HH:MM:SS`
  - `_fmt_ts_iso()` — epoch → ISO 8601
  - `eout()` — backward-compat logging wrapper (mode delegation to elog)
  - `vout()` — verbose output wrapper
  - `_json_escape()` — RFC 8259 string escaping
  - `_json_array_from_csv()` — CSV → JSON array
  - `format_duration()` — seconds → human-readable duration

### `bfd_validate.sh` — Input + Config Validation (~500 lines)

- `validate_ip()` — IPv4 validation (regex + octet range)
- `validate_ip6()` — IPv6 validation (:: expansion, zone ID stripping)
- `validate_ip_any()` — wrapper: try IPv4, fallback IPv6
- `validate_cidr()` — IPv4 CIDR notation (addr/mask, mask 8-32)
- `ip_to_subnet()` — compute network address from IP + prefix
- `sanitize_mod()` — service name validation (alphanum + underscore/hyphen)
- `sanitize_ports()` — port list validation ("all" or comma-separated integers)
- `validate_email()` — basic email format check
- `_check_file_safety()` — root ownership + permission validation
- `safe_source()` — source file after safety validation
- `extract_command_template()` — extract raw template from config
- `expand_command_template()` — safe `${var//pat/rep}` template expansion
- `validate_config()` (~230 lines) — comprehensive config variable validation
- `detect_log_paths()` — auto-detect auth/kernel/mail log paths

**Dependencies:** None (standalone). Sourced first among BFD modules.

### `bfd_fw.sh` — Firewall Backend Abstraction (~400 lines)

- `detect_firewall()` — auto-detect in priority order: apf → csf → firewalld →
  ufw → nftables → iptables → route
- 8 backends × 4 operations (32 private functions):
  - `_fw_{apf,csf,firewalld,ufw,nftables,iptables,route,custom}_{setup,ban,unban,status}()`
  - `_fw_nftables_count_elements()` — helper for nftables set counting
- Dispatch layer: `fw_resolve_backend()`, `fw_setup()`, `fw_ban()`, `fw_unban()`,
  `fw_status()`
- `_execute_fw_with_retry()` — exponential backoff retry (configurable count)

**Dependencies:** `bfd_validate.sh` (sanitize_ports, sanitize_mod,
expand_command_template for custom backend).

### `bfd_state.sh` — State I/O + Ban Execution (~550 lines)

**State initialization:**
- `state_init()` — create dirs/files with correct permissions (750 dirs, 600 files)

**Pool state (attack.pool):**
- `state_pool_append()` — flock-protected 10-field enriched event write
- `state_pool_prune()` — age-based pruning with safety cap

**Active ban state (bans.active):**
- `state_bans_active_append()` — idempotent flock-protected add
- `state_bans_active_remove()` — inode-preserving removal via cat
- `state_bans_active_check()` — AWK single-pass lookup
- `state_bans_active_expired()` — expired entry enumeration

**Ban history (bans.history):**
- `state_bans_history_append()` — append-only flock-protected log
- `state_bans_count_recent()` — windowed count for recidivism

**Pressure state (pressure.dat):**
- `state_pressure_append()` — weighted event recording
- `state_pressure_prune()` — windowed pruning with safety cap

**Ban execution:**
- `execute_ban()`, `execute_unban()` — high-level wrappers calling `fw_ban`/`fw_unban`
- `process_unbans()` — expire-and-unban loop
- `record_ban()` — record + compute escalation (expiry, recidivism, escalation curve)
- `compute_ban_duration()` — escalation modes: none/linear/double with cap
- `check_recidivism()` — permanent ban threshold check

**Ban management (CLI operations):**
- `manual_ban()`, `manual_unban()` — validate + execute + record
- `list_bans()`, `_list_bans_data()` — active ban display
- `list_bans_json()`, `list_bans_csv()` — structured ban list output
- `flush_bans()` — bulk unban (temp or all)

**Dependencies:** `bfd_validate.sh` (validate_ip_any, sanitize_mod),
`bfd_fw.sh` (fw_ban, fw_unban).

### `bfd_pressure.sh` — Pressure Model + Rule Infrastructure + Geolocation (~550 lines)

**Rule variable management:**
- `_save_rule_vars()`, `_restore_rule_vars()` — save/restore 11 rule variables to
  `_SV_*` globals
- `_clear_rule_vars()` — clear rule vars + legacy names for backward compat
- `_compat_rule_vars()` — map legacy names (REQ, LP, TLOG_TF, ARG_VAL) to canonical

**Pressure config loading:**
- `_load_pressure_conf()` — parse pressure.conf into `_PRESS_*` parallel arrays
- `_apply_pressure()` — fill empty vars from arrays (rule > conf > global precedence)
- `_load_thresholds()` — DEPRECATED: parse old thresholds.conf format
- `_apply_thresholds()` — DEPRECATED: fill from `_THRESH_*` arrays

**Rule activation:**
- `_rule_is_active()` — PREREQ binary existence check
- `validate_rule()` — post-source structural validation with journal fallback

**Pressure scoring:**
- `pressure_compute()` — exponential decay AWK (single-pass, ln2 constant)
- `pressure_format()` — scaled integer → decimal string (integer math)
- `_resolve_trip()` — per-rule trip threshold with global fallback
- `_resolve_min_trip()` — minimum trip across comma-separated service list
- `_pressure_aggregate_all()` — top-N IPs by pressure (AWK, sorted descending)
- `record_and_score()` — record weighted events + return pressure

**Geolocation:**
- `ip_to_country()` — IPv4 binary search AWK + IPv6 via geoip_lib, per-cycle cache
- `_resolve_cidr_cc()` — country lookup for CIDR entries (strip mask, look up base)
- `country_weight()` — pressure multiplier from pressure-country.conf
- `pressure_effective_weight()` — apply country multiplier to rule weight

**Batch optimization:**
- `_batch_pressure_compute()` — single AWK pass for all-IP per-mod + global pressure
- `_batch_ip_to_country()` — dual-stack batch country lookup (partition IPv4/IPv6)

**Dependencies:** `bfd_validate.sh` (_check_file_safety, validate_email),
`bfd_state.sh` (state_pressure_append).

### `bfd_detect.sh` — Detection Pipeline (~300 lines)

- `extract_hosts()` — IP extraction from log lines via `<HOST>` pattern expansion.
  Two sed passes (IPv4 with boundary guard, IPv6 inner group), AWK validation
  (octet ranges, hex:colon structure), IGNOREREGEX pre-filter. Sed `t`
  (test-and-branch) optimization: skip remaining patterns on first match.
- `filter_host()` — ignore cache > ignore files > local address exclusion
- `_build_ignore_cache()` — pre-merge all ignore lists into single file for O(1) lookup
- `_rule_tlog()` — BFD wrapper for tlog_lib log reading:
  - `_TLOG_PASSTHROUGH="1"` → entire log (test mode)
  - `_TLOG_PASSTHROUGH="file_path"` → specific file (test override)
  - `_SCAN_MODE="1"` → full file read (batch scan)
  - default → incremental read with cursor (watch mode)
- `count_subnet_attackers()` — subnet-level aggregation AWK (IPv4 bit-shift,
  IPv6 group-aligned)
- `check_distributed()` — subnet ban enforcement with CIDR alert sidecar files

**Dependencies:** `bfd_validate.sh` (validate_ip_any, validate_cidr),
`bfd_state.sh` (state_bans_active_check, execute_ban, record_ban, state_pool_append),
`bfd_pressure.sh` (_resolve_cidr_cc). tlog_lib.sh (tlog_read, tlog_read_full,
tlog_journal_read_full, tlog_journal_filter).

### `bfd_core.sh` — Orchestration + Initialization (~800 lines)

**Initialization:**
- `config_init()` (~180 lines) — source config files (conf.bfd, internals.conf),
  derive variables, load pressure arrays, validate config, setup firewall backend,
  initialize alert channels, register journal mappings. Supports reload mode for
  SIGHUP in watch.
- `_bfd_journal_register_all()` — 30+ service-to-journalctl filter registrations
  via `tlog_journal_register()`
- `pre()` — check prerequisites, migrate legacy logs, initialize state, discover
  local IPs

**Lock management:**
- `get_state()` — acquire or verify process lock with staleness/PID checks,
  configurable timeout

**Detection orchestration:**
- `check()` (~300 lines) — main detection cycle: iterate rules, source each,
  extract hosts, score pressure, execute bans, group alerts, dispatch alerts,
  check distributed attacks. Uses batch optimization helpers for performance.
- `run()` — `pre → get_state → process_unbans → check`

**Watch mode:**
- `watch()` — continuous daemon loop (sleep WATCH_INTERVAL, re-check, TLOG_FLOCK=1)
- `reload_watch()` — re-init config on SIGHUP, refresh local IPs
- `cleanup_watch()` — flush digest, remove locks on shutdown

**Cleanup:**
- `_cleanup_common()` — remove lock + ignore cache files
- `cleanup()` — remove lock + per-rule temp files (EXIT/INT/TERM trap handler)

**Dependencies:** All sub-libraries. This is the top-level orchestrator.

### `bfd_events.sh` — Event Queries + Attack Pool (Merged, ~1100-1200 lines)

This module merges the attack pool reporting functions (currently in `bfd`) with
the event query functions (currently in `bfd.lib.sh`). Both query the same state
files (attack.pool, pressure.dat, bans.active) and share helpers.

**Shared infrastructure:**
- `_batch_ban_status_init()` — precompute all ban statuses (2 AWK passes total)
- `_batch_ban_status_lookup()` — O(1) string lookup from precomputed file
- `_batch_ban_status_cleanup()` — remove temp lookup file

**Attack pool aggregation:**
- `_apool_awk()` — shared aggregation pipeline (search, filter, sort, limit, CIDR)
- `_apool_summary_awk()` — single-pass summary stats (unique IPs, total counts)
- `_apool_service_summary_awk()` — per-service breakdown AWK
- `_apool_service_dual_awk()` — dual-interval per-service AWK (24h/7d)

**Attack pool display (text/JSON/CSV):**
- `_apool_report()`, `_apool_report_json()`, `_apool_report_csv()`
- `_apool_summary()`, `_apool_summary_json()`, `_apool_summary_csv()`
- `_apool_service_summary()`, `_apool_service_summary_json()`,
  `_apool_service_summary_csv()`
- `_apool_service_dual()`, `_apool_service_dual_json()`, `_apool_service_dual_csv()`
- `apool_list()`, `apool_list_json()`, `apool_list_csv()` — public entry points

**Event list display (text/JSON/CSV):**
- `events_list()`, `events_list_json()`, `events_list_csv()`
- `events_list_ip()`, `events_list_ip_json()`, `events_list_ip_csv()`
- `events_list_cidr()`, `events_list_cidr_json()`, `events_list_cidr_csv()`

**IP search (text/JSON/CSV):**
- `search_ip()`, `search_ip_json()`, `search_ip_csv()`, `_search_ip_data()`

**Event data helpers:**
- `_events_ip_awk()` — per-IP data from pressure.dat (live, ephemeral)
- `_events_list_ip_pool_awk()` — per-IP aggregation from attack.pool (durable)
- `_events_rule_log_file()` — extract LOG_FILE from rule without detection
- `_events_rule_patterns()` — extract detection patterns from rule
- `_resolve_log_source_label()` — display label for rule's log source

**Dependencies:** `bfd_validate.sh` (validate_ip_any, validate_cidr),
`bfd_state.sh` (state_bans_active_check), `bfd_pressure.sh` (pressure_compute,
pressure_format, _resolve_trip, _resolve_min_trip, _resolve_cidr_cc,
_save_rule_vars, _restore_rule_vars, _clear_rule_vars, _compat_rule_vars,
_apply_pressure, _apply_thresholds).

### `bfd_alert.sh` — Alert Rendering + Delivery (~1080 lines, existing + 1 function)

**Existing 16 functions unchanged.** One function moves in:

- `send_alerts()` (~110 lines) — alert delivery orchestrator. Groups entries by
  RECIPIENT field, renders text/HTML via `_alert_render_text()`/`_alert_render_html()`,
  delivers via `_alert_deliver_email()`, dispatches messaging via
  `_bfd_dispatch_messaging()`. All called functions already live in this file.

### `bfd_report.sh` — Periodic Reports (~693 lines, unchanged)

No modifications.

---

## Dedup Findings

### 1. `_apool_ban_status()` → Replace with batch pattern (HIGH priority)

**Problem:** `_apool_ban_status()` spawns 2-3 AWK processes per IP. For the default
25-IP report, that's 50-75 subprocess spawns. The batch pattern
(`_batch_ban_status_init/lookup/cleanup`) does 2 AWK passes total for all IPs.

**Fix:** In `_apool_report()`, `_apool_report_json()`, and `_apool_report_csv()`:
replace per-IP `_apool_ban_status()` calls with batch init before loop, batch lookup
inside, batch cleanup after. Delete `_apool_ban_status()` entirely.

**Impact:** ~50-75 subprocess spawns eliminated per `--attackpool` invocation.
~25 lines removed.

### 2. `_apool_summary_awk()` cross-module usage (NO ACTION)

`_apool_summary_awk()` moves to `bfd_events.sh` and is called by `bfd_alert.sh`
(`_alert_compute_summary`) and `bfd_report.sh` (`_report_data`). This cross-module
call pattern is intentional and matches existing conventions — both callers already
reference functions across module boundaries.

### 3. Deprecated threshold functions (KEEP, document deprecation)

`_load_thresholds()` and `_apply_thresholds()` support the old `thresholds.conf`
format. Retained for backward compatibility with pre-2.0 upgrades. Flag for removal
in v3.0.

---

## Sub-Library Convention

All new sub-libraries follow the pattern established by `bfd_alert.sh` and
`bfd_report.sh`:

```bash
#!/bin/bash
# GPL v2 header
# (C) 1999-2026, R-fx Networks <proj@rfxn.com>
# Ryan MacDonald <ryan@rfxn.com>
# Description of module purpose

# Source guard
[[ -n "${_BFD_MODULE_LOADED:-}" ]] && return 0 2>/dev/null
_BFD_MODULE_LOADED=1

# Module version
# shellcheck disable=SC2034
BFD_MODULE_VERSION="1.0.0"

# Functions...
```

- Private functions: `_prefix_*` naming (e.g., `_fw_apf_ban`, `_hc_config`)
- Public functions: no leading underscore
- Internal state variables: `_PREFIXED_VAR` (underscore prefix)
- Data structures: parallel indexed arrays (bash 4.1 compat, no `declare -A`)
- AWK: mawk-compatible (no gensub, strftime, systime, length(array))

---

## Migration Safety

### Test Suite

All 1,651 unit/integration tests + 86 UAT tests call functions by name. Function
signatures do not change — only which file defines them. Tests source `bfd.lib.sh`
(which sources all sub-libraries), so the test harness works unchanged without
modification.

### Install Path

`install.sh` bulk-copies `files/internals/` to the install directory. New `bfd_*.sh`
files are automatically included — no installer changes needed.

### Existing Users

`bfd` still sources `bfd.lib.sh`, which still provides all functions at the same
names with the same signatures. The decomposition is internal to `files/internals/`
with zero external interface changes.

### Backward Compatibility

- All CLI flags unchanged (case dispatcher stays in `bfd`)
- All config variables unchanged
- All state file formats unchanged
- All exit codes unchanged
- Deprecated functions retained with backward-compat mappings

---

## Verification

After each phase:

```bash
bash -n files/bfd files/internals/bfd.lib.sh files/internals/bfd_*.sh
shellcheck -S warning files/bfd files/internals/bfd.lib.sh files/internals/bfd_*.sh
```

Standard grep checks per parent CLAUDE.md (hardcoded paths, bare cp/mv/rm,
backticks, unguarded cd, etc.).

Full test suite on Debian 12 + Rocky 9 after final phase.

---

## Risks

1. **Sourcing order sensitivity:** A function referenced before its defining module
   is sourced will fail at runtime. The dependency chain is acyclic and the sourcing
   order respects it, but each phase must verify with `bash -n` + targeted function
   call tests.

2. **Global variable initialization timing:** `config_init()` (moving to
   `bfd_core.sh`) sets globals consumed by all modules. Since it runs at call time
   (not source time), this is safe — all modules are sourced before `config_init()`
   executes.

3. **BATS test `load` ordering:** Tests use `load ../files/internals/bfd.lib.sh`
   which triggers the full source chain. Since the chain is preserved, no test
   changes needed. If any test sources individual internals files directly, those
   would need updating — grep for this during implementation.
