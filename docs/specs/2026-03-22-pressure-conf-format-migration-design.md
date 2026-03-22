# pressure.conf Format Migration Design

**Date:** 2026-03-22
**Version:** 2.0.2
**Status:** Draft

---

## 1. Problem Statement

BFD's `pressure.conf` uses a colon-delimited `RULE:KEY=VAL:KEY=VAL` format
inherited from the original thresholds.conf design:

```
sshd:PRESSURE_WEIGHT=3:PRESSURE_TRIP=15
dovecot:PRESSURE_WEIGHT=2:PRESSURE_TRIP=20:SKIP_ALERT=1:RULE_EMAIL=ops@test.com
```

This format is inconsistent with the two newer config files introduced in
v2.0.2, both of which use whitespace-delimited layouts:

- `cdn-providers.conf` — `NAME  TREATMENT  MULT  FORMAT  URL_V4  URL_V6`
- `pressure-country.conf` — `CC MULT` (migrated from `CC=MULT` in v2.0.2)

The uppercase `PRESSURE_WEIGHT`, `PRESSURE_TRIP` keys are also unnecessarily
verbose for a file where every entry is already scoped to pressure overrides.

Additionally, the codebase carries ~340 lines of dead code for
`thresholds.conf` — an intermediate development artifact from 2.0.1 that
was replaced by `pressure.conf` before any public release. This includes
two deprecated functions (`_load_thresholds`, `_apply_thresholds`), a
variable (`THRESHOLDS_CONF`), importconf migration logic, FHS package
path transforms, and a dedicated test file (`tests/27-thresholds.bats`).

**Metrics:**
- Current `pressure.conf`: 88 lines (65 active entries across 4 weight tiers)
- `_load_pressure_conf()`: 73 lines (lines 148–221 of bfd_pressure.sh)
- `_load_thresholds()`: 55 lines (lines 74–129)
- `_apply_thresholds()`: 15 lines (lines 131–146), with 6 active call sites
  in `bfd_diag.sh` (5) and `bfd_core.sh` (1)
- thresholds.conf importconf migration: 48 lines (lines 177–224)
- `tests/27-thresholds.bats`: 295 lines (25 tests — 15 thresholds-only,
  10 `_load_pressure_conf`/`_apply_pressure` that must be relocated)
- 4 tests in `tests/25-importconf.bats` reference thresholds.conf
- thresholds.conf FHS transforms: 2 lines across `pkg/rpm/bfd.spec` + `pkg/deb/debian/rules`
- `THRESHOLDS_CONF` variable: `internals.conf` line 41

---

## 2. Goals

1. **Format migration**: Ship `pressure.conf` in whitespace-delimited
   `rule key=val [key=val ...]` format with lowercase keys
2. **Dual-format parser**: `_load_pressure_conf()` accepts both old
   (colon-delimited uppercase) and new (whitespace-delimited lowercase)
   lines, per-line detection
3. **Upgrade conversion**: `importconf` detects old-format `pressure.conf`
   and converts to new format on upgrade
4. **Dead code removal**: Remove all `thresholds.conf` support — functions,
   variables, importconf migration path, tests, FHS transforms
5. **Documentation sync**: Update `bfd.1` man page, `README.md`, and
   `conf.bfd` comment to reflect the new format
6. **Zero regression**: All existing tests pass (modulo format fixture
   updates); no behavioral change in pressure scoring

---

## 3. Non-Goals

- **Rule file variable names**: `PRESSURE_WEIGHT`, `PRESSURE_TRIP` stay
  uppercase in rule files — they are shell variables set via `safe_source`,
  not config file keys
- **Rename pressure.conf file**: The filename stays `pressure.conf`
- **Change pressure scoring math**: This is a config format migration only
- **New pressure features**: No new keys, tiers, or scoring changes
- **importconf for pre-thresholds upgrades**: The `elif rules/` fallback
  path in importconf (lines 225–254) stays — it handles real pre-2.0
  upgrades from v1.5 rule files with uncommented `TRIG=` values
- **Lowercase rule names in files**: Rule names stay as-is (e.g.,
  `nginx-http-auth`, `asterisk_badauth`) — they match filenames in
  `rules/` which are consumed by the detection pipeline

---

## 4. Architecture

### 4.1 File Map

| File | Action | Est. Lines | Purpose |
|------|--------|-----------|---------|
| `files/pressure.conf` | **Rewrite** | 88→92 | New format with lowercase keys |
| `files/internals/bfd_pressure.sh` | **Modify** | 651→~580 | Dual-format parser, remove `_load_thresholds`/`_apply_thresholds` |
| `files/internals/bfd_core.sh` | **Modify** | 800→~792 | Remove thresholds.conf fallback + arrays + `_apply_thresholds` call |
| `files/internals/bfd_diag.sh` | **Modify** | ~1100→~1095 | Remove 5 `_apply_thresholds()` calls |
| `files/bfd` | **Modify** | 441→441 | Remove `_THRESH_*` from `declare -A` at line 64 |
| `files/internals/internals.conf` | **Modify** | 73→~71 | Remove `THRESHOLDS_CONF` variable |
| `importconf` | **Modify** | 379→~340 | Add old→new format conversion, remove thresholds.conf migration |
| `tests/27-thresholds.bats` | **Delete** | 295→0 | Dead test file (10 tests relocated to 30-pressure.bats) |
| `tests/30-pressure.bats` | **Modify** | 559→~620 | Update fixtures, add new-format + mixed-format tests, absorb 10 relocated tests |
| `tests/25-importconf.bats` | **Modify** | 1193→~1170 | Remove thresholds.conf tests, add format conversion test |
| `tests/17-check-pipeline.bats` | **Modify** | 1164→~1158 | Update fixture format in 3 tests, remove `_load_thresholds`/`_THRESH_*` calls |
| `tests/33-watch-mode.bats` | **Modify** | 545→545 | Update fixture format in 1 test |
| `bfd.1` | **Modify** | 1129→~1125 | Update format description, remove thresholds.conf ref |
| `README.md` | **Modify** | 1045→~1040 | Update format description, remove thresholds.conf ref |
| `CHANGELOG` | **Modify** | — | Add entries for format migration + dead code removal |
| `CHANGELOG.RELEASE` | **Modify** | — | Add entries for format migration + dead code removal |
| `pkg/rpm/bfd.spec` | **Modify** | ~320→~319 | Remove thresholds.conf FHS transform |
| `pkg/deb/debian/rules` | **Modify** | ~80→~79 | Remove thresholds.conf FHS transform |

### 4.2 Size Comparison

| Metric | Before | After | Delta |
|--------|--------|-------|-------|
| `bfd_pressure.sh` functions | 20 | 18 | -2 (dead code) |
| `bfd_pressure.sh` lines | 651 | ~580 | -71 |
| `bfd_core.sh` lines | 800 | ~792 | -8 |
| `bfd_diag.sh` `_apply_thresholds` calls | 5 | 0 | -5 |
| `internals.conf` lines | 73 | ~71 | -2 |
| `importconf` lines | 379 | ~340 | -39 |
| Test files | 4 files | 3 files | -1 (27-thresholds.bats deleted) |
| Test count | ~1490 | ~1478 | -12 (15 dead removed, 10 relocated, 3 new) |
| Total dead code removed | — | — | ~400 lines (code + tests + docs) |

### 4.3 Dependency Tree

```
files/bfd (CLI wrapper)
  ├─ declare -A _THRESH_* [REMOVED from line 64]
  └─ files/internals/bfd.lib.sh (sourcing hub)
       ├─ internals.conf ← PRESSURE_CONF defined here (THRESHOLDS_CONF removed)
       ├─ bfd_pressure.sh ← _load_pressure_conf() (dual-format parser)
       │                     _apply_pressure() (unchanged)
       │                     [_load_thresholds() REMOVED]
       │                     [_apply_thresholds() REMOVED]
       ├─ bfd_diag.sh ← 5 _apply_thresholds() calls [REMOVED]
       └─ bfd_core.sh ← config_init() calls _load_pressure_conf()
                         1 _apply_thresholds() call [REMOVED]
                         [thresholds.conf fallback REMOVED]
                         [_THRESH_* arrays REMOVED]
                         [_load_thresholds() call REMOVED]

importconf ← old→new format conversion (new)
             [thresholds.conf migration REMOVED]
             pre-thresholds rule TRIG migration (STAYS, writes new format)

files/pressure.conf ← shipped default (new format)
```

### 4.4 Key Changes

1. **Parser**: `_load_pressure_conf()` gains a per-line format detector.
   The first whitespace-delimited token is extracted; if it contains a
   colon, the line is parsed with the existing colon-delimiter logic.
   All other non-comment lines are parsed as whitespace-delimited
   `rule key=val [key=val ...]`.

2. **Key mapping** (new format only):
   - `weight` → `_PRESS_WEIGHT[rule]`
   - `trip` → `_PRESS_TRIP[rule]`
   - `skip_alert` → `_PRESS_SKIP_ALERT[rule]`
   - `rule_email` → `_PRESS_RULE_EMAIL[rule]`

3. **TRIG alias dropped**: Per Q4 decision, `TRIG` is no longer recognized
   as a key in pressure.conf (either format). importconf has been converting
   `TRIG` → `PRESSURE_TRIP` since 2.0.1, and no production install has
   `TRIG` in pressure.conf. Only `trip` (new format) and `PRESSURE_TRIP`
   (old format) are recognized. The `_apply_pressure()` rule-file
   TRIG→PRESSURE_TRIP mapping is unchanged.

4. **importconf**: The existing `if [ -f "$BK_LAST/pressure.conf" ]` block
   gains format detection. If the old file contains old-format lines
   (`grep -qE '^[a-z_-]+:PRESSURE_'`), it is converted via awk before
   copying. Otherwise copied as-is.

5. **importconf pre-thresholds path**: The `elif [ -f "$new_press" ] && [ -d "$BK_LAST/rules" ]`
   block (lines 225–254) stays but its output changes from old format
   (`rule:PRESSURE_TRIP=N`) to new format (`rule  trip=N`).

### 4.5 Dependency Rules

- `_load_pressure_conf()` must remain in `bfd_pressure.sh` (same file as
  `_apply_pressure()` which consumes the arrays)
- Format detection is per-line (not per-file) to handle mixed-format files
  during partial user edits
- The `modsec:` → `mod_sec:` rename in importconf must work for both
  old-format (`modsec:PRESSURE_...`) and new-format (`modsec  weight=...`)
  lines

---

## 5. File Contents

### 5.1 `files/pressure.conf` (rewrite)

New default file ships with whitespace-delimited lowercase keys. All 65
active entries converted. Comment header updated.

```
# Per-rule pressure overrides for BFD
#
# Format: RULE  key=value [key=value ...]
# Keys:   weight, trip, skip_alert, rule_email
#
# ...header comments (same structure as current, updated for new format)...
#
# Multi-field example:
#   postfix  weight=2  trip=20  skip_alert=1

# --- Weight 5: Control panels ---
cpanel          weight=5  trip=10
plesk           weight=5  trip=10
...
```

### 5.2 `files/internals/bfd_pressure.sh` (modify)

**Removed functions:**

| Function | Lines | Reason |
|----------|-------|--------|
| `_load_thresholds()` | 74–129 (55 lines) | Dead code — thresholds.conf never shipped |
| `_apply_thresholds()` | 131–146 (15 lines) | Dead code — thresholds.conf never shipped |

**Modified functions:**

| Function | Current Behavior | New Behavior | Lines Affected |
|----------|-----------------|--------------|----------------|
| `_load_pressure_conf()` | Parses colon-delimited `RULE:KEY=VAL` only | Per-line format detection: colon path (old) or whitespace path (new) | 148–221 (rewrite) |

**`_load_pressure_conf()` new-format parsing logic:**

```
read line
  → skip comments/blanks
  → _first="${line%%[[:space:]]*}"
  → case "$_first" in *:*)
      # OLD FORMAT: existing colon parser
      # (PRESSURE_WEIGHT, PRESSURE_TRIP, SKIP_ALERT, RULE_EMAIL)
      # NOTE: TRIG alias dropped per Q4 decision — not recognized
    ;;
    *)
      # NEW FORMAT: first whitespace-delimited field = rule_name
      # remaining fields = key=val pairs
      # recognized keys: weight, trip, skip_alert, rule_email
      # same validation logic (positive integer for weight/trip,
      # clamp trip≤200, validate_email)
    ;;
  esac
```

**Function inventory (after changes):**

| Function | Signature | Purpose | Dependencies |
|----------|-----------|---------|--------------|
| `_save_rule_vars()` | `()` | Save per-rule vars | — |
| `_restore_rule_vars()` | `()` | Restore per-rule vars | — |
| `_clear_rule_vars()` | `()` | Clear per-rule vars | — |
| `_compat_rule_vars()` | `()` | Legacy rule name mapping | — |
| `_load_pressure_conf()` | `(conf_file)` | **Dual-format parser** | `_check_file_safety()`, `validate_email()`, `elog()` |
| `_apply_pressure()` | `(rule_name)` | Fill empty vars from arrays | `_PRESS_*` arrays |
| `_rule_is_active()` | `()` | Check PREREQ exists | — |
| `validate_rule()` | `(rule_name)` | Validate sourced rule | `elog()`, `tlog_journal_filter()` |
| `pressure_compute()` | `(install_path, host, half_life, now, [mod])` | Compute decayed pressure | — |
| `pressure_format()` | `(scaled_pressure)` | Format scaled int as decimal | — |
| `_resolve_trip()` | `(service)` | Per-rule trip lookup | `_PRESS_TRIP[]` |
| `_resolve_min_trip()` | `(csv_services)` | Min trip across services | `_PRESS_TRIP[]` |
| `_pressure_aggregate_all()` | `(events_file, now, half_life)` | All-IP pressure aggregation | — |
| `ip_to_country()` | `(ip, db_file)` | GeoIP lookup | `geoip_ip6_lookup()` |
| `_resolve_cidr_cc()` | `(ip, cc)` | CIDR CC fallback | `ip_to_country()` |
| `country_weight()` | `(cc, weights_file)` | Country multiplier lookup | — |
| `_batch_pressure_compute()` | `(events_file, now, half_life, mod)` | Batch pressure computation | — |
| `_batch_ip_to_country()` | `(db_file)` | Batch dual-stack GeoIP | `geoip_ip6_lookup()` |

### 5.3 `files/internals/bfd_core.sh` (modify)

**Change inventory:**

| Location | Current | New | Lines |
|----------|---------|-----|-------|
| Line 151 | `unset PRESSURE_CONF THRESHOLDS_CONF TIME_ZONE` | `unset PRESSURE_CONF TIME_ZONE` | 1 |
| Lines 250–251 | `elif thresholds.conf` fallback to `_load_pressure_conf` | Remove entire `elif` block | 2 |
| Lines 253–256 | `_THRESH_*` array init + `_load_thresholds` call | Remove all 4 lines | 4 |
| Line 469 | `_apply_thresholds "$str"` | Remove call | 1 |

### 5.3a `files/internals/bfd_diag.sh` (modify)

**Change inventory:**

| Location | Current | New | Lines |
|----------|---------|-----|-------|
| Line 177 | `_apply_thresholds "$rule_name"` | Remove call | 1 |
| Line 723 | `_apply_thresholds "$service"` | Remove call | 1 |
| Line 903 | `_apply_thresholds "$rule_name"` | Remove call | 1 |
| Line 961 | `_apply_thresholds "$rule_name"` | Remove call | 1 |
| Line 1039 | `_apply_thresholds "$rule_name"` | Remove call | 1 |

These calls populate `TRIG`, `SKIP_ALERT`, and `RULE_EMAIL` from the
`_THRESH_*` arrays, which are always empty (thresholds.conf never exists
on any production install). The `_apply_pressure()` call that follows
each `_apply_thresholds()` at these sites already fills the same variables
from the `_PRESS_*` arrays. Removing the `_apply_thresholds()` calls
has zero behavioral impact.

### 5.3b `files/bfd` (modify)

**Change inventory:**

| Location | Current | New | Lines |
|----------|---------|-----|-------|
| Line 64 | `declare -A _THRESH_TRIG _THRESH_SKIP_ALERT _THRESH_RULE_EMAIL` | Remove entire line | 1 |

### 5.4 `files/internals/internals.conf` (modify)

**Change inventory:**

| Location | Current | New | Lines |
|----------|---------|-----|-------|
| Lines 37–38 | Comment: `# per-rule pressure overrides (replaces thresholds.conf)` | `# per-rule pressure overrides` | 1 |
| Lines 40–41 | `# legacy thresholds.conf path` + `THRESHOLDS_CONF=...` | Remove both lines | 2 |

### 5.5 `importconf` (modify)

**Change inventory:**

| Location | Current | New | Lines |
|----------|---------|-----|-------|
| Lines 169–176 | Copy old `pressure.conf` + `modsec` rename | Format detection + awk conversion + modsec rename (both formats) | ~20 (rewrite) |
| Lines 177–224 | `thresholds.conf → pressure.conf` migration | Remove entirely | -47 |
| Lines 225–254 | Pre-thresholds rule TRIG extraction (writes old format) | Update to write new format (`rule  trip=N`) | ~5 changes |

**New importconf `pressure.conf` preservation logic:**

```bash
if [ -f "$BK_LAST/pressure.conf" ]; then
    # detect old colon-delimited format
    if grep -qE '^[a-z_-]+:PRESSURE_' "$BK_LAST/pressure.conf" 2>/dev/null; then
        # convert: rule:KEY=VAL:KEY=VAL → rule  key=val key=val
        awk conversion copying comments through, transforming data lines
        echo "  Migrated pressure.conf from colon to whitespace format."
    else
        command cp -f "$BK_LAST/pressure.conf" "$new_press"
        echo "  Preserved pressure.conf from previous install."
    fi
    # modsec → mod_sec rename (both formats)
    if grep -q '^modsec[: \t]' "$new_press" 2>/dev/null; then
        sed -i 's/^modsec\([: \t]\)/mod_sec\1/' "$new_press"
    fi
fi
```

**importconf awk conversion logic:**

```awk
/^#/ || /^$/ { print; next }          # pass comments and blanks through
{
    rule = ""
    # split on first colon
    n = index($0, ":")
    if (n > 0) {
        rule = substr($0, 1, n-1)
        rest = substr($0, n+1)
    }
    if (rule == "") { print; next }

    # parse KEY=VAL pairs from colon-delimited rest
    out = rule
    np = split(rest, pairs, ":")
    for (i = 1; i <= np; i++) {
        eq = index(pairs[i], "=")
        if (eq > 0) {
            k = substr(pairs[i], 1, eq-1)
            v = substr(pairs[i], eq+1)
            # map old keys to new lowercase names
            if (k == "PRESSURE_WEIGHT") out = out "  weight=" v
            else if (k == "PRESSURE_TRIP" || k == "TRIG") out = out "  trip=" v
            else if (k == "SKIP_ALERT") out = out "  skip_alert=" v
            else if (k == "RULE_EMAIL") out = out "  rule_email=" v
        }
    }
    print out
}
```

### 5.6 `pkg/rpm/bfd.spec` and `pkg/deb/debian/rules` (modify)

| Location | Current | New | Lines |
|----------|---------|-----|-------|
| `bfd.spec` line 56 | `-e 's\|\$INSTALL_PATH/thresholds\.conf\|/etc/bfd/thresholds.conf\|'` | Remove line | -1 |
| `debian/rules` line 16 | `-e 's\|\$$INSTALL_PATH/thresholds\.conf\|/etc/bfd/thresholds.conf\|'` | Remove line | -1 |

### 5.7 No-Touch Files

These files reference `pressure.conf` but require **no changes**:

| File | Why No Change |
|------|---------------|
| 57 `files/rules/*` | Comment says "override pressure.conf" — filename unchanged |
| `files/conf.bfd` line 31 | Comment says "per-rule overrides: edit rules/ files or pressure.conf" — still true |
| `bfd.bash-completion` | No pressure.conf references |
| `install.sh` | No pressure.conf references |
| `bfd_core.sh` check() | Uses `_PRESS_*` arrays populated by `_load_pressure_conf()` |
| `pkg/deb/debian/conffiles` | Lists `/etc/bfd/pressure.conf` — filename unchanged |
| `pkg/deb/debian/links` | Symlink for `pressure.conf` — filename unchanged |
| `pkg/deb/debian/bfd.postinst` | chmod on `pressure.conf` — filename unchanged |
| `pkg/test/test-pkg-install.sh` | Tests `pressure.conf` existence + FHS path — filename unchanged |

---

## 5b. Examples

### New format (default pressure.conf)

```
$ head -30 /usr/local/bfd/pressure.conf
# Per-rule pressure overrides for BFD
#
# Format: RULE  key=value [key=value ...]
# Keys:   weight, trip, skip_alert, rule_email
#
# Precedence (highest to lowest):
#   1. Uncommented value in rule file (rules/sshd, etc.)
#   2. Value in this file (pressure.conf)
#   3. Global default in conf.bfd (PRESSURE_TRIP, PRESSURE_HALF_LIFE)
#
# Rules not listed here inherit the global PRESSURE_TRIP from conf.bfd.
# weight controls how fast pressure accumulates (higher = faster).
#
# Weight tiers:
#   5 — control panels (direct server access)
#   3 — SSH, VPN, critical auth (remote shell/admin)
#   2 — mail, FTP, web auth (application-level)
#   1 — noisy/high-volume services (info-gathering)
#
# Quick ref: trip / weight = minimum rapid failures for a ban.
#
# Multi-field example:
#   postfix  weight=2  trip=20  skip_alert=1

# --- Weight 5: Control panels ---
cpanel          weight=5  trip=10
plesk           weight=5  trip=10
webmin          weight=5  trip=10
directadmin     weight=5  trip=10
```

### importconf upgrade output (old format detected)

```
$ /usr/local/bfd/importconf
BFD 2.0.2 configuration import
  Importing from backup: /usr/local/bfd.bk.last
  ...
  Migrated pressure.conf from colon to whitespace format.
  ...
```

### importconf upgrade output (already new format)

```
  Preserved pressure.conf from previous install.
```

### Parser error output (invalid weight in new format)

```
pressure.conf: sshd weight='abc' invalid (must be positive integer), skipping
```

---

## 6. Conventions

### 6.1 Format Detection Heuristic

Per-line: check if the first field (before any whitespace) contains a colon.

```bash
# extract first whitespace-delimited token
_first="${line%%[[:space:]]*}"
case "$_first" in
    *:*) # old format: rule_name:KEY=VAL:...
         ;;
    *)   # new format: rule_name key=val ...
         ;;
esac
```

This is more precise than `*:*=*` on the full line — it avoids a
false-positive when a new-format `rule_email=` value contains a colon
(e.g., `sshd  rule_email=user:tag@host.com`). Since BFD rule names
never contain colons, and old-format lines always have `rule:` as the
first token, checking only the first field is a reliable discriminator.

This follows the same per-line detection approach used for
`pressure-country.conf` in `bfd_core.sh` lines 420–430.

### 6.2 Key Validation

All validation logic is identical between old-format and new-format paths:
- `weight`/`PRESSURE_WEIGHT`: positive integer (`^[0-9]+$`, > 0)
- `trip`/`PRESSURE_TRIP`: positive integer, clamped to ≤200
- `skip_alert`/`SKIP_ALERT`: stored as-is (no validation — existing behavior)
- `rule_email`/`RULE_EMAIL`: `validate_email()` check

### 6.3 Boilerplate

No new files created. All changes are modifications to existing files
following existing boilerplate patterns.

---

## 7. Interface Contracts

### 7.1 pressure.conf File Format (changed)

**Old format:**
```
rule_name:PRESSURE_WEIGHT=N:PRESSURE_TRIP=N[:SKIP_ALERT=N][:RULE_EMAIL=addr]
```

**New format:**
```
rule_name  weight=N  trip=N  [skip_alert=N]  [rule_email=addr]
```

**Dual-format**: Both formats accepted per-line during transition.

### 7.2 Internal Arrays (unchanged)

`_PRESS_WEIGHT[]`, `_PRESS_TRIP[]`, `_PRESS_SKIP_ALERT[]`, `_PRESS_RULE_EMAIL[]`
— populated identically regardless of input format.

### 7.3 Rule File Variables (unchanged)

`PRESSURE_WEIGHT`, `PRESSURE_TRIP`, `SKIP_ALERT`, `RULE_EMAIL` — uppercase
shell variables in rule files. Not affected by this change.

### 7.4 CLI Output (unchanged)

`bfd -c` (show_config) reads from arrays, not from the file. No output change.

---

## 8. Migration Safety

### 8.1 Upgrade Path: v2.0.2-current → v2.0.2-new

User has old-format `pressure.conf`. On install:
1. `importconf` detects old format via `grep -qE '^[a-z_-]+:PRESSURE_'`
2. awk converts to new format, preserving comments
3. `modsec:` → `mod_sec ` rename applied (broadened pattern)
4. User's custom values preserved in new format

### 8.2 Upgrade Path: v1.5 → v2.0.2-new

User has no `pressure.conf` or `thresholds.conf`, but may have uncommented
`TRIG=` values in rule files. The existing `elif rules/` block in importconf
handles this. **Change**: its output switches from `rule:PRESSURE_TRIP=N` to
`rule  trip=N`.

### 8.3 Upgrade Path: v2.0.2-new → v2.0.2-new (re-install)

User has new-format `pressure.conf`. `importconf` detects no old-format
lines, copies as-is. No conversion needed.

### 8.4 Fresh Install

Ships with new-format `pressure.conf`. No migration involved.

### 8.5 Hand-Edited Mixed Format

User upgraded but then hand-added an old-format line (or vice versa).
Per-line detection handles this gracefully — each line parsed independently.

### 8.6 Rollback

If user reverts to pre-migration BFD, their new-format `pressure.conf`
will not be parsed by the old colon-only parser. **Mitigation**: the old
parser silently ignores lines without colons (they fail `rule_name="${line%%:*}"`
→ `fields="${line#*:}"` → `fields == line` → parsed as one big KEY=VAL which
won't match any known key → silently skipped). This is not a crash, but
pressure overrides would be silently lost. This is acceptable — downgrade
is not a supported path.

### 8.7 RPM/DEB Packages

`pressure.conf` is marked `%config(noreplace)` (RPM) and in `conffiles`
(DEB). Package manager will not overwrite user's existing file. The
dual-format parser ensures old-format files continue to work after
package upgrade without running importconf.

### 8.8 Test Suite Impact

- `tests/27-thresholds.bats` deleted (25 tests — 15 dead, 10 relocated)
- `tests/30-pressure.bats`: ~10 fixtures updated to new format, ~3 new
  tests added (new-format parsing, mixed-format, old-format backward compat),
  10 tests absorbed from 27-thresholds.bats
- `tests/25-importconf.bats`: ~4 thresholds.conf tests removed, ~1 format
  conversion test added
- `tests/17-check-pipeline.bats`: 3 test fixtures updated, 6 lines of
  `_load_thresholds`/`_THRESH_*` calls removed
- `tests/33-watch-mode.bats`: 1 test fixture updated
- Net: ~-12 tests (15 dead removed, 10 relocated, 3 new added)

---

## 9. Dead Code and Cleanup

| Item | Location | Lines | Reason |
|------|----------|-------|--------|
| `_load_thresholds()` | `bfd_pressure.sh:74–129` | 55 | Never-shipped thresholds.conf parser |
| `_apply_thresholds()` | `bfd_pressure.sh:131–146` | 15 | Never-shipped thresholds.conf applicator |
| `THRESHOLDS_CONF` variable | `internals.conf:40–41` | 2 | Never-shipped path variable |
| `THRESHOLDS_CONF` unset | `bfd_core.sh:151` | 1 word | Part of dead variable |
| `elif thresholds.conf` fallback | `bfd_core.sh:250–251` | 2 | Dead fallback path |
| `_THRESH_*` array init | `bfd_core.sh:253–255` | 3 | Dead array initialization |
| `_load_thresholds` call | `bfd_core.sh:256` | 1 | Dead function call |
| thresholds.conf migration | `importconf:177–224` | 47 | Dead migration for never-shipped format |
| `tests/27-thresholds.bats` | entire file | 295 | Tests for dead code |
| thresholds.conf importconf tests | `tests/25-importconf.bats` | ~45 | Tests for dead migration path |
| thresholds.conf FHS transform | `pkg/rpm/bfd.spec:56` | 1 | FHS path for dead variable |
| thresholds.conf FHS transform | `pkg/deb/debian/rules:16` | 1 | FHS path for dead variable |
| `_apply_thresholds` call | `bfd_core.sh:469` | 1 | Dead — reads always-empty `_THRESH_*` arrays |
| `_apply_thresholds` calls (5) | `bfd_diag.sh:177,723,903,961,1039` | 5 | Dead — reads always-empty `_THRESH_*` arrays |
| `declare -A _THRESH_*` | `files/bfd:64` | 1 | Dead — arrays never populated |
| `thresholds.conf` ref in man page | `bfd.1:1057` | 1 phrase | Documentation for dead feature |
| `thresholds.conf` ref in README | `README.md:214` | 1 phrase | Documentation for dead feature |
| Comment "replaces thresholds.conf" | `internals.conf:37` | 1 phrase | Stale comment |

**Total dead code removed: ~480 lines** (code + call sites + tests + docs)

---

## 10a. Test Strategy

| Goal | Test File | Test Description |
|------|-----------|-----------------|
| G1: New format | `tests/30-pressure.bats` | `@test "_load_pressure_conf: parses new whitespace format"` |
| G1: New format multi-field | `tests/30-pressure.bats` | `@test "_load_pressure_conf: parses new format with all four keys"` |
| G2: Old format compat | `tests/30-pressure.bats` | `@test "_load_pressure_conf: parses old colon format (backward compat)"` |
| G2: Mixed format | `tests/30-pressure.bats` | `@test "_load_pressure_conf: handles mixed old and new format lines"` |
| G2: Validation (new) | `tests/30-pressure.bats` | Existing validation tests updated to new format fixtures |
| G3: importconf conversion | `tests/25-importconf.bats` | `@test "importconf: old-format pressure.conf converted to new format"` |
| G3: importconf preserve | `tests/25-importconf.bats` | Existing "post-pressure upgrade preserves" test updated for new format |
| G4: Dead code gone | (deletion verification) | `grep -r 'thresholds.conf' files/` returns 0 hits |
| G4: Dead tests gone | (file deletion) | `tests/27-thresholds.bats` does not exist |
| G5: Docs updated | (manual) | Man page and README show new format |
| G6: No regression | `make -C tests test` | Full suite passes on Debian 12 + Rocky 9 |

### Existing tests requiring fixture updates

| Test File | Test Name | Change |
|-----------|-----------|--------|
| `tests/30-pressure.bats` | `_load_pressure_conf: parses SKIP_ALERT and RULE_EMAIL` | Old→new format fixture |
| `tests/30-pressure.bats` | `_load_pressure_conf: skips comment lines` | Old→new format fixture |
| `tests/30-pressure.bats` | `_load_pressure_conf: handles legacy TRIG as PRESSURE_TRIP` | Keep old format (tests backward compat) |
| `tests/30-pressure.bats` | `_load_pressure_conf: weight-only entry works` | Old→new format fixture |
| `tests/30-pressure.bats` | `_load_pressure_conf: multiple rules parsed` | Old→new format fixture |
| `tests/30-pressure.bats` | `_load_pressure_conf: non-numeric PRESSURE_WEIGHT skipped` | Old→new format fixture |
| `tests/30-pressure.bats` | `_load_pressure_conf: zero PRESSURE_WEIGHT skipped` | Old→new format fixture |
| `tests/30-pressure.bats` | `_load_pressure_conf: non-numeric PRESSURE_TRIP skipped` | Old→new format fixture |
| `tests/30-pressure.bats` | `_load_pressure_conf: negative PRESSURE_TRIP skipped` | Old→new format fixture |
| `tests/30-pressure.bats` | `_load_pressure_conf: PRESSURE_TRIP above 200 clamped` | Old→new format fixture |
| `tests/30-pressure.bats` | `_load_pressure_conf: PRESSURE_TRIP=200 accepted` | Old→new format fixture |
| `tests/17-check-pipeline.bats` | `check: pressure.conf PRESSURE_TRIP used...` | Old→new format fixture |
| `tests/17-check-pipeline.bats` | `check: rule file TRIG overrides pressure.conf...` | Old→new format fixture |
| `tests/17-check-pipeline.bats` | `check: PRESSURE_WEIGHT from pressure.conf...` | Old→new format fixture |
| `tests/33-watch-mode.bats` | `reload_watch: clears pressure arrays...` | Old→new format fixture |

### tests/27-thresholds.bats disposition (25 tests total)

**Deleted — dead code tests (15):**
- `_load_thresholds: parses TRIG values`
- `_load_thresholds: parses multi-field entries`
- `_load_thresholds: skips comments and blank lines`
- `_load_thresholds: ignores unknown keys`
- `_load_thresholds: missing file returns 0 with empty arrays`
- `_load_thresholds: empty argument returns 0`
- `_load_thresholds: non-root-owned file is skipped`
- `_load_thresholds: world-writable file is skipped`
- `_apply_thresholds: rule TRIG wins over thresholds.conf`
- `_apply_thresholds: fills empty TRIG from thresholds.conf`
- `_apply_thresholds: fills SKIP_ALERT from thresholds.conf`
- `_apply_thresholds: fills RULE_EMAIL from thresholds.conf`
- `_apply_thresholds: no-op for unlisted rule`
- `_apply_thresholds: does not overwrite non-empty SKIP_ALERT`
- `precedence: thresholds.conf fills TRIG, then conf.bfd fallback`

**Relocated to `tests/30-pressure.bats` — unique coverage (10):**
- `_load_pressure_conf: parses PRESSURE_TRIP values`
- `_load_pressure_conf: parses PRESSURE_WEIGHT values`
- `_load_pressure_conf: parses multi-field entries`
- `_load_pressure_conf: ignores unknown keys`
- `_load_pressure_conf: missing file returns 0 with empty arrays`
- `_load_pressure_conf: empty argument returns 0`
- `_load_pressure_conf: non-root-owned file is skipped`
- `_load_pressure_conf: world-writable file is skipped`
- `_apply_pressure: does not overwrite non-empty SKIP_ALERT`
- `precedence: pressure.conf fills PRESSURE_TRIP, then GLOB_PRESSURE_TRIP fallback`

These 10 tests cover file safety rejection, empty-input graceful
degradation, unknown key handling, and precedence chain — all
correctness-critical behavior not duplicated in `tests/30-pressure.bats`.

### tests/25-importconf.bats tests being deleted

- `importconf: thresholds.conf migrated to pressure.conf on upgrade`
- Tests within this file that reference thresholds.conf fixtures

---

## 10b. Verification Commands

```bash
# Goal 1: New format ships
head -30 files/pressure.conf
# expect: "# Format: RULE  key=value [key=value ...]" in header
# expect: "sshd            weight=3  trip=15" (whitespace-delimited, lowercase)

# Goal 2: Dual-format parser accepts both
grep -c 'case.*\*:\*=\*' files/internals/bfd_pressure.sh
# expect: 1 (the format detection case)

# Goal 3: importconf has format conversion
grep -c 'colon.*whitespace\|PRESSURE_WEIGHT.*weight=' importconf
# expect: >=1 (conversion logic present)

# Goal 4: thresholds.conf dead code gone
grep -rn 'thresholds\.conf' files/
# expect: 0 matches

grep -rn '_load_thresholds\|_apply_thresholds' files/
# expect: 0 matches

grep -rn 'THRESHOLDS_CONF' files/
# expect: 0 matches

test -f tests/27-thresholds.bats && echo "FAIL: dead test file exists" || echo "PASS"
# expect: PASS

# Goal 5: Docs updated
grep -c 'thresholds\.conf' bfd.1
# expect: 0

grep -c 'thresholds\.conf' README.md
# expect: 0

# Goal 6: No regression
bash -n files/bfd files/internals/bfd.lib.sh files/internals/bfd_pressure.sh \
      files/internals/bfd_core.sh files/internals/internals.conf
# expect: exit 0

shellcheck -S warning files/internals/bfd_pressure.sh files/internals/bfd_core.sh
# expect: exit 0

make -C tests test 2>&1 | tail -5
# expect: "N tests, 0 failures"

make -C tests test-rocky9 2>&1 | tail -5
# expect: "N tests, 0 failures"
```

---

## 11. Risks

| # | Risk | Mitigation |
|---|------|------------|
| R1 | importconf awk conversion corrupts user customizations | Conversion preserves comments verbatim; data lines are field-mapped with no-match passthrough; test with multi-field entries including RULE_EMAIL containing `@` |
| R2 | RPM/DEB `%config(noreplace)` means package upgrade ships new-format default but user keeps old-format file | Dual-format parser handles this transparently — old-format files continue working indefinitely |
| R3 | Pre-thresholds importconf path writes new format but old BFD version can't read it (downgrade) | Downgrade is not a supported path. Old parser silently skips unrecognized lines (no crash, but overrides lost). Document in release notes. |
| R4 | `modsec` rename regex change breaks for edge cases | Broaden sed pattern to match both `:` and whitespace after `modsec`; test both formats |
| R5 | Test fixture updates miss a test, causing false pass | Grep `tests/` for old-format patterns (`PRESSURE_WEIGHT=`, `PRESSURE_TRIP=`) after all fixture updates — any remaining hits must be in backward-compat tests, not primary-path tests |

---

## 11b. Edge Cases

| # | Scenario | Expected Behavior | Handling |
|---|----------|-------------------|---------|
| E1 | Old-format line with only `TRIG=N` (no `PRESSURE_*` keys) | Parsed as trip=N via old-format path | `PRESSURE_TRIP\|TRIG` case arm in old-format branch |
| E2 | New-format line with unknown key (`sshd  badkey=5`) | Unknown key silently ignored, other keys on same line still parsed | Default case in key dispatch |
| E3 | Empty value (`sshd  weight=  trip=10`) | weight silently skipped (fails `^[0-9]+$` check), trip parsed normally | Existing validation logic |
| E4 | Rule name with hyphens (`nginx-http-auth  weight=2`) | Parsed correctly — first whitespace-delimited field is rule name | Standard `read` word splitting |
| E5 | Rule name with underscores (`asterisk_badauth  weight=2`) | Parsed correctly | Standard `read` word splitting |
| E6 | Line with extra whitespace (`sshd    weight=3     trip=15`) | Parsed correctly — `read` collapses whitespace | Bash `read` behavior |
| E7 | Tab-delimited line | Parsed correctly — `read` treats tabs as whitespace | Bash `read` behavior |
| E8 | Mixed old+new format in same file | Each line parsed independently by its format | Per-line case dispatch |
| E9 | `rule_email=user@domain.com` with `@` in value | Parsed correctly — `=` splits key from value, `@` is part of value | `${pair#*=}` stops at first `=` |
| E13 | New-format `rule_email=user:tag@host.com` with colon in email | Parsed correctly — format detection checks first token only (rule name), which has no colon | `_first="${line%%[[:space:]]*}"` extracts rule name without colon |
| E10 | importconf with old-format `pressure.conf` containing comments between entries | Comments preserved verbatim in conversion output | awk `/^#/` passthrough |
| E11 | File with 0640 permissions owned by root (normal) | Passes `_check_file_safety`, parsed normally | Existing safety check |
| E12 | File with world-writable permissions | Rejected by `_check_file_safety`, elog warning, arrays stay empty | Existing safety check |

---

## 12. Open Questions

None — all design decisions resolved in brainstorming.
