# CDN/Trusted Proxy IP Management — Design Spec

**Date:** 2026-03-21
**Version:** BFD 2.0.2 (feature targets 2.1.0 or later v2.0.x)
**Status:** Draft
**Author:** VPE pipeline (spec phase)

---

## 1. Problem Statement

BFD has no awareness of CDN or proxy infrastructure IPs. When upstream
services (mod_sec, nginx, Apache) log the proxy IP instead of the real
client, BFD detects and bans CDN edge nodes — blocking **all**
proxied traffic and escalating via the repeat-offender pipeline to
subnet bans.

**Production evidence (habs.rfxn.com, 2026-03-21):**
- 69 Cloudflare edge IP entries in attack.pool
- 41+ individual IP bans
- 14 /24 subnet bans against Cloudflare ranges (172.70.x.x, 172.71.x.x,
  172.68.x.x, 162.158.x.x)
- Escalation chain: 600s → 1200s → 1800s → 2400s per subnet
- Net effect: all Cloudflare-proxied traffic blocked for escalating durations

**Current mitigation:** Manual addition of IP ranges to `ignore.hosts`.
This does not scale — CDN providers rotate ranges, operators may not
realize they're banning infrastructure until traffic drops, and there
is no way to de-rate rather than fully ignore CDN-sourced traffic.

---

## 2. Goals

1. **G-01:** Automated CDN IP range fetching — BFD downloads and compiles
   provider IP ranges on a configurable schedule without operator intervention.
2. **G-02:** Per-provider treatment — each provider is independently
   configured as `ignore` (pre-filter), `exclude` (visible, never banned),
   or `derate` (reduced pressure multiplier).
3. **G-03:** Extensible provider framework — operators add custom providers
   via a single config line (name, URL, format, treatment).
4. **G-04:** Zero new external dependencies — no `jq`, no Python, no new
   packages. Pure bash/awk/grep.
5. **G-05:** CIDR-aware matching — O(log n) binary search on integer ranges,
   reusing the `ipcountry.dat` pattern. No IP expansion.
6. **G-06:** CLI management surface — `bfd --cdn` subcommands for provider
   listing, detail, update, and IP check.
7. **G-07:** Unified config format — `pressure-country.conf` migrated from
   `KEY=VALUE` to whitespace-delimited tabular format (fstab-style),
   consistent with the new `cdn-providers.conf`.
8. **G-08:** Backward-compatible integration — existing ignore cache,
   pressure pipeline, and detection loop modified minimally. No changes
   to the alert pipeline field contract.

---

## 3. Non-Goals

- **X-Forwarded-For parsing** — that's the web server's responsibility.
  BFD detects from log lines, not HTTP headers.
- **Real-time URL fetch during detection** — all data is pre-fetched.
  Detection reads compiled databases only.
- **Rule file modifications** — CDN treatment is orthogonal to rules.
- **Alert pipeline field contract changes** — the 13-field pipe format
  is unchanged.
- **Automatic CDN detection** — BFD does not guess whether an IP is a
  CDN. Operators configure providers explicitly.
- **IPv6-only CDN ranges** — IPv6 CDN ranges are supported but only
  providers that publish IPv6 CIDRs will have them. No synthesis.

---

## 4. Architecture

### 4.1 File Map

| File | Status | Est. Lines | Purpose |
|------|--------|------------|---------|
| `files/cdn-providers.conf` | **New** | ~30 | Provider config (whitespace-delimited tabular) |
| `files/internals/bfd_cdn.sh` | **New** | ~350 | CDN subsystem: load, lookup, fetch, compile, CLI |
| `files/update-cdn-providers.sh` | **New** | ~80 | Standalone fetch/compile script (parallel to update-ipcountry.sh) |
| `files/pressure-country.conf` | **Modified** | ~26 | Migrated from `CC=MULT` to whitespace-delimited `CC MULT` |
| `files/conf.bfd` | **Modified** | +15 | New `CDN_ENABLE`, `CDN_UPDATE_DAYS` variables |
| `files/internals/bfd_core.sh` | **Modified** | +40 | CDN database load in `check()`, CDN ignore injection, CDN pressure de-rate |
| `files/internals/bfd_pressure.sh` | **Modified** | +5 | `country_weight()` updated for new config format |
| `files/internals/bfd.lib.sh` | **Modified** | +4 | Source `bfd_cdn.sh` in chain |
| `files/bfd` | **Modified** | +50 | `--cdn` case branch, unset block, CDN summary in `-S` |
| `files/internals/bfd_validate.sh` | **Modified** | +10 | `validate_config()` CDN variable validation |
| `files/internals/bfd_diag.sh` | **Modified** | +10 | CDN provider status in `show_status()` |
| `files/internals/bfd_events.sh` | **Modified** | +5 | CDN match annotation in `search_ip()` / IP report |
| `cron.daily` | **Modified** | +10 | CDN staleness check + fetch trigger |
| `install.sh` | **Modified** | +10 | Copy `cdn-providers.conf`, `update-cdn-providers.sh`, `bfd_cdn.sh` |
| `importconf` | **Modified** | +5 | Migrate `pressure-country.conf` format |
| `.github/workflows/ci.yml` | **Modified** | +2 | Add `bfd_cdn.sh` to lint targets |

### 4.2 Size Comparison

| Metric | Before | After | Delta |
|--------|--------|-------|-------|
| Sub-libraries in `internals/` | 10 | 11 (+bfd_cdn.sh) | +1 |
| Config files | 3 (conf.bfd, pressure.conf, pressure-country.conf) | 4 (+cdn-providers.conf) | +1 |
| Standalone scripts | 1 (update-ipcountry.sh) | 2 (+update-cdn-providers.sh) | +1 |
| Source chain in bfd.lib.sh | 14 statements | 15 statements | +1 |
| CLI case branches in files/bfd | 21 | 22 (+--cdn) | +1 |

### 4.3 Dependency Tree

```
files/bfd
  └── files/internals/bfd.lib.sh (sourcing hub)
        ├── tlog_lib.sh
        ├── elog_lib.sh
        ├── alert_lib.sh
        ├── bfd_alert.sh
        ├── geoip_lib.sh        ← CDN lookup reuses same binary search pattern
        ├── bfd_report.sh
        ├── bfd_validate.sh     ← +CDN_ENABLE/CDN_UPDATE_DAYS validation
        ├── bfd_fw.sh
        ├── bfd_state.sh
        ├── bfd_pressure.sh     ← country_weight() format migration
        ├── bfd_detect.sh       ← _build_ignore_cache() unchanged
        ├── bfd_cdn.sh          ← NEW: CDN load, lookup, compile, CLI
        ├── bfd_events.sh       ← +CDN match annotation
        ├── bfd_diag.sh         ← +CDN status in show_status()
        └── bfd_core.sh         ← +CDN integration in check()

files/update-cdn-providers.sh   ← NEW standalone (sources bfd_cdn.sh)
cron.daily                      ← +CDN staleness check
install.sh                      ← +CDN file deployment
```

### 4.4 Key Changes

**Detection pipeline integration (bfd_core.sh `check()`):**
The CDN subsystem hooks into the existing detection loop at two points:

1. **CDN filter (line ~530, per-IP loop):** After the existing
   `grep -Fxf` ignore cache check, the per-IP loop performs an O(1)
   associative array lookup in `_cdn_map[$ATTACK_HOST]`. If the IP
   matches a CDN provider, the treatment determines behavior:
   - `ignore` → IP is skipped (same as ignore cache hit). No event
     recorded, no pressure accumulated.
   - `exclude` → continues through detection but ban is suppressed
     (see point 3).
   - `derate` → pressure multiplier is reduced (see point 2).
   The CDN cache is NOT appended to the ignore cache file — CIDRs are
   not compatible with the exact-match `grep -Fxf` filter. The CDN
   lookup is a separate code path using pre-computed batch results.

2. **Pressure de-rate (line ~556):** After country weight lookup, if the
   IP matches a CDN provider with `treatment=derate`, the scoring weight
   is further multiplied by the provider's pressure multiplier:
   ```
   scoring_weight = (scoring_weight * cdn_mult + 5) / 10
   ```
   Same integer rounding as country weights.

3. **Ban exclusion (line ~590):** After `should_ban=1`, if the IP matches
   a CDN provider with `treatment=exclude`, skip the ban execution but
   still record the observation in `attack.pool` with `ACTION=cdn-exclude`.

**CDN database format (compiled):**
Same as `ipcountry.dat` — sorted integer ranges, one per line:
```
# IPv4: START_INT END_INT PROVIDER TREATMENT MULT
2886729728 2886795263 cloudflare ignore 10
# IPv6: START_HEX END_HEX PROVIDER TREATMENT MULT
2a06098c00000000... 2a06098cffffffff... cloudflare ignore 10
```

This enables O(log n) binary search per IP using the same awk pattern
as `ip_to_country()` / `_batch_ip_to_country()`.

**Batch CDN lookup:**
A new `_batch_cdn_lookup()` function (parallel to `_batch_ip_to_country()`)
does a single awk pass over the compiled CDN database for all unique IPs
in a rule iteration. Returns text lines: `IP PROVIDER TREATMENT MULT`.
The caller (`check()` in `bfd_core.sh`) loads these into a `declare -A
_cdn_map` at function scope — same scoping pattern as the existing
`_cc_map`, `_filter_map`, `_cw_map` arrays. This avoids the bash 4.1
`declare -A` scoping trap (global-scope `declare -A` creates locals
when sourced from inside BATS `load`).

### 4.5 Dependency Rules

- `bfd_cdn.sh` sources after `bfd_detect.sh` and before `bfd_events.sh`
  in the chain (logical grouping: detection → CDN filter → events; no
  hard dependency on `bfd_detect.sh` functions — `bfd_cdn.sh` uses only
  awk binary search and curl/wget, which are self-contained)
- `bfd_cdn.sh` must NOT depend on `bfd_core.sh` (sourced before core)
- `update-cdn-providers.sh` sources `bfd_cdn.sh` directly (not via
  `bfd.lib.sh`) — same pattern as `update-ipcountry.sh` sourcing
  `geoip_lib.sh`
- CDN database files live in `$INSTALL_PATH/` alongside `ipcountry.dat`

---

## 5. File Contents

### 5.1 `files/cdn-providers.conf` (New)

Provider configuration in whitespace-delimited tabular format.

```bash
# CDN/Trusted Proxy Provider Configuration
#
# Fields: NAME  TREATMENT  MULT  FORMAT  URL_V4  URL_V6
#
# NAME:      provider identifier (alphanumeric + hyphens, no spaces)
# TREATMENT: ignore (pre-filter, invisible), exclude (visible, never banned),
#            derate (reduced pressure multiplier)
# MULT:      pressure multiplier (integer scale: 10=1.0x, 5=0.5x, 3=0.3x)
#            only meaningful for derate; ignored for ignore/exclude
# FORMAT:    text (one CIDR per line) or json (CIDRs extracted via grep)
# URL_V4:    IPv4 range URL (required)
# URL_V6:    IPv6 range URL (optional, use - for none)
#
# Uncomment providers as needed. Lines starting with # are ignored.
# BFD fetches ranges via curl/wget on a configurable schedule (CDN_UPDATE_DAYS).
#
#cloudflare     ignore   10  text  https://www.cloudflare.com/ips-v4/                               https://www.cloudflare.com/ips-v6/
#aws-cloudfront derate    3  json  https://d7uri8nf7uskq.cloudfront.net/tools/list-cloudfront-ips   -
#fastly         exclude  10  json  https://api.fastly.com/public-ip-list                            -
#google-cloud   derate    5  json  https://www.gstatic.com/ipranges/cloud.json                      -
#akamai         ignore   10  text  https://techdocs.akamai.com/property-manager/pdfs/akamai_ipv4_CIDRs.txt  https://techdocs.akamai.com/property-manager/pdfs/akamai_ipv6_CIDRs.txt
```

### 5.2 `files/internals/bfd_cdn.sh` (New)

| Function | Signature | Purpose | Dependencies |
|----------|-----------|---------|--------------|
| `_cdn_load_providers` | `(conf_file)` | Parse cdn-providers.conf into parallel arrays | None |
| `_cdn_load_db` | `(db_file)` | Load compiled CDN database into awk-ready state | None |
| `_cdn_lookup` | `(ip, db_file)` | Single IP lookup — returns `PROVIDER TREATMENT MULT` | awk binary search |
| `_batch_cdn_lookup` | `(db_file) < ip_list` | Batch lookup for all IPs — `IP PROVIDER TREATMENT MULT` | awk binary search |
| `_cdn_fetch_provider` | `(name, url, format)` | Fetch URL, extract CIDRs, validate | curl/wget, grep |
| `_cdn_compile_db` | `(conf_file, output_v4, output_v6)` | Fetch all providers, compile into integer-range databases | `_cdn_fetch_provider`, CIDR-to-range math |
| `_cdn_cidr_to_range_v4` | `(cidr)` | Convert IPv4 CIDR to START END integers | awk arithmetic |
| `_cdn_cidr_to_range_v6` | `(cidr)` | Convert IPv6 CIDR to START END hex strings | awk hex math |
| `_cdn_provider_status` | `(install_path)` | Return per-provider status (name, treatment, IP count, age) | stat, wc |
| `cdn_list` | `(install_path)` | CLI: list all providers with status | `_cdn_provider_status` |
| `cdn_list_json` | `(install_path)` | CLI: JSON provider list | `_cdn_provider_status` |
| `cdn_detail` | `(install_path, provider)` | CLI: show CIDRs for a provider | db file read |
| `cdn_detail_json` | `(install_path, provider)` | CLI: JSON CIDRs for a provider | db file read |
| `cdn_check_ip` | `(install_path, ip)` | CLI: test if IP matches any CDN | `_cdn_lookup` |
| `cdn_check_ip_json` | `(install_path, ip)` | CLI: JSON IP check result | `_cdn_lookup` |
| `cdn_update` | `(install_path)` | CLI: force refresh all providers | `_cdn_compile_db` |

### 5.3 `files/update-cdn-providers.sh` (New)

| Function | Signature | Purpose | Dependencies |
|----------|-----------|---------|--------------|
| (main script) | `[output_dir]` | Standalone fetch/compile entry point | `_cdn_compile_db` from bfd_cdn.sh |

Structure mirrors `update-ipcountry.sh`:
1. Set `INSTALL_PATH`, resolve script dir
2. Source `bfd_cdn.sh`
3. Call `_cdn_compile_db` with provider conf and output paths
4. Set permissions (chmod 640)
5. Report success/failure counts

### 5.4 `files/pressure-country.conf` (Modified)

| Change | Current format | New format | Lines affected |
|--------|---------------|------------|----------------|
| Format migration | `CC=MULT` with `#` comments | `CC  MULT` whitespace-delimited | All data lines (~0 active, ~10 commented examples) |

### 5.5 `files/conf.bfd` (Modified)

| Variable | Default | Purpose | Lines affected |
|----------|---------|---------|----------------|
| `CDN_ENABLE` | `"0"` | Master enable for CDN subsystem | New section (~15 lines) |
| `CDN_UPDATE_DAYS` | `"7"` | Staleness threshold for fetch (days) | Same section |

New section placed after "Advanced" and before "Attack Pool":
```bash
# =============================================
# CDN / Trusted Proxy
# =============================================

# enable CDN/trusted proxy IP awareness [0 = off, 1 = on]
# when enabled, BFD loads cdn-providers.conf and applies per-provider
# treatment (ignore, exclude, or derate) to matching IPs
CDN_ENABLE="0"

# how often to refresh provider IP ranges (days); 0 = never auto-refresh
CDN_UPDATE_DAYS="7"
```

### 5.6 `files/internals/bfd_core.sh` (Modified)

| Function | Current behavior | New behavior | Lines affected |
|----------|-----------------|--------------|----------------|
| `config_init()` | Loads pressure conf, validates, sets up FW | +Unset `CDN_ENABLE`/`CDN_UPDATE_DAYS` on reload; +CDN validation call | ~150 (unset block), ~270 (validation) |
| `check()` | Ignore cache + country weight + pressure loop | +CDN batch lookup after country lookup; +CDN treatment logic in per-IP loop | ~410 (cache setup), ~530-600 (per-IP loop) |
| `_cw_map` loading | `IFS='=' read` from `pressure-country.conf` | Whitespace-delimited awk parse | ~416-424 |

### 5.7 `files/bfd` (Modified)

| Change | Lines affected |
|--------|----------------|
| `--cdn` case branch (4 subcommands: list, detail, update, check) | ~430 (before `--flush-temp`) |
| `usage_short()` + `usage()` — add CDN section | ~97-103, ~160-180 |
| CDN summary line in `-S` output | delegated to `show_status()` in bfd_diag.sh |

Note: The config unset block for `CDN_ENABLE`/`CDN_UPDATE_DAYS` is in
`config_init()` in `bfd_core.sh` (lines 113-152), NOT in `files/bfd`.

### 5.8 Other Modified Files

**`files/internals/bfd.lib.sh`:**
- Add `bfd_cdn.sh` source statement after `bfd_detect.sh` (1 block, ~4 lines)

**`files/internals/bfd_validate.sh`:**
- Add `CDN_ENABLE` (must be 0 or 1) and `CDN_UPDATE_DAYS` (non-negative integer) validation (~10 lines)

**`files/internals/bfd_diag.sh`:**
- Add CDN provider summary to `show_status()` output (~10 lines)

**`files/internals/bfd_events.sh`:**
- Add CDN match annotation in `events_ip_report()` / `search_ip()` (~5 lines)
- Verify all `attack.pool` ACTION consumers handle the new `cdn-exclude`
  value gracefully. Consumers to check: `events_ip_report()`,
  `search_ip()`, `apool_list_*()`, `show_status()`, `_apool_ban_status()`,
  `cron.daily` pruning. All use `awk` with no ACTION whitelist — they
  pass through unknown values, so `cdn-exclude` requires no changes
  to existing consumers. New reporting/annotation code in `search_ip()`
  and `events_ip_report()` specifically recognizes `cdn-exclude`.

**Test infrastructure:**
- `tests/helpers/bfd-common.bash`: `_start_watch()` must add
  `bfd_cdn.sh` to the file copy list (same pattern as other sub-libs)
- `tests/helpers/bfd-common.bash`: `bfd_load_function` fallback list
  should include `bfd_cdn.sh` if any CDN functions are tested directly

**`cron.daily`:**
- Add CDN staleness check block after ipcountry.dat refresh (~10 lines), same pattern

**`install.sh`:**
- Add `cdn-providers.conf` to config copy
- Add `update-cdn-providers.sh` to executable list in `pkg_set_perms`
- Add `bfd_cdn.sh` via existing `internals/` directory copy (automatic)
- Add path replacement for `update-cdn-providers.sh`

**`importconf`:**
- Add `pressure-country.conf` format migration (detect old `CC=MULT` format, convert to `CC MULT`)

**`.github/workflows/ci.yml`:**
- Add `files/internals/bfd_cdn.sh` and `files/update-cdn-providers.sh` to `bash -n` and `shellcheck` targets

---

## 5b. Examples

### Enable CDN protection (Cloudflare)

1. Edit `conf.bfd`:
```bash
CDN_ENABLE="1"
```

2. Uncomment Cloudflare in `cdn-providers.conf`:
```
cloudflare  ignore  10  text  https://www.cloudflare.com/ips-v4/  https://www.cloudflare.com/ips-v6/
```

3. Fetch ranges:
```
$ bfd --cdn update
Fetching cloudflare (text)... 15 IPv4, 7 IPv6 CIDRs
Compiled CDN database: 22 ranges (1 provider)
```

### List providers

```
$ bfd --cdn
CDN Providers (1 active)
NAME          TREATMENT  MULT   IPv4  IPv6  UPDATED      STATUS
cloudflare    ignore     1.0x   15    7     2h ago       current
```

### Check an IP

```
$ bfd --cdn check 172.70.34.1
172.70.34.1: cloudflare (treatment: ignore)
```

```
$ bfd --cdn check 8.8.8.8
8.8.8.8: no CDN match
```

### JSON output

```
$ bfd --cdn --json
[{"name":"cloudflare","treatment":"ignore","mult":10,"ipv4_count":15,"ipv6_count":7,"updated":"2026-03-21T10:00:00","status":"current"}]
```

### Show CIDRs for a provider

```
$ bfd --cdn cloudflare
cloudflare — 22 CIDRs (ignore)
173.245.48.0/20
103.21.244.0/22
103.22.200.0/22
...
2400:cb00::/32
2606:4700::/32
...
```

### Error: no curl/wget

```
$ bfd --cdn update
error: neither curl nor wget found — cannot fetch CDN ranges.
Install curl or wget and retry.
```

### Status integration

```
$ bfd -S
...
CDN providers:  1 active (cloudflare: ignore) — updated 2h ago
...
```

### IP investigation annotation

```
$ bfd -a 172.70.34.1
...
CDN provider:   cloudflare (treatment: ignore)
...
```

---

## 6. Conventions

### Config file format (unified)

Both `cdn-providers.conf` and `pressure-country.conf` use:
- Whitespace-delimited fields (any whitespace: spaces or tabs)
- `#` comment lines (full line)
- Blank lines ignored
- `-` for absent optional fields
- Parsed with default `awk` field splitting (no `-F` needed)

### CDN database file format

IPv4 (`cdn.dat`):
```
# START_INT END_INT PROVIDER TREATMENT MULT
2886729728 2886795263 cloudflare ignore 10
```

IPv6 (`cdn6.dat`):
```
# START_HEX END_HEX PROVIDER TREATMENT MULT
2a0609... 2a0609... cloudflare ignore 10
```

Sorted by start value for binary search. Same structural pattern as
`ipcountry.dat` / `ipcountry6.dat` with two extra fields (PROVIDER, TREATMENT, MULT
vs just CC).

### Function naming

All CDN functions prefixed with `_cdn_` (internal) or `cdn_` (CLI-facing).
Source guard: `_BFD_CDN_LOADED` variable.

### CIDR extraction from JSON

Provider JSON is parsed with `grep -oE` for CIDR patterns:
```bash
# IPv4 CIDRs
grep -oE '"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+"' | tr -d '"'
# IPv6 CIDRs (requires at least two colon-separated groups)
grep -oE '"[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{0,4}){1,7}/[0-9]{1,3}"' | tr -d '"'
```

This is robust for the known provider JSON shapes (flat arrays of
CIDR strings in machine-generated output).

---

## 7. Interface Contracts

### CLI additions

| Flag | Arguments | Output |
|------|-----------|--------|
| `--cdn` | (none) | Provider list table (supports `--json`, `--csv`) |
| `--cdn` | `<provider>` | CIDR list for provider (supports `--json`) |
| `--cdn` | `update` | Force fetch + compile all providers |
| `--cdn` | `check <IP>` | CDN match result (supports `--json`) |

### Config additions

| Variable | File | Type | Default | Validation |
|----------|------|------|---------|------------|
| `CDN_ENABLE` | `conf.bfd` | 0/1 | `"0"` | Must be 0 or 1 |
| `CDN_UPDATE_DAYS` | `conf.bfd` | int >= 0 | `"7"` | Non-negative integer |

### File format additions

| File | Format | Fields |
|------|--------|--------|
| `cdn-providers.conf` | Whitespace-delimited | NAME TREATMENT MULT FORMAT URL_V4 [URL_V6] |
| `cdn.dat` | Whitespace-delimited | START_INT END_INT PROVIDER TREATMENT MULT |
| `cdn6.dat` | Whitespace-delimited | START_HEX END_HEX PROVIDER TREATMENT MULT |

### attack.pool ACTION values

New value: `cdn-exclude` — recorded when an IP matches a CDN provider
with `treatment=exclude` and would have been banned. Existing values
unchanged.

### pressure-country.conf format change

**Before:** `CC=MULT` (bash variable assignment, parsed with `IFS='='`)
**After:** `CC MULT` (whitespace-delimited, parsed with default awk)

`importconf` handles migration. The `country_weight()` function in
`bfd_pressure.sh` and the `_cw_map` loader in `bfd_core.sh` are
updated for the new format.

---

## 8. Migration Safety

### Install path

- `install.sh` copies `cdn-providers.conf` and `update-cdn-providers.sh`
  as new files. No conflict with existing installs.
- `bfd_cdn.sh` is inside `internals/` — copied automatically by
  `pkg_copy_tree`.
- `cdn.dat` / `cdn6.dat` do not exist on upgrade — BFD operates without
  CDN data until first fetch. `CDN_ENABLE="0"` by default.

### Config migration

- **`pressure-country.conf`:** The current `importconf` performs a raw
  `command cp -f` of config files — it has no format conversion logic.
  A new awk-based conversion block must be added BEFORE the copy:
  ```bash
  # Convert old CC=MULT format to whitespace-delimited CC MULT
  awk -F= '/^#/||/^$/{print;next}{print $1, $2}' "$old" > "$new"
  ```
  Detection: if any uncommented line contains `=`, the file is in old
  format and needs conversion. Comments are preserved as-is.
- `conf.bfd` new variables (`CDN_ENABLE`, `CDN_UPDATE_DAYS`) have sensible
  defaults — omission is safe.

### Upgrade path (prior version → this version)

1. No `cdn-providers.conf` exists → installed with all entries commented.
   Feature is off by default (`CDN_ENABLE="0"`).
2. No `cdn.dat`/`cdn6.dat` exist → CDN subsystem is no-op at runtime.
   No errors, no warnings.
3. `pressure-country.conf` in old format → `importconf` migrates
   automatically. If no customization, the commented defaults are
   already in new format.

### Rollback

- Removing `bfd_cdn.sh`, `cdn-providers.conf`, `update-cdn-providers.sh`,
  `cdn.dat`, `cdn6.dat` reverts to pre-feature state.
- `CDN_ENABLE="0"` disables all CDN logic even if files remain.
- The new `_cw_map` parser and `country_weight()` function use a
  **dual-format awk parser** that handles both old (`CC=MULT`) and new
  (`CC MULT`) format lines:
  ```awk
  /^#/||/^$/{next}
  index($0,"="){split($0,a,"="); cc=a[1]; val=a[2]; next}
  {cc=$1; val=$2}
  ```
  This means `importconf` format migration is best-effort — if skipped
  (e.g., manual file copy), the old-format file still loads correctly.

### Uninstall

- `uninstall.sh` removes `$INSTALL_PATH` entirely — no CDN-specific
  cleanup needed.

### No-Touch Files

These files must NOT be modified by this feature:
- Vendored libraries: `tlog_lib.sh`, `elog_lib.sh`, `alert_lib.sh`,
  `pkg_lib.sh`, `geoip_lib.sh`
- Alert templates: `files/alert/*.tpl`
- Rule files: `files/rules/*`
- Per-rule pressure config: `files/pressure.conf` (different from
  `pressure-country.conf`)
- Alert pipeline: 13-field pipe-delimited format unchanged
- Test infrastructure: `tests/infra/` (batsman submodule)

### CDN database staleness (cron.daily)

`cron.daily` adds a staleness check for `cdn.dat` (same pattern as
`ipcountry.dat`). When CDN_ENABLE=1 and the database is older than
`CDN_UPDATE_DAYS`, `update-cdn-providers.sh` is invoked.

Note: when a provider is removed from `cdn-providers.conf`, the
compiled `cdn.dat` retains stale ranges until the next rebuild.
Running `bfd --cdn update` after provider removal forces a clean
rebuild. Alternatively, `cron.daily` can unconditionally rebuild
when CDN_ENABLE=1 (since the provider list is small, rebuild cost
is negligible). The planner should choose the simpler approach.

### Test suite

- New tests in a dedicated `tests/NN-cdn-providers.bats` file.
- Existing tests unaffected — CDN feature is off by default and the
  pressure-country.conf format change is backward-compatible in tests
  (tests that set `_cw_map` directly are not format-dependent).

---

## 9. Dead Code and Cleanup

No dead code found during codebase reading. The `country_weight()` function
in `bfd_pressure.sh` (lines 496-509) uses `awk -F= -v cc="$cc"` which
will need updating for the new whitespace format. The old function body
becomes dead code after format migration.

---

## 10a. Test Strategy

| Goal | Test file | Test description |
|------|-----------|-----------------|
| G-01 | tests/NN-cdn-providers.bats | @test "cdn compile builds database from provider config" |
| G-01 | tests/NN-cdn-providers.bats | @test "cdn compile handles fetch failure gracefully" |
| G-01 | tests/NN-cdn-providers.bats | @test "cdn compile skips commented providers" |
| G-02 | tests/NN-cdn-providers.bats | @test "cdn ignore treatment skips IP in detection loop" |
| G-02 | tests/NN-cdn-providers.bats | @test "cdn exclude treatment records event but skips ban" |
| G-02 | tests/NN-cdn-providers.bats | @test "cdn derate treatment reduces pressure multiplier" |
| G-02 | tests/NN-cdn-providers.bats | @test "cdn treatment is per-provider independent" |
| G-03 | tests/NN-cdn-providers.bats | @test "custom provider with arbitrary URL is fetched" |
| G-04 | tests/NN-cdn-providers.bats | @test "json format extracted without jq" |
| G-04 | tests/NN-cdn-providers.bats | @test "text format parsed correctly" |
| G-05 | tests/NN-cdn-providers.bats | @test "cdn lookup matches IP within CIDR range" |
| G-05 | tests/NN-cdn-providers.bats | @test "cdn lookup rejects IP outside all ranges" |
| G-05 | tests/NN-cdn-providers.bats | @test "cdn lookup handles IPv6 CIDRs" |
| G-05 | tests/NN-cdn-providers.bats | @test "cdn batch lookup returns all matches in single pass" |
| G-06 | tests/NN-cdn-providers.bats | @test "bfd --cdn lists active providers" |
| G-06 | tests/NN-cdn-providers.bats | @test "bfd --cdn cloudflare shows CIDRs" |
| G-06 | tests/NN-cdn-providers.bats | @test "bfd --cdn check IP returns match" |
| G-06 | tests/NN-cdn-providers.bats | @test "bfd --cdn check IP returns no-match" |
| G-06 | tests/NN-cdn-providers.bats | @test "bfd --cdn --json outputs valid JSON" |
| G-07 | tests/NN-cdn-providers.bats | @test "pressure-country.conf whitespace format loads correctly" |
| G-07 | tests/NN-cdn-providers.bats | @test "country_weight reads whitespace-delimited format" |
| G-08 | tests/NN-cdn-providers.bats | @test "CDN_ENABLE=0 skips all CDN processing" |
| G-08 | tests/NN-cdn-providers.bats | @test "missing cdn.dat is no-op (no errors)" |

Estimated: ~23 tests in one new BATS file.

---

## 10b. Verification Commands

```bash
# G-01: CDN database compiled
ls -la /usr/local/bfd/cdn.dat /usr/local/bfd/cdn6.dat
# expect: -rw-r----- 1 root root <size> <date> /usr/local/bfd/cdn.dat

# G-02: Treatment modes work
bfd --cdn check 172.70.34.1
# expect: 172.70.34.1: cloudflare (treatment: ignore)

# G-03: Custom provider accepted
grep -c '^[^#]' /usr/local/bfd/cdn-providers.conf
# expect: N (number of uncommented providers)

# G-04: No jq/python dependency in CDN subsystem
grep -cE '\bjq\b|\bpython' files/internals/bfd_cdn.sh files/update-cdn-providers.sh
# expect: 0 per file (no external tool references)
# functional: bfd --cdn update succeeds with jq absent from PATH

# G-05: Binary search on compiled DB
wc -l /usr/local/bfd/cdn.dat
# expect: N lines (one per CIDR range, sorted)

# G-06: CLI subcommands work
bfd --cdn | head -3
# expect: CDN Providers (N active)
bfd --cdn --json | python3 -m json.tool > /dev/null
# expect: exit 0 (valid JSON)

# G-07: pressure-country.conf format
grep -c '=' /usr/local/bfd/pressure-country.conf
# expect: 0 (no = signs in data lines after migration)

# G-08: Disabled by default
grep 'CDN_ENABLE' /usr/local/bfd/conf.bfd
# expect: CDN_ENABLE="0"
```

---

## 11. Risks

1. **R-01: Provider URL changes break fetch.**
   *Mitigation:* Fetch failure is non-fatal — existing compiled database
   is preserved. `bfd --cdn` shows staleness age so operators notice.
   Log warning via `eout` on fetch failure.

2. **R-02: Performance regression from CDN lookup in per-IP loop.**
   *Mitigation:* Batch CDN lookup (`_batch_cdn_lookup`) does a single
   awk pass over the CDN database for all unique IPs per rule — same
   pattern as `_batch_ip_to_country`. CDN databases are small (~20-100
   ranges vs ~256K for ipcountry.dat). Lookup cost is negligible.

3. **R-03: curl/wget not available on minimal installs.**
   *Mitigation:* `_cdn_fetch_provider` tries `curl` then `wget`. If
   neither exists, log error and skip fetch. CDN subsystem degrades
   gracefully to no-op. `bfd --cdn update` reports the missing tool.

4. **R-04: pressure-country.conf format migration breaks custom configs.**
   *Mitigation:* `importconf` detects format before converting. Old
   `CC=MULT` is auto-converted to `CC MULT`. User comments are
   preserved. If detection is ambiguous, leave the file unchanged
   (both parsers handle both formats during transition).

5. **R-05: CDN CIDR regex extraction from JSON produces false positives.**
   *Mitigation:* The CIDR regex `[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+`
   matches only IP/prefix strings. JSON from CDN providers contains
   CIDRs and metadata strings — metadata strings don't look like CIDRs.
   Validation step: each extracted CIDR is validated (valid IP, prefix
   length 0-32 for v4, 0-128 for v6) before compilation.

---

## 11b. Edge Cases

| Scenario | Expected behavior | Handling |
|----------|-------------------|---------|
| CDN_ENABLE=1 but no cdn.dat exists | CDN subsystem is no-op, no errors | `_cdn_load_db` returns empty; batch lookup returns no matches |
| Provider URL returns empty body | Provider skipped, existing ranges preserved | `_cdn_fetch_provider` returns non-zero; compile continues with other providers |
| Provider URL returns HTML error page | CIDR regex extracts nothing from HTML | Zero valid CIDRs extracted; provider logged as "0 ranges", preserved from prior compile |
| IP matches both CDN range and ignore.hosts | Ignore cache wins (checked first in filter order) | Existing `grep -Fxf` filter runs before CDN lookup; CDN lookup is skipped for already-filtered IPs |
| IP matches CDN range with derate, mult=0 | Scoring weight becomes 0 → pressure never accumulates | Clamped to minimum 1 in scoring: `[ "$scoring_weight" -lt 1 ] && scoring_weight=1` (existing clamp) |
| Overlapping CIDRs from different providers | First match wins (binary search stops at first hit) | Database is sorted by start; first matching range determines provider. Document: operators should not configure overlapping providers |
| cdn-providers.conf has invalid URL | Fetch fails, provider skipped | `curl`/`wget` returns non-zero; error logged, compilation continues |
| cdn-providers.conf has invalid TREATMENT value | Provider skipped with warning | `_cdn_load_providers` validates treatment ∈ {ignore, exclude, derate} |
| Very large provider (>10K CIDRs) | Compiled database grows but lookup stays O(log n) | Binary search handles any size. 10K ranges = ~14 comparisons per lookup |
| Network timeout during fetch | Provider skipped after timeout (30s default) | `curl --max-time 30` / `wget --timeout=30`; same pattern as geoip_lib.sh |
| CDN database file has wrong permissions | Safety check rejects file | `_check_file_safety` validates ownership/permissions before loading |
| pressure-country.conf has mixed old/new format lines | Each line parsed by its detected format | Awk parser handles both: line with `=` → split on `=`; line without → split on whitespace |
| IPv6-only provider (no URL_V4) | Only IPv6 ranges compiled | URL_V4 = `-` in config; fetch skips it; only URL_V6 fetched |

---

## 12. Open Questions

None — all design decisions resolved in brainstorming.
