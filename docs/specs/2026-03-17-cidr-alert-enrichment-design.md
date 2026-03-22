# CIDR Escalation Alert Enrichment

> **Date:** 2026-03-17
> **Status:** Draft
> **Scope:** CIDR subnet ban alerts show aggregate pressure + per-IP breakdown

---

## Problem

When BFD escalates a distributed attack to a CIDR subnet ban, the alert displays
pressure and failure stats for the /24 entry itself rather than the aggregate
picture across all contributing IPs. The alert currently shows "1 failed logins =
+1 this scan" and "0.0 accumulated pressure" because `check_distributed()`
hardcodes field 13 (fail\_count) to `0` and stuffs `unique_count` into field 4
(pressure\_scaled) — a field the alert renderer interprets as thousandths of
accumulated pressure.

The result is an alert that tells the operator almost nothing about the scope or
severity of the distributed attack that triggered the ban.

## Solution

Extend the existing `count_subnet_attackers()` AWK pass to collect per-IP detail
(failure count, weighted pressure sum) alongside the subnet summary. Use this data
to populate aggregate stats in the alert pipeline fields and a top-N contributing
hosts breakdown in the source logs section of all alert channels.

## Data Flow

### 1. count\_subnet\_attackers() — detail file emission

The existing single-pass AWK over `pressure.dat` already groups events by
subnet+service and counts unique IPs. Extend it to also track per-IP totals:

- Per-IP failure count (number of pressure events)
- Per-IP weighted sum (sum of weight field values)

**Output contract (unchanged):** stdout emits `subnet mod unique_count` for
subnets meeting the `SUBNET_TRIG` threshold.

**New output:** write a detail file (path passed as a new argument) with per-IP
rows for subnets that meet the threshold:

```
subnet mod ip fail_count weighted_sum
```

One row per unique IP per service per qualifying subnet. The detail file is a temp
file created by the caller and cleaned up after `check_distributed()` completes.

**Weight field handling:** The `pressure.dat` weight field (`$4`) is optional and
defaults to 1 when absent (older events or unit-weight rules). The AWK must use
`w = ($4+0 > 0) ? $4+0 : 1` to handle missing fields — mawk returns `""` for
unset fields, and `""+0` yields `0` which must fall back to 1.

### 2. check\_distributed() — aggregate and encode

After receiving a subnet that trips, read the detail file to:

1. **Aggregate totals** for the subnet+service:
   - `total_failures` — sum of all per-IP failure counts
   - `total_pressure_raw` — sum of all per-IP weighted sums (raw, not decayed)
   - `unique_count` — already available from stdout

2. **Build top-N breakdown** sorted by weighted sum descending:
   - Read matching rows from detail file
   - Sort by weighted sum (descending), take top N
   - Format as a compact table

3. **Write sidecar file** for alert rendering:
   - Path: `$INSTALL_PATH/tmp/.cidr_detail_<sanitized_subnet>`
   - Contains: header line with aggregates, then per-IP rows (top N + overflow count)
   - Cleaned up by `_alert_set_entry_vars` after reading, or by cron.daily

4. **Encode aggregates into alert pipeline:**
   - Field 4 (`pressure_scaled`): `total_pressure_raw * 1000` (proper thousandths)
   - Field 13 (`fail_count`): `total_failures`
   - All other fields unchanged

### 3. \_alert\_set\_entry\_vars() — render enriched breakdown

In the `lp == "(multiple)"` branch of `_alert_set_entry_vars()` (bfd\_alert.sh),
instead of the static "Source logs not available" message:

1. Derive sidecar path from `$HOST` (the subnet address)
2. If sidecar exists, read and format:
   - `SOURCE_LOGS_SECTION_TEXT`: contributing hosts table
   - `SOURCE_LOGS_SECTION_HTML`: styled HTML table
3. If sidecar missing (race, cleanup), fall back to existing static message
4. Clean up sidecar file after reading

The Pressure line in templates will now render correctly because fields 4 and 13
carry real aggregate values. The "failed logins" display will read
"N failed logins across M IPs" to distinguish from individual IP alerts.

### 4. Messaging channels

Email templates (`text.entry.tpl`, `html.entry.tpl`) already render
`{{SOURCE_LOGS_SECTION_TEXT}}` / `{{SOURCE_LOGS_SECTION_HTML}}` — the enriched
contributing hosts table flows through those placeholders unchanged.

Messaging templates (`slack.entry.tpl`, `telegram.entry.tpl`, `discord.entry.tpl`)
do NOT have source log placeholders. A new `{{SUBNET_HOSTS_SECTION}}` placeholder
must be added to each messaging template (empty string for non-CIDR alerts).
Placement: after the pressure line, as a compact multi-line text block.

The top-N cap (default 5) keeps the output compact enough for Discord's embed
limits (1024 chars per field value, 4096 chars per embed description).

## Pressure Line Rendering

The `_alert_set_entry_vars` function needs to detect CIDR entries and adjust the
pressure line wording. When `lp == "(multiple)"`:

```
Pressure:    47 failed logins across 6 IPs = +47 this scan
             47.0 accumulated pressure · trips at 5 (subnet) · weight 1 · half-life 50m
```

The "across N IPs" qualifier requires a display variant of `FAIL_COUNT` because
templates use `{{FAIL_COUNT}}` for both the human-readable text and math
(`PRESSURE_CONTRIB = FAIL_COUNT * weight`). The solution:

1. Compute `PRESSURE_CONTRIB` from the integer `fail_count` as today
2. Export `FAIL_COUNT_DISPLAY` — a human-readable string:
   - CIDR alerts: `"47 across 6 IPs"` (integer failures + unique IP count from sidecar header)
   - Individual IP alerts: same as `FAIL_COUNT` (e.g., `"47"`)
3. All five entry templates change `{{FAIL_COUNT}}` to `{{FAIL_COUNT_DISPLAY}}`
   in the "failed logins" text. `{{FAIL_COUNT}}` remains available as a raw
   integer for any future numeric use.

The unique IP count comes from the sidecar header line (field 3: `unique_count`).

New template variables for CIDR alerts:
- `FAIL_COUNT_DISPLAY` — human-readable failure count string (always exported; equals `FAIL_COUNT` for non-CIDR)
- `SUBNET_IP_COUNT` — unique contributing IP count (exported when `lp == "(multiple)"`; empty otherwise)
- `SUBNET_HOSTS_SECTION` — pre-formatted contributing hosts text for messaging templates (empty for non-CIDR)

## Contributing Hosts Table Format

### Text (email + messaging)

```
  Contributing hosts (6 IPs from 45.143.162.0/24):
    45.143.162.12     mod_sec    14 failures    14.0 pressure
    45.143.162.88     sshd        9 failures     9.0 pressure
    45.143.162.201    sshd        8 failures     8.0 pressure
    45.143.162.45     mod_sec     7 failures     7.0 pressure
    45.143.162.177    sshd        5 failures     5.0 pressure
    ... and 1 more IP(s)
```

### HTML (email)

Styled table within the existing source logs row, using the project's email
design system (zinc palette, monospace for IPs, right-aligned numbers).

## Configuration

New variable in `internals.conf`:

```bash
SUBNET_ALERT_TOP_N="${SUBNET_ALERT_TOP_N:-5}"
```

Internal-only — not exposed in `conf.bfd`, `help()`, man page, or README.
Operators who need to tune it can set it in `internals.conf` overrides.

## Sidecar File Management

- **Path pattern:** `$INSTALL_PATH/tmp/.cidr_detail_<subnet_with_slash_replaced>`
  (e.g., `.cidr_detail_45.143.162.0_24`)
- **Lifecycle:** Created by `check_distributed()`, read+deleted by
  `_alert_set_entry_vars()` during alert rendering in the same cycle
- **Cleanup safety net:** `cron.daily` needs a new glob: `command rm -f "$INSTALL_PATH"/tmp/.cidr_detail_*`
  (existing cleanup only covers `.alist.*`, `.alerts.*`, `.bfd_rpt_*`)
- **Format:**
  ```
  # subnet unique_count total_failures total_pressure_raw
  HEADER 45.143.162.0/24 6 47 47000
  45.143.162.12 mod_sec 14 14000
  45.143.162.88 sshd 9 9000
  ...
  OVERFLOW 1
  ```

## Files Changed

| File | Change |
|------|--------|
| `files/internals/bfd.lib.sh` | Extend `count_subnet_attackers()` AWK to write detail file (default `$4` to 1 when absent); update `check_distributed()` to compute aggregates, build sidecar, encode fields 4+13 |
| `files/internals/bfd_alert.sh` | Enrich `_alert_set_entry_vars` `(multiple)` branch: read sidecar, format breakdown, export `FAIL_COUNT_DISPLAY`, `SUBNET_IP_COUNT`, `SUBNET_HOSTS_SECTION`; adjust pressure line wording for CIDR |
| `files/internals/internals.conf` | Add `SUBNET_ALERT_TOP_N` default |
| `files/alert/text.entry.tpl` | Replace `{{FAIL_COUNT}}` with `{{FAIL_COUNT_DISPLAY}}` in pressure line |
| `files/alert/html.entry.tpl` | Replace `{{FAIL_COUNT}}` with `{{FAIL_COUNT_DISPLAY}}` in pressure line |
| `files/alert/slack.entry.tpl` | Replace `{{FAIL_COUNT}}` with `{{FAIL_COUNT_DISPLAY}}`; add `{{SUBNET_HOSTS_SECTION}}` |
| `files/alert/telegram.entry.tpl` | Replace `{{FAIL_COUNT}}` with `{{FAIL_COUNT_DISPLAY}}`; add `{{SUBNET_HOSTS_SECTION}}` |
| `files/alert/discord.entry.tpl` | Replace `{{FAIL_COUNT}}` with `{{FAIL_COUNT_DISPLAY}}`; add `{{SUBNET_HOSTS_SECTION}}` |
| `cron.daily` | Add `.cidr_detail_*` cleanup glob |
| `tests/` | New or extended tests for CIDR alert enrichment (including adding field 4+13 assertions to `tests/19-subnet-detection.bats`) |

## Files NOT Changed

- Alert template files (`files/alert/*.summary.tpl`, `files/alert/*.report.*`) — report
  and summary templates are unaffected; only the five `*.entry.tpl` files change
- `files/conf.bfd` — internal config only
- `files/bfd` — `check_distributed()` call site unchanged; the detail file is
  created and managed internally by `check_distributed()`, not passed from the caller
- `attack.pool` format — the pool append in `check_distributed()` already records
  `unique_count`; this does not change

## Backward Compatibility: ATTACK\_COUNT in send\_alerts()

`send_alerts()` (bfd.lib.sh:2981) has a backward-compat path that reads field 4
and computes `ATTACK_COUNT="$(( _count / 1000 ))"` for custom hooks. Currently,
for distributed bans, `_count` is `unique_count` (e.g., 3), yielding
`ATTACK_COUNT=0` (floored to 1 by the min-1 guard) — already broken.

With the proposed change, `_count` becomes `total_pressure_raw * 1000` (e.g.,
47000), yielding `ATTACK_COUNT=47` — the actual aggregate pressure in whole units.
This is a behavioral improvement: custom hooks will see a meaningful count instead
of a constant `1`. No backward-compat shim is needed; the current value was wrong.

## Verified Consumers of Alert Pipeline Fields 4 and 13

| Consumer | Field 4 usage | Field 13 usage | Impact |
|----------|---------------|----------------|--------|
| `_alert_set_entry_vars()` | `pressure_scaled` → formatting | `fail_count` → FAIL\_COUNT | Improved (real values) |
| `send_alerts()` ATTACK\_COUNT | `_count / 1000` | Not used | Improved (see above) |
| `_alert_compute_summary()` | Not referenced in AWK | Not referenced | No impact |
| Spool format (14-field) | Positional pass-through | Positional pass-through | No impact (epoch prefix + cut -d'\|' -f2-) |

## Sidecar Filename: IPv6 Sanitization

IPv6 subnets (e.g., `2001:db8:abcd:1234::/48`) contain colons. While legal on
Linux filesystems, colons are unusual in filenames. The subnet-to-filename
sanitization must replace both `/` and `:` with safe characters (e.g., `_` and `-`):
`.cidr_detail_2001-db8-abcd-1234--_48`.

## Field 12 (weight) — Stays Hardcoded at 1

The current distributed alert line hardcodes field 12 (weight) to `1`. This
remains unchanged. For the pressure line display, `PRESSURE_CONTRIB = FAIL_COUNT *
weight` will equal `total_failures * 1 = total_failures`, which is the correct
representation: the aggregate raw failure count across the subnet. Per-rule weights
are already reflected in the `total_pressure_raw` value (field 4) since the AWK
sums the weight column from `pressure.dat`.

## Pressure Computation Note

The aggregate pressure displayed is the **raw weighted sum** from `pressure.dat`,
not true exponentially-decayed pressure. For active distributed attacks (the only
scenario triggering CIDR bans), events are recent and the difference from decayed
values is negligible. This avoids reimplementing exponential decay math in AWK or
adding a per-IP bash loop.

## Testing

- Unit: verify `count_subnet_attackers()` detail file output format and content
- Unit: verify `check_distributed()` aggregate computation and sidecar generation
- Unit: verify `_alert_set_entry_vars` renders enriched breakdown from sidecar
- Integration: end-to-end CIDR ban alert with synthetic pressure.dat containing
  multiple IPs in the same subnet, verify alert output contains aggregate stats
  and contributing hosts table
- Edge cases: single IP triggers subnet (unique\_count == SUBNET\_TRIG == 1),
  more IPs than SUBNET\_ALERT\_TOP\_N, missing sidecar fallback
