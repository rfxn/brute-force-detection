# BFD Periodic Threat Report — Design Spec

## Problem

BFD has rich on-demand activity data (`bfd -a`) but no scheduled reporting.
Administrators need periodic proof-point reports — daily, weekly, monthly —
delivered via all existing channels (text, email, Slack, Telegram, Discord)
without additional configuration burden.

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Channel config | `REPORT_CHANNELS` (comma-separated) | Decouples report delivery from ban alert routing; empty = use all enabled alert channels |
| Email subject | `{{INTERVAL}}` template syntax | `$INTERVAL` doesn't exist at conf.bfd source time; rendered via `_alert_tpl_render()` |
| Function naming | `report()` entry point | Matches `watch()`, `health_check()` convention |
| Architecture | Layered: data / render / deliver | Scalable — adding format or channel = one function |
| Cron stdout | Redirect at call site | `bfd --report daily >/dev/null 2>&1` — avoids coupling with `-q` flag |
| Duplicate guard | None | Users can self-serve `bfd --report daily` anytime |
| Monthly window | Fixed 30 days (2592000s) | Matches existing `--30d` convention throughout BFD |
| Country display | Abbreviated CC with flag emoji | Consistent across all channels: `CN`, `RU` not full names |

---

## Configuration

New section in `conf.bfd` after Discord Alerts, before Banning:

```bash
# =============================================
# Periodic Reports
# =============================================

# enable periodic threat reports [0 = disabled, 1 = enabled]
# when enabled, cron.daily triggers reports on configured intervals
REPORT_ENABLED="0"

# report intervals to generate (comma-separated: daily,weekly,monthly)
REPORT_INTERVALS="daily"

# delivery channels (comma-separated: email,slack,telegram,discord)
# empty = use all enabled alert channels above
REPORT_CHANNELS=""

# report email recipient (defaults to EMAIL_ADDRESS if empty)
REPORT_EMAIL_ADDRESS=""

# email subject template ({{INTERVAL}} and {{HOSTNAME}} expand at send time)
REPORT_EMAIL_SUBJECT="BFD {{INTERVAL}} Threat Report for {{HOSTNAME}}"

# maximum IPs to include in report tables (default 25)
REPORT_TOP_N="25"
```

---

## Function Architecture

All functions in `files/internals/bfd_report.sh`.

### Layered Primitive

```
report(interval)                            # public CLI entry — orchestrator
+-- _report_init(interval)                  # validate interval, compute windows
|   returns: _RPT_WINDOW, _RPT_CUTOFF, _RPT_PREV_CUTOFF, _RPT_LABEL
|
+-- _report_data(pool_file, cutoffs)        # gather all stats, export REPORT_* vars
|   +-- _apool_summary_awk()               # REUSE: unique IPs, total events
|   +-- _apool_awk()                        # REUSE: top N IP aggregation
|   +-- _apool_service_dual_awk()           # REUSE: per-service breakdown
|   +-- _report_trend_awk()                 # NEW: current vs prior window comparison
|   +-- _report_top_ips_text()              # format text table via format_table
|   +-- _report_top_ips_html()              # format HTML table
|   +-- _report_top_ips_brief()             # top 5 structured block for messaging
|   +-- _report_services_text()             # format service text table
|   +-- _report_services_html()             # format service HTML table
|   +-- _report_services_brief()            # structured block for messaging
|
+-- _report_deliver(interval, tpl_dir)      # render + deliver all channels
|   +-- _report_render_text(tpl_dir)        # assemble text body from templates
|   +-- _report_render_html(tpl_dir)        # assemble HTML body from templates
|   +-- _report_deliver_email(subj, text_file, html_file)
|   |                                       # wraps _alert_deliver_email
|   +-- _report_dispatch_messaging(tpl_dir) # wraps alert_dispatch()
|
+-- stdout output (always, for CLI use)
```

### Window Mapping

| Interval | Primary cutoff | Comparison cutoff | Label |
|----------|---------------|-------------------|-------|
| daily | now - 86400 | now - 172800 | "Daily" |
| weekly | now - 604800 | now - 1209600 | "Weekly" |
| monthly | now - 2592000 | now - 5184000 | "Monthly" |

### Channel Routing (`_report_deliver`)

```
if REPORT_CHANNELS is empty:
    email:     deliver if EMAIL_ALERTS=1
    messaging: deliver to all enabled channels (SLACK/TELEGRAM/DISCORD_ALERTS)
else:
    email:     deliver if "email" in REPORT_CHANNELS and SMTP is configured
    messaging: temporarily override channel registry per REPORT_CHANNELS
               before calling alert_dispatch(), restore after
```

### Sourcing

Added to `bfd.lib.sh` after `geoip_lib.sh` (line 57), before `unset _internals_dir`
(line 58):

```bash
# Source BFD report functions (periodic threat reports)
if [ -f "$_internals_dir/bfd_report.sh" ]; then
    # shellcheck disable=SC1091
    . "$_internals_dir/bfd_report.sh"
fi
```

### CLI Dispatcher

New case entry in `files/bfd` (between `--scan` block and `--flush-temp`):

```bash
--report)
    vhead; pre
    report "${2:-daily}" || exit "$?"
    ;;
```

---

## Reused Infrastructure

| Existing Function | Used By | Purpose |
|-------------------|---------|---------|
| `_apool_summary_awk()` | `_report_data` | Unique IPs, total events for window |
| `_apool_awk()` | `_report_top_ips_*` | Top N IP aggregation with cutoff |
| `_apool_service_dual_awk()` | `_report_services_*` | Per-service breakdown |
| `format_table()` | `_report_top_ips_text`, `_report_services_text` | Column-aligned text tables |
| `_alert_set_global_vars()` | `_report_data` | HOSTNAME, TIMESTAMP, BFD_VERSION |
| `_alert_tpl_resolve()` | `_report_render_*` | Template file resolution |
| `_alert_tpl_render()` | `_report_render_*`, subject | `{{VAR}}` substitution |
| `_alert_deliver_email()` | `_report_deliver_email` | SMTP relay / local MTA |
| `alert_dispatch()` | `_report_dispatch_messaging` | Slack/Telegram/Discord delivery |
| `_batch_ban_status_init/lookup()` | `_report_top_ips_*` | Ban status for IP tables |
| `pressure_compute()` / `pressure_format()` | `_report_top_ips_*` | Live pressure display |
| `_alert_country_flag()` | `_report_top_ips_brief`, `_report_services_brief` | Flag emoji from CC |
| `geoip_cc_name()` | not used | Full names not needed (abbreviated CC) |

### New AWK Helper

`_report_trend_awk(file, current_cutoff, prior_cutoff)` — single pass over
attack.pool producing:

```
current_total|current_uniq|prior_total|prior_uniq
```

Computes events in `[current_cutoff, now]` and `[prior_cutoff, current_cutoff]`.

---

## Template Variables

All `REPORT_` prefixed to avoid collision with ban alert vars.

```
REPORT_INTERVAL          "daily" / "weekly" / "monthly"
REPORT_INTERVAL_LABEL    "Daily" / "Weekly" / "Monthly"
REPORT_WINDOW            "24h" / "7d" / "30d"
REPORT_DATE_RANGE        "2026-03-15 00:00 -- 2026-03-16 00:00"
REPORT_UNIQUE_IPS        unique IPs in primary window
REPORT_TOTAL_EVENTS      total event count in primary window
REPORT_TOTAL_BANS        ban actions in primary window
REPORT_ACTIVE_BANS       current active ban count
REPORT_TOP_IPS_TEXT      pre-rendered text table (email)
REPORT_TOP_IPS_HTML      pre-rendered HTML table (email)
REPORT_TOP_IPS_BRIEF     top 5 structured block (messaging)
REPORT_SERVICES_TEXT     pre-rendered service text table (email)
REPORT_SERVICES_HTML     pre-rendered service HTML table (email)
REPORT_SERVICES_BRIEF    service block with country (messaging)
REPORT_TREND_DIRECTION   "up" / "down" / "flat"
REPORT_TREND_PCT         percentage change vs prior window
REPORT_TREND_LABEL       "23% increase vs prior 24h" / "no change"
```

Pre-formatted tables are necessary — the template engine only does `{{VAR}}`
substitution with no loop constructs.

---

## Templates

### Email (4 files)

- `report.text.header.tpl` — Banner: interval, hostname, date range, timezone
- `report.text.body.tpl` — Summary stats, top IPs table, service breakdown, trend, footer
- `report.html.header.tpl` — Teal-branded responsive header (adapted from ban alert style)
- `report.html.body.tpl` — Styled cards: summary grid, top IPs table, service breakdown, trend, footer

### Messaging (3 files)

- `report.slack.message.tpl` — Block Kit JSON: header, summary, top 5 IPs w/ CC, services w/ CC, trend
- `report.telegram.message.tpl` — MarkdownV2: header, summary, top 5 IPs w/ CC, services w/ CC, trend
- `report.discord.message.tpl` — Embed JSON: title, summary fields, top 5 IPs w/ CC, services w/ CC, trend

---

## Output Previews

### Text (stdout / email text part)

```
================================================================================
  BFD Daily Threat Report for habs.rfxn.com
  Period: 2026-03-15 00:00 -- 2026-03-16 00:00 (24h)
  Generated: 2026-03-16 00:15:03 EST
================================================================================

  Threat Summary
  ----------------------------------------
  Unique IPs:      47
  Total Events:    312
  Total Bans:      19
  Active Bans:     12

  Trend: Events up 23% vs prior 24h (312 vs 254)

  Top 25 Threat IPs (24h)
  ----------------------------------------
  COUNT  IP               COUNTRY  PRESSURE  RULES          STATUS
  43     203.0.113.50     CN       18.4/20   sshd           BANNED(perm)
  31     198.51.100.12    RU       15.2/20   sshd,dovecot   BANNED(45m)
  28     192.0.2.88       BR       12.1/20   sshd           prev:3
  19     198.51.100.77    IN       9.8/20    postfix        BANNED(perm)
  14     203.0.113.201    US       7.3/20    wordpress      prev:1
  ...

  Service Breakdown (24h)
  ----------------------------------------
  SERVICE      EVENTS  UNIQUE IPS  TOP COUNTRY
  sshd         187     31          CN
  dovecot      52      8           RU
  postfix      41      6           IN
  wordpress    22      4           US
  exim_main    10      3           BR

--------------------------------------------------------------------------------
  BFD 2.0.1 -- https://rfxn.com | GNU GPL v2
```

### Slack

```
+---------------------------------------------+
|  BFD Daily Threat Report                     |
|  habs.rfxn.com . 2026-03-16                 |
|---------------------------------------------|
|  47 unique IPs . 312 events . 19 bans       |
|  ^ 23% increase vs prior 24h                |
|                                              |
|  Top threats:                                |
|  CN 203.0.113.50 -- 43 hits (sshd) BANNED   |
|  RU 198.51.100.12 -- 31 hits (sshd,dovecot) |
|  BR 192.0.2.88 -- 28 hits (sshd)            |
|  IN 198.51.100.77 -- 19 hits (postfix)      |
|  US 203.0.113.201 -- 14 hits (wordpress)    |
|                                              |
|  Services:                                   |
|  sshd       187 events  31 IPs  CN          |
|  dovecot     52 events   8 IPs  RU          |
|  postfix     41 events   6 IPs  IN          |
|  wordpress   22 events   4 IPs  US          |
|  exim_main   10 events   3 IPs  BR          |
|---------------------------------------------|
|  BFD 2.0.1 . rfxn.com                       |
+---------------------------------------------+
```

(Flag emoji rendered by Slack from CC where supported)

### Telegram / Discord

Same structure as Slack with platform-appropriate formatting
(MarkdownV2 escaping for Telegram, embed JSON for Discord).

### Empty Pool (all channels)

```
BFD Daily Threat Report for habs.rfxn.com
Period: 2026-03-15 00:00 -- 2026-03-16 00:00 (24h)

No threat activity recorded in this period.
```

Still delivered so admin knows BFD is running and reporting.

---

## Scheduling (cron.daily)

Added after ipcountry refresh (line 107), before transient cleanup (line 109):

```bash
# --- Periodic threat reports ---
if [ "${REPORT_ENABLED:-0}" = "1" ]; then
    case ",${REPORT_INTERVALS:-daily}," in
        *,daily,*) "$INSTALL_PATH/bfd" --report daily >/dev/null 2>&1 || true ;;
    esac
    _dow=$(date +%u)  # 1=Monday
    if [ "$_dow" = "1" ]; then
        case ",${REPORT_INTERVALS:-daily}," in
            *,weekly,*) "$INSTALL_PATH/bfd" --report weekly >/dev/null 2>&1 || true ;;
        esac
    fi
    _dom=$(date +%d)
    if [ "$_dom" = "01" ]; then
        case ",${REPORT_INTERVALS:-daily}," in
            *,monthly,*) "$INSTALL_PATH/bfd" --report monthly >/dev/null 2>&1 || true ;;
        esac
    fi
fi
```

- Non-fatal (`|| true`) so report failure never breaks daily maintenance
- Weekly triggers on Monday (`date +%u` = 1)
- Monthly triggers on 1st of month (`date +%d` = 01)
- Stdout redirected at call site (not via `-q` flag)

---

## Implementation Phases

### Phase 1: Config + Core Functions
- Add `REPORT_*` config vars to `conf.bfd`
- Create `files/internals/bfd_report.sh` with all report functions
- Add sourcing to `bfd.lib.sh`
- Add `--report` to case dispatcher and usage text in `files/bfd`
- **Files**: `conf.bfd`, `bfd_report.sh` (new), `bfd.lib.sh`, `bfd`

### Phase 2: Templates
- Create all 7 report templates
- **Files**: `files/alert/report.{text,html}.{header,body}.tpl`, `files/alert/report.{slack,telegram,discord}.message.tpl`

### Phase 3: Cron Scheduling
- Add report triggers to `cron.daily`
- **Files**: `cron.daily`

### Phase 4: Documentation + Tests
- Man page (`bfd.1`): `--report` option, `REPORT_*` config vars
- README: feature description
- CHANGELOG + CHANGELOG.RELEASE
- `tests/46-report.bats`: unit + integration tests
- Add `bfd_report.sh` to verification lists
- **Files**: `bfd.1`, `README`, `CHANGELOG`, `CHANGELOG.RELEASE`, `tests/46-report.bats` (new)

### Phase 5: Install/Upgrade Verification
- Verify `pkg_copy_tree` handles `bfd_report.sh` in `internals/`
- Verify `pkg_config_merge()` handles new `REPORT_*` variables
- Verify all 7 new templates copied by installer
- **Files**: `install.sh`, `importconf` (verify only)

---

## File Summary

| Action | File | Phase |
|--------|------|-------|
| Create | `files/internals/bfd_report.sh` | 1 |
| Create | `files/alert/report.text.header.tpl` | 2 |
| Create | `files/alert/report.text.body.tpl` | 2 |
| Create | `files/alert/report.html.header.tpl` | 2 |
| Create | `files/alert/report.html.body.tpl` | 2 |
| Create | `files/alert/report.slack.message.tpl` | 2 |
| Create | `files/alert/report.telegram.message.tpl` | 2 |
| Create | `files/alert/report.discord.message.tpl` | 2 |
| Create | `tests/46-report.bats` | 4 |
| Modify | `files/conf.bfd` | 1 |
| Modify | `files/internals/bfd.lib.sh` | 1 |
| Modify | `files/bfd` | 1 |
| Modify | `cron.daily` | 3 |
| Modify | `bfd.1` | 4 |
| Modify | `README` | 4 |
| Modify | `CHANGELOG` | 4 |
| Modify | `CHANGELOG.RELEASE` | 4 |
| Verify | `install.sh`, `importconf` | 5 |

---

## Verification Plan

1. `bash -n` + `shellcheck -S warning` on `bfd_report.sh`
2. `make -C tests test` — run `tests/46-report.bats`
3. `bfd --report daily` with populated attack.pool — verify text output
4. `bfd --report daily` with EMAIL_ALERTS=1 — verify email delivery
5. `bfd --report daily` with empty attack.pool — verify "no activity" message
6. `bfd --report weekly` / `bfd --report monthly` — verify window computation
7. `bfd --report invalid` — verify error handling
8. Channel routing: REPORT_CHANNELS="email" with SLACK_ALERTS=1 — verify Slack skipped
9. Fresh `install.sh` — verify `bfd_report.sh` and templates deployed
