# Brute Force Detection (BFD)

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/banner-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="assets/banner-light.svg">
    <img alt="Brute Force Detection (BFD)" src="assets/banner-dark.svg" width="830">
  </picture>
</p>

<p align="center">
  <a href="https://github.com/rfxn/brute-force-detection/actions/workflows/ci.yml"><img src="https://github.com/rfxn/brute-force-detection/actions/workflows/ci.yml/badge.svg?branch=master" alt="CI"></a>
  <a href="CHANGELOG"><img src="https://img.shields.io/badge/version-2.0.2-blue.svg?style=flat-square" alt="Version"></a>
  <a href="COPYING.GPL"><img src="https://img.shields.io/badge/license-GPL_v2-green.svg?style=flat-square" alt="License: GPL v2"></a>
  <a href="https://www.gnu.org/software/bash/"><img src="https://img.shields.io/badge/language-bash-89e051.svg?style=flat-square" alt="Shell"></a>
  <a href="#11-supported-systems"><img src="https://img.shields.io/badge/platform-linux-lightgrey.svg?style=flat-square" alt="Platform"></a>
</p>

Log-based brute force detection and automatic IP banning for Linux servers.
Pressure-based scoring lets humans make mistakes while stopping bots cold —
57 service rules, 8 firewall backends, IPv4/IPv6, GeoIP enrichment,
multi-channel alerting, and continuous watch mode with ~10s detection latency.

*Copyright (C) 1999-2026 [R-fx Networks](https://www.rfxn.com) · Ryan MacDonald · [GPL v2](COPYING.GPL)*

---

## What's New in 2.0.2

- **CDN/trusted proxy subsystem** — per-provider IP range databases with ignore/exclude/derate treatment modes, `bfd --cdn` CLI, automatic cron.daily refresh
- **Structured audit events** — 12 new audit event types for ban escalation, alert delivery, detection triggers, and scan lifecycle
- **Periodic threat reports** — scheduled daily/weekly/monthly reports via all alert channels with trend comparison
- **Pressure config migration** — `pressure.conf` and `pressure-country.conf` migrated to whitespace format with backward-compatible dual-format parsing
- **Multi-channel alert fixes** — per-channel dispatch prevents cross-contamination between Slack/Telegram/Discord

## Contents

- [1. Introduction](#1-introduction)
  - [1.1 Supported Systems](#11-supported-systems)
- [2. Installation](#2-installation)
  - [2.1 Scheduling](#21-scheduling)
  - [2.2 Upgrading](#22-upgrading)
- [3. Configuration](#3-configuration)
  - [3.1 Pressure Model (Detection)](#31-pressure-model-detection)
  - [3.2 Email Alerts](#32-email-alerts)
  - [3.3 Banning](#33-banning)
  - [3.4 Repeat Offender Handling](#34-repeat-offender-handling)
  - [3.5 IPv6](#35-ipv6)
  - [3.6 Log Paths](#36-log-paths)
  - [3.7 Advanced](#37-advanced)
  - [3.8 Country Weighting](#38-country-weighting)
  - [3.9 SMTP Relay](#39-smtp-relay)
  - [3.10 Email Templates](#310-email-templates)
  - [3.11 Slack Alerts](#311-slack-alerts)
  - [3.12 Telegram Alerts](#312-telegram-alerts)
  - [3.13 Discord Alerts](#313-discord-alerts)
- [4. Usage](#4-usage)
  - [4.1 Dry Run](#41-dry-run)
  - [4.2 Health Check](#42-health-check)
  - [4.3 Threat Activity](#43-threat-activity)
  - [4.4 Watch Mode](#44-watch-mode)
  - [4.5 Flush Bans](#45-flush-bans)
  - [4.6 Structured Output](#46-structured-output)
  - [4.7 Scan Mode](#47-scan-mode)
  - [4.8 Events and Investigation](#48-events-and-investigation)
  - [4.9 Exit Codes](#49-exit-codes)
- [5. Firewall](#5-firewall)
- [6. Rule Engine](#6-rule-engine)
  - [6.1 Rule Catalog](#61-rule-catalog)
  - [6.2 Rule Customization](#62-rule-customization)
- [7. Ignore Lists](#7-ignore-lists)
- [8. CDN / Trusted Proxy](#8-cdn--trusted-proxy)
  - [8.1 Configuration](#81-configuration)
  - [8.2 Provider Configuration](#82-provider-configuration)
  - [8.3 Treatment Modes](#83-treatment-modes)
  - [8.4 CLI Commands](#84-cli-commands)
  - [8.5 Automatic Updates](#85-automatic-updates)
  - [8.6 Adding Custom Providers](#86-adding-custom-providers)
- [9. Periodic Reports](#9-periodic-reports)
- [10. Ban Management](#10-ban-management)
- [11. IPv6](#11-ipv6)
- [Integration](#integration)
- [Troubleshooting](#troubleshooting)
- [License](#license)
- [Support](#support)

---

## Quick Start

```bash
# Install (as root)
./install.sh

# Configure — set your firewall ban command
vi /usr/local/bfd/conf.bfd

# Verify — watch mode should be running (auto-enabled by installer)
systemctl status bfd-watch       # systemd
bfd -c                           # health check

# Dry run — detect without banning
bfd -d

# Run with output
bfd -s

# View top attackers and ban status
bfd -a

# Manage bans
bfd -l               # list active bans
bfd -b 192.0.2.1 sshd # manually ban an IP
bfd -u 192.0.2.1      # unban an IP
```

---

## 1. Introduction

Brute Force Detection (BFD) is a modular shell script for parsing application logs and detecting authentication failures. It ships with 57 service rules covering SSH, mail, FTP, web, database, control panel, DNS, VPN, VoIP, proxy, and messaging services. Each rule declares fail2ban-compatible `<HOST>` regex patterns; the engine handles log reading, IP extraction, IPv6 normalization, and validation.

Unlike traditional count-based tools that ban at a fixed failure count — forcing operators to choose between catching attackers fast or tolerating legitimate mistakes — BFD uses **exponential-decay pressure scoring**. Each failure adds pressure weighted by service severity, and pressure decays over time via a configurable half-life. A user who mistypes a password a few times over several minutes generates pressure that naturally fades, staying well below the trip point. A bot hammering the same service generates pressure faster than it can decay and trips the threshold almost immediately. The result is fewer false positives on real users with faster response to actual attacks.

BFD uses a log tracking system so logs are only parsed from the point at which they were last read. This greatly assists in performance as we are not constantly reading the same log data. The log tracking system is compatible with syslog/logrotate style log rotations — it detects when rotations have occurred and grabs log tails from both the new log file and the rotated log file.

**Detection**
- 57 service rules with fail2ban-compatible `<HOST>` regex patterns
- Exponential-decay pressure scoring — human typos fade away, bot attacks trip instantly
- Per-service severity weights (SSH=3, control panels=5, noisy services=1)
- Per-rule and global cross-service pressure trip points
- Optional country-based pressure multipliers
- Incremental log parsing with rotation-aware tracking

**Banning**
- Temporary bans with automatic expiry and firewall rule cleanup
- Repeat offender escalation (linear, doubling, or capped growth)
- 8 firewall backends with auto-detection (APF, CSF, firewalld, UFW, nftables, iptables, route, custom)
- Manual ban/unban CLI with full state tracking

**IPv4/IPv6**
- Dual-stack detection and banning with no rule modifications needed
- Separate IPv6 ban commands for firewalls that require it (ip6tables)
- Automatic local address exclusion for both address families

**Operational**
- Health check mode for non-destructive diagnostics (`bfd -c`)
- Dry-run mode for testing rules without banning (`bfd -d`)
- Verbose mode for detailed per-rule and per-ban output (`bfd --verbose`)
- Threat activity reporting with summary, dual-interval service breakdown, and ban status (`bfd -a`)
- Per-run statistics logging (rules checked, events parsed, bans executed)
- Batched email alerts with enriched context (ban type, duration, history) and per-rule routing
- Man page (`man bfd`) and bash tab completion installed automatically

### 1.1 Supported Systems

BFD runs on any Linux distribution with bash 4.1+ and standard GNU utilities (grep, awk, sed). It has been tested and is supported on:

**RHEL-family:**
- CentOS 6, 7
- Rocky Linux 8, 9, 10

**Debian-family:**
- Ubuntu 14.04, 16.04, 18.04, 20.04, 22.04, 24.04
- Debian 12

Log paths are auto-detected at runtime:
- RHEL: `/var/log/secure`, `/var/log/messages`, `/var/log/maillog`
- Debian/Ubuntu: `/var/log/auth.log`, `/var/log/syslog`, `/var/log/mail.log`

BFD requires root privileges. No additional dependencies beyond the base system are needed.

---

## 2. Installation

The included `install.sh` script handles all installation tasks:

```bash
./install.sh
```

This will:
- Install BFD to `/usr/local/bfd`
- Place the `bfd` command at `/usr/local/sbin/bfd`
- Auto-enable watch mode for ~10s detection latency (systemd or SysVinit)
- Install a 2-minute cronjob as fallback (skipped while watch runs)
- If upgrading, import settings from the previous installation and restart watch mode

Previous installations are backed up before overwriting.

- **Install Path:** `/usr/local/bfd`
- **Bin Path:** `/usr/local/sbin/bfd`

Custom install paths via environment variables:

```bash
INSTALL_PATH=/opt/bfd BIN_PATH=/usr/sbin/bfd ./install.sh
```

### 2.1 Scheduling

**Watch mode (recommended):**

BFD's watch mode runs as a persistent daemon, polling for new log data every `WATCH_INTERVAL` seconds (default 10). Detection latency is ~10 seconds, comparable to fail2ban and other daemon-based tools.

The installer automatically enables and starts watch mode on fresh installs.
On upgrades, the existing scheduling choice is preserved — if watch mode was
running it is restarted; if `bfd.timer` was enabled it is left active.

To manually manage watch mode:

```bash
# systemd (Rocky 8+, Debian 12, Ubuntu 20+)
systemctl enable --now bfd-watch.service

# SysVinit (CentOS 6/7, Ubuntu 14.04)
service bfd-watch start
chkconfig bfd-watch on    # enable at boot (RHEL)
```

**Cron (automatic fallback):**

The installer places a cronjob at `/etc/cron.d/bfd` that runs BFD every 2 minutes in quiet mode. This serves as a fallback — when watch mode is active, cron runs detect the lock and silently skip. If the watch daemon exits, cron automatically resumes detection within 2 minutes.

The cron entry does not need to be removed when using watch mode.

### 2.2 Upgrading

When upgrading from a previous BFD installation (including v1.5-2), `install.sh` automatically:

- Backs up the existing installation to `/usr/local/bfd.bk.DDMMYYYY-EPOCH` (symlinked as `/usr/local/bfd.bk.last` for easy access)
- Runs `importconf` to merge your configuration and preserve state

**What importconf migrates automatically:**

| Category | Details |
|----------|---------|
| User configuration | `conf.bfd` values merged onto new template |
| Legacy variable names | `TRIG` → `PRESSURE_TRIP`, `TRIG_WINDOW` → `PRESSURE_HALF_LIFE`, `TRIG_GLOBAL` → `PRESSURE_TRIP_GLOBAL`, `BAN_DURATION` → `BAN_TTL`, `BAN_PERMANENT_*` → `BAN_ESCALATE_*` |
| Per-rule overrides | `pressure.conf` preserved from previous install; old colon format auto-converted to whitespace format |
| Firewall backend | Set to `"custom"` if pre-2.0.1 `BAN_COMMAND` detected |
| Ban state | `bans.active`, `bans.history`, `pressure.dat` |
| Log tracking state | tlog byte-offsets, journal cursors |
| Alert templates | `alert/` partials (user-modified preserved), legacy `alert.bfd` |
| Ignore lists | `ignore.hosts` |

**Post-upgrade verification:**

```bash
bfd -c                    # health check and diagnostics
bfd --status              # show current ban/event summary
```

**Rollback:**

If the upgrade causes issues, restore from backup:

```bash
bfd --flush-all           # clear any new bans
rm -rf /usr/local/bfd
cp -a /usr/local/bfd.bk.last /usr/local/bfd
```

---

## 3. Configuration

The main configuration file is `/usr/local/bfd/conf.bfd`. Each option has a descriptive comment directly above it in the file. Review the file from top to bottom before your first run.

Use `bfd -c` to validate your configuration without banning anything.

### 3.1 Pressure Model (Detection)

BFD uses exponential-decay pressure scoring: each failed login adds pressure weighted by service severity, and pressure decays over time via a half-life. A ban fires when accumulated pressure crosses a trip point. This naturally separates human mistakes from automated attacks — a few typos over several minutes decay away harmlessly, while rapid-fire failures from a bot accumulate faster than they can decay.

```
pressure = SUM { weight * 2^(-(now - event_time) / half_life) }
```

**Example** (SSH rule: weight=3, trip=15, half-life=300s):
- **Bot attack** — 7 failures in 1 second: pressure = 3×7 = 21.0 → exceeds 15 → **BAN**
- **Human typos** — 5 failures over 4 minutes: earlier events decay, total ≈ 11.1 → below 15 → **NO BAN**

> **Quick reference:** `PRESSURE_TRIP / weight` = minimum rapid failures for a ban. Default: 20 / 3 (sshd) = 7 rapid failures. Spread-out failures need more attempts (older ones decay).

| Variable | Default | Description |
|----------|---------|-------------|
| `PRESSURE_TRIP` | `20` | Accumulated pressure needed to trigger a ban; per-rule overrides in rule files or `pressure.conf` |
| `PRESSURE_HALF_LIFE` | `300` | Half-life in seconds (how fast pressure decays); shorter = more forgiving |
Per-rule weights are configured in `pressure.conf` (centralized) or in individual rule files via `PRESSURE_WEIGHT`. Higher weight = faster pressure accumulation. Default tiers: 5 (control panels), 3 (SSH/VPN/database/critical), 2 (mail/FTP/web), 1 (noisy/generic).

`pressure.conf` uses whitespace-delimited `key=value` format:

```
sshd       weight=3  trip=20
postfix    weight=2  trip=20  skip_alert=1
```

### 3.2 Email Alerts

| Variable | Default | Description |
|----------|---------|-------------|
| `EMAIL_ALERTS` | `0` | Send email alerts (0 = off, 1 = on) |
| `EMAIL_ADDRESS` | `root` | Alert recipient(s), comma-separated |
| `EMAIL_SUBJECT` | `Brute Force Warning for $HOSTNAME` | Subject line (auto-appends `(N bans)` when batched) |
| `EMAIL_LOGLINES` | `5` | Number of log lines per host in alert body and events view |
| `EMAIL_FORMAT` | `text` | Email body format: `text` (plain text), `html` (HTML only), `both` (multipart text+HTML) |
| `EMAIL_DIGEST` | `cycle` | Digest mode: `cycle` (one email per run), `timed` (accumulate and send on interval) |
| `EMAIL_DIGEST_INTERVAL` | `900` | Digest flush interval in seconds when `EMAIL_DIGEST="timed"` (default 15 minutes) |
| `EMAIL_REPUTATION_LINKS` | *(empty)* | IP reputation links in alerts, comma-separated: `abuseipdb`, `shodan`, `virustotal`, `ipinfo`, `greynoise` |

Alerts are **batched**: multiple bans in one check cycle produce a single email per recipient instead of one email per ban. Each alert includes host, service, pressure score with threshold, ban type (temporary/permanent/escalated) with duration and expiry, country code, recidivism history, IP reputation links, a pressure visualization bar, and source log lines.

**Digest modes**: In `cycle` mode (default), one email is sent at the end of each detection run. In `timed` mode, alerts accumulate across runs and are flushed when `EMAIL_DIGEST_INTERVAL` expires — reducing email volume on active servers. Watch mode checks the spool each iteration; cron mode checks each run. Accumulated alerts are force-flushed on shutdown and daily rotation.

**Format options**: `text` sends plain text via `mail`. `html` sends HTML via `sendmail`. `both` sends a multipart MIME message with both text and HTML parts via `sendmail`, so the recipient's email client displays whichever it prefers. If `sendmail` is not available, `html` and `both` fall back to text-only via `mail`.

Email templates are customizable — see [section 3.10](#310-email-templates). Individual rules can suppress alerts by setting `SKIP_ALERT="1"` in the rule file. Set `RULE_EMAIL="addr"` in a rule file to route that rule's alerts to a different recipient.

### 3.3 Banning

| Variable | Default | Description |
|----------|---------|-------------|
| `FIREWALL` | `auto` | Firewall backend; see [section 5](#5-firewall) |
| `BAN_TTL` | `600` | Ban duration in seconds (0 = permanent). Temporary bans auto-expire |
| `BAN_COMMAND` | APF deny | Command when `FIREWALL="custom"`. See [section 5](#5-firewall) |
| `UNBAN_COMMAND` | APF unban | Reverse command. Required for temporary ban auto-expiry |

The variables `$ATTACK_HOST`, `$MOD` (service name), and `$PORTS` (from rule file) are available in ban/unban commands.

### 3.4 Repeat Offender Handling

These four settings form a pipeline: `BAN_ESCALATION` controls how ban duration grows, `BAN_ESCALATION_CAP` limits that growth, `BAN_ESCALATE_AFTER` flips to permanent once the count is reached, and `BAN_ESCALATE_WINDOW` is the lookback window for all of the above.

| Variable | Default | Description |
|----------|---------|-------------|
| `BAN_ESCALATION` | `none` | How duration grows: `none` (fixed), `linear` (10m, 20m, 30m...), `double` (10m, 20m, 40m, 80m...) |
| `BAN_ESCALATION_CAP` | `86400` | Maximum escalated duration in seconds (0 = no cap) |
| `BAN_ESCALATE_AFTER` | `5` | Temporary bans before flipping to permanent (0 = never) |
| `BAN_ESCALATE_WINDOW` | `86400` | Lookback window in seconds for counting repeat offenses |

**Examples** (with `BAN_TTL="600"`):
- **Fixed 10m bans, permanent after 5th:** `ESCALATION=none`, `ESCALATE_AFTER=5` → 10m, 10m, 10m, 10m, 10m → permanent
- **Doubling bans, permanent after 5th:** `ESCALATION=double`, `ESCALATE_AFTER=5` → 10m, 20m, 40m, 80m, 160m → permanent
- **Linear growth, capped, never permanent:** `ESCALATION=linear`, `CAP=3600`, `ESCALATE_AFTER=0` → 10m, 20m, 30m... 1h, 1h, 1h (always temporary)

### 3.5 IPv6

| Variable | Default | Description |
|----------|---------|-------------|
| `BAN_COMMAND_V6` | *(empty)* | IPv6-specific ban command. When empty, `BAN_COMMAND` is used for both address families |
| `UNBAN_COMMAND_V6` | *(empty)* | IPv6-specific unban command. When empty, `UNBAN_COMMAND` is used for both |

Leave empty when using tools that handle both protocols natively (nft with `inet` family, APF, ip route). Set explicitly for tools that require separate IPv4/IPv6 commands (iptables/ip6tables). See [IPv6](#11-ipv6).

### 3.6 Log Paths

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTH_LOG_PATH` | `/var/log/secure` | Auth log (auto-detected: `/var/log/auth.log` on Debian) |
| `KERNEL_LOG_PATH` | `/var/log/messages` | Kernel/syslog (auto-detected: `/var/log/syslog` on Debian) |
| `MAIL_LOG_PATH` | `/var/log/maillog` | Mail log (auto-detected: `/var/log/mail.log` on Debian) |
| `BFD_LOG_PATH` | `/var/log/bfd/bfd.log` | BFD's own application log |

Log paths are auto-detected based on the distribution. Override in `conf.bfd` if your system uses non-standard paths.

### 3.7 Advanced

| Variable | Default | Description |
|----------|---------|-------------|
| `PRESSURE_TRIP_GLOBAL` | `0` | Cross-service aggregate pressure trip (0 = disabled) |
| `SUBNET_TRIG` | `0` | Unique IPs from same subnet to trigger subnet ban (0 = disabled) |
| `SUBNET_MASK` | `24` | IPv4 subnet mask for distributed detection |
| `SUBNET_MASK_V6` | `48` | IPv6 subnet mask (must be multiple of 16) |
| `WATCH_INTERVAL` | `10` | Watch mode polling interval in seconds |
| `SCAN_MAX_LINES` | `50000` | Max lines per log during scan mode; 0 = unlimited |
| `SCAN_TIMEOUT` | `120` | Journal timeout per rule during scan in seconds |
| `OUTPUT_SYSLOG` | `1` | Log to syslog (0 = off, 1 = on) |
| `LOG_IDLE_SUPPRESS` | `1` | Suppress idle (0-event) run-complete messages from syslog (0 = off, 1 = on) |
| `LOG_FORMAT` | `classic` | Log format: `classic` (syslog-style) or `json` (JSONL) |
| `LOG_LEVEL` | `1` | Min severity: 0=debug, 1=info, 2=warn, 3=error |
| `APOOL_RETENTION_DAYS` | `365` | Max age in days for attack pool entries |
| `APOOL_MAX_LINES` | `500000` | Max lines in attack pool file |

Additional variables (`LOG_SOURCE`, `LOCK_FILE_TIMEOUT`, `BAN_RETRY_COUNT`, `OUTPUT_SYSLOG_FILE`) have sensible defaults in `internals.conf` and can be overridden by adding them to `conf.bfd`.

**JSON log format**: When `LOG_FORMAT="json"`, each log line is a JSON object with fields: `ts` (ISO 8601), `host`, `app`, `pid` (integer), `level` (debug/info/warn/error/critical), `tag` (service name, extracted from `{tag}` prefix if present), `msg`. Example:

```json
{"ts":"2026-02-27T14:30:00+0000","host":"srv1","app":"bfd","pid":1234,"level":"info","tag":"sshd","msg":"192.0.2.1 exceeded login failures"}
```

### 3.8 Country Weighting

Country weighting is active automatically when `pressure-country.conf` contains uncommented entries. No toggle is required — if the file has entries, they are applied; if all entries are commented out (the default), country weighting is off.

The country database maps IP addresses to 2-letter country codes. IPv4 ranges are stored in `ipcountry.dat` (integer-range format) and IPv6 ranges in `ipcountry6.dat` (hex-range format). Both are downloaded automatically at install time (background) and refreshed via `cron.daily` when data is older than 30 days. Manual updates can be run with `update-ipcountry.sh`, which downloads per-country CIDR zones from ipverse.net (ipdeny.com fallback) and converts them to BFD's lookup format. Both IPv4 and IPv6 addresses are resolved to country codes.

The multiplier file (`pressure-country.conf`) uses whitespace-delimited `CC N` format where N is weight×10 (e.g., `CN 20` means 2.0× weight, `US 10` means 1.0× = no change). Unlisted countries default to 1.0×. The legacy `CC=N` format is also accepted for backward compatibility.

### 3.9 SMTP Relay

By default, BFD sends alerts through the local MTA (`mail` or `sendmail`). For servers without a local MTA or for routing through an external mail service, BFD supports authenticated SMTP relay via `curl`.

| Variable | Default | Description |
|----------|---------|-------------|
| `SMTP_RELAY` | *(empty)* | SMTP relay server URL (empty = use local MTA) |
| `SMTP_FROM` | *(empty)* | Sender address (required when `SMTP_RELAY` is set) |
| `SMTP_USER` | *(empty)* | SMTP authentication username |
| `SMTP_PASS` | *(empty)* | SMTP authentication password |

**URL formats:**

| Format | Example | Description |
|--------|---------|-------------|
| `smtps://host:465` | `smtps://smtp.gmail.com:465` | Implicit TLS (Gmail, etc.) |
| `smtp://host:587` | `smtp://relay.example.com:587` | STARTTLS (most relay services) |
| `smtp://host:25` | `smtp://relay.internal:25` | Plain (internal relays) |

**Example — Gmail SMTP relay:**

```bash
SMTP_RELAY="smtps://smtp.gmail.com:465"
SMTP_FROM="alerts@example.com"
SMTP_USER="alerts@example.com"
SMTP_PASS="app-password-here"
```

`curl` is present on all target distributions and handles TLS/authentication natively. Credentials are stored in `conf.bfd` (permissions 640, root-owned). Use `bfd -c` to validate relay configuration.

### 3.10 Email Templates

Alert emails are rendered from customizable template partials in the `alert/` directory under the BFD install path (`/usr/local/bfd/alert/`). Templates use `{{VAR}}` mustache-style placeholders replaced at render time via a safe awk-based engine — no shell code execution, so templates cannot introduce security risks.

**Template files:**

| File | Description |
|------|-------------|
| `text.header.tpl` | Text: banner, hostname, timestamp |
| `text.entry.tpl` | Text: per-ban detail block |
| `text.summary.tpl` | Text: digest summary statistics |
| `text.footer.tpl` | Text: version, project link |
| `html.header.tpl` | HTML: banner and hostname bar |
| `html.entry.tpl` | HTML: per-ban card with pressure detail |
| `html.summary.tpl` | HTML: aggregate statistics table |
| `html.footer.tpl` | HTML: footer and closing tags |

The entry template is rendered once per ban. The summary template is included only when multiple bans are batched in one email. Header and footer wrap the entire message.

To customize, copy the desired partial(s) into `alert/custom.d/` and edit the copies. BFD checks `custom.d/` first for each partial and falls back to the shipped default. Templates in `custom.d/` persist across upgrades automatically.

**Key template variables:**

| Variable | Example | Description |
|----------|---------|-------------|
| `{{HOSTNAME}}` | `web01.example.com` | System hostname |
| `{{HOST}}` | `192.0.2.1` | Banned IP address |
| `{{SERVICE}}` | `sshd` | Service name |
| `{{PRESSURE}}` | `21.4` | Pressure score |
| `{{FAIL_COUNT_DISPLAY}}` | `7` | Failed login attempts detected this cycle |
| `{{BAN_TYPE}}` | `Temporary` | Ban type (Temporary/Permanent/Escalated) |
| `{{BAN_DURATION_DETAIL}}` | `10m` | Human-readable duration |
| `{{COUNTRY_FLAG}}` | `CN` | 2-letter country code |
| `{{COUNTRY_DISPLAY}}` | `China (CN)` | Country name with code (degrades to bare code) |
| `{{SOURCE_LOGS_SECTION_TEXT}}` | *(log lines)* | Sanitized source log excerpt |
| `{{REPUTATION_SECTION_TEXT}}` | `AbuseIPDB: https://...` | Text-format reputation links |

See the shipped template files for the complete variable reference.

Messaging channels (Slack, Telegram, Discord) have their own template partials:

| File | Description |
|------|-------------|
| `slack.message.tpl` | Slack Block Kit JSON wrapper |
| `slack.entry.tpl` | Slack per-ban section |
| `telegram.message.tpl` | Telegram MarkdownV2 wrapper |
| `telegram.entry.tpl` | Telegram per-ban block |
| `discord.message.tpl` | Discord embed JSON wrapper |
| `discord.entry.tpl` | Discord per-ban embed field |

Periodic reports (see [section 9](#9-periodic-reports)) use their own template partials:

| File | Description |
|------|-------------|
| `report.html.header.tpl` | HTML report header and styles |
| `report.html.body.tpl` | HTML report body and tables |
| `report.text.header.tpl` | Plain text report header |
| `report.text.body.tpl` | Plain text report body |
| `report.slack.message.tpl` | Slack report summary |
| `report.telegram.message.tpl` | Telegram report summary |
| `report.discord.message.tpl` | Discord report summary |

### 3.11 Slack Alerts

BFD can send alert notifications to Slack channels via incoming webhooks or the Bot API.

| Variable | Default | Description |
|----------|---------|-------------|
| `SLACK_ALERTS` | `0` | Enable Slack alerts (`1` = enabled) |
| `SLACK_MODE` | `webhook` | Delivery mode: `webhook` or `bot` |
| `SLACK_WEBHOOK_URL` | *(empty)* | Incoming webhook URL (webhook mode) |
| `SLACK_TOKEN` | *(empty)* | Bot API token, `xoxb-...` (bot mode) |
| `SLACK_CHANNEL` | *(empty)* | Channel ID or `#name` (bot mode) |

**Webhook mode** is simpler — create a webhook at [Slack Incoming Webhooks](https://api.slack.com/messaging/webhooks) and paste the URL. **Bot mode** supports file uploads and uses the [Slack Web API](https://api.slack.com/methods/chat.postMessage).

Requires `curl` in PATH. Test with `bfd --test-alert slack`.

### 3.12 Telegram Alerts

BFD can send alert notifications via the Telegram Bot API.

| Variable | Default | Description |
|----------|---------|-------------|
| `TELEGRAM_ALERTS` | `0` | Enable Telegram alerts (`1` = enabled) |
| `TELEGRAM_BOT_TOKEN` | *(empty)* | Bot token from [@BotFather](https://t.me/BotFather) |
| `TELEGRAM_CHAT_ID` | *(empty)* | Chat, group, or channel ID |

Use `@userinfobot` or the `getUpdates` API endpoint to find your chat ID. Messages are sent using MarkdownV2 formatting.

Requires `curl` in PATH. Test with `bfd --test-alert telegram`.

### 3.13 Discord Alerts

BFD can send alert notifications to Discord channels via webhooks.

| Variable | Default | Description |
|----------|---------|-------------|
| `DISCORD_ALERTS` | `0` | Enable Discord alerts (`1` = enabled) |
| `DISCORD_WEBHOOK_URL` | *(empty)* | Webhook URL from Server Settings > Integrations |

Alerts are rendered as Discord embeds with per-ban fields and a summary footer.

Requires `curl` in PATH. Test with `bfd --test-alert discord`.

---

## 4. Usage

The `/usr/local/sbin/bfd` command provides the following options:

```
usage: bfd [OPTION]

Run Modes:
  -s, --standard              run detection cycle with output
  -q, --quiet                 run detection cycle silently
  -d, --dryrun                run detection without banning
  -w, --watch                 run continuous watch mode (foreground)

Ban Management:
  -b, --ban IP [SERVICE]      manually ban an IP (permanent)
  -u, --unban IP              unban an IP address
  --flush-temp                remove all temporary bans
  --flush-all                 remove all bans

Reporting:                                      Supports: --json --csv
  -l, --list                  list active bans
  -a, --activity [IP|STR]     threat activity and IP investigation
  -e, --events [IP|CIDR] [N]  event history, IP or subnet detail (N=log lines)

System:
  -S, --status [SERVICE]      operational status overview
  -C, --config [VAR]          show active configuration
  -R, --rules [RULE]          list rules or show rule detail (--active)
  -c, --check                 health check diagnostics

Testing:
  -T, --test RULE [FILE|-]    test rule patterns against log or stdin
  --test-pattern PAT [FILE|-] test raw <HOST> pattern against log or stdin
  --test-alert TYPE           send test alert (email,slack,telegram,discord)

Scan Mode:
  --scan [RULE] [-d]          full-log scan (all rules or specific rule)
  --max-lines=N               max lines per log during scan (default 50000)
  --scan-timeout=N            journal timeout per rule during scan (default 120)

Output Modifiers:
  --json                      JSON output (with -l, -e, -a)
  --csv                       CSV output (with -l, -e, -a)
  --sort=MODE                 sort events: count (default), time, ip
  --limit=N                   max IPs to display (default 100, 0=all)
  --24h                       events from last 24 hours (default)
  --7d                        events from last 7 days
  --30d                       events from last 30 days
  --active                    show only active rules (with -R)
  -V, --verbose               detailed output (with -s, -d, -c, -S, --scan)

General:
  -v, --version               display version
  -h, --help                  display this help (see bfd.1 for full docs)
```

The **`-s|--standard`** and **`-q|--quiet`** options run the full detection and banning cycle. Standard mode prints output; quiet mode suppresses it (used by cron). Both parse logs, compute pressure against trip points, and execute bans.

### 4.1 Dry Run

The **`-d|--dryrun`** option runs full detection but logs "would ban" instead of executing the ban command. Use this to test rules safely, validate your configuration, and see what BFD would do without affecting production.

```bash
bfd -d
```

### 4.2 Health Check

The **`-c|--check`** option performs a non-destructive diagnostic check of your entire BFD installation:

- Validates configuration (required variables, sane values)
- Checks log file paths exist and are readable
- Verifies ban command binary exists and is executable
- Warns if `UNBAN_COMMAND` is empty when `BAN_TTL > 0`
- Checks `BAN_COMMAND_V6` binary if configured
- Scans all rules: reports active vs inactive, pressure weight/trip, ports, log paths
- Displays pressure model summary (half-life, trip, global trip)
- Verifies tlog (log tracking script) is executable
- Checks state directories exist with correct permissions
- Reports lock file status
- Counts active bans

```bash
bfd -c
```

Output uses `[PASS]`, `[WARN]`, `[FAIL]`, and `[SKIP]` (inactive rules) indicators with a final summary.

### 4.3 Threat Activity

The **`-a|--activity`** option displays a threat activity report with aggregate summary, top threat IPs, and per-service breakdown:

```bash
bfd -a           # show threat activity report
bfd --activity   # same as above
bfd -a 192.0.2   # search for a specific string
```

The report includes:
- **Threat Activity Summary** — unique IPs and total count for 24h and 7d windows, plus active bans
- **Top 25 threat IPs (24h)** — event count, IP, pressure, country, first/last seen, services, ban status (active bans show `BANNED(perm)` or `BANNED(Xm)`, previous bans show `prev:N`)
- **Top 25 threat IPs (7d)** — same format, 7-day window
- **Per-service threat breakdown (24h / 7d)** — dual-interval count, unique IPs, and top country per service

> **`-a` vs `-e`:** Both commands read from the same attack pool data store. `-a` provides a summary-oriented threat activity overview with dual-interval (24h/7d) views and per-service breakdown. `-e` provides event-level detail with configurable time windows (`--24h`, `--7d`, `--30d`) and sort modes (`--sort=count|time|ip`). Use `-a` to review aggregate threat patterns and `-e` to drill into specific IPs or subnets.

### 4.4 Watch Mode

The **`-w|--watch`** option runs BFD as a continuous daemon, polling for new log data every `WATCH_INTERVAL` seconds (default 10). This is the **recommended operating mode** — detection latency is ~10 seconds, comparable to fail2ban and other daemon-based tools.

```bash
bfd --watch
```

Watch mode holds a lock for its entire lifetime, so cron-based runs (`bfd -q`) will silently skip when watch mode is active. If the watch daemon exits unexpectedly (OOM, crash), cron automatically detects the dead PID and resumes detection within one cycle (~2 minutes). No cron modification is needed.

**Signal handling:**

| Signal | Action |
|--------|--------|
| `SIGTERM` / `SIGINT` | Clean shutdown (removes lock file) |
| `SIGHUP` | Reload `conf.bfd`, `internals.conf`, and `pressure.conf` without restart (allows changing `WATCH_INTERVAL`, `PRESSURE_TRIP`, ban commands, etc.) |

**Service management:**

```bash
# systemd (Rocky 8+, Debian 12, Ubuntu 20+)
systemctl enable --now bfd-watch.service
systemctl reload bfd-watch     # send SIGHUP
systemctl status bfd-watch
```

This conflicts with `bfd.timer` — systemd prevents enabling both simultaneously.

```bash
# SysVinit (CentOS 6/7, Ubuntu 14.04)
service bfd-watch start
service bfd-watch reload        # send SIGHUP
service bfd-watch status
chkconfig bfd-watch on          # enable at boot (RHEL)
```

**Configuration:**

| Variable | Default | Description |
|----------|---------|-------------|
| `WATCH_INTERVAL` | `10` | Polling interval in seconds for watch mode |

### 4.5 Flush Bans

Remove multiple bans at once:

```bash
bfd --flush-temp    # remove all temporary bans (keep permanent)
bfd --flush-all     # remove all bans (temporary + permanent)
```

Flushed bans are recorded in the ban history.

### 4.6 Structured Output

Use `--json` or `--csv` with `-l`, `-e`, or `-a` for machine-readable output:

```bash
bfd -l --json          # active bans as JSON
bfd -l --csv           # active bans as CSV
bfd -e --json          # active events as JSON
bfd -e 192.0.2.1 --csv # per-IP events as CSV
bfd -a --json          # threat activity as JSON
bfd -a 192.0.2.1 --csv # IP report as CSV
```

**JSON** outputs arrays of objects (or nested objects for IP detail and CIDR):
```json
[{"ip": "...", "pressure": 18.4, "pressure_trip": 20, "events": 5, "services": ["sshd"], ...}]
```

**CSV** outputs with a header row:
```
ip,pressure,pressure_trip,events,services,first_seen,last_seen,status
```

Timestamps in structured output use ISO 8601 format (`YYYY-MM-DDTHH:MM:SS`).
Pressure values are unquoted numbers in JSON.

### 4.7 Scan Mode

Scan mode processes the **full current log file** through the detection pipeline, bypassing the incremental tlog reader. This is useful for:

- **First install:** Catch existing attackers immediately instead of waiting for new log events.
- **Rule changes:** Retroactively apply new rules to existing log data.
- **Recovery:** Process missed events after a detection gap (daemon down, cron disabled).
- **Forensic review:** Combine with `-d` (dry-run) to see what would be detected without banning.

```bash
bfd --scan              # scan all active rules against full logs
bfd --scan sshd         # scan a specific rule only
bfd --scan -d           # dry-run: detect without banning or advancing cursors
bfd --scan --max-lines=100000   # override line limit
bfd --scan --scan-timeout=60    # override journal timeout
```

After a non-dry-run scan, tlog cursors are advanced to the current log position so the next normal run starts fresh. In dry-run mode, cursors are not modified.

**Safety limits:** `SCAN_MAX_LINES` (default 50000) bounds the number of lines processed per log file. `SCAN_TIMEOUT` (default 120s) limits journal reads. Set `--max-lines=0` for unlimited (use with caution on large logs). Both can be configured in `conf.bfd` or overridden on the command line.

**Lock behavior:** Scan acquires the same global lock as normal runs. If watch mode is running, stop it first (`systemctl stop bfd-watch`), run the scan, then restart.

### 4.8 Events and Investigation

The `--events` command provides event history and IP investigation, reading from the attack pool which records all detected auth failures (both ban-triggering and sub-trip observations) with configurable retention (default: 365 days):

```bash
bfd --events                  # event list — top 100 IPs, last 24h
bfd --events --7d --sort=time # last 7 days, newest first
bfd --events --limit=0 --30d  # all IPs from last 30 days
bfd --events 192.0.2.1        # IP investigation — history + pressure + logs
bfd --events 192.0.2.0/24     # CIDR report — subnet-scoped view
```

**Event list** (no argument) shows IPs with failure counts, services, country, first/last seen, and ban status. Default: top 100 IPs sorted by count descending, 24-hour window. Use `--limit=N` to change the output cap (`0` for unlimited), `--sort=time` or `--sort=ip` to change ordering, and `--7d` or `--30d` to expand the time window.

**IP investigation** shows a comprehensive report: historical failure counts from the attack pool (total and per-service breakdown), live pressure detail if the IP has active pressure, and a log sample from the triggering service.

**CIDR mode** filters to a subnet (IPv4, mask 8-32) and includes a summary line with match count, total events, and banned count.

All three modes support `--json` and `--csv`:

```bash
bfd --events --json           # event list as JSON array
bfd --events 192.0.2.1 --json # IP detail as single JSON object
bfd --events 10.0.0.0/8 --csv # CIDR as CSV
```

### 4.9 Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Configuration error (invalid config, unknown option) |
| 2 | Lock error (another instance running) |
| 3 | Prerequisite error (missing tlog, rules directory) |

*See `man bfd`(1) §EXIT CODES for the authoritative reference.*

---

## 5. Firewall

BFD supports automatic firewall detection via `FIREWALL="auto"` (default). When set to auto, BFD probes for installed firewalls in priority order: APF > CSF > firewalld > UFW > nftables > iptables > ip route.

| `FIREWALL` Value | Description |
|------------------|-------------|
| `auto` | Auto-detect (default) |
| `apf` | Advanced Policy Firewall |
| `csf` | ConfigServer Security & Firewall |
| `firewalld` | firewalld rich rules |
| `ufw` | Uncomplicated Firewall |
| `nftables` | nftables sets (inet bfd table) |
| `iptables` | iptables/ip6tables chains |
| `route` | ip route blackhole |
| `custom` | User-defined BAN_COMMAND/UNBAN_COMMAND |

When `FIREWALL="auto"` or a named backend is configured, BFD handles ban/unban natively — `BAN_COMMAND` and `UNBAN_COMMAND` are only used with `FIREWALL="custom"`.

The following examples are for `FIREWALL="custom"` mode. The variable `$ATTACK_HOST` is replaced with the offending IP address at ban time. For temporary bans, also set `UNBAN_COMMAND` to the reverse operation.

**APF:**
```bash
BAN_COMMAND="/etc/apf/apf -d $ATTACK_HOST {bfd.$MOD}"
UNBAN_COMMAND="/etc/apf/apf -u $ATTACK_HOST"
```

**iptables (CentOS 6/7, Ubuntu 14-20):**
```bash
BAN_COMMAND="/sbin/iptables -I INPUT -s $ATTACK_HOST -j DROP"
UNBAN_COMMAND="/sbin/iptables -D INPUT -s $ATTACK_HOST -j DROP"
```

**firewalld (Rocky 8+, CentOS 7):**
```bash
BAN_COMMAND="/usr/bin/firewall-cmd --add-rich-rule='rule family=ipv4 source address=$ATTACK_HOST drop'"
UNBAN_COMMAND="/usr/bin/firewall-cmd --remove-rich-rule='rule family=ipv4 source address=$ATTACK_HOST drop'"
```

**nftables (Rocky 9+, Debian 12, Ubuntu 22+):**
```bash
BAN_COMMAND="/usr/sbin/nft add rule inet filter input ip saddr $ATTACK_HOST drop"
UNBAN_COMMAND="/usr/sbin/nft delete rule inet filter input handle $(/usr/sbin/nft -a list chain inet filter input | grep $ATTACK_HOST | awk '{print $NF}')"
```

**ip route null-route (all distros):**
```bash
BAN_COMMAND="/sbin/ip route add blackhole $ATTACK_HOST/32"
UNBAN_COMMAND="/sbin/ip route del blackhole $ATTACK_HOST/32"
```

**Port-specific blocking (uses `$PORTS` from rule files):**
```bash
BAN_COMMAND="/sbin/iptables -I INPUT -s $ATTACK_HOST -p tcp -m multiport --dports $PORTS -j DROP"
UNBAN_COMMAND="/sbin/iptables -D INPUT -s $ATTACK_HOST -p tcp -m multiport --dports $PORTS -j DROP"
```

**IPv6 firewall commands** — set `BAN_COMMAND_V6` if your firewall needs separate commands for IPv6 (leave empty for tools that handle both):
```bash
BAN_COMMAND_V6="/sbin/ip6tables -I INPUT -s $ATTACK_HOST -j DROP"
UNBAN_COMMAND_V6="/sbin/ip6tables -D INPUT -s $ATTACK_HOST -j DROP"
```

---

## 6. Rule Engine

Rules are located under `/usr/local/bfd/rules/`. Each rule is a shell fragment that declares the service name, required binary, log path, and a regex pattern for matching authentication failures.

Each rule auto-enables based on the existence of a specific application binary (`PREREQ`). For example, if `/usr/sbin/sshd` exists, the sshd rule is active. No manual activation is needed — install the application and BFD will detect it.

Use `bfd -c` to see which rules are active on your system.

### 6.1 Rule Catalog

BFD ships with 57 rules:

| Category | Rules |
|----------|-------|
| **SSH** | sshd, dropbear |
| **Mail** | dovecot, courier, postfix, postscreen, sendmail, exim_authfail, exim_nxuser, vpopmail, cyrus-imap, sogo |
| **FTP** | vsftpd, vsftpd2, proftpd, pure-ftpd |
| **Web** | apache-auth, nginx-http-auth, mod_sec, wordpress, roundcube, http_401, lighttpd, phpmyadmin, gitea, nextcloud, vaultwarden, drupal, jellyfin |
| **Panel** | cpanel, plesk, webmin, directadmin, interworx, cockpit, gitlab, grafana, proxmox, guacamole |
| **Auth** | pam_generic, xrdp |
| **Database** | mysqld-auth, postgresql, mongodb |
| **DNS** | named, powerdns |
| **VPN** | openvpnas, openvpn |
| **VoIP** | asterisk_badauth, asterisk_iax, asterisk_nopeer, freeswitch |
| **Proxy** | haproxy, squid |
| **Messaging** | ejabberd |
| **Legacy** | rh_imapd, rh_ipop3d |

### 6.2 Rule Customization

Each rule file supports the following variables:

| Variable | Description |
|----------|-------------|
| `PREREQ` | Path to required binary or file. Rule is active only if this file exists |
| `LOG_FILE` | Log file path to monitor (uses config variables like `$AUTH_LOG_PATH`) |
| `MATCHED_HOSTS` | Extracted IP list — tlog + extract_hosts pipeline using `<HOST>` patterns |
| `PRESSURE_WEIGHT` | Per-service pressure weight (overrides `pressure.conf`; higher = faster accumulation) |
| `PRESSURE_TRIP` | Per-service trip point (overrides `pressure.conf` and global `PRESSURE_TRIP`) |
| `PORTS` | Service ports for port-specific blocking (e.g., `"22"` for sshd) |
| `SKIP_ALERT` | Set to `"1"` to suppress email alerts for this service |
| `RULE_EMAIL` | Override `EMAIL_ADDRESS` for this rule's alerts (per-rule routing) |
| `LOG_TAG` | Tracking tag for tlog state file naming and journal filter dispatch (e.g., `"sshd"`, `"dovecot"`) |
| `IGNOREREGEX` | Lines matching this ERE pattern are excluded before IP extraction (fail2ban-compatible) |

To customize a rule's pressure weight and trip point:
```bash
# In /usr/local/bfd/rules/sshd — make SSH failures count triple
PRESSURE_WEIGHT="3"
PRESSURE_TRIP="15"
```

Centralized per-rule overrides (without editing rule files) go in `/usr/local/bfd/pressure.conf` (whitespace-delimited `key=value` format; see [Pressure Model](#31-pressure-model-detection) for syntax).

---

## 7. Ignore Lists

BFD provides two mechanisms for excluding addresses from bans:

- **`/usr/local/bfd/ignore.hosts`** — IPs to never ban, one per line. Supports IPv4 and IPv6 addresses.
- **`/usr/local/bfd/exclude.files`** — additional files containing IPs to ignore. One file path per line; each referenced file contains IPs to exclude.

BFD automatically detects local IPv4 and IPv6 addresses (including `::1`) and excludes them from bans. No manual configuration is needed for local address exclusion.

---

## 8. CDN / Trusted Proxy

When BFD monitors services behind a CDN or reverse proxy (e.g., Cloudflare, AWS CloudFront), the log may contain the proxy's IP instead of the real client. Without awareness of CDN IP ranges, BFD bans CDN infrastructure — blocking all proxied traffic.

The CDN subsystem fetches provider IP ranges automatically and applies per-provider treatment during detection.

### 8.1 Configuration

Enable in `conf.bfd`:
```bash
CDN_ENABLE="1"           # enable CDN IP awareness
CDN_UPDATE_DAYS="7"      # refresh interval (days); 0 = manual only
```

### 8.2 Provider Configuration

Edit `cdn-providers.conf` to enable providers. Whitespace-delimited format:

```
# NAME          TREATMENT  MULT  FORMAT  URL_V4                                                    URL_V6
cloudflare      ignore     10    text    https://www.cloudflare.com/ips-v4/                        https://www.cloudflare.com/ips-v6/
aws-cloudfront  derate      3    json    https://d7uri8nf7uskq.cloudfront.net/tools/list-cloudfront-ips  -
fastly          exclude    10    json    https://api.fastly.com/public-ip-list                     -
```

Fields:
- **NAME**: Provider identifier (alphanumeric + hyphens)
- **TREATMENT**: `ignore` (fully invisible), `exclude` (visible but never banned), `derate` (reduced pressure)
- **MULT**: Pressure multiplier (10=1.0x, 5=0.5x, 3=0.3x) — only applies to `derate`
- **FORMAT**: `text` (one CIDR per line) or `json` (CIDRs extracted automatically)
- **URL_V4/URL_V6**: Provider IP range URLs (`-` for none)

### 8.3 Treatment Modes

| Mode | Detection | Events | Pressure | Ban |
|------|-----------|--------|----------|-----|
| `ignore` | Skipped | None | None | No |
| `exclude` | Processed | Recorded (`cdn-exclude`) | Accumulated | No |
| `derate` | Processed | Recorded | Reduced by MULT | Yes (if threshold met) |

### 8.4 CLI Commands

```bash
bfd --cdn                    # list all providers with status
bfd --cdn cloudflare         # show CIDRs for a provider
bfd --cdn update             # force refresh all provider ranges
bfd --cdn check 172.70.34.1  # check if an IP matches a CDN range
bfd --cdn --json             # JSON output
```

### 8.5 Automatic Updates

`cron.daily` checks the CDN database age against `CDN_UPDATE_DAYS` and refreshes when stale. Manual refresh: `bfd --cdn update` or run `update-cdn-providers.sh` directly.

### 8.6 Adding Custom Providers

Add a line to `cdn-providers.conf` with any provider that publishes IP ranges as plain-text CIDRs or JSON:

```
my-proxy  derate  5  text  https://example.com/ip-ranges.txt  -
```

---

## 9. Periodic Reports

BFD can generate scheduled threat reports delivered via all configured alerting channels (email, Slack, Telegram, Discord):

```bash
bfd --report              # daily report (default)
bfd --report weekly       # last 7 days
bfd --report monthly      # last 30 days
```

Reports include:
- **Threat summary:** unique IPs, total events, bans, active bans
- **Top threat IPs** with country codes, live pressure, and ban status
- **Per-service breakdown** with event counts and top country
- **Trend comparison** vs the prior equivalent time window

**Scheduled delivery** is configured in `conf.bfd`:

| Variable | Default | Description |
|----------|---------|-------------|
| `REPORT_ENABLED` | `0` | Enable periodic reports (0 = off, 1 = on) |
| `REPORT_INTERVALS` | `"daily"` | Comma-separated intervals: `daily`, `weekly`, `monthly` |
| `REPORT_CHANNELS` | *(empty)* | Delivery channels (empty = all enabled alert channels) |
| `REPORT_EMAIL_ADDRESS` | *(empty)* | Report email recipient (empty = `EMAIL_ADDRESS`) |
| `REPORT_EMAIL_SUBJECT` | *(template)* | Email subject (`{{INTERVAL}}` and `{{HOSTNAME}}` expand at send time) |
| `REPORT_TOP_N` | `25` | Maximum IPs in report tables |

When `REPORT_ENABLED=1`, `cron.daily` triggers daily reports every day, weekly reports on Mondays, and monthly reports on the 1st. Reports can also be generated on-demand from the CLI at any time.

---

## 10. Ban Management

Bans can be temporary (auto-expire after `BAN_TTL` seconds) or permanent (`BAN_TTL=0`). Temporary bans require `UNBAN_COMMAND` to be set for the firewall rule to be removed automatically on expiry.

Repeat offenders are escalated to permanent bans after `BAN_ESCALATE_AFTER` temporary bans within `BAN_ESCALATE_WINDOW` seconds.

**CLI commands:**
```bash
bfd -l                   # list all active bans (service, ports, expiry)
bfd -u 192.0.2.1          # unban an IP address
bfd -b 192.0.2.1          # manually ban an IP permanently
bfd -b 192.0.2.1 sshd     # manually ban with a service label
```

**State files** in `/usr/local/bfd/tmp/`:

| File | Description |
|------|-------------|
| `bans.active` | Currently active bans (timestamp, expiry, IP, service, ports) |
| `bans.history` | Append-only log of all ban/unban events |
| `pressure.dat` | Pressure scoring workspace (timestamp, IP, service, weight); pruned every ~10 half-lives |

**State files** in `/usr/local/bfd/stats/`:

| File | Description |
|------|-------------|
| `attack.pool` | Unified event store — all detected auth failures (ban, escalate, observed) and outcomes |

Both `bfd -a` (threat activity) and `bfd -e` (events) read from the attack pool. Sub-trip observations (ACTION=observed) are recorded alongside ban decisions so event history persists across pressure decay cycles. Each IP shows whether it is currently banned, its ban type (permanent or time remaining), and historical ban count.

---

## 11. IPv6

BFD detects and bans both IPv4 and IPv6 addresses automatically. Rules do not need modification — the extraction engine handles both address families. IPv6 addresses are normalized before counting and comparison.

For firewalls that handle both protocols natively (nft with `inet` family, APF, ip route), leave `BAN_COMMAND_V6` empty — `BAN_COMMAND` is used for all addresses.

For firewalls that require separate commands (iptables/ip6tables), set `BAN_COMMAND_V6` and `UNBAN_COMMAND_V6`:

```bash
BAN_COMMAND_V6="/sbin/ip6tables -I INPUT -s $ATTACK_HOST -j DROP"
UNBAN_COMMAND_V6="/sbin/ip6tables -D INPUT -s $ATTACK_HOST -j DROP"
```

Local IPv6 addresses (including `::1` and all link-local addresses) are auto-detected and excluded from bans.

---

## Integration

BFD integrates with existing infrastructure through standard interfaces.

**Firewall backends** — auto-detected or user-selected from 8 backends (APF, CSF, firewalld, UFW, nftables, iptables, route, custom). See [Firewall](#5-firewall).

**Log systems** — reads from syslog files or systemd journal via tlog. Rotation-aware: detects logrotate and grabs tails from both current and rotated files.

**Alert channels** — email (local MTA or SMTP relay), Slack (webhook or Bot API), Telegram (Bot API), Discord (webhooks). All channels support batched digest delivery and customizable templates.

**Structured output** — `--json` and `--csv` modifiers on `-l`, `-e`, and `-a` for SIEM, log aggregator, or automation pipeline consumption.

**CDN awareness** — per-provider IP range databases with configurable treatment (ignore, exclude, derate) prevent banning CDN infrastructure. See [CDN / Trusted Proxy](#8-cdn--trusted-proxy).

**Scheduling** — watch mode (systemd/SysVinit daemon, ~10s latency) or cron (2-minute fallback). Both coexist safely via lock coordination.

---

## Troubleshooting

Run `bfd -c` first — it validates config, log paths, firewall binaries, rule status, state directories, and active bans in a single non-destructive check.

| Symptom | Cause & Fix |
|---------|-------------|
| "locked subsystem, already running?" | A previous BFD run is still active or was killed. The lock auto-clears after 300 seconds |
| "BAN_COMMAND binary not found" | The configured firewall tool is not installed. Update `BAN_COMMAND` in `conf.bfd` |
| Rules not triggering | Check that the log path exists and the application is writing to the expected file. Use `bfd -d` to test detection without banning. Use `bfd -c` to see which rules are active |
| Wrong log paths on Debian/Ubuntu | Log paths are auto-detected but can be overridden in `conf.bfd`: `AUTH_LOG_PATH`, `MAIL_LOG_PATH`, `KERNEL_LOG_PATH` |
| "UNBAN_COMMAND is empty" | Set `UNBAN_COMMAND` in `conf.bfd` for temporary bans to auto-remove firewall rules on expiry |
| IPv6 addresses not detected | IPv6 support is automatic. If using ip6tables, set `BAN_COMMAND_V6` in `conf.bfd` |

---

## License

BFD is developed and supported on a volunteer basis by Ryan MacDonald [ryan@rfxn.com].

BFD (Brute Force Detection) is distributed under the GNU General Public License (GPL) without restrictions on usage or redistribution. The BFD copyright statement, and GNU GPL, "COPYING.GPL" are included in the top-level directory of the distribution. Credit must be given for derivative works as required under GNU GPL.

---

## Support

The BFD source repository is at: https://github.com/rfxn/brute-force-detection

Bugs, feature requests, and general questions can be filed as GitHub issues or sent to proj@rfxn.com. When reporting issues, include the output of `bfd -c` to help diagnose configuration problems.

The official project page is at: https://www.rfxn.com/projects/brute-force-detection/
