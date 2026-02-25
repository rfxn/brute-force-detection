# Brute Force Detection (BFD)

[![Version](https://img.shields.io/badge/version-2.0.1-blue.svg)](CHANGELOG)
[![License: GPL v2](https://img.shields.io/badge/license-GPL_v2-green.svg)](COPYING.GPL)

**Log-based brute force attack detection and IP banning for Linux servers** — pressure-based
scoring that lets humans make mistakes while stopping bots cold, automatic ban lifecycle,
and IPv4/IPv6 support across 42 service rules.

> (C) 1999-2026, R-fx Networks &lt;proj@rfxn.com&gt;<br>
> (C) 2026, Ryan MacDonald &lt;ryan@rfxn.com&gt;<br>
> Licensed under [GNU GPL v2](COPYING.GPL)

---

## Contents

- [1. Introduction](#1-introduction)
  - [1.1 Supported Systems](#11-supported-systems)
- [2. Installation](#2-installation)
  - [2.1 Scheduling](#21-scheduling)
- [3. Configuration](#3-configuration)
  - [3.1 Pressure Model (Detection)](#31-pressure-model-detection)
  - [3.2 Email Alerts](#32-email-alerts)
  - [3.3 Banning](#33-banning)
  - [3.4 Repeat Offender Handling](#34-repeat-offender-handling)
  - [3.5 IPv6](#35-ipv6)
  - [3.6 Log Paths](#36-log-paths)
  - [3.7 Advanced](#37-advanced)
  - [3.8 Country Weighting](#38-country-weighting)
- [4. Firewall Integration](#4-firewall-integration)
- [5. General Usage](#5-general-usage)
  - [5.1 Dry Run](#51-dry-run)
  - [5.2 Health Check](#52-health-check)
  - [5.3 Attack Pool](#53-attack-pool)
  - [5.4 Watch Mode](#54-watch-mode)
  - [5.5 Flush Bans](#55-flush-bans)
  - [5.6 Structured Output](#56-structured-output)
- [6. Rule Engine](#6-rule-engine)
  - [6.1 Rule Catalog](#61-rule-catalog)
  - [6.2 Rule Customization](#62-rule-customization)
- [7. Ignore Lists](#7-ignore-lists)
- [8. Ban Management](#8-ban-management)
- [9. IPv6 Support](#9-ipv6-support)
- [10. Troubleshooting](#10-troubleshooting)
- [11. License](#11-license)
- [12. Support](#12-support)

---

## Quick Start

```bash
# Install (as root)
./install.sh

# Configure — set your firewall ban command
vi /usr/local/bfd/conf.bfd

# Enable watch mode (recommended — ~10s detection latency)
systemctl enable --now bfd-watch.service    # systemd
service bfd-watch start                     # SysVinit

# Health check — validate config, log paths, and rules
bfd -c

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

Brute Force Detection (BFD) is a modular shell script for parsing application logs and detecting authentication failures. It ships with 42 service rules covering SSH, mail, FTP, web, database, control panel, DNS, VPN, and VoIP services. Each rule declares fail2ban-compatible `<HOST>` regex patterns; the engine handles log reading, IP extraction, IPv6 normalization, and validation.

Unlike traditional count-based tools that ban at a fixed failure count — forcing operators to choose between catching attackers fast or tolerating legitimate mistakes — BFD uses **exponential-decay pressure scoring**. Each failure adds pressure weighted by service severity, and pressure decays over time via a configurable half-life. A user who mistypes a password a few times over several minutes generates pressure that naturally fades, staying well below the trip point. A bot hammering the same service generates pressure faster than it can decay and trips the threshold almost immediately. The result is fewer false positives on real users with faster response to actual attacks.

BFD uses a log tracking system so logs are only parsed from the point at which they were last read. This greatly assists in performance as we are not constantly reading the same log data. The log tracking system is compatible with syslog/logrotate style log rotations — it detects when rotations have occurred and grabs log tails from both the new log file and the rotated log file.

**Detection**
- 42 service rules with fail2ban-compatible `<HOST>` regex patterns
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
- Attack pool reporting with per-service breakdown and ban status (`bfd -a`)
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
- Install a 2-minute cronjob in `/etc/cron.d/bfd`
- On systemd systems, install `bfd.service` and `bfd.timer` (not enabled by default)
- If upgrading, run `importconf` to import settings from the previous installation

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

| Variable | Default | Description |
|----------|---------|-------------|
| `PRESSURE_TRIP` | `20` | Accumulated pressure needed to trigger a ban; per-rule overrides in rule files or `pressure.conf` |
| `PRESSURE_HALF_LIFE` | `300` | Half-life in seconds (how fast pressure decays); shorter = more forgiving |
Per-rule weights are configured in `pressure.conf` (centralized) or in individual rule files via `PRESSURE_WEIGHT`. Higher weight = faster pressure accumulation. Default tiers: 5 (control panels), 3 (SSH/VPN/critical), 2 (mail/FTP/web), 1 (noisy/generic).

### 3.2 Email Alerts

| Variable | Default | Description |
|----------|---------|-------------|
| `EMAIL_ALERTS` | `0` | Send email alerts (0 = off, 1 = on) |
| `EMAIL_ADDRESS` | `root` | Alert recipient(s), comma-separated |
| `EMAIL_SUBJECT` | `Brute Force Warning for $HOSTNAME` | Subject line (auto-appends `(N bans)` when batched) |
| `EMAIL_LOGLINES` | `50` | Number of log lines per host in alert body |

Alerts are **batched**: multiple bans in one check cycle produce a single email per recipient instead of one email per ban. Each alert includes host, service, failure count with threshold, ban type (temporary/permanent/escalated) with duration and expiry, recidivism history, the ban command, and source log lines.

The email template (`alert.bfd`) is fully customizable. Individual rules can suppress alerts by setting `SKIP_ALERT="1"` in the rule file. Set `RULE_EMAIL="addr"` in a rule file to route that rule's alerts to a different recipient.

### 3.3 Banning

| Variable | Default | Description |
|----------|---------|-------------|
| `FIREWALL` | `auto` | Firewall backend; see [section 4](#4-firewall-integration) |
| `BAN_TTL` | `600` | Ban duration in seconds (0 = permanent). Temporary bans auto-expire |
| `BAN_COMMAND` | APF deny | Command when `FIREWALL="custom"`. See [section 4](#4-firewall-integration) |
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

Leave empty when using tools that handle both protocols natively (nft with `inet` family, APF, ip route). Set explicitly for tools that require separate IPv4/IPv6 commands (iptables/ip6tables). See [section 9](#9-ipv6-support).

### 3.6 Log Paths

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTH_LOG_PATH` | `/var/log/secure` | Auth log (auto-detected: `/var/log/auth.log` on Debian) |
| `KERNEL_LOG_PATH` | `/var/log/messages` | Kernel/syslog (auto-detected: `/var/log/syslog` on Debian) |
| `MAIL_LOG_PATH` | `/var/log/maillog` | Mail log (auto-detected: `/var/log/mail.log` on Debian) |
| `BFD_LOG_PATH` | `/var/log/bfd_log` | BFD's own application log |

Log paths are auto-detected based on the distribution. Override in `conf.bfd` if your system uses non-standard paths.

### 3.7 Advanced

| Variable | Default | Description |
|----------|---------|-------------|
| `PRESSURE_TRIP_GLOBAL` | `0` | Cross-service aggregate pressure trip (0 = disabled) |
| `SUBNET_TRIG` | `0` | Unique IPs from same subnet to trigger subnet ban (0 = disabled) |
| `SUBNET_MASK` | `24` | IPv4 subnet mask for distributed detection |
| `SUBNET_MASK_V6` | `48` | IPv6 subnet mask (must be multiple of 16) |
| `WATCH_INTERVAL` | `10` | Watch mode polling interval in seconds |
| `OUTPUT_SYSLOG` | `1` | Log to syslog (0 = off, 1 = on) |

Additional variables (`LOG_SOURCE`, `LOCK_FILE_TIMEOUT`, `BAN_RETRY_COUNT`, `OUTPUT_SYSLOG_FILE`) have sensible defaults in `internals.conf` and can be overridden by adding them to `conf.bfd`.

### 3.8 Country Weighting

Country weighting is active automatically when `pressure-country.conf` contains uncommented entries. No toggle is required — if the file has entries, they are applied; if all entries are commented out (the default), country weighting is off.

The country database (`ipcountry.dat`) maps IPv4 addresses to 2-letter country codes. Update it periodically with `update-ipcountry.sh` (or the pre-built file ships with BFD).

The multiplier file (`pressure-country.conf`) uses `CC=N` format where N is weight×10 (e.g., `CN=20` means 2.0× weight, `US=10` means 1.0× = no change). Unlisted countries default to 1.0×.

---

## 4. Firewall Integration

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

## 5. General Usage

The `/usr/local/sbin/bfd` command provides the following options:

```
usage: bfd [OPTION]
-s|--standard .............. run standard with output
-q|--quiet ................. run quiet with output hidden
-d|--dryrun ................ run detection without banning
-w|--watch ................. run in continuous watch mode (foreground)
-a|--attackpool [IP|STR] ... attack pool; valid IP shows full report
-c|--check ................. health check and diagnostics
-l|--list .................. list active bans
-u|--unban IP .............. unban an IP address
-b|--ban IP [SERVICE] ...... manually ban an IP (permanent)
-S|--status [SERVICE] ...... system or per-service status
-C|--config [VAR] .......... show config values
-R|--rules [RULE] .......... list rules (weight/trip) or show rule details
-T|--test RULE [FILE|-] .... test rule patterns against log or stdin
   --test-pattern PAT [FILE|-] test a raw <HOST> pattern against log or stdin
   --flush-temp ............ unban all temporary bans
   --flush-all ............. unban all bans
   --json .................. output in JSON format (with -l)
   --csv ................... output in CSV format (with -l)
-V|--verbose ............... show detailed output
-v|--version ............... display version
-h|--help .................. display this help
```

The **`-s|--standard`** and **`-q|--quiet`** options run the full detection and banning cycle. Standard mode prints output; quiet mode suppresses it (used by cron). Both parse logs, compute pressure against trip points, and execute bans.

### 5.1 Dry Run

The **`-d|--dryrun`** option runs full detection but logs "would ban" instead of executing the ban command. Use this to test rules safely, validate your configuration, and see what BFD would do without affecting production.

```bash
bfd -d
```

### 5.2 Health Check

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

### 5.3 Attack Pool

The **`-a|--attackpool`** option displays the top brute force attackers with per-service breakdown and ban status for each IP:

```bash
bfd -a           # show top attackers
bfd -a 192.0.2   # search for a specific string
```

The report includes:
- **Top 25 attackers today** — event count, IP, first/last seen, services, and ban status (active bans show `BANNED(perm)` or `BANNED(Xm)`, previous bans show `prev:N`)
- **Per-service breakdown** — event count and unique IP count per service
- **Top 25 attackers this week** — same format, aggregated from the weekly pool

### 5.4 Watch Mode

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

### 5.5 Flush Bans

Remove multiple bans at once:

```bash
bfd --flush-temp    # remove all temporary bans (keep permanent)
bfd --flush-all     # remove all bans (temporary + permanent)
```

Flushed bans are recorded in the ban history.

### 5.6 Structured Output

Use `--json` or `--csv` with `-l` for machine-readable ban lists:

```bash
bfd -l --json
bfd -l --csv
```

**JSON** outputs an array of objects:
```json
[{"ip": "...", "service": "...", "ports": "...", "banned": "ISO-8601", "expires": "ISO-8601|permanent"}]
```

**CSV** outputs with a header row:
```
ip,service,ports,banned,expires
```

---

## 6. Rule Engine

Rules are located under `/usr/local/bfd/rules/`. Each rule is a shell fragment that declares the service name, required binary, log path, and a regex pattern for matching authentication failures.

Each rule auto-enables based on the existence of a specific application binary (`PREREQ`). For example, if `/usr/sbin/sshd` exists, the sshd rule is active. No manual activation is needed — install the application and BFD will detect it.

Use `bfd -c` to see which rules are active on your system.

### 6.1 Rule Catalog

BFD ships with 42 rules:

| Category | Rules |
|----------|-------|
| **SSH** | sshd, dropbear |
| **Mail** | dovecot, courier, postfix, sendmail, exim_authfail, exim_nxuser, vpopmail, cyrus-imap |
| **FTP** | vsftpd, vsftpd2, proftpd, pure-ftpd |
| **Web** | apache-auth, nginx-http-auth, modsec, wordpress, roundcube, http_401, lighttpd, phpmyadmin |
| **Panel** | cpanel, plesk, webmin, directadmin, gitlab, grafana, proxmox |
| **Auth** | pam_generic, xrdp |
| **Database** | mysqld-auth, postgresql, mongodb |
| **DNS** | named |
| **VPN** | openvpnas, openvpn |
| **VoIP** | asterisk_badauth, asterisk_iax, asterisk_nopeer |
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

Centralized per-rule overrides (without editing rule files) go in `/usr/local/bfd/pressure.conf`.

---

## 7. Ignore Lists

BFD provides two mechanisms for excluding addresses from bans:

- **`/usr/local/bfd/ignore.hosts`** — IPs to never ban, one per line. Supports IPv4 and IPv6 addresses.
- **`/usr/local/bfd/exclude.files`** — additional files containing IPs to ignore. One file path per line; each referenced file contains IPs to exclude.

BFD automatically detects local IPv4 and IPv6 addresses (including `::1`) and excludes them from bans. No manual configuration is needed for local address exclusion.

---

## 8. Ban Management

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
| `events.dat` | Per-IP failure events with pressure weights (timestamp, IP, service, weight) |
| `attack.pool` | Persistent attack pool — all detected events for reporting |

The `bfd -a` attack pool report integrates with ban state — each IP shows whether it is currently banned, its ban type (permanent or time remaining), and historical ban count.

---

## 9. IPv6 Support

BFD detects and bans both IPv4 and IPv6 addresses automatically. Rules do not need modification — the extraction engine handles both address families. IPv6 addresses are normalized before counting and comparison.

For firewalls that handle both protocols natively (nft with `inet` family, APF, ip route), leave `BAN_COMMAND_V6` empty — `BAN_COMMAND` is used for all addresses.

For firewalls that require separate commands (iptables/ip6tables), set `BAN_COMMAND_V6` and `UNBAN_COMMAND_V6`:

```bash
BAN_COMMAND_V6="/sbin/ip6tables -I INPUT -s $ATTACK_HOST -j DROP"
UNBAN_COMMAND_V6="/sbin/ip6tables -D INPUT -s $ATTACK_HOST -j DROP"
```

Local IPv6 addresses (including `::1` and all link-local addresses) are auto-detected and excluded from bans.

---

## 10. Troubleshooting

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

## 11. License

BFD is developed and supported on a volunteer basis by Ryan MacDonald [ryan@rfxn.com].

BFD (Brute Force Detection) is distributed under the GNU General Public License (GPL) without restrictions on usage or redistribution. The BFD copyright statement, and GNU GPL, "COPYING.GPL" are included in the top-level directory of the distribution. Credit must be given for derivative works as required under GNU GPL.

---

## 12. Support

The BFD source repository is at: https://github.com/rfxn/brute-force-detection

Bugs, feature requests, and general questions can be filed as GitHub issues or sent to proj@rfxn.com. When reporting issues, include the output of `bfd -c` to help diagnose configuration problems.

The official project page is at: https://www.rfxn.com/projects/brute-force-detection/
