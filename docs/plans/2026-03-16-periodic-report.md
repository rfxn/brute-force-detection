# Periodic Threat Report Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add daily/weekly/monthly periodic threat reports delivered via text, email, and all messaging channels (Slack, Telegram, Discord).

**Architecture:** Layered primitive in `bfd_report.sh` — data gathering, rendering, and delivery are separate layers. Reuses existing `_apool_*` AWK helpers for data, `_alert_tpl_render()` for templates, and `_alert_deliver_email()` / `alert_dispatch()` for delivery. One new AWK helper (`_report_trend_awk`) for window-over-window comparison.

**Tech Stack:** Bash 4.1+, mawk-compatible AWK, BATS test framework.

**Design spec:** `docs/superpowers/specs/2026-03-16-periodic-report-design.md`

---

## File Structure

| Action | File | Responsibility |
|--------|------|---------------|
| Create | `files/internals/bfd_report.sh` | Report function library (data, render, deliver layers) |
| Create | `files/alert/report.text.header.tpl` | Email/CLI text header template |
| Create | `files/alert/report.text.body.tpl` | Email/CLI text body template |
| Create | `files/alert/report.html.header.tpl` | Email HTML header template |
| Create | `files/alert/report.html.body.tpl` | Email HTML body template |
| Create | `files/alert/report.slack.message.tpl` | Slack Block Kit JSON template |
| Create | `files/alert/report.telegram.message.tpl` | Telegram MarkdownV2 template |
| Create | `files/alert/report.discord.message.tpl` | Discord embed JSON template |
| Create | `tests/46-report.bats` | Report unit + integration tests |
| Modify | `files/conf.bfd` (line 125) | Add REPORT_* config section |
| Modify | `files/internals/bfd.lib.sh` (line 57) | Source bfd_report.sh |
| Modify | `files/bfd` (lines 1383, 1434, 1685) | CLI dispatcher + usage text |
| Modify | `cron.daily` (line 108) | Report scheduling triggers |
| Modify | `bfd.1` | Man page: --report option + REPORT_* vars |
| Modify | `README` | Feature description |
| Modify | `CHANGELOG` | Release notes |
| Modify | `CHANGELOG.RELEASE` | Release notes |

---

## Chunk 1: Config, Sourcing, CLI Wiring

### Task 1: Add REPORT_* config variables to conf.bfd

**Files:**
- Modify: `files/conf.bfd:124-126` (insert between Discord and Banning sections)

- [ ] **Step 1: Add Periodic Reports config section**

Insert after line 124 (`DISCORD_WEBHOOK_URL=""`) and before line 126 (`# =============================================` Banning header):

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

- [ ] **Step 2: Verify syntax**

Run: `bash -n files/conf.bfd`
Expected: no output (clean parse)

- [ ] **Step 3: Commit**

```bash
git add files/conf.bfd
git commit -m "$(cat <<'EOF'
2.0.1 | Add REPORT_* config variables for periodic reports

[New] REPORT_ENABLED, REPORT_INTERVALS, REPORT_CHANNELS,
REPORT_EMAIL_ADDRESS, REPORT_EMAIL_SUBJECT, REPORT_TOP_N
config variables for periodic threat reporting.
Defaults to disabled (REPORT_ENABLED="0").
EOF
)"
```

---

### Task 2: Create bfd_report.sh — init + trend AWK layer

**Files:**
- Create: `files/internals/bfd_report.sh`
- Test: `tests/46-report.bats`

- [ ] **Step 1: Write failing tests for _report_init and _report_trend_awk**

Create `tests/46-report.bats`:

```bash
#!/usr/bin/env bats
#
# Tests for periodic threat report functions
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

setup() {
	bfd_standard_setup
	UTIME=$(date +"%s")
	# Load report functions
	# shellcheck disable=SC1091
	source "$PROJECT_ROOT/files/internals/bfd_report.sh"
}

teardown() {
	bfd_teardown
}

# --- _report_init ---

@test "report_init: daily sets correct window vars" {
	_report_init "daily"
	[ "$_RPT_LABEL" = "Daily" ]
	[ "$_RPT_WINDOW" = "24h" ]
	[ "$_RPT_CUTOFF" -gt 0 ]
	[ "$_RPT_PREV_CUTOFF" -gt 0 ]
	[ "$_RPT_PREV_CUTOFF" -lt "$_RPT_CUTOFF" ]
}

@test "report_init: weekly sets 7d window" {
	_report_init "weekly"
	[ "$_RPT_LABEL" = "Weekly" ]
	[ "$_RPT_WINDOW" = "7d" ]
}

@test "report_init: monthly sets 30d window" {
	_report_init "monthly"
	[ "$_RPT_LABEL" = "Monthly" ]
	[ "$_RPT_WINDOW" = "30d" ]
}

@test "report_init: invalid interval returns error" {
	run _report_init "hourly"
	assert_failure
	assert_output --partial "invalid report interval"
}

# --- _report_trend_awk ---

@test "trend_awk: computes current and prior window totals" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	local now
	now=$(date +%s)
	# 3 events in current window (last 24h)
	echo "$((now - 100)) 192.0.2.1 sshd 1 CN ban 600 22 15000 service" >> "$pool"
	echo "$((now - 200)) 192.0.2.2 sshd 1 RU ban 600 22 15000 service" >> "$pool"
	echo "$((now - 300)) 192.0.2.1 dovecot 1 CN ban 600 143 15000 service" >> "$pool"
	# 1 event in prior window (24h-48h ago)
	echo "$((now - 90000)) 192.0.2.3 sshd 1 BR ban 600 22 15000 service" >> "$pool"
	# 1 event outside both windows (>48h ago)
	echo "$((now - 200000)) 192.0.2.4 sshd 1 US ban 600 22 15000 service" >> "$pool"

	local cutoff=$((now - 86400))
	local prev_cutoff=$((now - 172800))
	run _report_trend_awk "$pool" "$cutoff" "$prev_cutoff"
	assert_success
	# Output: current_total|current_uniq|prior_total|prior_uniq
	# Current: 3 events, 2 unique IPs; Prior: 1 event, 1 unique IP
	assert_output "3|2|1|1"
}

@test "trend_awk: empty pool returns zeros" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	touch "$pool"
	local now
	now=$(date +%s)
	run _report_trend_awk "$pool" "$((now - 86400))" "$((now - 172800))"
	assert_success
	assert_output "0|0|0|0"
}

@test "trend_awk: all events in prior window" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	local now
	now=$(date +%s)
	echo "$((now - 90000)) 192.0.2.1 sshd 1 CN ban 600 22 15000 service" >> "$pool"
	echo "$((now - 95000)) 192.0.2.2 sshd 1 RU ban 600 22 15000 service" >> "$pool"
	local cutoff=$((now - 86400))
	local prev_cutoff=$((now - 172800))
	run _report_trend_awk "$pool" "$cutoff" "$prev_cutoff"
	assert_success
	assert_output "0|0|2|2"
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /root/admin/work/proj/brute-force-detection && bats tests/46-report.bats 2>&1 | head -20`
Expected: FAIL — `bfd_report.sh` doesn't exist yet

- [ ] **Step 3: Create bfd_report.sh with _report_init and _report_trend_awk**

Create `files/internals/bfd_report.sh`:

```bash
#!/bin/bash
#
# Brute Force Detection 2.0.1 - Periodic Report Functions
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
# This file is sourced by bfd.lib.sh after bfd_alert.sh and geoip_lib.sh.
# It provides periodic report functions: data gathering, rendering, and delivery.

# Source guard — prevent double-sourcing
[[ -n "${_BFD_REPORT_LOADED:-}" ]] && return 0 2>/dev/null
_BFD_REPORT_LOADED=1

# shellcheck disable=SC2034  # version checked by health_check and show_config
BFD_REPORT_VERSION="1.0.0"

# ---------------------------------------------------------------------------
# Init Layer — validate interval, compute time windows
# ---------------------------------------------------------------------------

# _report_init interval — validate and set window variables
# Sets: _RPT_LABEL, _RPT_WINDOW, _RPT_CUTOFF, _RPT_PREV_CUTOFF, _RPT_NOW
# Returns 1 on invalid interval.
_report_init() {
	local interval="$1"
	_RPT_NOW=$(date +%s)
	case "$interval" in
		daily)
			_RPT_LABEL="Daily"
			_RPT_WINDOW="24h"
			_RPT_CUTOFF=$((_RPT_NOW - 86400))
			_RPT_PREV_CUTOFF=$((_RPT_NOW - 172800))
			;;
		weekly)
			_RPT_LABEL="Weekly"
			_RPT_WINDOW="7d"
			_RPT_CUTOFF=$((_RPT_NOW - 604800))
			_RPT_PREV_CUTOFF=$((_RPT_NOW - 1209600))
			;;
		monthly)
			_RPT_LABEL="Monthly"
			_RPT_WINDOW="30d"
			_RPT_CUTOFF=$((_RPT_NOW - 2592000))
			_RPT_PREV_CUTOFF=$((_RPT_NOW - 5184000))
			;;
		*)
			echo "error: invalid report interval '$interval' (use daily, weekly, or monthly)." >&2
			return 1
			;;
	esac
	return 0
}

# ---------------------------------------------------------------------------
# Data Layer — AWK helpers and stat gathering
# ---------------------------------------------------------------------------

# _report_trend_awk pool_file current_cutoff prior_cutoff
# Single-pass AWK: counts events and unique IPs in two adjacent time windows.
# Output: current_total|current_uniq|prior_total|prior_uniq
_report_trend_awk() {
	local pool_file="$1" current_cutoff="$2" prior_cutoff="$3"
	if [ ! -f "$pool_file" ] || [ ! -s "$pool_file" ]; then
		echo "0|0|0|0"
		return 0
	fi
	awk -v cur="$current_cutoff" -v prev="$prior_cutoff" '
	{
		ts = $1 + 0
		ip = $2
		if (ts >= cur) {
			ct++
			if (!ci[ip]++) cu++
		} else if (ts >= prev) {
			pt++
			if (!pi[ip]++) pu++
		}
	}
	END {
		printf "%d|%d|%d|%d\n", ct+0, cu+0, pt+0, pu+0
	}' "$pool_file"
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /root/admin/work/proj/brute-force-detection && bats tests/46-report.bats 2>&1 | tail -20`
Expected: All tests PASS

- [ ] **Step 5: Lint**

Run: `bash -n files/internals/bfd_report.sh && shellcheck -S warning files/internals/bfd_report.sh`
Expected: clean

- [ ] **Step 6: Commit**

```bash
git add files/internals/bfd_report.sh tests/46-report.bats
git commit -m "$(cat <<'EOF'
2.0.1 | Add bfd_report.sh with init and trend AWK layers

[New] _report_init() validates interval, computes time windows.
[New] _report_trend_awk() single-pass window-over-window comparison.
[New] tests/46-report.bats with unit tests for both functions.
EOF
)"
```

---

### Task 3: Add _report_data layer (stat gathering + formatting)

**Files:**
- Modify: `files/internals/bfd_report.sh`
- Modify: `tests/46-report.bats`

- [ ] **Step 1: Write failing tests for _report_data**

Append to `tests/46-report.bats`:

```bash
# --- _report_data ---

@test "report_data: exports REPORT_* vars from populated pool" {
	bfd_require_bash42
	local pool="$INSTALL_PATH/stats/attack.pool"
	APOOL_LIST="$pool"
	local now
	now=$(date +%s)
	# Populate pool with test data
	echo "$((now - 100)) 192.0.2.1 sshd 1 CN ban 600 22 15000 service" >> "$pool"
	echo "$((now - 200)) 192.0.2.2 sshd 1 RU observed 0 22 10000 service" >> "$pool"
	echo "$((now - 300)) 192.0.2.3 dovecot 1 BR ban 600 143 20000 service" >> "$pool"

	_report_init "daily"
	_report_data "$pool"

	[ -n "$REPORT_UNIQUE_IPS" ]
	[ "$REPORT_UNIQUE_IPS" -ge 1 ]
	[ -n "$REPORT_TOTAL_EVENTS" ]
	[ "$REPORT_TOTAL_EVENTS" -ge 1 ]
	[ -n "$REPORT_TREND_LABEL" ]
	[ -n "$REPORT_TOP_IPS_TEXT" ]
	[ -n "$REPORT_SERVICES_TEXT" ]
}

@test "report_data: empty pool sets zero counts" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	APOOL_LIST="$pool"
	touch "$pool"
	_report_init "daily"
	_report_data "$pool"
	[ "$REPORT_UNIQUE_IPS" = "0" ]
	[ "$REPORT_TOTAL_EVENTS" = "0" ]
}

@test "report_data: trend label computed correctly" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	APOOL_LIST="$pool"
	local now
	now=$(date +%s)
	# 5 current events
	local i
	for i in 1 2 3 4 5; do
		echo "$((now - i * 100)) 192.0.2.$i sshd 1 CN ban 600 22 15000 service" >> "$pool"
	done
	# 2 prior events
	echo "$((now - 90000)) 192.0.2.10 sshd 1 RU ban 600 22 15000 service" >> "$pool"
	echo "$((now - 91000)) 192.0.2.11 sshd 1 BR ban 600 22 15000 service" >> "$pool"

	_report_init "daily"
	_report_data "$pool"
	[ "$REPORT_TREND_DIRECTION" = "up" ]
	[ -n "$REPORT_TREND_PCT" ]
}
```

- [ ] **Step 2: Run to verify failure**

Run: `bats tests/46-report.bats --filter "report_data" 2>&1 | head -10`
Expected: FAIL — `_report_data` not defined

- [ ] **Step 3: Implement _report_data and formatting helpers**

Append to `files/internals/bfd_report.sh` (after `_report_trend_awk`):

```bash
# _report_data pool_file — gather all report stats, export REPORT_* vars
# Requires: _RPT_* vars from _report_init(), INSTALL_PATH, APOOL_LIST
# Reuses: _apool_summary_awk, _apool_awk, _apool_service_dual_awk,
#         format_table, _batch_ban_status_init/lookup/cleanup, pressure_compute,
#         pressure_format, _resolve_min_trip, _alert_country_flag
_report_data() {
	local pool_file="$1"
	local top_n="${REPORT_TOP_N:-25}"

	# --- Summary stats ---
	local summary_line
	if [ -f "$pool_file" ] && [ -s "$pool_file" ]; then
		summary_line=$(_apool_summary_awk "$pool_file" "$_RPT_CUTOFF" "$((_RPT_CUTOFF - (_RPT_NOW - _RPT_CUTOFF)))")
	else
		summary_line="0|0|0|0"
	fi
	local u_cur t_cur u_prev t_prev
	IFS='|' read -r u_cur t_cur u_prev t_prev <<< "$summary_line"

	export REPORT_UNIQUE_IPS="${u_cur:-0}"
	export REPORT_TOTAL_EVENTS="${t_cur:-0}"

	# Ban counts
	local bans_active="${INSTALL_PATH:-}/tmp/bans.active"
	local active_bans=0
	if [ -f "$bans_active" ] && [ -s "$bans_active" ]; then
		active_bans=$(wc -l < "$bans_active")
	fi
	export REPORT_ACTIVE_BANS="$active_bans"

	# Total bans in window (ACTION=ban or escalate)
	local total_bans=0
	if [ -f "$pool_file" ] && [ -s "$pool_file" ]; then
		total_bans=$(awk -v cutoff="$_RPT_CUTOFF" '
			$1+0 >= cutoff && ($6 == "ban" || $6 == "escalate") { c++ }
			END { print c+0 }' "$pool_file")
	fi
	export REPORT_TOTAL_BANS="$total_bans"

	# --- Interval metadata ---
	export REPORT_INTERVAL="${_RPT_WINDOW%%[hd]*}"
	local interval_name
	case "$_RPT_WINDOW" in
		24h) interval_name="daily" ;;
		7d)  interval_name="weekly" ;;
		30d) interval_name="monthly" ;;
		*)   interval_name="daily" ;;
	esac
	export REPORT_INTERVAL="$interval_name"
	export REPORT_INTERVAL_LABEL="$_RPT_LABEL"
	export REPORT_WINDOW="$_RPT_WINDOW"

	# Date range
	local start_fmt end_fmt
	start_fmt=$(date -d "@$_RPT_CUTOFF" +"%Y-%m-%d %H:%M" 2>/dev/null || echo "$_RPT_CUTOFF")
	end_fmt=$(date -d "@$_RPT_NOW" +"%Y-%m-%d %H:%M" 2>/dev/null || echo "$_RPT_NOW")
	export REPORT_DATE_RANGE="$start_fmt -- $end_fmt"

	# --- Trend ---
	local trend_line
	trend_line=$(_report_trend_awk "$pool_file" "$_RPT_CUTOFF" "$_RPT_PREV_CUTOFF")
	local ct cu pt pu
	IFS='|' read -r ct cu pt pu <<< "$trend_line"
	ct=${ct:-0}; pt=${pt:-0}

	if [ "$pt" -eq 0 ] && [ "$ct" -eq 0 ]; then
		export REPORT_TREND_DIRECTION="flat"
		export REPORT_TREND_PCT="0"
		export REPORT_TREND_LABEL="no activity in either period"
	elif [ "$pt" -eq 0 ]; then
		export REPORT_TREND_DIRECTION="up"
		export REPORT_TREND_PCT="100"
		export REPORT_TREND_LABEL="new activity ($ct events, none in prior $_RPT_WINDOW)"
	else
		local pct_change=$(( (ct - pt) * 100 / pt ))
		local abs_pct=${pct_change#-}
		if [ "$pct_change" -gt 5 ]; then
			export REPORT_TREND_DIRECTION="up"
			export REPORT_TREND_PCT="$abs_pct"
			export REPORT_TREND_LABEL="${abs_pct}% increase vs prior $_RPT_WINDOW ($ct vs $pt)"
		elif [ "$pct_change" -lt -5 ]; then
			export REPORT_TREND_DIRECTION="down"
			export REPORT_TREND_PCT="$abs_pct"
			export REPORT_TREND_LABEL="${abs_pct}% decrease vs prior $_RPT_WINDOW ($ct vs $pt)"
		else
			export REPORT_TREND_DIRECTION="flat"
			export REPORT_TREND_PCT="$abs_pct"
			export REPORT_TREND_LABEL="no significant change vs prior $_RPT_WINDOW ($ct vs $pt)"
		fi
	fi

	# --- Top IPs (text + HTML + brief) ---
	_report_format_top_ips "$pool_file" "$_RPT_CUTOFF" "$top_n"

	# --- Service breakdown (text + HTML + brief) ---
	_report_format_services "$pool_file" "$_RPT_CUTOFF" "$((_RPT_CUTOFF - (_RPT_NOW - _RPT_CUTOFF)))"
}

# _report_format_top_ips pool_file cutoff limit
# Exports: REPORT_TOP_IPS_TEXT, REPORT_TOP_IPS_HTML, REPORT_TOP_IPS_BRIEF
_report_format_top_ips() {
	local pool_file="$1" cutoff="$2" limit="$3"
	local text_table="" html_table="" brief=""

	if [ ! -f "$pool_file" ] || [ ! -s "$pool_file" ]; then
		export REPORT_TOP_IPS_TEXT=""
		export REPORT_TOP_IPS_HTML=""
		export REPORT_TOP_IPS_BRIEF="No activity."
		return 0
	fi

	# Use _apool_awk to aggregate — outputs: cnt|ip|first_ts|last_ts|rules_csv|cc
	local agg_data
	agg_data=$(_apool_awk "$pool_file" "" "$cutoff" "count" "$limit")
	if [ -z "$agg_data" ]; then
		export REPORT_TOP_IPS_TEXT="No threat IPs in this period."
		export REPORT_TOP_IPS_HTML="<p>No threat IPs in this period.</p>"
		export REPORT_TOP_IPS_BRIEF="No threat IPs."
		return 0
	fi

	# Initialize ban status batch lookup
	_batch_ban_status_init "${INSTALL_PATH:-}"

	# Build text table
	text_table="COUNT|IP|COUNTRY|PRESSURE|RULES|STATUS"
	local brief_count=0
	local line cnt ip first_ts last_ts rules_csv cc ban_status
	local pressure_scaled pressure_fmt trip_val
	while IFS='|' read -r cnt ip first_ts last_ts rules_csv cc; do
		[ -z "$ip" ] && continue
		ban_status=$(_batch_ban_status_lookup "$ip")
		# Compute live pressure
		pressure_scaled=$(pressure_compute "${INSTALL_PATH:-}" "$ip" \
			"${PRESSURE_HALF_LIFE:-300}" "$_RPT_NOW")
		pressure_fmt=$(pressure_format "$pressure_scaled")
		trip_val=$(_resolve_min_trip "$rules_csv")
		text_table="${text_table}
${cnt}|${ip}|${cc:---}|${pressure_fmt}/${trip_val}|${rules_csv}|${ban_status:---}"
		# Brief: top 5 for messaging
		if [ "$brief_count" -lt 5 ]; then
			local flag=""
			if [ -n "$cc" ] && [ "$cc" != "--" ] && type _alert_country_flag >/dev/null 2>&1; then
				flag=$(_alert_country_flag "$cc")
				flag="${flag:+$flag }"
			fi
			brief="${brief}${flag}${ip} -- ${cc:---} -- ${cnt} hits (${rules_csv})${ban_status:+ $ban_status}
"
			brief_count=$((brief_count + 1))
		fi
	done <<< "$agg_data"

	_batch_ban_status_cleanup

	export REPORT_TOP_IPS_TEXT
	REPORT_TOP_IPS_TEXT=$(echo "$text_table" | format_table)
	export REPORT_TOP_IPS_BRIEF="${brief%
}"

	# HTML table
	local html_rows=""
	while IFS='|' read -r cnt ip first_ts last_ts rules_csv cc; do
		[ -z "$ip" ] && continue
		html_rows="${html_rows}<tr><td>${cnt}</td><td>${ip}</td><td>${cc:---}</td><td>${rules_csv}</td></tr>
"
	done <<< "$agg_data"
	export REPORT_TOP_IPS_HTML="<table><tr><th>COUNT</th><th>IP</th><th>COUNTRY</th><th>RULES</th></tr>
${html_rows}</table>"
}

# _report_format_services pool_file cutoff_a cutoff_b
# Exports: REPORT_SERVICES_TEXT, REPORT_SERVICES_HTML, REPORT_SERVICES_BRIEF
_report_format_services() {
	local pool_file="$1" cutoff_a="$2" cutoff_b="$3"

	if [ ! -f "$pool_file" ] || [ ! -s "$pool_file" ]; then
		export REPORT_SERVICES_TEXT=""
		export REPORT_SERVICES_HTML=""
		export REPORT_SERVICES_BRIEF="No services."
		return 0
	fi

	# _apool_service_dual_awk outputs: service|count_a|count_b|uniq_a|uniq_b|top_cc
	local svc_data
	svc_data=$(_apool_service_dual_awk "$pool_file" "$cutoff_a" "$cutoff_b")
	if [ -z "$svc_data" ]; then
		export REPORT_SERVICES_TEXT="No service activity."
		export REPORT_SERVICES_HTML="<p>No service activity.</p>"
		export REPORT_SERVICES_BRIEF="No services."
		return 0
	fi

	local text_table="SERVICE|EVENTS|UNIQUE IPS|TOP COUNTRY"
	local brief="" html_rows=""
	local svc cnt_a cnt_b uq_a uq_b top_cc
	while IFS='|' read -r svc cnt_a cnt_b uq_a uq_b top_cc; do
		[ -z "$svc" ] && continue
		text_table="${text_table}
${svc}|${cnt_a}|${uq_a}|${top_cc:---}"
		local flag=""
		if [ -n "$top_cc" ] && [ "$top_cc" != "--" ] && type _alert_country_flag >/dev/null 2>&1; then
			flag=$(_alert_country_flag "$top_cc")
			flag="${flag:+$flag }"
		fi
		brief="${brief}${svc} -- ${cnt_a} events . ${uq_a} IPs . ${flag}${top_cc:---}
"
		html_rows="${html_rows}<tr><td>${svc}</td><td>${cnt_a}</td><td>${uq_a}</td><td>${top_cc:---}</td></tr>
"
	done <<< "$svc_data"

	export REPORT_SERVICES_TEXT
	REPORT_SERVICES_TEXT=$(echo "$text_table" | format_table)
	export REPORT_SERVICES_BRIEF="${brief%
}"
	export REPORT_SERVICES_HTML="<table><tr><th>SERVICE</th><th>EVENTS</th><th>UNIQUE IPS</th><th>TOP COUNTRY</th></tr>
${html_rows}</table>"
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `bats tests/46-report.bats 2>&1 | tail -20`
Expected: All tests PASS

- [ ] **Step 5: Lint**

Run: `bash -n files/internals/bfd_report.sh && shellcheck -S warning files/internals/bfd_report.sh`
Expected: clean

- [ ] **Step 6: Commit**

```bash
git add files/internals/bfd_report.sh tests/46-report.bats
git commit -m "$(cat <<'EOF'
2.0.1 | Add report data layer with stat gathering and formatting

[New] _report_data() gathers summary stats, trend, top IPs, services.
[New] _report_format_top_ips() formats text/HTML/brief IP tables.
[New] _report_format_services() formats text/HTML/brief service tables.
Reuses _apool_summary_awk, _apool_awk, _apool_service_dual_awk,
_batch_ban_status_*, pressure_compute, format_table.
EOF
)"
```

---

### Task 4: Add render + deliver + report() orchestrator

**Files:**
- Modify: `files/internals/bfd_report.sh`
- Modify: `tests/46-report.bats`

- [ ] **Step 1: Write failing tests for report() orchestrator**

Append to `tests/46-report.bats`:

```bash
# --- report() orchestrator ---

@test "report: daily with populated pool produces text output" {
	bfd_require_bash42
	local pool="$INSTALL_PATH/stats/attack.pool"
	APOOL_LIST="$pool"
	ALERT_TEMPLATE_DIR="$PROJECT_ROOT/files/alert"
	EMAIL_ALERTS="0"
	REPORT_ENABLED="1"
	V="2.0.1"
	local now
	now=$(date +%s)
	echo "$((now - 100)) 192.0.2.1 sshd 1 CN ban 600 22 15000 service" >> "$pool"
	echo "$((now - 200)) 192.0.2.2 sshd 1 RU observed 0 22 10000 service" >> "$pool"

	run report "daily"
	assert_success
	assert_output --partial "Daily Threat Report"
	assert_output --partial "Threat Summary"
	assert_output --partial "Unique IPs"
	assert_output --partial "Trend"
}

@test "report: empty pool produces no-activity message" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	APOOL_LIST="$pool"
	ALERT_TEMPLATE_DIR="$PROJECT_ROOT/files/alert"
	EMAIL_ALERTS="0"
	V="2.0.1"
	touch "$pool"

	run report "daily"
	assert_success
	assert_output --partial "No threat activity"
}

@test "report: invalid interval returns error" {
	run report "biweekly"
	assert_failure
	assert_output --partial "invalid report interval"
}
```

- [ ] **Step 2: Run to verify failure**

Run: `bats tests/46-report.bats --filter "report:" 2>&1 | head -10`
Expected: FAIL — `report` function not defined

- [ ] **Step 3: Implement render, deliver, and report() orchestrator**

Append to `files/internals/bfd_report.sh`:

```bash
# ---------------------------------------------------------------------------
# Render Layer — assemble templates into report bodies
# ---------------------------------------------------------------------------

# _report_render_text tpl_dir — render text report to stdout
# Requires: all REPORT_* vars exported by _report_data()
_report_render_text() {
	local tpl_dir="$1"
	_alert_tpl_resolve "$tpl_dir" "report.text.header.tpl"
	if [ -f "$_ALERT_TPL_RESOLVED" ]; then
		_alert_tpl_render "$_ALERT_TPL_RESOLVED"
	fi
	_alert_tpl_resolve "$tpl_dir" "report.text.body.tpl"
	if [ -f "$_ALERT_TPL_RESOLVED" ]; then
		_alert_tpl_render "$_ALERT_TPL_RESOLVED"
	fi
}

# _report_render_html tpl_dir — render HTML report to stdout
_report_render_html() {
	local tpl_dir="$1"
	_alert_tpl_resolve "$tpl_dir" "report.html.header.tpl"
	if [ -f "$_ALERT_TPL_RESOLVED" ]; then
		_alert_tpl_render "$_ALERT_TPL_RESOLVED"
	fi
	_alert_tpl_resolve "$tpl_dir" "report.html.body.tpl"
	if [ -f "$_ALERT_TPL_RESOLVED" ]; then
		_alert_tpl_render "$_ALERT_TPL_RESOLVED"
	fi
}

# ---------------------------------------------------------------------------
# Deliver Layer — send reports to configured channels
# ---------------------------------------------------------------------------

# _report_deliver_email subject text_file html_file recipient
# Wraps _alert_deliver_email with report-specific recipient handling.
_report_deliver_email() {
	local subject="$1" text_file="$2" html_file="$3"
	local recipient="${REPORT_EMAIL_ADDRESS:-${EMAIL_ADDRESS:-root}}"
	local format="${EMAIL_FORMAT:-text}"
	_alert_deliver_email "$recipient" "$subject" "$text_file" "$html_file" "$format"
}

# _report_dispatch_messaging tpl_dir subject
# Sends report to enabled messaging channels via alert_dispatch().
# Respects REPORT_CHANNELS filtering.
_report_dispatch_messaging() {
	local tpl_dir="$1" subject="$2"

	# Early exit if no messaging channels enabled
	if ! alert_channel_enabled "slack" && \
	   ! alert_channel_enabled "telegram" && \
	   ! alert_channel_enabled "discord"; then
		return 0
	fi

	alert_dispatch "$tpl_dir" "$subject" "slack,telegram,discord"
}

# _report_channel_override — temporarily override channel registry per REPORT_CHANNELS
# Saves current state, then enables only the channels listed in REPORT_CHANNELS.
# Call _report_channel_restore to undo.
_report_channel_override() {
	_RPT_SAVED_SLACK=$(alert_channel_enabled "slack" && echo 1 || echo 0)
	_RPT_SAVED_TELEGRAM=$(alert_channel_enabled "telegram" && echo 1 || echo 0)
	_RPT_SAVED_DISCORD=$(alert_channel_enabled "discord" && echo 1 || echo 0)

	local channels=",${REPORT_CHANNELS:-},"
	if [[ "$channels" == *",slack,"* ]]; then
		alert_channel_enable "slack"
	else
		alert_channel_disable "slack"
	fi
	if [[ "$channels" == *",telegram,"* ]]; then
		alert_channel_enable "telegram"
	else
		alert_channel_disable "telegram"
	fi
	if [[ "$channels" == *",discord,"* ]]; then
		alert_channel_enable "discord"
	else
		alert_channel_disable "discord"
	fi
}

# _report_channel_restore — restore channel registry to pre-override state
_report_channel_restore() {
	if [ "${_RPT_SAVED_SLACK:-0}" = "1" ]; then
		alert_channel_enable "slack"
	else
		alert_channel_disable "slack"
	fi
	if [ "${_RPT_SAVED_TELEGRAM:-0}" = "1" ]; then
		alert_channel_enable "telegram"
	else
		alert_channel_disable "telegram"
	fi
	if [ "${_RPT_SAVED_DISCORD:-0}" = "1" ]; then
		alert_channel_enable "discord"
	else
		alert_channel_disable "discord"
	fi
}

# _report_deliver interval tpl_dir — render and deliver report to all channels
_report_deliver() {
	local interval="$1" tpl_dir="$2"

	# Render subject from template
	local subject_tpl="${REPORT_EMAIL_SUBJECT:-BFD {{INTERVAL}} Threat Report for {{HOSTNAME}}}"
	local subject_file
	subject_file=$(mktemp "${TMPDIR:-/tmp}/.bfd_rpt_subj.XXXXXX")
	echo "$subject_tpl" > "$subject_file"
	# Export vars for subject template
	export INTERVAL="$_RPT_LABEL"
	local subject
	subject=$(_alert_tpl_render "$subject_file")
	command rm -f "$subject_file"

	# Override channels if REPORT_CHANNELS is set
	local channels_overridden=0
	if [ -n "${REPORT_CHANNELS:-}" ]; then
		_report_channel_override
		channels_overridden=1
	fi

	# Email delivery
	local send_email=0
	if [ -n "${REPORT_CHANNELS:-}" ]; then
		case ",${REPORT_CHANNELS}," in
			*",email,"*) send_email=1 ;;
		esac
	else
		[ "${EMAIL_ALERTS:-0}" = "1" ] && send_email=1
	fi

	if [ "$send_email" = "1" ]; then
		local text_file html_file
		text_file=$(mktemp "${TMPDIR:-/tmp}/.bfd_rpt_text.XXXXXX")
		html_file=$(mktemp "${TMPDIR:-/tmp}/.bfd_rpt_html.XXXXXX")
		_report_render_text "$tpl_dir" > "$text_file"
		_report_render_html "$tpl_dir" > "$html_file"
		_report_deliver_email "$subject" "$text_file" "$html_file"
		command rm -f "$text_file" "$html_file"
	fi

	# Messaging delivery
	_report_dispatch_messaging "$tpl_dir" "$subject"

	# Restore channels if overridden
	if [ "$channels_overridden" = "1" ]; then
		_report_channel_restore
	fi
}

# ---------------------------------------------------------------------------
# Public Entry Point
# ---------------------------------------------------------------------------

# report interval — generate and deliver periodic threat report
# Called from CLI: bfd --report [daily|weekly|monthly]
report() {
	local interval="${1:-daily}"

	# Init — validate interval, compute windows
	_report_init "$interval" || return $?

	local pool_file="${APOOL_LIST:-${INSTALL_PATH:-/usr/local/bfd}/stats/attack.pool}"
	local tpl_dir="${ALERT_TEMPLATE_DIR:-${INSTALL_PATH:-/usr/local/bfd}/alert}"

	# Set global template vars (HOSTNAME, TIMESTAMP, BFD_VERSION, etc.)
	_alert_set_global_vars 0

	# Empty pool — short-circuit with no-activity message
	if [ ! -f "$pool_file" ] || [ ! -s "$pool_file" ]; then
		echo "BFD $_RPT_LABEL Threat Report for ${HOSTNAME:-$(hostname)}"
		local start_fmt end_fmt
		start_fmt=$(date -d "@$_RPT_CUTOFF" +"%Y-%m-%d %H:%M" 2>/dev/null || echo "$_RPT_CUTOFF")
		end_fmt=$(date -d "@$_RPT_NOW" +"%Y-%m-%d %H:%M" 2>/dev/null || echo "$_RPT_NOW")
		echo "Period: $start_fmt -- $end_fmt ($_RPT_WINDOW)"
		echo ""
		echo "No threat activity recorded in this period."
		return 0
	fi

	# Gather data — export all REPORT_* vars
	_report_data "$pool_file"

	# Text output to stdout (always — CLI use)
	_report_render_text "$tpl_dir"

	# Deliver via email + messaging
	_report_deliver "$interval" "$tpl_dir"

	# Log report generation
	if type eout >/dev/null 2>&1; then
		eout "$_RPT_LABEL report generated: $REPORT_UNIQUE_IPS IPs, $REPORT_TOTAL_EVENTS events" le
	fi
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `bats tests/46-report.bats 2>&1 | tail -20`
Expected: All tests PASS

- [ ] **Step 5: Lint**

Run: `bash -n files/internals/bfd_report.sh && shellcheck -S warning files/internals/bfd_report.sh`

- [ ] **Step 6: Commit**

```bash
git add files/internals/bfd_report.sh tests/46-report.bats
git commit -m "$(cat <<'EOF'
2.0.1 | Add report render, deliver, and orchestrator layers

[New] _report_render_text/html() assemble templates into report bodies.
[New] _report_deliver_email() wraps _alert_deliver_email with report recipient.
[New] _report_dispatch_messaging() dispatches to Slack/Telegram/Discord.
[New] _report_channel_override/restore() handles REPORT_CHANNELS filtering.
[New] report() public orchestrator: init → data → render → deliver.
EOF
)"
```

---

### Task 5: Wire sourcing and CLI dispatcher

**Files:**
- Modify: `files/internals/bfd.lib.sh:57`
- Modify: `files/bfd:1383,1434,1685`

- [ ] **Step 1: Add sourcing to bfd.lib.sh**

Insert after line 57 (after geoip_lib.sh sourcing, before `unset _internals_dir`):

```bash
# Source BFD report functions (periodic threat reports)
if [ -f "$_internals_dir/bfd_report.sh" ]; then
	# shellcheck disable=SC1091
	. "$_internals_dir/bfd_report.sh"
fi
```

- [ ] **Step 2: Add --report to case dispatcher in files/bfd**

Insert before the `--flush-temp)` line (line 1686):

```bash
--report)
	vhead; pre
	report "${2:-daily}" || exit "$?"
	;;
```

- [ ] **Step 3: Update usage_short() in files/bfd**

After line 1383 (`bfd -e [IP|CIDR]    active events...`), add:

```bash
	echo "  bfd --report [INTERVAL] periodic threat report (daily|weekly|monthly)"
```

- [ ] **Step 4: Update usage() in files/bfd**

After the Scan Mode section (after line 1437), add:

```bash
	echo ""
	echo "Reports:"
	echo "  --report [daily|weekly|monthly]  generate and deliver periodic threat report"
```

Add to Examples section (after line 1461):

```bash
	echo "  bfd --report weekly             generate and deliver weekly report"
```

- [ ] **Step 5: Verify syntax**

Run: `bash -n files/bfd files/internals/bfd.lib.sh files/internals/bfd_report.sh`
Expected: clean

- [ ] **Step 6: Commit**

```bash
git add files/internals/bfd.lib.sh files/bfd
git commit -m "$(cat <<'EOF'
2.0.1 | Wire --report CLI flag and bfd_report.sh sourcing

[New] --report [daily|weekly|monthly] CLI option for periodic reports.
[Change] bfd.lib.sh sources bfd_report.sh after geoip_lib.sh.
[Change] usage() and usage_short() updated with --report documentation.
EOF
)"
```

---

## Chunk 2: Templates

### Task 6: Create email text templates

**Files:**
- Create: `files/alert/report.text.header.tpl`
- Create: `files/alert/report.text.body.tpl`

- [ ] **Step 1: Create report.text.header.tpl**

```
================================================================================
  BFD {{REPORT_INTERVAL_LABEL}} Threat Report for {{HOSTNAME}}
  Period: {{REPORT_DATE_RANGE}} ({{REPORT_WINDOW}})
  Generated: {{TIMESTAMP}} GMT {{TIME_ZONE}}
================================================================================

```

- [ ] **Step 2: Create report.text.body.tpl**

```
  Threat Summary
  ----------------------------------------
  Unique IPs:      {{REPORT_UNIQUE_IPS}}
  Total Events:    {{REPORT_TOTAL_EVENTS}}
  Total Bans:      {{REPORT_TOTAL_BANS}}
  Active Bans:     {{REPORT_ACTIVE_BANS}}

  Trend: {{REPORT_TREND_LABEL}}

  Top Threat IPs ({{REPORT_WINDOW}})
  ----------------------------------------
{{REPORT_TOP_IPS_TEXT}}

  Service Breakdown ({{REPORT_WINDOW}})
  ----------------------------------------
{{REPORT_SERVICES_TEXT}}

--------------------------------------------------------------------------------
  BFD {{BFD_VERSION}} -- https://rfxn.com | GNU GPL v2
```

- [ ] **Step 3: Commit**

```bash
git add files/alert/report.text.header.tpl files/alert/report.text.body.tpl
git commit -m "$(cat <<'EOF'
2.0.1 | Add email text templates for periodic reports

[New] report.text.header.tpl and report.text.body.tpl for
text email and CLI stdout rendering.
EOF
)"
```

---

### Task 7: Create email HTML templates

**Files:**
- Create: `files/alert/report.html.header.tpl`
- Create: `files/alert/report.html.body.tpl`

- [ ] **Step 1: Create report.html.header.tpl**

Adapted from existing `html.header.tpl` teal branding — responsive email table layout with report-specific header (interval badge, date range).

- [ ] **Step 2: Create report.html.body.tpl**

Styled cards matching existing ban alert HTML: summary metrics grid, top IPs table with striped rows, service breakdown table, trend indicator, R-fx branded footer.

- [ ] **Step 3: Commit**

```bash
git add files/alert/report.html.header.tpl files/alert/report.html.body.tpl
git commit -m "$(cat <<'EOF'
2.0.1 | Add email HTML templates for periodic reports

[New] report.html.header.tpl and report.html.body.tpl with
teal-branded responsive cards matching ban alert styling.
EOF
)"
```

---

### Task 8: Create messaging templates (Slack, Telegram, Discord)

**Files:**
- Create: `files/alert/report.slack.message.tpl`
- Create: `files/alert/report.telegram.message.tpl`
- Create: `files/alert/report.discord.message.tpl`

- [ ] **Step 1: Create report.slack.message.tpl**

Slack Block Kit JSON with header, summary section, top 5 IPs with CC, service breakdown with CC, trend, version footer. Uses `{{REPORT_TOP_IPS_BRIEF}}` and `{{REPORT_SERVICES_BRIEF}}`.

- [ ] **Step 2: Create report.telegram.message.tpl**

MarkdownV2 format with bold header, summary, top 5 IPs, services, trend. All special characters properly escaped per MarkdownV2 rules.

- [ ] **Step 3: Create report.discord.message.tpl**

Discord embed JSON with title, description, summary fields, top IPs field, services field, trend field, footer. Color: 3319890 (teal, matching existing ban alerts).

- [ ] **Step 4: Commit**

```bash
git add files/alert/report.slack.message.tpl files/alert/report.telegram.message.tpl files/alert/report.discord.message.tpl
git commit -m "$(cat <<'EOF'
2.0.1 | Add messaging templates for periodic reports

[New] report.slack.message.tpl (Block Kit JSON),
report.telegram.message.tpl (MarkdownV2),
report.discord.message.tpl (embed JSON).
All include top 5 IPs and service breakdown with country codes.
EOF
)"
```

---

## Chunk 3: Scheduling, Docs, Verification

### Task 9: Add cron.daily report triggers

**Files:**
- Modify: `cron.daily:108`

- [ ] **Step 1: Add report scheduling block**

Insert after line 107 (ipcountry refresh block), before line 109 (`# clear transient state`):

```bash

# --- Periodic threat reports ---
if [ "${REPORT_ENABLED:-0}" = "1" ]; then
	case ",${REPORT_INTERVALS:-daily}," in
		*,daily,*) "$INSTALL_PATH/bfd" --report daily >/dev/null 2>&1 || true ;;  # non-fatal
	esac
	_dow=$(date +%u)  # 1=Monday
	if [ "$_dow" = "1" ]; then
		case ",${REPORT_INTERVALS:-daily}," in
			*,weekly,*) "$INSTALL_PATH/bfd" --report weekly >/dev/null 2>&1 || true ;;  # non-fatal
		esac
	fi
	_dom=$(date +%d)
	if [ "$_dom" = "01" ]; then
		case ",${REPORT_INTERVALS:-daily}," in
			*,monthly,*) "$INSTALL_PATH/bfd" --report monthly >/dev/null 2>&1 || true ;;  # non-fatal
		esac
	fi
fi
```

- [ ] **Step 2: Verify syntax**

Run: `bash -n cron.daily`
Expected: clean

- [ ] **Step 3: Commit**

```bash
git add cron.daily
git commit -m "$(cat <<'EOF'
2.0.1 | Add periodic report triggers to cron.daily

[New] Daily/weekly/monthly report triggers gated on REPORT_ENABLED.
Weekly fires on Mondays, monthly on 1st. Non-fatal (|| true).
Stdout redirected at call site to avoid -q coupling.
EOF
)"
```

---

### Task 10: Documentation updates

**Files:**
- Modify: `bfd.1`
- Modify: `README`
- Modify: `CHANGELOG`
- Modify: `CHANGELOG.RELEASE`

- [ ] **Step 1: Update man page (bfd.1)**

Add `--report` to OPTIONS section. Add `REPORT_ENABLED`, `REPORT_INTERVALS`, `REPORT_CHANNELS`, `REPORT_EMAIL_ADDRESS`, `REPORT_EMAIL_SUBJECT`, `REPORT_TOP_N` to CONFIGURATION section.

- [ ] **Step 2: Update README**

Add periodic reports to feature list and configuration documentation.

- [ ] **Step 3: Update CHANGELOG and CHANGELOG.RELEASE**

```
[New] Periodic threat report (--report daily|weekly|monthly) with multi-channel delivery
[New] REPORT_ENABLED, REPORT_INTERVALS, REPORT_CHANNELS config for scheduled reports
[New] REPORT_EMAIL_ADDRESS, REPORT_EMAIL_SUBJECT, REPORT_TOP_N report customization
```

- [ ] **Step 4: Commit**

```bash
git add bfd.1 README CHANGELOG CHANGELOG.RELEASE
git commit -m "$(cat <<'EOF'
2.0.1 | Document periodic report feature

[New] bfd.1: --report option and REPORT_* config variables.
[Change] README: periodic report feature description.
[Change] CHANGELOG/CHANGELOG.RELEASE: release notes.
EOF
)"
```

---

### Task 11: Full verification pass

**Files:** None modified — verification only.

- [ ] **Step 1: Lint all shell files**

Run:
```bash
bash -n files/bfd files/internals/bfd.lib.sh files/internals/bfd_report.sh \
     files/internals/elog_lib.sh files/tlog files/internals/tlog_lib.sh \
     files/update-ipcountry.sh files/internals/alert_lib.sh \
     files/internals/bfd_alert.sh files/internals/pkg_lib.sh \
     files/internals/geoip_lib.sh cron.daily
shellcheck -S warning files/internals/bfd_report.sh
```

- [ ] **Step 2: Run report tests**

Run: `make -C tests test 2>&1 | tee /tmp/test-bfd-report.log | tail -30`
Verify: `grep "not ok" /tmp/test-bfd-report.log` returns nothing

- [ ] **Step 3: Verify install.sh handles new files**

Check that `pkg_copy_tree` in `install.sh` copies `internals/bfd_report.sh` with `chmod 640`, and that all 7 `report.*.tpl` templates in `files/alert/` are included.

- [ ] **Step 4: Verify importconf handles new config**

Check that `pkg_config_merge()` will merge `REPORT_*` variables from the new `conf.bfd` into existing user configs during upgrade (this should be automatic since they have defaults).

- [ ] **Step 5: Verify template count**

Run: `ls -la files/alert/report.* | wc -l`
Expected: 7

- [ ] **Step 6: Verification greps**

```bash
grep -rn '/usr/bin/\(rm\|mv\|cp\)' files/internals/bfd_report.sh
grep -rn '^\s*cd ' files/internals/bfd_report.sh
grep -rn 'local [a-z_]*=\$(' files/internals/bfd_report.sh
grep -rn '|| true' files/internals/bfd_report.sh
grep -rn '2>/dev/null' files/internals/bfd_report.sh
```
Each hit must have an inline comment explaining why the suppression is safe.
