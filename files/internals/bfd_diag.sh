#!/bin/bash
#
# Brute Force Detection 2.0.2 - Health Check, Status, and Diagnostics
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
# Sourced by bfd.lib.sh. Provides health check, system status, config display,
# rule inspection, and alert testing operations.

# Source guard — prevent double-sourcing
[[ -n "${_BFD_DIAG_LOADED:-}" ]] && return 0 2>/dev/null
_BFD_DIAG_LOADED=1

# shellcheck disable=SC2034
BFD_DIAG_VERSION="1.0.0"

# --- Health check sub-functions ---
# Each returns pass/warn/fail counts via _hc_pass/_hc_warn/_hc_fail globals.

# _hc_config — validate config and log paths
_hc_config() {
	local config_out config_rc=0
	config_out=$(validate_config 2>&1) || config_rc=$?
	if [ "$config_rc" -ne 0 ]; then
		echo "[FAIL] Configuration: $config_out"
		_hc_fail=$((_hc_fail + 1))
	elif [ -n "$config_out" ]; then
		echo "[WARN] Configuration: $config_out"
		_hc_warn=$((_hc_warn + 1))
	else
		echo "[PASS] Configuration validated"
		_hc_pass=$((_hc_pass + 1))
	fi

	local log_name log_path
	for log_name in AUTH_LOG_PATH KERNEL_LOG_PATH MAIL_LOG_PATH; do
		case "$log_name" in
			AUTH_LOG_PATH)    log_path="${AUTH_LOG_PATH:-}" ;;
			KERNEL_LOG_PATH)  log_path="${KERNEL_LOG_PATH:-}" ;;
			MAIL_LOG_PATH)    log_path="${MAIL_LOG_PATH:-}" ;;
		esac
		if [ -z "$log_path" ]; then
			echo "[WARN] $log_name: not configured"
			_hc_warn=$((_hc_warn + 1))
		elif [ -f "$log_path" ] && [ -r "$log_path" ]; then
			echo "[PASS] $log_name: $log_path (exists, readable)"
			_hc_pass=$((_hc_pass + 1))
		else
			echo "[WARN] $log_name: $log_path (not found)"
			_hc_warn=$((_hc_warn + 1))
		fi
	done
}

# _hc_binaries — validate firewall backend and ban/unban binaries
_hc_binaries() {
	echo "[PASS] Firewall backend: $_FW_BACKEND ($(fw_status))"
	_hc_pass=$((_hc_pass + 1))

	if [ "$_FW_BACKEND" = "custom" ]; then
		local ban_bin
		ban_bin=$(echo "$BAN_COMMAND_TEMPLATE" | awk '{print $1}')
		if [ -z "$ban_bin" ]; then
			echo "[FAIL] BAN_COMMAND: not configured"
			_hc_fail=$((_hc_fail + 1))
		elif [ -x "$ban_bin" ]; then
			echo "[PASS] BAN_COMMAND binary: $ban_bin (found)"
			_hc_pass=$((_hc_pass + 1))
		else
			echo "[WARN] BAN_COMMAND binary: $ban_bin (not found)"
			_hc_warn=$((_hc_warn + 1))
		fi

		if [ -n "${UNBAN_COMMAND_TEMPLATE:-}" ]; then
			local unban_bin
			unban_bin=$(echo "$UNBAN_COMMAND_TEMPLATE" | awk '{print $1}')
			if [ -x "$unban_bin" ]; then
				echo "[PASS] UNBAN_COMMAND binary: $unban_bin (found)"
				_hc_pass=$((_hc_pass + 1))
			else
				echo "[WARN] UNBAN_COMMAND binary: $unban_bin (not found)"
				_hc_warn=$((_hc_warn + 1))
			fi
		elif [ "${BAN_TTL:-${BAN_DURATION:-0}}" -gt 0 ]; then
			echo "[WARN] UNBAN_COMMAND is empty; temp bans won't auto-unban firewall rules"
			_hc_warn=$((_hc_warn + 1))
		fi

		if [ -n "${BAN_COMMAND_V6_TEMPLATE:-}" ]; then
			local ban_v6_bin
			ban_v6_bin=$(echo "$BAN_COMMAND_V6_TEMPLATE" | awk '{print $1}')
			if [ -x "$ban_v6_bin" ]; then
				echo "[PASS] BAN_COMMAND_V6 binary: $ban_v6_bin (found)"
				_hc_pass=$((_hc_pass + 1))
			else
				echo "[WARN] BAN_COMMAND_V6 binary: $ban_v6_bin (not found)"
				_hc_warn=$((_hc_warn + 1))
			fi
		else
			echo "[PASS] BAN_COMMAND_V6: not configured (will use BAN_COMMAND for IPv6)"
			_hc_pass=$((_hc_pass + 1))
		fi

		if [ -n "${UNBAN_COMMAND_V6_TEMPLATE:-}" ]; then
			local unban_v6_bin
			unban_v6_bin=$(echo "$UNBAN_COMMAND_V6_TEMPLATE" | awk '{print $1}')
			if [ -x "$unban_v6_bin" ]; then
				echo "[PASS] UNBAN_COMMAND_V6 binary: $unban_v6_bin (found)"
				_hc_pass=$((_hc_pass + 1))
			else
				echo "[WARN] UNBAN_COMMAND_V6 binary: $unban_v6_bin (not found)"
				_hc_warn=$((_hc_warn + 1))
			fi
		fi
	fi

	local has_journalctl=0
	if command -v journalctl >/dev/null 2>&1; then
		local jctl_bin
		jctl_bin=$(command -v journalctl)
		echo "[PASS] journalctl: available ($jctl_bin)"
		_hc_pass=$((_hc_pass + 1))
		has_journalctl=1
	else
		echo "[SKIP] journalctl: not available (file-only mode)"
		_hc_pass=$((_hc_pass + 1))
	fi
	local _hc_bin
	for _hc_bin in awk grep sed date hostname; do
		vout "  command: $_hc_bin = $(command -v "$_hc_bin" 2>/dev/null || echo 'not found')"
	done
	_hc_has_journalctl="$has_journalctl"

	local log_source="${LOG_SOURCE:-auto}"
	if [ "$log_source" = "auto" ]; then
		echo "[PASS] LOG_SOURCE: auto (journal fallback enabled)"
	elif [ "$log_source" = "journal" ]; then
		echo "[PASS] LOG_SOURCE: journal (prefer journal for syslog rules)"
	else
		echo "[PASS] LOG_SOURCE: file (journal disabled)"
	fi
	_hc_pass=$((_hc_pass + 1))
}

# _hc_rules install_path — scan and validate rules
_hc_rules() {
	local install_path="$1"
	local rules_active=0 rules_inactive=0 rules_total=0
	local log_source="${LOG_SOURCE:-auto}"
	if [ -d "${RULES_PATH:-$install_path/rules}" ]; then
		local rule_file rule_name
		for rule_file in "${RULES_PATH:-$install_path/rules}"/*; do
			[ ! -f "$rule_file" ] && continue
			rule_name=$(basename "$rule_file")
			rules_total=$((rules_total + 1))
			_save_rule_vars
			_clear_rule_vars
			if safe_source "$rule_file" "rule:$rule_name" 2>/dev/null; then
				_compat_rule_vars
				_apply_pressure "$rule_name"
				_apply_thresholds "$rule_name"
				if _rule_is_active; then
					local rule_weight="${PRESSURE_WEIGHT:-1}"
					local rule_trip="${PRESSURE_TRIP:-${TRIG:-${GLOB_PRESSURE_TRIP:-${GLOB_TRIG:-20}}}}"
					if [ -n "${LOG_FILE:-}" ] && [ ! -f "$LOG_FILE" ] && [ "$_hc_has_journalctl" -eq 1 ] && \
					   [ "$log_source" != "file" ] && \
					   tlog_journal_filter "${LOG_TAG:-}" >/dev/null 2>&1; then
						rules_active=$((rules_active + 1))
						echo "  [PASS] $rule_name: active via journal (weight=$rule_weight, trip=$rule_trip, PORTS=${PORTS:-all})"
					else
						rules_active=$((rules_active + 1))
						echo "  [PASS] $rule_name: active (weight=$rule_weight, trip=$rule_trip, PORTS=${PORTS:-all}, LOG=${LOG_FILE:-n/a})"
					fi
				else
					rules_inactive=$((rules_inactive + 1))
					echo "  [SKIP] $rule_name: inactive (PREREQ ${PREREQ:-unset} not found)"
				fi
			else
				rules_inactive=$((rules_inactive + 1))
				echo "  [SKIP] $rule_name: failed to source"
			fi
			_restore_rule_vars
		done
		echo "[PASS] Rules: $rules_active active, $rules_inactive inactive ($rules_total total)"
		_hc_pass=$((_hc_pass + 1))
		echo "  Pressure model: half-life ${PRESSURE_HALF_LIFE:-${TRIG_WINDOW:-300}}s, trip ${PRESSURE_TRIP:-${TRIG:-20}}, global trip ${PRESSURE_TRIP_GLOBAL:-${TRIG_GLOBAL:-0}}"
	else
		echo "[FAIL] Rules directory not found: ${RULES_PATH:-$install_path/rules}"
		_hc_fail=$((_hc_fail + 1))
	fi
}

# _hc_state install_path — validate tlog, state dirs, lock, active bans
_hc_state() {
	local install_path="$1"

	local tlog="${TLOG_PATH:-$install_path/tlog}"
	if [ -f "$tlog" ] && [ -x "$tlog" ]; then
		echo "[PASS] tlog: $tlog (executable)"
		_hc_pass=$((_hc_pass + 1))
	elif [ -f "$tlog" ]; then
		echo "[WARN] tlog: $tlog (exists but not executable)"
		_hc_warn=$((_hc_warn + 1))
	else
		echo "[WARN] tlog: $tlog (not found)"
		_hc_warn=$((_hc_warn + 1))
	fi

	local _tlog_lib="${INSTALL_PATH:-$install_path}/internals/tlog_lib.sh"
	if [ -f "$_tlog_lib" ]; then
		echo "[PASS] tlog_lib.sh: $_tlog_lib (present)"
		_hc_pass=$((_hc_pass + 1))
	else
		echo "[WARN] tlog_lib.sh: $_tlog_lib (not found)"
		_hc_warn=$((_hc_warn + 1))
	fi

	local _tlog_br="${TLOG_BASERUN:-$install_path/tmp}"
	if [ -d "$_tlog_br" ] && [ -d "$install_path/stats" ]; then
		echo "[PASS] State: TLOG_BASERUN=$_tlog_br and stats/ exist"
		_hc_pass=$((_hc_pass + 1))
	else
		echo "[WARN] State: missing tmp/ or stats/ directory"
		_hc_warn=$((_hc_warn + 1))
	fi

	local lock="${LOCK_FILE:-$install_path/lock.utime}"
	if [ -f "$lock" ]; then
		echo "[WARN] Lock: active lock file exists ($lock)"
		_hc_warn=$((_hc_warn + 1))
	else
		echo "[PASS] Lock: no active lock"
		_hc_pass=$((_hc_pass + 1))
	fi

	echo "[PASS] WATCH_INTERVAL: ${WATCH_INTERVAL:-10}s (for bfd --watch)"
	_hc_pass=$((_hc_pass + 1))

	local bans_file="$install_path/tmp/bans.active"
	local ban_count=0
	if [ -f "$bans_file" ] && [ -s "$bans_file" ]; then
		ban_count=$(wc -l < "$bans_file")
	fi
	echo "[PASS] Active bans: $ban_count"
	_hc_pass=$((_hc_pass + 1))
}

# _hc_alerts — validate email alert configuration
_hc_alerts() {
	if [ "$EMAIL_ALERTS" != "1" ]; then
		echo "[PASS] Email alerts: disabled"
		_hc_pass=$((_hc_pass + 1))
	else
		# mail command (local MTA)
		if command -v mail >/dev/null 2>&1; then
			echo "[PASS] Email alerts: enabled (mail command found)"
			_hc_pass=$((_hc_pass + 1))
		else
			echo "[WARN] Email alerts: enabled but 'mail' command not found"
			_hc_warn=$((_hc_warn + 1))
		fi
		# sendmail required for html/both formats
		local _ef="${EMAIL_FORMAT:-text}"
		if [ "$_ef" = "html" ] || [ "$_ef" = "both" ]; then
			if command -v sendmail >/dev/null 2>&1; then
				echo "[PASS] sendmail: found (required for EMAIL_FORMAT=$_ef)"
				_hc_pass=$((_hc_pass + 1))
			else
				echo "[WARN] sendmail: not found (EMAIL_FORMAT=$_ef will fall back to text)"
				_hc_warn=$((_hc_warn + 1))
			fi
		fi
		# SMTP relay checks
		if [ -n "${SMTP_RELAY:-}" ]; then
			if command -v curl >/dev/null 2>&1; then
				echo "[PASS] curl: found (required for SMTP relay)"
				_hc_pass=$((_hc_pass + 1))
			else
				echo "[WARN] curl: not found (SMTP relay delivery will fail)"
				_hc_warn=$((_hc_warn + 1))
			fi
			if [ -z "${SMTP_FROM:-}" ]; then
				echo "[WARN] SMTP_FROM: not set (required for SMTP relay)"
				_hc_warn=$((_hc_warn + 1))
			fi
			if [ -z "${SMTP_USER:-}" ] || [ -z "${SMTP_PASS:-}" ]; then
				echo "[WARN] SMTP credentials: SMTP_USER/SMTP_PASS not set"
				_hc_warn=$((_hc_warn + 1))
			fi
		fi
	fi
	# Alert template directory
	local _atd="${ALERT_TEMPLATE_DIR:-}"
	if [ -n "$_atd" ]; then
		if [ -d "$_atd" ]; then
			echo "[PASS] Alert templates: $_atd (exists)"
			_hc_pass=$((_hc_pass + 1))
			# check for all 8 template partials
			local _tpl _tpl_missing=0
			for _tpl in text.header.tpl text.entry.tpl text.summary.tpl text.footer.tpl \
			            html.header.tpl html.entry.tpl html.summary.tpl html.footer.tpl; do
				if [ ! -f "$_atd/$_tpl" ]; then
					echo "[WARN] Alert template missing: $_tpl"
					_hc_warn=$((_hc_warn + 1))
					_tpl_missing=1
				fi
			done
			if [ "$_tpl_missing" -eq 0 ]; then
				echo "[PASS] Alert templates: all 8 partials present"
				_hc_pass=$((_hc_pass + 1))
			fi
			# report custom.d/ overrides
			local _custom_dir="$_atd/custom.d"
			if [ -d "$_custom_dir" ]; then
				local _custom_count=0
				for _tpl in text.header.tpl text.entry.tpl text.summary.tpl text.footer.tpl \
				            html.header.tpl html.entry.tpl html.summary.tpl html.footer.tpl; do
					if [ -f "$_custom_dir/$_tpl" ]; then
						echo "[PASS] Custom override: $_tpl"
						_hc_pass=$((_hc_pass + 1))
						_custom_count=$((_custom_count + 1))
					fi
				done
				if [ "$_custom_count" -gt 0 ]; then
					echo "[PASS] Custom templates: $_custom_count override(s) active in custom.d/"
					_hc_pass=$((_hc_pass + 1))
				fi
			fi
		else
			echo "[WARN] Alert templates: $_atd (not found)"
			_hc_warn=$((_hc_warn + 1))
		fi
	fi

	# --- Slack health checks ---
	if [ "${SLACK_ALERTS:-0}" = "1" ]; then
		if command -v curl >/dev/null 2>&1; then
			echo "[PASS] Slack alerts: enabled (curl found)"
			_hc_pass=$((_hc_pass + 1))
		else
			echo "[FAIL] Slack alerts: enabled but curl not found"
			_hc_fail=$((_hc_fail + 1))
		fi
		local _sm="${SLACK_MODE:-webhook}"
		if [ "$_sm" = "webhook" ]; then
			if [ -n "${SLACK_WEBHOOK_URL:-}" ]; then
				echo "[PASS] Slack webhook URL: configured"
				_hc_pass=$((_hc_pass + 1))
			else
				echo "[FAIL] Slack webhook URL: SLACK_WEBHOOK_URL not set"
				_hc_fail=$((_hc_fail + 1))
			fi
		elif [ "$_sm" = "bot" ]; then
			if [ -n "${SLACK_TOKEN:-}" ]; then
				echo "[PASS] Slack token: configured"
				_hc_pass=$((_hc_pass + 1))
			else
				echo "[FAIL] Slack token: SLACK_TOKEN not set"
				_hc_fail=$((_hc_fail + 1))
			fi
			if [ -n "${SLACK_CHANNEL:-}" ]; then
				echo "[PASS] Slack channel: configured"
				_hc_pass=$((_hc_pass + 1))
			else
				echo "[FAIL] Slack channel: SLACK_CHANNEL not set"
				_hc_fail=$((_hc_fail + 1))
			fi
		else
			echo "[WARN] Slack mode: unknown value '$_sm' (expected: webhook, bot)"
			_hc_warn=$((_hc_warn + 1))
		fi
	fi

	# --- Telegram health checks ---
	if [ "${TELEGRAM_ALERTS:-0}" = "1" ]; then
		if command -v curl >/dev/null 2>&1; then
			echo "[PASS] Telegram alerts: enabled (curl found)"
			_hc_pass=$((_hc_pass + 1))
		else
			echo "[FAIL] Telegram alerts: enabled but curl not found"
			_hc_fail=$((_hc_fail + 1))
		fi
		if [ -n "${TELEGRAM_BOT_TOKEN:-}" ]; then
			echo "[PASS] Telegram bot token: configured"
			_hc_pass=$((_hc_pass + 1))
		else
			echo "[FAIL] Telegram bot token: TELEGRAM_BOT_TOKEN not set"
			_hc_fail=$((_hc_fail + 1))
		fi
		if [ -n "${TELEGRAM_CHAT_ID:-}" ]; then
			echo "[PASS] Telegram chat ID: configured"
			_hc_pass=$((_hc_pass + 1))
		else
			echo "[FAIL] Telegram chat ID: TELEGRAM_CHAT_ID not set"
			_hc_fail=$((_hc_fail + 1))
		fi
	fi

	# --- Discord health checks ---
	if [ "${DISCORD_ALERTS:-0}" = "1" ]; then
		if command -v curl >/dev/null 2>&1; then
			echo "[PASS] Discord alerts: enabled (curl found)"
			_hc_pass=$((_hc_pass + 1))
		else
			echo "[FAIL] Discord alerts: enabled but curl not found"
			_hc_fail=$((_hc_fail + 1))
		fi
		if [ -n "${DISCORD_WEBHOOK_URL:-}" ]; then
			echo "[PASS] Discord webhook URL: configured"
			_hc_pass=$((_hc_pass + 1))
		else
			echo "[FAIL] Discord webhook URL: DISCORD_WEBHOOK_URL not set"
			_hc_fail=$((_hc_fail + 1))
		fi
	fi
}

# health_check install_path — non-destructive diagnostic report
# Validates configuration, paths, rules, state, and reports status.
# Each check prints [PASS], [WARN], [FAIL], or [SKIP] with description.
health_check() {
	local install_path="$1"
	_hc_pass=0 _hc_warn=0 _hc_fail=0
	_hc_has_journalctl=0

	_hc_config
	_hc_binaries
	_hc_rules "$install_path"
	_hc_state "$install_path"
	_hc_alerts

	echo
	echo "Summary: $_hc_pass passed, $_hc_warn warnings, $_hc_fail failures"
}

# format_duration seconds — human-readable duration string
# 0 → "permanent", 30 → "30s", 300 → "5m", 3661 → "1h 1m"
format_duration() {
	local seconds="$1"
	if [ "$seconds" -eq 0 ]; then
		echo "permanent"
		return 0
	fi
	local hours minutes secs result=""
	hours=$((seconds / 3600))
	minutes=$(( (seconds % 3600) / 60 ))
	secs=$((seconds % 60))
	if [ "$hours" -gt 0 ]; then
		result="${hours}h"
	fi
	if [ "$minutes" -gt 0 ]; then
		if [ -n "$result" ]; then
			result="$result ${minutes}m"
		else
			result="${minutes}m"
		fi
	fi
	if [ "$secs" -gt 0 ] && [ "$hours" -eq 0 ]; then
		if [ -n "$result" ]; then
			result="$result ${secs}s"
		else
			result="${secs}s"
		fi
	fi
	# edge case: exactly N hours with 0 minutes and 0 seconds
	if [ -z "$result" ]; then
		result="${hours}h"
	fi
	echo "$result"
}

# detect_run_mode — determine how BFD is being run.
# Outputs one of: watch/systemd, watch/init, watch/manual,
# timer/systemd, cron, unknown
detect_run_mode() {
	local watch_pid=""
	watch_pid=$(pgrep -f "bfd.*--watch" 2>/dev/null | head -1) || true  # no process is normal
	if [ -z "$watch_pid" ]; then
		watch_pid=$(pgrep -f "bfd.*-w " 2>/dev/null | head -1) || true  # no process is normal
	fi
	if [ -n "$watch_pid" ] && [ "$watch_pid" != "$$" ]; then
		if command -v systemctl >/dev/null 2>&1 && \
		   systemctl is-active bfd-watch.service >/dev/null 2>&1; then
			echo "watch/systemd"
		elif [ -f /var/run/bfd-watch.pid ]; then
			echo "watch/init"
		else
			echo "watch/manual"
		fi
		return 0
	fi
	if command -v systemctl >/dev/null 2>&1; then
		if systemctl is-active bfd.timer >/dev/null 2>&1; then
			echo "timer/systemd"
			return 0
		fi
	fi
	if [ -f /etc/cron.d/bfd ] || crontab -l 2>/dev/null | grep -q 'bfd'; then
		echo "cron"
		return 0
	fi
	echo "unknown"
}

# show_status install_path — display global system status
show_status() {
	local install_path="$1"
	local now
	now=$(date +"%s")

	echo "BFD Status ($(date +"%Y-%m-%d %H:%M:%S"))"
	echo ""

	# Mode detection via detect_run_mode()
	local run_mode mode="unknown"
	run_mode=$(detect_run_mode)
	case "$run_mode" in
		watch/*)
			local watch_pid=""
			watch_pid=$(pgrep -f "bfd.*--watch" 2>/dev/null | head -1) || true  # no process is normal
			if [ -z "$watch_pid" ]; then
				watch_pid=$(pgrep -f "bfd.*-w " 2>/dev/null | head -1) || true  # no process is normal
			fi
			local uptime_secs=""
			if [ -n "$watch_pid" ]; then
				uptime_secs=$(ps -o etimes= -p "$watch_pid" 2>/dev/null | tr -d ' ') || uptime_secs=""
			fi
			local watch_type="${run_mode#watch/}"
			if [ -n "$uptime_secs" ]; then
				mode="watch ($watch_type, pid $watch_pid, uptime $(format_duration "$uptime_secs"))"
			else
				mode="watch ($watch_type${watch_pid:+, pid $watch_pid})"
			fi
			;;
		timer/systemd)
			mode="timer (systemd)"
			;;
		cron)
			mode="cron (/etc/cron.d/bfd)"
			;;
		*)
			mode="unknown (no scheduler detected)"
			;;
	esac
	echo "  Mode:           $mode"
	vout "  (detected via: $run_mode)"

	# Firewall backend
	if [ -n "${_FW_BACKEND:-}" ]; then
		local fw_auto=""
		if [ "${FIREWALL:-auto}" = "auto" ]; then
			fw_auto=" (auto-detected)"
		fi
		echo "  Firewall:       ${_FW_BACKEND}${fw_auto}"
	fi

	# Active bans
	local bans_file="$install_path/tmp/bans.active"
	local total_bans=0 temp_bans=0 perm_bans=0
	if [ -f "$bans_file" ] && [ -s "$bans_file" ]; then
		total_bans=$(wc -l < "$bans_file")
		perm_bans=$(awk '$2+0 == 0' "$bans_file" | wc -l)
		temp_bans=$((total_bans - perm_bans))
	fi
	echo "  Active bans:    $total_bans ($temp_bans temporary, $perm_bans permanent)"

	# Events (24h) from pressure.dat
	local events_file="$install_path/tmp/pressure.dat"
	local cutoff_24h=$((now - 86400))
	local event_count=0 service_count=0
	if [ -f "$events_file" ] && [ -s "$events_file" ]; then
		event_count=$(awk -v cutoff="$cutoff_24h" '$1+0 >= cutoff' "$events_file" | wc -l)
		service_count=$(awk -v cutoff="$cutoff_24h" '$1+0 >= cutoff {s[$3]=1} END {for(k in s) c++; print c+0}' "$events_file")
	fi
	echo "  Events (24h):   $event_count across $service_count services"

	# Last run from bfd_log
	local last_run=""
	if [ -f "${BFD_LOG_PATH:-/var/log/bfd_log}" ]; then
		last_run=$(grep 'run complete:' "${BFD_LOG_PATH:-/var/log/bfd_log}" 2>/dev/null | tail -1)
	fi
	if [ -n "$last_run" ]; then
		local run_ts run_info
		run_ts=$(echo "$last_run" | awk '{print $1, $2, $3}')
		run_info=$(echo "$last_run" | sed 's/.*run complete: //')
		echo "  Last run:       $run_ts ($run_info)"
	else
		echo "  Last run:       unknown"
	fi

	# Top attacker
	if [ -f "$events_file" ] && [ -s "$events_file" ]; then
		local top_line top_count top_ip top_svc
		top_line=$(awk -v cutoff="$cutoff_24h" '$1+0 >= cutoff {print $2}' "$events_file" \
			| sort | uniq -c | sort -rn | head -1)
		if [ -n "$top_line" ]; then
			top_count=$(echo "$top_line" | awk '{print $1}')
			top_ip=$(echo "$top_line" | awk '{print $2}')
			top_svc=$(awk -v cutoff="$cutoff_24h" -v ip="$top_ip" \
				'$1+0 >= cutoff && $2 == ip {print $3}' "$events_file" \
				| sort | uniq -c | sort -rn | head -1 | awk '{print $2}')
			echo "  Top attacker:   $top_ip ($top_svc, $top_count events)"
		fi
	fi
	echo ""

	# Active rules
	local rules_active=0 rules_total=0
	if [ -d "${RULES_PATH:-$install_path/rules}" ]; then
		local rule_file rule_name
		for rule_file in "${RULES_PATH:-$install_path/rules}"/*; do
			[ ! -f "$rule_file" ] && continue
			rules_total=$((rules_total + 1))
			rule_name=$(basename "$rule_file")
			_save_rule_vars
			_clear_rule_vars
			if safe_source "$rule_file" "rule:$rule_name" 2>/dev/null; then
				_compat_rule_vars
				if _rule_is_active; then
					rules_active=$((rules_active + 1))
				fi
			fi
			_restore_rule_vars
		done
	fi
	echo "  Active Rules:   $rules_active/$rules_total"

	# Top services
	if [ -f "$events_file" ] && [ -s "$events_file" ]; then
		local top_svcs
		top_svcs=$(awk -v cutoff="$cutoff_24h" \
			'$1+0 >= cutoff {s[$3]++} END {for(k in s) print s[k], k}' \
			"$events_file" | sort -rn | head -3 \
			| awk '{if(NR>1) printf ", "; printf "%s (%s)", $2, $1}')
		if [ -n "$top_svcs" ]; then
			echo "  Top services:   $top_svcs"
		fi
	fi

	# Top-5 IPs by current pressure
	local half_life="${PRESSURE_HALF_LIFE:-${TRIG_WINDOW:-300}}"
	if [ -f "$events_file" ] && [ -s "$events_file" ]; then
		local top_pressure
		top_pressure=$(_pressure_aggregate_all "$events_file" "$now" "$half_life" | head -5)
		if [ -n "$top_pressure" ]; then
			echo ""
			echo "  Top pressure:"
			local p_scaled p_ip
			while read -r p_scaled p_ip; do
				[ -z "$p_scaled" ] && continue
				local p_disp
				p_disp=$(pressure_format "$p_scaled")
				echo "    $p_ip: $p_disp"
			done <<< "$top_pressure"
		fi
	fi
}

# show_service_status install_path service — per-service status display
show_service_status() {
	local install_path="$1" service="$2"
	local now
	now=$(date +"%s")

	echo "BFD Status: $service ($(date +"%Y-%m-%d %H:%M:%S"))"
	echo ""

	# Find rule file
	local rule_file="${RULES_PATH:-$install_path/rules}/$service"
	if [ ! -f "$rule_file" ]; then
		echo "  error: no rule found for '$service'"
		return 1
	fi

	# Source rule to get config
	_save_rule_vars
	_clear_rule_vars
	safe_source "$rule_file" "rule:$service" 2>/dev/null
	_compat_rule_vars
	_apply_pressure "$service"
	_apply_thresholds "$service"

	local rule_weight="${PRESSURE_WEIGHT:-1}"
	local rule_trip="${PRESSURE_TRIP:-${TRIG:-${GLOB_PRESSURE_TRIP:-${GLOB_TRIG:-20}}}}"
	local half_life="${PRESSURE_HALF_LIFE:-${TRIG_WINDOW:-300}}"
	local rule_ports="${PORTS:-all}"

	# Log source
	if [ -n "${LOG_FILE:-}" ] && [ -f "$LOG_FILE" ]; then
		echo "  Log:            $LOG_FILE (file)"
	elif command -v journalctl >/dev/null 2>&1 && \
	     tlog_journal_filter "${LOG_TAG:-}" >/dev/null 2>&1; then
		echo "  Log:            journal (${LOG_TAG:-})"
	else
		echo "  Log:            not available"
	fi

	echo "  Weight:         $rule_weight"
	echo "  Trip:           $rule_trip (half-life ${half_life}s)"
	echo "  Ports:          $rule_ports"

	# Events (24h) for this service
	local events_file="$install_path/tmp/pressure.dat"
	local cutoff_24h=$((now - 86400))
	local svc_events=0 svc_ips=0
	if [ -f "$events_file" ] && [ -s "$events_file" ]; then
		svc_events=$(awk -v cutoff="$cutoff_24h" -v svc="$service" \
			'$1+0 >= cutoff && $3 == svc' "$events_file" | wc -l)
		svc_ips=$(awk -v cutoff="$cutoff_24h" -v svc="$service" \
			'$1+0 >= cutoff && $3 == svc {ips[$2]=1} END {for(k in ips) c++; print c+0}' \
			"$events_file")
	fi
	echo "  Events (24h):   $svc_events from $svc_ips unique IPs"

	# Active bans for this service
	local bans_file="$install_path/tmp/bans.active"
	if [ -f "$bans_file" ] && [ -s "$bans_file" ]; then
		local svc_bans
		svc_bans=$(awk -v svc="$service" '$4 == svc' "$bans_file")
		if [ -n "$svc_bans" ]; then
			local ban_count
			ban_count=$(echo "$svc_bans" | wc -l)
			echo "  Active bans:    $ban_count"
			local ts expiry ip mod ports
			# shellcheck disable=SC2034  # mod and ports consumed for positional field alignment
			while IFS=' ' read -r ts expiry ip mod ports; do
				[ -z "$ts" ] && continue
				if [ "$expiry" = "0" ]; then
					echo "    $ip (permanent)"
				else
					local remain=$(( (expiry - now) / 60 ))
					[ "$remain" -lt 0 ] && remain=0
					echo "    $ip (expires in ${remain}m)"
				fi
			done <<< "$svc_bans"
		else
			echo "  Active bans:    0"
		fi
	else
		echo "  Active bans:    0"
	fi

	# Restore saved variables
	_restore_rule_vars
}

# show_config [var] — dump active config or single variable value
show_config() {
	local var="${1:-}"
	local config_vars="FIREWALL PRESSURE_TRIP PRESSURE_HALF_LIFE PRESSURE_TRIP_GLOBAL SUBNET_TRIG SUBNET_MASK SUBNET_MASK_V6 BAN_COMMAND BAN_COMMAND_V6 UNBAN_COMMAND UNBAN_COMMAND_V6 BAN_TTL BAN_ESCALATE_AFTER BAN_ESCALATE_WINDOW BAN_RETRY_COUNT BAN_ESCALATION BAN_ESCALATION_CAP EMAIL_ALERTS EMAIL_ADDRESS EMAIL_SUBJECT EMAIL_LOGLINES EMAIL_FORMAT EMAIL_DIGEST EMAIL_DIGEST_INTERVAL EMAIL_REPUTATION_LINKS SMTP_RELAY SMTP_FROM SMTP_USER SMTP_PASS SLACK_ALERTS SLACK_MODE SLACK_WEBHOOK_URL SLACK_TOKEN SLACK_CHANNEL TELEGRAM_ALERTS TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID DISCORD_ALERTS DISCORD_WEBHOOK_URL ALERT_TEMPLATE_DIR REPORT_ENABLED REPORT_INTERVALS REPORT_CHANNELS REPORT_EMAIL_ADDRESS REPORT_EMAIL_SUBJECT REPORT_TOP_N LOG_FORMAT LOG_LEVEL LOG_SOURCE AUTH_LOG_PATH KERNEL_LOG_PATH MAIL_LOG_PATH BFD_LOG_PATH OUTPUT_SYSLOG LOG_IDLE_SUPPRESS OUTPUT_SYSLOG_FILE LOCK_FILE_TIMEOUT WATCH_INTERVAL SCAN_MAX_LINES SCAN_TIMEOUT APOOL_RETENTION_DAYS APOOL_MAX_LINES PRESSURE_CONF"
	local _secret_vars="SMTP_USER SMTP_PASS SLACK_WEBHOOK_URL SLACK_TOKEN TELEGRAM_BOT_TOKEN DISCORD_WEBHOOK_URL"

	# _mask_secret val — mask sensitive values for display
	# Shows first 8 and last 4 chars for long values, "****" for short/empty
	_mask_secret() {
		local val="$1"
		local len=${#val}
		if [ "$len" -le 12 ] || [ -z "$val" ]; then
			echo "****"
		else
			echo "${val:0:8}...${val: -4}"
		fi
	}

	if [ -n "$var" ]; then
		# validate against whitelist
		local _found=0 _v
		for _v in $config_vars; do
			if [ "$var" = "$_v" ]; then
				_found=1
				break
			fi
		done
		if [ "$_found" -eq 0 ]; then
			echo "error: unknown config variable '$var'." >&2
			return 1
		fi
		# map user-facing BAN_COMMAND names to _TEMPLATE variants
		# (conf.bfd expands $ATTACK_HOST at source time; templates have raw text)
		case "$var" in
			BAN_COMMAND)      var="BAN_COMMAND_TEMPLATE" ;;
			UNBAN_COMMAND)    var="UNBAN_COMMAND_TEMPLATE" ;;
			BAN_COMMAND_V6)   var="BAN_COMMAND_V6_TEMPLATE" ;;
			UNBAN_COMMAND_V6) var="UNBAN_COMMAND_V6_TEMPLATE" ;;
		esac
		local val
		val="${!var}"
		# mask secrets in single-var lookup
		local _sv _is_secret=0
		for _sv in $_secret_vars; do
			if [ "$var" = "$_sv" ]; then
				_is_secret=1
				break
			fi
		done
		if [ "$_is_secret" -eq 1 ] && [ -n "$val" ]; then
			val=$(_mask_secret "$val")
		fi
		echo "$val"
	else
		# dump all active config variables
		local v val _display
		for v in $config_vars; do
			_display="$v"
			case "$v" in
				BAN_COMMAND)      v="BAN_COMMAND_TEMPLATE" ;;
				UNBAN_COMMAND)    v="UNBAN_COMMAND_TEMPLATE" ;;
				BAN_COMMAND_V6)   v="BAN_COMMAND_V6_TEMPLATE" ;;
				UNBAN_COMMAND_V6) v="UNBAN_COMMAND_V6_TEMPLATE" ;;
			esac
			val="${!v}"
			# mask secrets in dump-all output
			local _sv _is_secret=0
			for _sv in $_secret_vars; do
				if [ "$v" = "$_sv" ]; then
					_is_secret=1
					break
				fi
			done
			if [ "$_is_secret" -eq 1 ] && [ -n "$val" ]; then
				val=$(_mask_secret "$val")
			fi
			echo "$_display=$val"
		done
	fi
}

# list_rules install_path [active_only] — list all rules with status in table format
list_rules() {
	local install_path="$1"
	local active_only="${2:-0}"
	local rules_dir="${RULES_PATH:-$install_path/rules}"
	local log_source="${LOG_SOURCE:-auto}"

	if [ ! -d "$rules_dir" ]; then
		echo "error: rules directory not found." >&2
		return 1
	fi

	local atmp
	atmp=$(mktemp "$install_path/tmp/.rules.XXXXXX")
	echo "RULE|STATUS|WEIGHT|TRIP|PORTS|LOG SOURCE" > "$atmp"

	local active=0 inactive=0 total=0
	local has_journalctl=0
	if [ "$log_source" != "file" ] && command -v journalctl >/dev/null 2>&1; then
		has_journalctl=1
	fi
	local rule_file rule_name
	for rule_file in "$rules_dir"/*; do
		[ ! -f "$rule_file" ] && continue
		rule_name=$(basename "$rule_file")
		total=$((total + 1))

		_save_rule_vars
		_clear_rule_vars

		if safe_source "$rule_file" "rule:$rule_name" 2>/dev/null; then
			_compat_rule_vars
			_apply_pressure "$rule_name"
			_apply_thresholds "$rule_name"
			local rule_weight="${PRESSURE_WEIGHT:-1}"
			local rule_trip="${PRESSURE_TRIP:-${TRIG:-${GLOB_PRESSURE_TRIP:-${GLOB_TRIG:-20}}}}"
			local rule_ports="${PORTS:-all}"
			if _rule_is_active; then
				active=$((active + 1))
				local log_info
				log_info=$(_resolve_log_source_label "$log_source" "$has_journalctl")
				echo "$rule_name|active|$rule_weight|$rule_trip|$rule_ports|$log_info" >> "$atmp"
			else
				inactive=$((inactive + 1))
				if [ "$active_only" != "1" ]; then
					echo "$rule_name|inactive|-|-|-|(no prereq)" >> "$atmp"
				fi
			fi
		else
			inactive=$((inactive + 1))
			if [ "$active_only" != "1" ]; then
				echo "$rule_name|error|-|-|-|(source failed)" >> "$atmp"
			fi
		fi

		_restore_rule_vars
	done

	format_table < "$atmp"
	echo ""
	if [ "$active_only" = "1" ]; then
		echo "$active active (filtered, $total total)"
	else
		echo "$active active, $inactive inactive ($total total)"
	fi
	command rm -f "$atmp"
}

# show_rule install_path rule_name — show detailed rule info
show_rule() {
	local install_path="$1" rule_name="$2"
	local rule_file="${RULES_PATH:-$install_path/rules}/$rule_name"
	local log_source="${LOG_SOURCE:-auto}"

	if [ ! -f "$rule_file" ]; then
		echo "error: rule '$rule_name' not found." >&2
		return 1
	fi

	echo "Rule: $rule_name"

	_save_rule_vars
	_clear_rule_vars

	if ! safe_source "$rule_file" "rule:$rule_name" 2>/dev/null; then
		echo "  Status:     error (failed to source)"
		_restore_rule_vars
		return 1
	fi
	_compat_rule_vars
	_apply_pressure "$rule_name"
	_apply_thresholds "$rule_name"

	if _rule_is_active; then
		echo "  Status:     active"
	else
		echo "  Status:     inactive (${PREREQ:-unset} not found)"
	fi

	local rule_weight="${PRESSURE_WEIGHT:-1}"
	local rule_trip="${PRESSURE_TRIP:-${TRIG:-${GLOB_PRESSURE_TRIP:-${GLOB_TRIG:-20}}}}"
	local half_life="${PRESSURE_HALF_LIFE:-${TRIG_WINDOW:-300}}"
	echo "  Weight:     $rule_weight"
	echo "  Trip:       $rule_trip (half-life ${half_life}s)"
	echo "  Ports:      ${PORTS:-all}"

	local has_journalctl=0
	if [ "$log_source" != "file" ] && command -v journalctl >/dev/null 2>&1; then
		has_journalctl=1
	fi
	local has_journal=0
	if [ "$has_journalctl" = "1" ] && [ -n "${LOG_TAG:-}" ] && \
	   tlog_journal_filter "$LOG_TAG" >/dev/null 2>&1; then
		has_journal=1
	fi
	if [ -n "${LOG_FILE:-}" ] && [ -f "$LOG_FILE" ]; then
		if [ "$has_journal" = "1" ]; then
			echo "  Log:        $LOG_FILE (file, journal avail: $LOG_TAG)"
		else
			echo "  Log:        $LOG_FILE (file)"
		fi
	elif [ "$has_journal" = "1" ]; then
		echo "  Log:        journal ($LOG_TAG)"
	elif [ -n "${LOG_FILE:-}" ]; then
		echo "  Log:        ${LOG_FILE} (not found)"
	else
		echo "  Log:        not configured"
	fi

	_restore_rule_vars
}

# test_rule install_path rule_name [log_file] — test a rule against a log file
# Sets _TLOG_PASSTHROUGH so _rule_tlog() outputs the full file content, then
# sources the rule normally to reuse the full existing pipeline.
test_rule() {
	local install_path="$1" rule_name="$2" log_file="${3:-}"
	local rules_dir="${RULES_PATH:-$install_path/rules}"
	local rule_file="$rules_dir/$rule_name"
	[ ! -f "$rule_file" ] && { echo "error: rule '$rule_name' not found" >&2; return 1; }

	local stdin_file=""
	if [ "$log_file" = "-" ]; then
		stdin_file=$(mktemp "$install_path/tmp/.test_stdin.XXXXXX")
		cat > "$stdin_file"
		_TLOG_PASSTHROUGH="$stdin_file"
	elif [ -n "$log_file" ]; then
		[ ! -f "$log_file" ] && { echo "error: file '$log_file' not found" >&2; return 1; }
		_TLOG_PASSTHROUGH="$log_file"
	else
		_TLOG_PASSTHROUGH="1"
	fi

	# save globals, source rule, restore
	_save_rule_vars
	_clear_rule_vars
	TLOG_BASERUN="${TLOG_BASERUN:-$install_path/tmp}"
	safe_source "$rule_file" "rule:$rule_name"
	local src_rc=$?
	_TLOG_PASSTHROUGH=""

	if [ "$src_rc" -ne 0 ]; then
		echo "error: failed to source rule '$rule_name'" >&2
		command rm -f "$stdin_file"
		_restore_rule_vars
		return 1
	fi
	_compat_rule_vars
	_apply_pressure "$rule_name"
	_apply_thresholds "$rule_name"

	# report
	echo "Rule:         $rule_name"
	echo "Log file:     ${log_file:-${LOG_FILE:-n/a}}"
	echo "Weight:       ${PRESSURE_WEIGHT:-1}"
	echo "Trip:         ${PRESSURE_TRIP:-${TRIG:-${GLOB_PRESSURE_TRIP:-${GLOB_TRIG:-20}}}}"
	[ -n "${PORTS:-}" ] && echo "Ports:        $PORTS"
	echo ""

	local total=0 unique=0
	if [ -n "$MATCHED_HOSTS" ]; then
		total=$(echo "$MATCHED_HOSTS" | tr ' ' '\n' | grep -c . 2>/dev/null || echo 0)
		unique=$(echo "$MATCHED_HOSTS" | tr ' ' '\n' | sort -u | grep -c . 2>/dev/null || echo 0)
	fi
	echo "Results:      $total matches, $unique unique IPs"
	if [ "$total" -gt 0 ]; then
		echo ""
		echo "Top IPs:"
		echo "$MATCHED_HOSTS" | tr ' ' '\n' | sort | uniq -c | sort -rn | head -10 | \
			while IFS= read -r line; do
				echo "  $(echo "$line" | awk '{print $2}') ($(echo "$line" | awk '{print $1}'))"
			done
	fi

	command rm -f "$stdin_file"
	_restore_rule_vars
}

# test_pattern pattern [log_file] — test a raw <HOST> pattern against input
# Reads from log_file or stdin, runs through extract_hosts(), reports matches.
test_pattern() {
	local pattern="$1" log_file="${2:-}"
	local input
	if [ -z "$log_file" ] || [ "$log_file" = "-" ]; then
		input=$(cat)
	else
		[ ! -f "$log_file" ] && { echo "error: file '$log_file' not found" >&2; return 1; }
		input=$(cat "$log_file")
	fi

	local _sv_ign="${IGNOREREGEX:-}"
	IGNOREREGEX=""

	echo "Pattern:  \"$pattern\""
	echo ""
	local results=""
	[ -n "$input" ] && results=$(echo "$input" | extract_hosts "$pattern")
	local total=0 unique=0
	if [ -n "$results" ]; then
		total=$(echo "$results" | grep -c . 2>/dev/null || echo 0)
		unique=$(echo "$results" | sort -u | grep -c . 2>/dev/null || echo 0)
	fi
	echo "Matches:  $total"
	echo "IPs:      $unique unique"
	if [ "$total" -gt 0 ]; then
		echo ""
		echo "Top IPs:"
		echo "$results" | sort | uniq -c | sort -rn | head -10 | \
			while IFS= read -r line; do
				echo "  $(echo "$line" | awk '{print $2}') ($(echo "$line" | awk '{print $1}'))"
			done
	fi
	IGNOREREGEX="$_sv_ign"
}

# test_alert install_path [type] — dispatch test alert by type
test_alert() {
	local install_path="$1"
	local alert_type="${2:-}"

	case "$alert_type" in
		email) test_alert_email "$install_path" ;;
		slack) test_alert_messaging "$install_path" "slack" "SLACK_ALERTS" ;;
		telegram) test_alert_messaging "$install_path" "telegram" "TELEGRAM_ALERTS" ;;
		discord) test_alert_messaging "$install_path" "discord" "DISCORD_ALERTS" ;;
		"")
			echo "error: --test-alert requires a type (e.g., email, slack, telegram, discord)." >&2
			echo >&2; usage >&2; return 1 ;;
		*)
			echo "error: unknown alert type '$alert_type' (available: email, slack, telegram, discord)." >&2
			return 1 ;;
	esac
}

# test_alert_email install_path — send a test email alert through the full pipeline
# Builds a synthetic 13-field alert entry using RFC 5737 test IP and calls
# send_alerts() directly (bypasses digest spool).
test_alert_email() {
	local install_path="$1"

	# validate email is configured
	if [ "${EMAIL_ALERTS:-0}" != "1" ]; then
		echo "error: EMAIL_ALERTS is not enabled (set EMAIL_ALERTS=\"1\" in conf.bfd)." >&2
		return 1
	fi
	if [ -z "${EMAIL_ADDRESS:-}" ]; then
		echo "error: EMAIL_ADDRESS is not set in conf.bfd." >&2
		return 1
	fi

	local format="${EMAIL_FORMAT:-text}"
	local delivery="local MTA"
	if [ -n "${SMTP_RELAY:-}" ]; then
		delivery="SMTP relay ($SMTP_RELAY)"
	else
		local _sm_bin
		_sm_bin=$(command -v sendmail 2>/dev/null || true)  # binary may not be installed
		if [ -n "$_sm_bin" ] && [ "$format" != "text" ]; then
			delivery="local MTA (sendmail)"
		else
			local _ml_bin
			_ml_bin=$(command -v mail 2>/dev/null || true)  # binary may not be installed
			if [ -n "$_ml_bin" ]; then
				delivery="local MTA (mail)"
			else
				delivery="local MTA (no binary found)"
			fi
		fi
	fi

	echo "Sending test alert email..."
	echo "  Recipient: $EMAIL_ADDRESS"
	echo "  Format:    $format"
	echo "  Delivery:  $delivery"
	echo ""

	# build synthetic alert entry (12 pipe-delimited fields matching check() format)
	local test_ip="192.0.2.1"
	local test_service="sshd"
	local test_ports="22"
	local test_pressure=21400    # 21.4 scaled (above default trip of 20)
	local test_trip=20000        # 20.0 scaled
	local test_weight=3          # sshd default
	local test_half_life="${PRESSURE_HALF_LIFE:-300}"
	local test_recent=0
	local test_log="${AUTH_LOG_PATH:-/var/log/secure}"
	local test_recip="$EMAIL_ADDRESS"
	local test_expiry test_action
	if [ "${BAN_TTL:-600}" = "0" ]; then
		test_expiry=0
		test_action="permanent"
	else
		test_expiry=$(( $(date +%s) + ${BAN_TTL:-600} ))
		test_action="temporary"
	fi

	local alerts_file
	alerts_file=$(mktemp "$install_path/tmp/.test_alert.XXXXXX")
	local test_fail_count=7
	echo "${test_ip}|${test_service}|${test_ports}|${test_pressure}|${test_expiry}|${test_action}|${test_recent}|${test_log}|${test_recip}|${test_trip}|${test_half_life}|${test_weight}|${test_fail_count}" > "$alerts_file"

	local subject="${EMAIL_SUBJECT:-[BFD] brute force attempt on \$HOSTNAME}"
	subject="${subject//\$HOSTNAME/$(hostname)}"
	subject="[TEST] $subject"

	if send_alerts "$alerts_file" "$subject" "${EMAIL_LOGLINES:-5}"; then
		echo "Test alert sent successfully."
		command rm -f "$alerts_file"
		return 0
	else
		echo "Test alert failed — check EMAIL_* and SMTP_* configuration (bfd -c)." >&2
		command rm -f "$alerts_file"
		return 1
	fi
}

# test_alert_messaging install_path channel enable_var — send a test alert to a messaging channel
# Builds a synthetic alert entry, temporarily enables the target channel,
# and dispatches via _bfd_dispatch_messaging. Other channels are temporarily disabled.
test_alert_messaging() {
	local install_path="$1" channel="$2" enable_var="$3"

	# validate channel is configured
	local _enabled="${!enable_var}"
	if [ "${_enabled:-0}" != "1" ]; then
		echo "error: ${enable_var} is not enabled (set ${enable_var}=\"1\" in conf.bfd)." >&2
		return 1
	fi

	if ! command -v curl >/dev/null 2>&1; then
		echo "error: curl is required for $channel alerts." >&2
		return 1
	fi

	echo "Sending test $channel alert..."

	# build synthetic alert entry (same as test_alert_email)
	local test_ip="192.0.2.1"
	local test_service="sshd"
	local test_ports="22"
	local test_pressure=21400
	local test_trip=20000
	local test_weight=3
	local test_half_life="${PRESSURE_HALF_LIFE:-300}"
	local test_recent=0
	local test_log="${AUTH_LOG_PATH:-/var/log/secure}"
	local test_recip="${EMAIL_ADDRESS:-root}"
	local test_fail_count=7
	local test_expiry test_action
	if [ "${BAN_TTL:-600}" = "0" ]; then
		test_expiry=0
		test_action="permanent"
	else
		test_expiry=$(( $(date +%s) + ${BAN_TTL:-600} ))
		test_action="temporary"
	fi

	local alerts_file
	alerts_file=$(mktemp "$install_path/tmp/.test_alert.XXXXXX")
	echo "${test_ip}|${test_service}|${test_ports}|${test_pressure}|${test_expiry}|${test_action}|${test_recent}|${test_log}|${test_recip}|${test_trip}|${test_half_life}|${test_weight}|${test_fail_count}" > "$alerts_file"

	local subject
	subject="[TEST] BFD Alert ($(hostname))"
	local tpl_dir="${ALERT_TEMPLATE_DIR:-$INSTALL_PATH/alert}"

	# Save and disable non-target channels for isolated test dispatch (F-A07)
	local _saved_slack="${SLACK_ALERTS:-0}" _saved_tg="${TELEGRAM_ALERTS:-0}" _saved_dc="${DISCORD_ALERTS:-0}"
	case "$channel" in
		slack)    TELEGRAM_ALERTS=0; DISCORD_ALERTS=0 ;;
		telegram) SLACK_ALERTS=0; DISCORD_ALERTS=0 ;;
		discord)  SLACK_ALERTS=0; TELEGRAM_ALERTS=0 ;;
	esac
	_bfd_alert_init

	local _dispatch_rc=0
	if _bfd_dispatch_messaging "$alerts_file" "$subject" "${EMAIL_LOGLINES:-5}" "$tpl_dir"; then
		_dispatch_rc=0
	else
		_dispatch_rc=1
	fi

	# Restore channel states
	SLACK_ALERTS="$_saved_slack"; TELEGRAM_ALERTS="$_saved_tg"; DISCORD_ALERTS="$_saved_dc"
	_bfd_alert_init

	if [ "$_dispatch_rc" -eq 0 ]; then
		echo "Test $channel alert sent successfully."
		command rm -f "$alerts_file"
		return 0
	else
		local _uc
		_uc=$(echo "$channel" | tr '[:lower:]' '[:upper:]')
		echo "Test $channel alert failed — check ${_uc}_* configuration (bfd -c)." >&2
		command rm -f "$alerts_file"
		return 1
	fi
}
