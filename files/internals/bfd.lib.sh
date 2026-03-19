#!/bin/bash
#
# Brute Force Detection 2.0.2 - Function Library
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
# This file is sourced by bfd and test scripts.
# Functions here are defined but not called; callers invoke as needed.

# Source sibling libraries (all co-located in internals/)
_internals_dir="${BASH_SOURCE[0]%/*}"

# Source shared tlog library
if [ -f "$_internals_dir/tlog_lib.sh" ]; then
	# shellcheck disable=SC1091
	. "$_internals_dir/tlog_lib.sh"
fi

# Source shared elog library
if [ -f "$_internals_dir/elog_lib.sh" ]; then
	# shellcheck disable=SC1091
	. "$_internals_dir/elog_lib.sh"
fi

# Source shared alert library (template engine, MIME, delivery, channel registry)
if [ -f "$_internals_dir/alert_lib.sh" ]; then
	# shellcheck disable=SC1091
	. "$_internals_dir/alert_lib.sh"
fi

# Source BFD-specific alert functions (content helpers, rendering, digest wrappers)
if [ -f "$_internals_dir/bfd_alert.sh" ]; then
	# shellcheck disable=SC1091
	. "$_internals_dir/bfd_alert.sh"
fi

# Source shared GeoIP metadata library (country names, continents, validation)
if [ -f "$_internals_dir/geoip_lib.sh" ]; then
	# shellcheck disable=SC1091
	. "$_internals_dir/geoip_lib.sh"
fi

# Source BFD report functions (periodic threat reports)
if [ -f "$_internals_dir/bfd_report.sh" ]; then
	# shellcheck disable=SC1091
	. "$_internals_dir/bfd_report.sh"
fi

# Source BFD input and config validation
if [ -f "$_internals_dir/bfd_validate.sh" ]; then
	# shellcheck disable=SC1091
	. "$_internals_dir/bfd_validate.sh"
fi

# Source BFD firewall backend abstraction
if [ -f "$_internals_dir/bfd_fw.sh" ]; then
	# shellcheck disable=SC1091
	. "$_internals_dir/bfd_fw.sh"
fi

# Source BFD state I/O and ban execution
if [ -f "$_internals_dir/bfd_state.sh" ]; then
	# shellcheck disable=SC1091
	. "$_internals_dir/bfd_state.sh"
fi

# Source BFD pressure model and rule infrastructure
if [ -f "$_internals_dir/bfd_pressure.sh" ]; then
	# shellcheck disable=SC1091
	. "$_internals_dir/bfd_pressure.sh"
fi

# Source BFD detection pipeline
if [ -f "$_internals_dir/bfd_detect.sh" ]; then
	# shellcheck disable=SC1091
	. "$_internals_dir/bfd_detect.sh"
fi

# _bfd_journal_register_all: populate journal filter mappings for all BFD rules
# Wrapped in a function so reload_watch can re-register after clearing arrays
_bfd_journal_register_all() {
	tlog_journal_register "sshd" "SYSLOG_IDENTIFIER=sshd"
	tlog_journal_register "dropbear" "SYSLOG_IDENTIFIER=dropbear"
	tlog_journal_register "dovecot" "SYSLOG_IDENTIFIER=dovecot"
	tlog_journal_register "postfix" "SYSLOG_IDENTIFIER=postfix"
	tlog_journal_register "courier" "SYSLOG_IDENTIFIER=couriertcpd"
	tlog_journal_register "sendmail" "SYSLOG_IDENTIFIER=sm-mta"
	tlog_journal_register "vpopmail" "SYSLOG_IDENTIFIER=vpopmail"
	tlog_journal_register "cyrus" "SYSLOG_IDENTIFIER=cyrus"
	tlog_journal_register "pure-ftpd" "SYSLOG_IDENTIFIER=pure-ftpd"
	tlog_journal_register "proftpd" "SYSLOG_IDENTIFIER=proftpd"
	tlog_journal_register "vsftpd" "SYSLOG_IDENTIFIER=vsftpd"
	tlog_journal_register "webmin" "SYSLOG_IDENTIFIER=webmin"
	tlog_journal_register "wordpress" "SYSLOG_IDENTIFIER=wordpress"
	tlog_journal_register "rh_imapd" "SYSLOG_IDENTIFIER=imapd"
	tlog_journal_register "rh_ipop3" "SYSLOG_IDENTIFIER=ipop3d"
	tlog_journal_register "named" "SYSLOG_IDENTIFIER=named"
	tlog_journal_register "openvpn" "SYSLOG_IDENTIFIER=openvpn"
	tlog_journal_register "exim_authfail" "SYSLOG_IDENTIFIER=exim4 + SYSLOG_IDENTIFIER=exim"
	tlog_journal_register "exim_nxuser" "SYSLOG_IDENTIFIER=exim4 + SYSLOG_IDENTIFIER=exim"
	tlog_journal_register "cockpit" "SYSLOG_IDENTIFIER=cockpit-ws"
	tlog_journal_register "gitea" "SYSLOG_IDENTIFIER=gitea"
	tlog_journal_register "postscreen" "SYSLOG_IDENTIFIER=postfix/postscreen"
	tlog_journal_register "xrdp" "SYSLOG_IDENTIFIER=xrdp-sesman"
	tlog_journal_register "asterisk" "SYSLOG_IDENTIFIER=asterisk"
	tlog_journal_register "asterisk.iax" "SYSLOG_IDENTIFIER=asterisk"
	tlog_journal_register "asterisk_nopeer" "SYSLOG_IDENTIFIER=asterisk"
	tlog_journal_register "vaultwarden" "SYSLOG_IDENTIFIER=vaultwarden"
	tlog_journal_register "guacamole" "SYSLOG_IDENTIFIER=guacamole-client"
	tlog_journal_register "haproxy" "SYSLOG_IDENTIFIER=haproxy"
	tlog_journal_register "squid" "SYSLOG_IDENTIFIER=squid"
	tlog_journal_register "sogod" "SYSLOG_IDENTIFIER=sogod"
	tlog_journal_register "freeswitch" "SYSLOG_IDENTIFIER=freeswitch"
	tlog_journal_register "ejabberd" "SYSLOG_IDENTIFIER=ejabberd"
	tlog_journal_register "drupal" "SYSLOG_IDENTIFIER=drupal"
	tlog_journal_register "jellyfin" "SYSLOG_IDENTIFIER=jellyfin"
	tlog_journal_register "pdns" "SYSLOG_IDENTIFIER=pdns_server"
	tlog_journal_register "proxmox" "SYSLOG_IDENTIFIER=pvedaemon + SYSLOG_IDENTIFIER=pveproxy"
	tlog_journal_register "phpmyadmin" "SYSLOG_IDENTIFIER=phpmyadmin"
}
# Register at module load
_bfd_journal_register_all

# exit codes (used by bfd, exported for callers)
# shellcheck disable=SC2034
EXIT_OK=0
# shellcheck disable=SC2034
EXIT_CONFIG_ERROR=1
# shellcheck disable=SC2034
EXIT_LOCK_ERROR=2
# shellcheck disable=SC2034
EXIT_PREREQ_ERROR=3

# eout(message [, "le"])
# Backward-compatible wrapper delegating to elog().
# Contract: always echo to stdout; "le" = also write to log + syslog.
# Syncs BFD config vars (OUTPUT_SYSLOG, BFD_LOG_PATH) to ELOG at call time
# so tests that change these mid-flight still work.
eout() {
	local _msg="${1:-}"
	local _flag="${2:-}"
	[ -z "$_msg" ] && return 0
	if [ "$_flag" = "le" ]; then
		ELOG_LOG_FILE="${BFD_LOG_PATH:-}"
		if [ "${OUTPUT_SYSLOG:-0}" = "1" ]; then
			ELOG_SYSLOG_FILE="${OUTPUT_SYSLOG_FILE:-}"
		else
			ELOG_SYSLOG_FILE=""
		fi
		elog info "$_msg"
	elif [ "$_flag" = "l" ]; then
		# log-file-only: write to BFD log but skip syslog
		ELOG_LOG_FILE="${BFD_LOG_PATH:-}"
		ELOG_SYSLOG_FILE=""
		elog info "$_msg"
	else
		# stdout-only: bypass file logging
		local _saved_log="${ELOG_LOG_FILE:-}"
		local _saved_syslog="${ELOG_SYSLOG_FILE:-}"
		ELOG_LOG_FILE=""
		ELOG_SYSLOG_FILE=""
		elog info "$_msg"
		ELOG_LOG_FILE="$_saved_log"
		ELOG_SYSLOG_FILE="$_saved_syslog"
	fi
}

# vout — verbose-only output via elog debug level
# Syncs VERBOSE to ELOG_VERBOSE so callers setting VERBOSE=1 still work.
vout() {
	# shellcheck disable=SC2034
	ELOG_VERBOSE="${VERBOSE:-0}"
	elog debug "$*"
}

format_table() {
	if command -v column >/dev/null 2>&1; then
		column -s '|' -t
	else
		tr '|' '\t'
	fi
}

# _fmt_ts epoch — format epoch as short human-readable timestamp for text tables
# Returns "mm/dd/yy HH:MM:SS" or the raw epoch on failure.
_fmt_ts() {
	date -d "@$1" +"%D %H:%M:%S" 2>/dev/null || echo "$1"
}

# _fmt_ts_iso epoch — format epoch as ISO 8601 timestamp for JSON/CSV output
# Returns "YYYY-MM-DDTHH:MM:SS" or the raw epoch on failure.
_fmt_ts_iso() {
	date -d "@$1" +"%Y-%m-%dT%H:%M:%S" 2>/dev/null || echo "$1"
}

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

# send_alerts alerts_file subject loglines — orchestrate batched alert emails
# Groups entries by RECIPIENT field, renders text/HTML via alert_lib.sh pipeline,
# delivers via local MTA or SMTP relay.
send_alerts() {
	local alerts_file="$1" subject="$2" loglines="${3:-50}"

	if [ ! -f "$alerts_file" ] || [ ! -s "$alerts_file" ]; then
		return 0
	fi

	# resolve template directory
	local tpl_dir="${ALERT_TEMPLATE_DIR:-$INSTALL_PATH/alert}"
	if [ ! -d "$tpl_dir" ] || [ ! -f "$tpl_dir/text.header.tpl" ]; then
		elog warn "alert template directory '$tpl_dir' invalid, skipping alerts."
		return 1
	fi

	# Cleanup trap: ensures temp files are removed even on unexpected return.
	# FUNCNAME guard required: BATS sets -T (functrace) which causes RETURN traps
	# to fire on sub-function returns; without the guard, files are deleted while
	# still in use by _alert_render_text/_alert_render_html.
	local -a _cleanup_files=()
	trap '[ "${FUNCNAME[0]}" = "send_alerts" ] && [ ${#_cleanup_files[@]} -gt 0 ] && command rm -f "${_cleanup_files[@]}"' RETURN

	local format="${EMAIL_FORMAT:-text}"

	# get unique recipients (field 9)
	local recipients
	recipients=$(awk -F'|' '{print $9}' "$alerts_file" | sort -u)

	local recip
	while IFS= read -r recip; do
		[ -z "$recip" ] && continue
		# create per-recipient temp file
		local recip_file
		recip_file=$(mktemp "${alerts_file}.recip.XXXXXX")
		_cleanup_files+=("$recip_file")
		awk -F'|' -v r="$recip" '$9 == r' "$alerts_file" > "$recip_file"

		local alert_count
		alert_count=$(wc -l < "$recip_file")

		# augment subject for multi-ban
		local mail_subject="$subject"
		if [ "$alert_count" -gt 1 ]; then
			mail_subject="$subject ($alert_count bans)"
		fi

		# render text body
		local text_file=""
		if [ "$format" = "text" ] || [ "$format" = "both" ]; then
			text_file=$(mktemp "${alerts_file}.text.XXXXXX")
			_cleanup_files+=("$text_file")
			_alert_render_text "$recip_file" "$tpl_dir" "$loglines" > "$text_file"
		fi

		# render HTML body
		local html_file=""
		if [ "$format" = "html" ] || [ "$format" = "both" ]; then
			html_file=$(mktemp "${alerts_file}.html.XXXXXX")
			_cleanup_files+=("$html_file")
			_alert_render_html "$recip_file" "$tpl_dir" "$loglines" > "$html_file"
		fi

		# for text-only: html_file needed by relay path, render it too
		if [ "$format" = "text" ] && [ -n "${SMTP_RELAY:-}" ]; then
			html_file=$(mktemp "${alerts_file}.html.XXXXXX")
			_cleanup_files+=("$html_file")
			_alert_render_html "$recip_file" "$tpl_dir" "$loglines" > "$html_file"
		fi
		# for html-only: text_file needed as sendmail fallback
		if [ "$format" = "html" ] && [ -z "$text_file" ]; then
			text_file=$(mktemp "${alerts_file}.text.XXXXXX")
			_cleanup_files+=("$text_file")
			_alert_render_text "$recip_file" "$tpl_dir" "$loglines" > "$text_file"
		fi

		if _alert_deliver_email "$recip" "$mail_subject" "$text_file" "$html_file" "$format"; then
			elog info "alert email sent to $recip ($alert_count ban(s), format=$format)."
		else
			elog error "alert email to $recip failed."
		fi

		# set backward-compat globals for single-ban case
		# (needed by custom hooks or external integrations that read these after send_alerts)
		if [ "$alert_count" -eq 1 ]; then
			local _host _mod _ports _count _expiry _action _recent _lp _recip _trig _tw _wt _fc
			IFS='|' read -r _host _mod _ports _count _expiry _action _recent _lp _recip _trig _tw _wt _fc < "$recip_file"
			# shellcheck disable=SC2034  # consumed by expand_command_template (bfd_validate.sh) and custom hooks
			ATTACK_HOST="$_host"
			# shellcheck disable=SC2034  # consumed by expand_command_template (bfd_validate.sh) and custom hooks
			MOD="$_mod"
			# backward compat: _count is pressure_scaled (e.g., 18400);
			# custom hooks expect a count, so use whole pressure units
			ATTACK_COUNT="$(( _count / 1000 ))"
			if [ "$ATTACK_COUNT" -lt 1 ]; then ATTACK_COUNT=1; fi
			LOG_FILE="$_lp"
			# shellcheck disable=SC2034  # consumed by custom hooks
			LP="$_lp"
			PORTS="$_ports"
			if [ "${_FW_BACKEND:-custom}" = "custom" ]; then
				BAN_COMMAND=$(expand_command_template "$BAN_COMMAND_TEMPLATE")
			else
				# shellcheck disable=SC2034  # consumed by custom hooks
				BAN_COMMAND="fw_ban $_host ($_FW_BACKEND)"
			fi
		fi
		# shellcheck disable=SC2034  # consumed by custom hooks
		ALERT_COUNT="$alert_count"

		command rm -f "$recip_file" "$text_file" "$html_file"
	done <<< "$recipients"

	# --- Messaging delivery (per-batch, not per-recipient) ---
	_bfd_dispatch_messaging "$alerts_file" "$subject" "$loglines" "$tpl_dir"

	# Clean up CIDR sidecar files after all rendering passes complete (F-A04)
	command rm -f "${INSTALL_PATH}/tmp/.cidr_detail_"* 2>/dev/null  # alert sidecars consumed
}

# --- Phase 18: CLI Evolution functions ---

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
			| awk '{printf "%s (%s)", $2, $1; if(NR<3) printf ", "}')
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

# _search_ip_data install_path ip — shared data gatherer for search_ip triplet
# Validates IP, reads all state files once.
# Outputs multi-line structured data:
#   D|ban_ts|ban_expiry|hist_24h|hist_total|evt_count|first_ts|last_ts|pressure_fmt|trip|half_life|pool_count
#   E|service|count_24h         (one per service with 24h events)
#   P|service|pressure_fmt      (one per service, overall pressure window)
# Returns 1 if invalid IP (with error on stderr).
_search_ip_data() {
	local install_path="$1" ip="$2"
	local now
	now=$(date +"%s")

	ip=$(validate_ip_any "$ip") || { echo "error: invalid IP address '$2'." >&2; return 1; }

	local half_life trip
	half_life="${PRESSURE_HALF_LIFE:-300}"
	trip="${GLOB_PRESSURE_TRIP:-20}"

	# Ban status (bans.active)
	local ban_ts="" ban_expiry=""
	local bans_file="$install_path/tmp/bans.active"
	if [ -f "$bans_file" ] && [ -s "$bans_file" ]; then
		local ban_line
		ban_line=$(awk -v ip="$ip" '$3 == ip {print $1, $2; exit}' "$bans_file")
		if [ -n "$ban_line" ]; then
			ban_ts="${ban_line%% *}"
			ban_expiry="${ban_line##* }"
		fi
	fi

	# Ban history (bans.history) — single AWK for both 24h and total
	local hist_24h=0 hist_total=0
	local history_file="$install_path/tmp/bans.history"
	local cutoff_24h=$((now - 86400))
	if [ -f "$history_file" ] && [ -s "$history_file" ]; then
		local hist_raw
		hist_raw=$(awk -v ip="$ip" -v cutoff="$cutoff_24h" '
			$3 == ip && ($5 == "ban" || $5 == "escalate") {
				total++
				if ($1+0 >= cutoff) recent++
			}
			END { print recent+0 "|" total+0 }' "$history_file")
		IFS='|' read -r hist_24h hist_total <<< "$hist_raw"
	fi

	# Events (attack.pool) — durable 24h failure counts and all-time totals
	local events_file="$install_path/tmp/pressure.dat"
	local pool_file="$install_path/stats/attack.pool"
	local evt_count=0 first_ts="" last_ts=""
	local _gp_fmt="0.0"
	local pool_triggers=0 pool_failures=0
	local evt_raw=""
	if [ -f "$pool_file" ] && [ -s "$pool_file" ]; then
		evt_raw=$(awk -v ip="$ip" -v cutoff="$cutoff_24h" '
			$2 == ip {
				cnt = ($4+0 > 0) ? $4+0 : 1
				total += cnt; ts = $1+0
				if (ts >= cutoff) { recent += cnt; rsvc[$3] += cnt }
				if (!(first) || ts < first) first = ts
				if (ts > last) last = ts
				act = $6
				if (act == "ban" || act == "escalate") bans++
			}
			END {
				printf "X|%d|%d|%d|%d|%d\n", recent+0, first+0, last+0, total+0, bans+0
				for (s in rsvc) printf "E|%s|%d\n", s, rsvc[s]
			}' "$pool_file")
		if [ -n "$evt_raw" ]; then
			local x_line
			x_line=$(echo "$evt_raw" | grep '^X|')
			IFS='|' read -r _ evt_count first_ts last_ts pool_failures pool_triggers <<< "$x_line"
		fi
	fi

	# Live pressure (pressure.dat) — for P lines and pressure display
	local ip_awk_raw=""
	if [ -f "$events_file" ] && [ -s "$events_file" ]; then
		ip_awk_raw=$(_events_ip_awk "$events_file" "$ip" "$now" "$half_life")
		if [ -n "$ip_awk_raw" ]; then
			local h_line _gp
			h_line=$(echo "$ip_awk_raw" | grep '^H|')
			IFS='|' read -r _ _gp _ _ <<< "$h_line"
			_gp_fmt=$(pressure_format "$_gp")
		fi
	fi

	# Compute min-trip from per-service pressure lines (if live pressure available)
	if [ -n "${ip_awk_raw:-}" ]; then
		local _p_svcs=""
		local _type _svc _wt _cnt _sp
		while IFS='|' read -r _type _svc _wt _cnt _sp; do
			[ "$_type" != "S" ] && continue
			_p_svcs="${_p_svcs:+$_p_svcs,}$_svc"
		done <<< "$ip_awk_raw"
		if [ -n "$_p_svcs" ]; then
			trip=$(_resolve_min_trip "$_p_svcs")
		fi
	fi

	# Output: D line (core data)
	echo "D|$ban_ts|$ban_expiry|$hist_24h|$hist_total|$evt_count|$first_ts|$last_ts|$_gp_fmt|$trip|$half_life|$pool_triggers|$pool_failures"

	# Output: E lines (per-service 24h event counts)
	if [ -n "${evt_raw:-}" ]; then
		echo "$evt_raw" | grep '^E|'
	fi

	# Output: P lines (per-service live pressure + per-rule trip)
	if [ -n "${ip_awk_raw:-}" ]; then
		local _sp_fmt _svc_trip
		while IFS='|' read -r _type _svc _wt _cnt _sp; do
			[ "$_type" != "S" ] && continue
			_sp_fmt=$(pressure_format "$_sp")
			_svc_trip=$(_resolve_trip "$_svc")
			echo "P|$_svc|$_sp_fmt|$_svc_trip"
		done <<< "$ip_awk_raw"
	fi
}

# search_ip install_path ip — unified IP search across all state files
search_ip() {
	local install_path="$1" ip="$2"

	local data
	data=$(_search_ip_data "$install_path" "$ip") || return 1

	# parse D line
	local d_line ban_ts ban_expiry hist_24h hist_total evt_count first_ts last_ts _gp_fmt trip half_life pool_triggers pool_failures
	d_line=$(echo "$data" | grep '^D|')
	IFS='|' read -r _ ban_ts ban_expiry hist_24h hist_total evt_count first_ts last_ts _gp_fmt trip half_life pool_triggers pool_failures <<< "$d_line"

	local now
	now=$(date +"%s")

	echo "IP Report: $ip"
	echo ""

	# Ban status
	if [ -n "$ban_ts" ]; then
		local ban_since
		ban_since=$(date -d "@${ban_ts}" +"%Y-%m-%d %H:%M:%S" 2>/dev/null || echo "$ban_ts")
		if [ "$ban_expiry" = "0" ]; then
			echo "  Status:         BANNED (permanent since $ban_since)"
		else
			local remain=$(( (ban_expiry - now) / 60 ))
			[ "$remain" -lt 0 ] && remain=0
			echo "  Status:         BANNED (temporary, ${remain}m remaining)"
		fi
	else
		echo "  Status:         not banned"
	fi

	# Ban history
	if [ "$hist_24h" -gt 0 ] 2>/dev/null || [ "$hist_total" -gt 0 ] 2>/dev/null; then
		echo "  Ban history:    $hist_24h bans in 24h ($hist_total total)"
	else
		echo "  Ban history:    none"
	fi

	# Events (from attack.pool — durable across pressure decay)
	if [ "$evt_count" -gt 0 ] 2>/dev/null; then
		# Build svc_summary from E lines: "sshd(5) dovecot(2)"
		local evt_svcs=""
		local _type _svc _cnt
		while IFS='|' read -r _type _svc _cnt; do
			[ "$_type" != "E" ] && continue
			evt_svcs="${evt_svcs}${_svc}(${_cnt}) "
		done <<< "$data"
		echo "  Failures (24h): $evt_count across $evt_svcs"
	else
		echo "  Failures (24h): 0"
	fi

	# First/last seen and total (from attack.pool all-time data)
	if [ -n "$first_ts" ] && [ "$first_ts" -gt 0 ] 2>/dev/null; then
		echo "  First seen:     $(date -d "@${first_ts}" +"%Y-%m-%d %H:%M:%S" 2>/dev/null || echo "$first_ts")"
	fi
	if [ -n "$last_ts" ] && [ "$last_ts" -gt 0 ] 2>/dev/null; then
		echo "  Last seen:      $(date -d "@${last_ts}" +"%Y-%m-%d %H:%M:%S" 2>/dev/null || echo "$last_ts")"
	fi
	if [ "$pool_failures" -gt 0 ] 2>/dev/null; then
		if [ "$pool_failures" -ne "$evt_count" ] 2>/dev/null; then
			echo "  Total failures: $pool_failures ($pool_triggers ban triggers)"
		fi
	fi

	# Live pressure
	echo "  Pressure:       ${_gp_fmt}/${trip} (half-life=${half_life}s)"
	# Per-service pressure from P lines
	local _ptype _psvc _pfmt _ptrip
	while IFS='|' read -r _ptype _psvc _pfmt _ptrip; do
		[ "$_ptype" != "P" ] && continue
		echo "                  ${_psvc}: ${_pfmt}/${_ptrip}"
	done <<< "$data"
}

# _resolve_log_source_label log_source has_journalctl
# Determines the display label for a rule's log source based on:
#   - LOG_FILE existence, LOG_TAG, journal filter registration
# Uses rule variables (LOG_FILE, LOG_TAG) from the caller's scope.
_resolve_log_source_label() {
	local log_source="$1" has_journalctl="$2"
	local has_journal=0
	if [ "$has_journalctl" = "1" ] && [ -n "${LOG_TAG:-}" ] && \
	   tlog_journal_filter "$LOG_TAG" >/dev/null 2>&1; then
		has_journal=1
	fi
	if [ -n "${LOG_FILE:-}" ] && [ -f "$LOG_FILE" ]; then
		if [ "$has_journal" = "1" ]; then
			echo "$LOG_FILE (file+journal)"
		else
			echo "$LOG_FILE (file)"
		fi
	elif [ "$has_journal" = "1" ]; then
		echo "journal ($LOG_TAG)"
	elif [ -n "${LOG_FILE:-}" ]; then
		echo "${LOG_FILE} (not found)"
	else
		echo "n/a"
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

# --- Structured output formatters ---

# _json_escape str — escape string for JSON output (RFC 8259 §7)
_json_escape() {
	local s="$1"
	s="${s//\\/\\\\}"
	s="${s//\"/\\\"}"
	s="${s//$'\n'/\\n}"
	s="${s//$'\t'/\\t}"
	s="${s//$'\r'/\\r}"
	s="${s//$'\b'/\\b}"
	s="${s//$'\f'/\\f}"
	echo "$s"
}

# _json_array_from_csv csv_string — convert "sshd,dovecot" to ["sshd","dovecot"]
_json_array_from_csv() {
	local csv="$1"
	if [ -z "$csv" ]; then
		echo "[]"
		return
	fi
	local result="[" first=1
	local IFS=','
	local item
	for item in $csv; do
		if [ "$first" -eq 1 ]; then
			first=0
		else
			result="$result,"
		fi
		result="$result\"$(_json_escape "$item")\""
	done
	echo "${result}]"
}

# _events_ip_awk events_file ip now half_life — single-pass per-IP data extraction
# Outputs per service: S|service|weight|event_count|pressure_scaled
# Summary line:        H|overall_pressure_scaled|first_ts|last_ts
# Returns no output if IP has no events (caller checks).
_events_ip_awk() {
	local events_file="$1" ip="$2" now="$3" half_life="$4"
	local cutoff=$((now - half_life * 10))
	awk -v cutoff="$cutoff" -v now="$now" -v hl="$half_life" -v tgt="$ip" '
	BEGIN { ln2 = 0.693147180559945; gfirst = 0; glast = 0 }
	$1+0 >= cutoff && $2 == tgt {
		mod = $3; ts = $1+0
		w = ($4+0 > 0) ? $4+0 : 1
		age = now - ts
		decay = w * exp(-ln2 * age / hl)
		gp += decay
		sp[mod] += decay
		cnt[mod]++
		found = 1
		if (w > wt[mod]) wt[mod] = w
		if (!(mod in sfirst) || ts < sfirst[mod]) sfirst[mod] = ts
		if (ts > slast[mod]) slast[mod] = ts
		if (gfirst == 0 || ts < gfirst) gfirst = ts
		if (ts > glast) glast = ts
	}
	END {
		if (!found) exit
		for (mod in cnt) {
			printf "S|%s|%d|%d|%d\n", mod, (wt[mod] > 0 ? wt[mod] : 1), cnt[mod], int(sp[mod] * 1000)
		}
		printf "H|%d|%d|%d\n", int(gp * 1000), gfirst, glast
	}' "$events_file"
}

# _events_rule_log_file rule — extract LOG_FILE from a rule without detection
# Sources the rule in a subshell with _rule_tlog() no-op'd, so the detection
# pipeline does not execute. Outputs the LOG_FILE value if set.
# Returns 1 if the rule file does not exist or LOG_FILE is empty.
_events_rule_log_file() {
	local rule="$1"
	local rule_file="${RULES_PATH:-}/$rule"
	[ ! -f "$rule_file" ] && return 1
	(
		# no-op the tlog function so sourcing the rule doesn't run detection
		_rule_tlog() { :; }
		extract_hosts() { :; }
		# shellcheck disable=SC1090,SC1091
		. "$rule_file" 2>/dev/null
		[ -n "${LOG_FILE:-}" ] && echo "$LOG_FILE"
	)
}

# _events_rule_patterns rule — extract detection patterns from a rule file
# Sources the rule in a subshell with a custom extract_hosts() that prints the
# pattern arguments (one per line) instead of processing log data.
# Returns 1 if the rule file does not exist or no patterns are found.
_events_rule_patterns() {
	local rule="$1"
	local rule_file="${RULES_PATH:-}/$rule"
	[ ! -f "$rule_file" ] && return 1
	local patterns
	patterns=$(
		# no-op the tlog function so sourcing the rule doesn't run detection
		_rule_tlog() { :; }
		# override extract_hosts to print its pattern arguments
		extract_hosts() {
			local _p
			for _p in "$@"; do
				printf '%s\n' "$_p"
			done
		}
		# shellcheck disable=SC1090,SC1091
		. "$rule_file" 2>/dev/null
	)
	[ -z "$patterns" ] && return 1
	echo "$patterns"
}

# --- Event list functions (attack.pool-backed, durable history) ---

# _events_list_ip_pool_awk pool_file ip — per-IP aggregation from attack.pool
# Outputs: H|total|first_ts|last_ts|bans|cc  (header)
#          S|service|count|first_ts|last_ts   (per service)
# Returns 1 if no data for IP.
_events_list_ip_pool_awk() {
	local pool_file="$1" ip="$2"
	awk -v tgt="$ip" '
	$2 == tgt {
		mod = $3; ts = $1+0
		cnt = ($4+0 > 0) ? $4+0 : 1
		cc = ($5 != "" && $5 != "--") ? $5 : ""
		act = $6
		total += cnt
		svc_cnt[mod] += cnt
		if (act == "ban" || act == "escalate") bans++
		if (!(mod in sfirst) || ts < sfirst[mod]) sfirst[mod] = ts
		if (ts > slast[mod]) slast[mod] = ts
		if (gfirst == 0 || ts < gfirst) gfirst = ts
		if (ts > glast) glast = ts
		if (cc != "" && gcc == "") gcc = cc
	}
	END {
		if (total == 0) exit 1
		printf "H|%d|%d|%d|%d|%s\n", total, gfirst, glast, bans+0, gcc
		for (mod in svc_cnt)
			printf "S|%s|%d|%d|%d\n", mod, svc_cnt[mod], sfirst[mod], slast[mod]
	}' "$pool_file"
}

# events_list install_path [sort_mode] [limit] — event list dashboard from attack.pool
# Lists IPs with auth failure events, sorted by count (default), time, or ip.
# limit: max IPs to return (default 100, 0 = unlimited).
# Uses _EVENTS_CUTOFF global (set by pre-parse) for time window filtering.
events_list() {
	local install_path="$1" sort_mode="${2:-count}" limit="${3:-100}"
	local pool_file="$install_path/stats/attack.pool"
	local cutoff="${_EVENTS_CUTOFF:-0}"

	if [ ! -f "$pool_file" ] || [ ! -s "$pool_file" ]; then
		echo "No events recorded."
		return 0
	fi

	_batch_ban_status_init "$install_path"
	local atmp
	atmp=$(mktemp "$install_path/tmp/.evtlist.XXXXXX")
	echo "#IP|COUNT|SERVICES|COUNTRY|FIRST_SEEN|LAST_SEEN|STATUS" > "$atmp"
	local cnt ip first_ts last_ts svcs cc row_count=0
	while IFS='|' read -r cnt ip first_ts last_ts svcs cc; do
		[ -z "$cnt" ] && continue
		cc=$(_resolve_cidr_cc "$ip" "$cc")
		local first_fmt last_fmt ban_status
		first_fmt=$(_fmt_ts "$first_ts")
		last_fmt=$(_fmt_ts "$last_ts")
		ban_status=$(_batch_ban_status_lookup "$ip")
		echo "$ip|$cnt|$svcs|${cc:---}|$first_fmt|$last_fmt|$ban_status"
		row_count=$((row_count + 1))
	done < <(_apool_awk "$pool_file" "" "$cutoff" "$sort_mode" "$limit") >> "$atmp"
	_batch_ban_status_cleanup

	if [ "$(wc -l < "$atmp")" -le 1 ]; then
		command rm -f "$atmp"
		echo "No events recorded."
		return 0
	fi

	format_table < "$atmp"
	if [ "$limit" -gt 0 ] 2>/dev/null && [ "$row_count" -ge "$limit" ]; then  # 2>/dev/null: suppress non-numeric comparison error when limit is empty
		echo "(showing $limit IPs -- use --limit=0 for all)"
	fi
	command rm -f "$atmp"
}

# events_list_ip install_path ip [loglines] — per-IP event detail from attack.pool
# Shows historical event summary, live pressure (if available), and log sample.
events_list_ip() {
	local install_path="$1" ip="$2" _cli_loglines="${3:-}"
	local pool_file="$install_path/stats/attack.pool"
	local half_life="${PRESSURE_HALF_LIFE:-300}"

	ip=$(validate_ip_any "$ip") || { echo "error: invalid IP address '$2'." >&2; return 1; }

	# Pool data (durable history)
	local pool_data=""
	if [ -f "$pool_file" ] && [ -s "$pool_file" ]; then
		pool_data=$(_events_list_ip_pool_awk "$pool_file" "$ip") || true  # no pool data for IP is normal
	fi

	# Live pressure data (ephemeral)
	local pressure_data=""
	local events_file="$install_path/tmp/pressure.dat"
	local now
	now=$(date +"%s")
	if [ -f "$events_file" ] && [ -s "$events_file" ]; then
		pressure_data=$(_events_ip_awk "$events_file" "$ip" "$now" "$half_life") || true  # no pressure data for IP is normal
	fi

	# If both empty, no data
	if [ -z "$pool_data" ] && [ -z "$pressure_data" ]; then
		echo "No events for $ip."
		return 0
	fi

	# Parse pool header
	local total_failures=0 first_ts="" last_ts="" ban_triggers=0 country=""
	if [ -n "$pool_data" ]; then
		local h_line
		h_line=$(echo "$pool_data" | grep '^H|')
		IFS='|' read -r _ total_failures first_ts last_ts ban_triggers country <<< "$h_line"
	fi

	# Ban status
	local ban_status
	ban_status=$(_apool_ban_status "$ip")
	[ -z "$ban_status" ] && ban_status="not banned"

	echo "IP:               $ip"
	[ -n "$country" ] && [ "$country" != "--" ] && echo "Country:          $country"
	echo "Status:           $ban_status"
	echo ""

	# Historical summary from attack.pool
	if [ -n "$pool_data" ]; then
		echo "Total failures:   $total_failures"
		[ "$ban_triggers" -gt 0 ] && echo "Ban triggers:     $ban_triggers"
		if [ -n "$first_ts" ] && [ "$first_ts" -gt 0 ] 2>/dev/null; then
			echo "First seen:       $(date -d "@${first_ts}" +"%Y-%m-%d %H:%M:%S" 2>/dev/null || echo "$first_ts")"
		fi
		if [ -n "$last_ts" ] && [ "$last_ts" -gt 0 ] 2>/dev/null; then
			echo "Last seen:        $(date -d "@${last_ts}" +"%Y-%m-%d %H:%M:%S" 2>/dev/null || echo "$last_ts")"
		fi
		echo ""

		# Per-service table
		local atmp
		atmp=$(mktemp "$install_path/tmp/.evtip.XXXXXX")
		echo "#SERVICE|COUNT|FIRST_SEEN|LAST_SEEN" > "$atmp"
		local _type _svc _cnt _sfirst _slast
		while IFS='|' read -r _type _svc _cnt _sfirst _slast; do
			[ "$_type" != "S" ] && continue
			local _sfmt _lfmt
			_sfmt=$(_fmt_ts "$_sfirst")
			_lfmt=$(_fmt_ts "$_slast")
			echo "$_svc|$_cnt|$_sfmt|$_lfmt"
		done <<< "$pool_data" >> "$atmp"
		format_table < "$atmp"
		command rm -f "$atmp"
		echo ""
	fi

	# Live pressure (if available)
	if [ -n "$pressure_data" ]; then
		local p_h_line _gp
		p_h_line=$(echo "$pressure_data" | grep '^H|')
		IFS='|' read -r _ _gp _ _ <<< "$p_h_line"
		local _gp_fmt
		_gp_fmt=$(pressure_format "$_gp")
		local _svcs=""
		local _type _svc _wt _cnt _sp
		while IFS='|' read -r _type _svc _wt _cnt _sp; do
			[ "$_type" != "S" ] && continue
			_svcs="${_svcs:+$_svcs,}$_svc"
		done <<< "$pressure_data"
		local _trip
		_trip=$(_resolve_min_trip "${_svcs:-}")
		echo "Live pressure:    ${_gp_fmt}/${_trip} (half-life=${half_life}s)"
		echo ""
	fi

	# Log sample
	echo "Recent log activity:"
	local _log_total=0 _log_cap="${_cli_loglines:-${EMAIL_LOGLINES:-5}}"
	local _seen_logs="" _log_file _log_lines _log_patterns
	# Get service list from pool_data (preferred) or pressure_data
	local _svc_source="$pool_data"
	[ -z "$_svc_source" ] && _svc_source="$pressure_data"
	local _type _svc
	while IFS='|' read -r _type _svc _; do
		[ "$_type" != "S" ] && continue
		[ "$_log_total" -ge "$_log_cap" ] && break
		_log_file=$(_events_rule_log_file "$_svc") || continue
		case ",$_seen_logs," in
			*",$_log_file,"*) continue ;;
		esac
		_seen_logs="${_seen_logs:+$_seen_logs,}$_log_file"
		_log_patterns=$(_events_rule_patterns "$_svc") || _log_patterns=""
		local _remain=$((_log_cap - _log_total))
		_log_lines=$(_alert_sanitize_logs "$_log_file" "$ip" "$_remain" "$_log_patterns") || continue
		echo "$_log_lines"
		_log_total=$((_log_total + $(echo "$_log_lines" | wc -l)))
	done <<< "$_svc_source"
	if [ "$_log_total" -eq 0 ]; then
		echo "  (no matching log entries found)"
	fi
}

# events_list_cidr install_path cidr [sort_mode] [limit] — subnet event search from attack.pool
events_list_cidr() {
	local install_path="$1" cidr="$2" sort_mode="${3:-count}" limit="${4:-100}"
	local pool_file="$install_path/stats/attack.pool"
	local cutoff="${_EVENTS_CUTOFF:-0}"

	cidr=$(validate_cidr "$cidr") || { echo "error: invalid CIDR notation '$2' (IPv4, mask 8-32)." >&2; return 1; }
	local target_addr target_mask
	target_addr="${cidr%/*}"
	target_mask="${cidr#*/}"

	if [ ! -f "$pool_file" ] || [ ! -s "$pool_file" ]; then
		echo "No events found for $cidr."
		return 0
	fi

	_batch_ban_status_init "$install_path"
	local atmp
	atmp=$(mktemp "$install_path/tmp/.evtcidr.XXXXXX")
	echo "#IP|COUNT|SERVICES|COUNTRY|FIRST_SEEN|LAST_SEEN|STATUS" > "$atmp"
	local _cidr_summary
	_cidr_summary=$(mktemp "$install_path/tmp/.evtcidr_s.XXXXXX")
	local cnt ip first_ts last_ts svcs cc row_count=0
	while IFS='|' read -r cnt ip first_ts last_ts svcs cc; do
		[ -z "$cnt" ] && continue
		local first_fmt last_fmt ban_status
		first_fmt=$(_fmt_ts "$first_ts")
		last_fmt=$(_fmt_ts "$last_ts")
		ban_status=$(_batch_ban_status_lookup "$ip")
		echo "$ip|$cnt|$svcs|${cc:---}|$first_fmt|$last_fmt|$ban_status"
		echo "$cnt|${ban_status}" >&3
		row_count=$((row_count + 1))
	done 3>"$_cidr_summary" < <(_apool_awk "$pool_file" "" "$cutoff" "$sort_mode" "$limit" "$target_addr" "$target_mask") >> "$atmp"
	_batch_ban_status_cleanup

	local match_count=0 total_events=0 banned_count=0
	if [ -f "$_cidr_summary" ] && [ -s "$_cidr_summary" ]; then
		match_count=$(wc -l < "$_cidr_summary")
		total_events=$(awk -F'|' '{s+=$1} END {print s+0}' "$_cidr_summary")
		banned_count=$(awk -F'|' '$2 ~ /BANNED/ {c++} END {print c+0}' "$_cidr_summary")
	fi
	command rm -f "$_cidr_summary"

	if [ "$match_count" -eq 0 ]; then
		command rm -f "$atmp"
		echo "No events found for $cidr."
		return 0
	fi

	format_table < "$atmp"
	echo ""
	local _summary="$match_count IPs, $total_events failures, $banned_count banned"
	if [ "$limit" -gt 0 ] 2>/dev/null && [ "$row_count" -ge "$limit" ]; then  # 2>/dev/null: suppress non-numeric comparison error when limit is empty
		_summary="$_summary (showing $limit -- use --limit=0 for all)"
	fi
	echo "$_summary"
	command rm -f "$atmp"
}

# --- Event list JSON/CSV variants ---

# events_list_json install_path [sort_mode] [limit] — JSON array of event list entries
events_list_json() {
	local install_path="$1" sort_mode="${2:-count}" limit="${3:-100}"
	local pool_file="$install_path/stats/attack.pool"
	local cutoff="${_EVENTS_CUTOFF:-0}"

	if [ ! -f "$pool_file" ] || [ ! -s "$pool_file" ]; then
		echo "[]"
		return 0
	fi

	_batch_ban_status_init "$install_path"
	local first=1
	local cnt ip first_ts last_ts svcs cc
	while IFS='|' read -r cnt ip first_ts last_ts svcs cc; do
		[ -z "$cnt" ] && continue
		cc=$(_resolve_cidr_cc "$ip" "$cc")
		local first_fmt last_fmt ban_status
		first_fmt=$(_fmt_ts_iso "$first_ts")
		last_fmt=$(_fmt_ts_iso "$last_ts")
		ban_status=$(_batch_ban_status_lookup "$ip")
		[ -z "$ban_status" ] && ban_status="not banned"
		if [ "$first" -eq 1 ]; then
			echo "["
			first=0
		else
			echo ","
		fi
		printf '  {"ip": "%s", "count": %s, "services": %s, "country": "%s", "first_seen": "%s", "last_seen": "%s", "status": "%s"}' \
			"$(_json_escape "$ip")" "$cnt" \
			"$(_json_array_from_csv "$svcs")" "$(_json_escape "${cc:---}")" \
			"$first_fmt" "$last_fmt" "$(_json_escape "$ban_status")"
	done < <(_apool_awk "$pool_file" "" "$cutoff" "$sort_mode" "$limit")
	_batch_ban_status_cleanup

	if [ "$first" -eq 1 ]; then
		echo "[]"
	else
		echo ""
		echo "]"
	fi
}

# events_list_csv install_path [sort_mode] [limit] — CSV formatted event list
events_list_csv() {
	local install_path="$1" sort_mode="${2:-count}" limit="${3:-100}"
	local pool_file="$install_path/stats/attack.pool"
	local cutoff="${_EVENTS_CUTOFF:-0}"

	echo "ip,count,services,country,first_seen,last_seen,status"

	if [ ! -f "$pool_file" ] || [ ! -s "$pool_file" ]; then
		return 0
	fi

	_batch_ban_status_init "$install_path"
	local cnt ip first_ts last_ts svcs cc
	while IFS='|' read -r cnt ip first_ts last_ts svcs cc; do
		[ -z "$cnt" ] && continue
		cc=$(_resolve_cidr_cc "$ip" "$cc")
		local first_fmt last_fmt ban_status
		first_fmt=$(_fmt_ts_iso "$first_ts")
		last_fmt=$(_fmt_ts_iso "$last_ts")
		ban_status=$(_batch_ban_status_lookup "$ip")
		[ -z "$ban_status" ] && ban_status="not banned"
		echo "$ip,$cnt,$svcs,${cc:---},$first_fmt,$last_fmt,$ban_status"
	done < <(_apool_awk "$pool_file" "" "$cutoff" "$sort_mode" "$limit")
	_batch_ban_status_cleanup
}

# events_list_ip_json install_path ip [loglines] — JSON per-IP event detail
events_list_ip_json() {
	local install_path="$1" ip="$2" _cli_loglines="${3:-}"
	local pool_file="$install_path/stats/attack.pool"
	local half_life="${PRESSURE_HALF_LIFE:-300}"
	local trip="${GLOB_PRESSURE_TRIP:-20}"

	ip=$(validate_ip_any "$ip") || { echo "error: invalid IP address '$2'." >&2; return 1; }

	# Pool data (durable history)
	local pool_data=""
	if [ -f "$pool_file" ] && [ -s "$pool_file" ]; then
		pool_data=$(_events_list_ip_pool_awk "$pool_file" "$ip") || true  # no pool data for IP is normal
	fi

	# Live pressure data
	local pressure_data=""
	local events_file="$install_path/tmp/pressure.dat"
	local now
	now=$(date +"%s")
	if [ -f "$events_file" ] && [ -s "$events_file" ]; then
		pressure_data=$(_events_ip_awk "$events_file" "$ip" "$now" "$half_life") || true  # no pressure data for IP is normal
	fi

	# If both empty, return zero-state
	if [ -z "$pool_data" ] && [ -z "$pressure_data" ]; then
		printf '{"ip": "%s", "country": "--", "status": "not banned", "total_failures": 0, "ban_triggers": 0, "first_seen": null, "last_seen": null, "services": [], "pressure": 0.0, "pressure_trip": %s, "half_life": %s, "log_sample": []}\n' \
			"$(_json_escape "$ip")" "$trip" "$half_life"
		return 0
	fi

	# Parse pool header
	local total_failures=0 first_ts="" last_ts="" ban_triggers=0 country="--"
	if [ -n "$pool_data" ]; then
		local h_line
		h_line=$(echo "$pool_data" | grep '^H|')
		IFS='|' read -r _ total_failures first_ts last_ts ban_triggers country <<< "$h_line"
		[ -z "$country" ] && country="--"
	fi

	# Ban status
	local ban_status
	ban_status=$(_apool_ban_status "$ip")
	[ -z "$ban_status" ] && ban_status="not banned"

	# Build services JSON array from pool data
	local svcs_json="[]"
	if [ -n "$pool_data" ]; then
		svcs_json="["
		local svc_first=1
		local _type _svc _cnt _sfirst _slast
		while IFS='|' read -r _type _svc _cnt _sfirst _slast; do
			[ "$_type" != "S" ] && continue
			if [ "$svc_first" -eq 1 ]; then
				svc_first=0
			else
				svcs_json="$svcs_json, "
			fi
			local _sfmt _lfmt
			_sfmt=$(_fmt_ts_iso "$_sfirst")
			_lfmt=$(_fmt_ts_iso "$_slast")
			svcs_json="$svcs_json{\"service\": \"$(_json_escape "$_svc")\", \"count\": $_cnt, \"first_seen\": \"$_sfmt\", \"last_seen\": \"$_lfmt\"}"
		done <<< "$pool_data"
		svcs_json="$svcs_json]"
	fi

	# Live pressure
	local _gp_fmt="0.0"
	if [ -n "$pressure_data" ]; then
		local p_h_line _gp
		p_h_line=$(echo "$pressure_data" | grep '^H|')
		IFS='|' read -r _ _gp _ _ <<< "$p_h_line"
		_gp_fmt=$(pressure_format "$_gp")
		# compute min-trip from pressure services
		local _svcs=""
		local _type _svc _wt _cnt _sp
		while IFS='|' read -r _type _svc _wt _cnt _sp; do
			[ "$_type" != "S" ] && continue
			_svcs="${_svcs:+$_svcs,}$_svc"
		done <<< "$pressure_data"
		[ -n "$_svcs" ] && trip=$(_resolve_min_trip "$_svcs")
	fi

	# First/last seen
	local first_fmt="null" last_fmt="null"
	if [ -n "$first_ts" ] && [ "$first_ts" -gt 0 ] 2>/dev/null; then
		first_fmt="\"$(_fmt_ts_iso "$first_ts")\""
	fi
	if [ -n "$last_ts" ] && [ "$last_ts" -gt 0 ] 2>/dev/null; then
		last_fmt="\"$(_fmt_ts_iso "$last_ts")\""
	fi

	# Build log_sample JSON array
	local log_json="[" _log_total=0 _log_cap="${_cli_loglines:-${EMAIL_LOGLINES:-5}}"
	local _seen_logs="" _log_file _log_lines _log_patterns _log_first=1
	local _svc_source="$pool_data"
	[ -z "$_svc_source" ] && _svc_source="$pressure_data"
	local _type _svc
	while IFS='|' read -r _type _svc _; do
		[ "$_type" != "S" ] && continue
		[ "$_log_total" -ge "$_log_cap" ] && break
		_log_file=$(_events_rule_log_file "$_svc") || continue
		case ",$_seen_logs," in
			*",$_log_file,"*) continue ;;
		esac
		_seen_logs="${_seen_logs:+$_seen_logs,}$_log_file"
		_log_patterns=$(_events_rule_patterns "$_svc") || _log_patterns=""
		local _remain=$((_log_cap - _log_total))
		_log_lines=$(_alert_sanitize_logs "$_log_file" "$ip" "$_remain" "$_log_patterns") || continue
		local _line
		while IFS= read -r _line; do
			if [ "$_log_first" -eq 1 ]; then
				_log_first=0
			else
				log_json="$log_json, "
			fi
			log_json="$log_json\"$(_json_escape "$_line")\""
			_log_total=$((_log_total + 1))
		done <<< "$_log_lines"
	done <<< "$_svc_source"
	log_json="$log_json]"

	printf '{"ip": "%s", "country": "%s", "status": "%s", "total_failures": %d, "ban_triggers": %d, "first_seen": %s, "last_seen": %s, "services": %s, "pressure": %s, "pressure_trip": %s, "half_life": %s, "log_sample": %s}\n' \
		"$(_json_escape "$ip")" "$(_json_escape "${country:---}")" "$(_json_escape "$ban_status")" \
		"$total_failures" "$ban_triggers" "$first_fmt" "$last_fmt" \
		"$svcs_json" "$_gp_fmt" "$trip" "$half_life" "$log_json"
}

# events_list_ip_csv install_path ip — CSV per-IP event detail (one row per service)
events_list_ip_csv() {
	local install_path="$1" ip="$2"
	local pool_file="$install_path/stats/attack.pool"

	ip=$(validate_ip_any "$ip") || { echo "error: invalid IP address '$2'." >&2; return 1; }

	echo "ip,total_failures,ban_triggers,country,service,count,first_seen,last_seen,status"

	local pool_data=""
	if [ -f "$pool_file" ] && [ -s "$pool_file" ]; then
		pool_data=$(_events_list_ip_pool_awk "$pool_file" "$ip") || true  # no pool data for IP is normal
	fi
	if [ -z "$pool_data" ]; then
		return 0
	fi

	# Parse header
	local h_line total_failures first_ts last_ts ban_triggers country
	h_line=$(echo "$pool_data" | grep '^H|')
	IFS='|' read -r _ total_failures first_ts last_ts ban_triggers country <<< "$h_line"

	local ban_status
	ban_status=$(_apool_ban_status "$ip")
	[ -z "$ban_status" ] && ban_status="not banned"

	# Per-service rows
	local _type _svc _cnt _sfirst _slast
	while IFS='|' read -r _type _svc _cnt _sfirst _slast; do
		[ "$_type" != "S" ] && continue
		local _sfmt _lfmt
		_sfmt=$(_fmt_ts_iso "$_sfirst")
		_lfmt=$(_fmt_ts_iso "$_slast")
		echo "$ip,$total_failures,$ban_triggers,${country:---},$_svc,$_cnt,$_sfmt,$_lfmt,$ban_status"
	done <<< "$pool_data"
}

# events_list_cidr_json install_path cidr [sort_mode] [limit] — JSON CIDR event search
events_list_cidr_json() {
	local install_path="$1" cidr="$2" sort_mode="${3:-count}" limit="${4:-100}"
	local pool_file="$install_path/stats/attack.pool"
	local cutoff="${_EVENTS_CUTOFF:-0}"

	cidr=$(validate_cidr "$cidr") || { echo "error: invalid CIDR notation '$2' (IPv4, mask 8-32)." >&2; return 1; }
	local target_addr target_mask
	target_addr="${cidr%/*}"
	target_mask="${cidr#*/}"

	if [ ! -f "$pool_file" ] || [ ! -s "$pool_file" ]; then
		printf '{"cidr": "%s", "summary": {"match_count": 0, "total_count": 0, "banned_count": 0, "truncated": false}, "ips": []}\n' \
			"$(_json_escape "$cidr")"
		return 0
	fi

	_batch_ban_status_init "$install_path"
	local _cidr_summary _cidr_ips
	_cidr_summary=$(mktemp "$install_path/tmp/.cidr_json_s.XXXXXX")
	_cidr_ips=$(mktemp "$install_path/tmp/.cidr_json_i.XXXXXX")

	local first=1 row_count=0
	local cnt ip first_ts last_ts svcs cc
	while IFS='|' read -r cnt ip first_ts last_ts svcs cc; do
		[ -z "$cnt" ] && continue
		local first_fmt last_fmt ban_status
		first_fmt=$(_fmt_ts_iso "$first_ts")
		last_fmt=$(_fmt_ts_iso "$last_ts")
		ban_status=$(_batch_ban_status_lookup "$ip")
		[ -z "$ban_status" ] && ban_status="not banned"
		if [ "$first" -eq 1 ]; then
			first=0
		else
			echo ","
		fi
		printf '    {"ip": "%s", "count": %s, "services": %s, "country": "%s", "first_seen": "%s", "last_seen": "%s", "status": "%s"}' \
			"$(_json_escape "$ip")" "$cnt" \
			"$(_json_array_from_csv "$svcs")" "$(_json_escape "${cc:---}")" \
			"$first_fmt" "$last_fmt" "$(_json_escape "$ban_status")"
		echo "$cnt|${ban_status}" >&3
		row_count=$((row_count + 1))
	done 3>"$_cidr_summary" < <(_apool_awk "$pool_file" "" "$cutoff" "$sort_mode" "$limit" "$target_addr" "$target_mask") > "$_cidr_ips"
	_batch_ban_status_cleanup

	local match_count=0 total_events=0 banned_count=0
	if [ -f "$_cidr_summary" ] && [ -s "$_cidr_summary" ]; then
		match_count=$(wc -l < "$_cidr_summary")
		total_events=$(awk -F'|' '{s+=$1} END {print s+0}' "$_cidr_summary")
		banned_count=$(awk -F'|' '$2 ~ /BANNED/ {c++} END {print c+0}' "$_cidr_summary")
	fi

	local _truncated="false"
	if [ "$limit" -gt 0 ] 2>/dev/null && [ "$row_count" -ge "$limit" ]; then  # 2>/dev/null: suppress non-numeric comparison error when limit is empty
		_truncated="true"
	fi
	printf '{"cidr": "%s", "summary": {"match_count": %d, "total_count": %d, "banned_count": %d, "truncated": %s}, "ips": [\n' \
		"$(_json_escape "$cidr")" "$match_count" "$total_events" "$banned_count" "$_truncated"
	cat "$_cidr_ips" 2>/dev/null
	echo ""
	echo "]}"
	command rm -f "$_cidr_summary" "$_cidr_ips"
}

# events_list_cidr_csv install_path cidr [sort_mode] [limit] — CSV CIDR event search
events_list_cidr_csv() {
	local install_path="$1" cidr="$2" sort_mode="${3:-count}" limit="${4:-100}"
	local pool_file="$install_path/stats/attack.pool"
	local cutoff="${_EVENTS_CUTOFF:-0}"

	cidr=$(validate_cidr "$cidr") || { echo "error: invalid CIDR notation '$2' (IPv4, mask 8-32)." >&2; return 1; }
	local target_addr target_mask
	target_addr="${cidr%/*}"
	target_mask="${cidr#*/}"

	echo "ip,count,services,country,first_seen,last_seen,status"

	if [ ! -f "$pool_file" ] || [ ! -s "$pool_file" ]; then
		return 0
	fi

	_batch_ban_status_init "$install_path"
	local cnt ip first_ts last_ts svcs cc
	while IFS='|' read -r cnt ip first_ts last_ts svcs cc; do
		[ -z "$cnt" ] && continue
		local first_fmt last_fmt ban_status
		first_fmt=$(_fmt_ts_iso "$first_ts")
		last_fmt=$(_fmt_ts_iso "$last_ts")
		ban_status=$(_batch_ban_status_lookup "$ip")
		[ -z "$ban_status" ] && ban_status="not banned"
		echo "$ip,$cnt,$svcs,${cc:---},$first_fmt,$last_fmt,$ban_status"
	done < <(_apool_awk "$pool_file" "" "$cutoff" "$sort_mode" "$limit" "$target_addr" "$target_mask")
	_batch_ban_status_cleanup
}

# search_ip_json install_path ip — JSON formatted unified IP report
search_ip_json() {
	local install_path="$1" ip="$2"

	local data
	data=$(_search_ip_data "$install_path" "$ip") || return 1

	# parse D line
	local d_line ban_ts ban_expiry hist_24h hist_total evt_count first_ts last_ts _gp_fmt trip half_life pool_triggers pool_failures
	d_line=$(echo "$data" | grep '^D|')
	IFS='|' read -r _ ban_ts ban_expiry hist_24h hist_total evt_count first_ts last_ts _gp_fmt trip half_life pool_triggers pool_failures <<< "$d_line"

	local now
	now=$(date +"%s")

	# Ban status (compact format)
	local status_str="not banned"
	if [ -n "$ban_ts" ]; then
		if [ "$ban_expiry" = "0" ]; then
			status_str="BANNED(perm)"
		else
			local remain=$(( (ban_expiry - now) / 60 ))
			[ "$remain" -lt 0 ] && remain=0
			status_str="BANNED(${remain}m)"
		fi
	fi

	# Per-service counts as JSON object from E lines
	local svcs_json="{}"
	local e_lines
	e_lines=$(echo "$data" | grep '^E|')
	if [ -n "$e_lines" ]; then
		svcs_json="{"
		local svc_first=1
		local _type _svc _cnt
		while IFS='|' read -r _type _svc _cnt; do
			[ "$_type" != "E" ] && continue
			if [ "$svc_first" -eq 1 ]; then
				svc_first=0
			else
				svcs_json="$svcs_json, "
			fi
			svcs_json="$svcs_json\"$(_json_escape "$_svc")\": $_cnt"
		done <<< "$e_lines"
		svcs_json="$svcs_json}"
	fi

	# First/last seen
	local first_fmt="null" last_fmt="null"
	if [ -n "$first_ts" ] && [ "$first_ts" -gt 0 ] 2>/dev/null; then
		first_fmt="\"$(_fmt_ts_iso "$first_ts")\""
	fi
	if [ -n "$last_ts" ] && [ "$last_ts" -gt 0 ] 2>/dev/null; then
		last_fmt="\"$(_fmt_ts_iso "$last_ts")\""
	fi

	printf '{"ip": "%s", "status": "%s", "pressure": %s, "pressure_trip": %s, "ban_history_24h": %d, "ban_history_total": %d, "count_24h": %d, "services": %s, "first_seen": %s, "last_seen": %s, "attack_pool_triggers": %d, "attack_pool_failures": %d}\n' \
		"$(_json_escape "$ip")" "$(_json_escape "$status_str")" \
		"$_gp_fmt" "$trip" \
		"$hist_24h" "$hist_total" "$evt_count" "$svcs_json" \
		"$first_fmt" "$last_fmt" "$pool_triggers" "$pool_failures"
}

# search_ip_csv install_path ip — CSV formatted unified IP report
search_ip_csv() {
	local install_path="$1" ip="$2"

	local data
	data=$(_search_ip_data "$install_path" "$ip") || return 1

	echo "ip,status,pressure,pressure_trip,ban_history_24h,ban_history_total,count_24h,first_seen,last_seen,attack_pool_triggers,attack_pool_failures"

	# parse D line
	local d_line ban_ts ban_expiry hist_24h hist_total evt_count first_ts last_ts _gp_fmt trip half_life pool_triggers pool_failures
	d_line=$(echo "$data" | grep '^D|')
	IFS='|' read -r _ ban_ts ban_expiry hist_24h hist_total evt_count first_ts last_ts _gp_fmt trip half_life pool_triggers pool_failures <<< "$d_line"

	local now
	now=$(date +"%s")

	# Ban status (compact format)
	local status_str="not banned"
	if [ -n "$ban_ts" ]; then
		if [ "$ban_expiry" = "0" ]; then
			status_str="BANNED(perm)"
		else
			local remain=$(( (ban_expiry - now) / 60 ))
			[ "$remain" -lt 0 ] && remain=0
			status_str="BANNED(${remain}m)"
		fi
	fi

	# First/last seen
	local first_fmt="" last_fmt=""
	if [ -n "$first_ts" ] && [ "$first_ts" -gt 0 ] 2>/dev/null; then
		first_fmt=$(_fmt_ts_iso "$first_ts")
	fi
	if [ -n "$last_ts" ] && [ "$last_ts" -gt 0 ] 2>/dev/null; then
		last_fmt=$(_fmt_ts_iso "$last_ts")
	fi

	echo "$ip,$status_str,$_gp_fmt,$trip,$hist_24h,$hist_total,$evt_count,$first_fmt,$last_fmt,$pool_triggers,$pool_failures"
}
