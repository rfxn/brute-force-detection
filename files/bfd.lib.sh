#!/bin/bash
#
# Brute Force Detection 2.0.1 - Function Library
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

# exit codes (used by bfd, exported for callers)
# shellcheck disable=SC2034
EXIT_OK=0
EXIT_CONFIG_ERROR=1
# shellcheck disable=SC2034
EXIT_LOCK_ERROR=2
# shellcheck disable=SC2034
EXIT_PREREQ_ERROR=3

validate_ip() {
	local ip="$1"
	local ip_pattern='^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$'
	if [[ "$ip" =~ $ip_pattern ]]; then
		local i
		for i in 1 2 3 4; do
			if [ "${BASH_REMATCH[$i]}" -gt 255 ]; then
				return 1
			fi
		done
		echo "$ip"
		return 0
	fi
	return 1
}

validate_ip6() {
	local ip="$1"
	ip="${ip%%\%*}"                          # strip zone ID (%eth0)
	[ -z "$ip" ] && return 1
	local valid='^[0-9a-fA-F:]+$'
	[[ "$ip" =~ $valid ]] || return 1        # only hex+colon
	[[ "$ip" == *:* ]] || return 1           # must have colon
	[[ "$ip" == *:::* ]] && return 1         # no triple colon
	# reject leading/trailing single colon (not part of ::)
	[[ "$ip" == :* ]] && [[ "$ip" != ::* ]] && return 1
	[[ "$ip" == *: ]] && [[ "$ip" != *:: ]] && return 1
	# at most one ::
	local no_dc="${ip/::}"
	[[ "$no_dc" == *::* ]] && return 1
	# split into groups, count and validate
	local has_dc=0
	[[ "$ip" == *::* ]] && has_dc=1
	IFS=':' read -ra groups <<< "$ip"
	local non_empty=0 g
	for g in "${groups[@]}"; do
		[ -z "$g" ] && continue
		non_empty=$((non_empty + 1))
		[ "${#g}" -gt 4 ] && return 1        # max 4 hex per group
	done
	if [ "$has_dc" -eq 1 ]; then
		[ "$non_empty" -gt 7 ] && return 1   # :: must replace ≥1 group
	else
		[ "$non_empty" -ne 8 ] && return 1   # no :: → exactly 8 groups
	fi
	echo "$ip"
	return 0
}

validate_ip_any() {
	validate_ip "$1" 2>/dev/null && return 0
	validate_ip6 "$1" 2>/dev/null
}

sanitize_mod() {
	local mod="$1"
	local mod_pattern='^[a-zA-Z0-9_-]+$'
	if [[ "$mod" =~ $mod_pattern ]]; then
		echo "$mod"
		return 0
	fi
	return 1
}

# eout requires: BFD_LOG_PATH, OUTPUT_SYSLOG, OUTPUT_SYSLOG_FILE
eout() {
	local arg="${1:-}"
	local val="${2:-}"
	if [ -n "$arg" ]; then
		local ts
		ts=$(date +"%b %e %H:%M:%S")
		local host
		host=$(hostname -s)
		echo "$ts $host bfd($$): $arg"
		if [ "$val" == "le" ]; then
			echo "$ts $host bfd($$): $arg" >> "$BFD_LOG_PATH"
		fi
		if [ "$OUTPUT_SYSLOG" == "1" ] && [ "$val" == "le" ]; then
			echo "$ts $host bfd($$): $arg" >> "$OUTPUT_SYSLOG_FILE"
		fi
	fi
}

# safe_source requires: eout() to be functional
safe_source() {
	local file="$1"
	local label="${2:-$file}"
	if [ ! -f "$file" ]; then
		eout "safe_source: $label does not exist." le
		return 1
	fi
	local fowner
	fowner=$(stat -c '%u' "$file")
	if [ "$fowner" != "0" ]; then
		eout "safe_source: $label is not owned by root (uid=$fowner)." le
		return 1
	fi
	local fperms
	fperms=$(stat -c '%a' "$file")
	# check world-writable: last digit has write bit (2, 3, 6, 7)
	local world_digit="${fperms: -1}"
	if [ "$((world_digit & 2))" -ne 0 ]; then
		eout "safe_source: $label is world-writable (perms=$fperms)." le
		return 1
	fi
	# shellcheck disable=SC1090
	. "$file"
}

# extract_command_template config_file var_name — extract raw template value
# Reads the last occurrence of VAR_NAME="value" from config_file without
# shell expansion (preserves $ATTACK_HOST, $MOD, $PORTS as literals).
extract_command_template() {
	local config_file="$1" var_name="$2"
	grep "^${var_name}=" "$config_file" | tail -1 | sed "s/^${var_name}=//;s/^\"//;s/\"$//"
}

# validate_config requires: TRIG, TRIG_WINDOW, TRIG_GLOBAL, BAN_DURATION,
#   BAN_PERMANENT_AFTER, BAN_PERMANENT_WINDOW, EMAIL_ALERTS,
#   LOCK_FILE_TIMEOUT, BAN_COMMAND_TEMPLATE, INSTALL_PATH, EXIT_CONFIG_ERROR
validate_config() {
	local int_pattern='^[0-9]+$'
	if ! [[ "$TRIG" =~ $int_pattern ]] || [ "$TRIG" -eq 0 ]; then
		echo "error: TRIG must be a positive integer (got '$TRIG')."
		exit $EXIT_CONFIG_ERROR
	fi
	if ! [[ "$TRIG_WINDOW" =~ $int_pattern ]] || [ "$TRIG_WINDOW" -eq 0 ]; then
		echo "error: TRIG_WINDOW must be a positive integer (got '$TRIG_WINDOW')."
		exit $EXIT_CONFIG_ERROR
	fi
	if ! [[ "$TRIG_GLOBAL" =~ $int_pattern ]]; then
		echo "error: TRIG_GLOBAL must be a non-negative integer (got '$TRIG_GLOBAL')."
		exit $EXIT_CONFIG_ERROR
	fi
	if ! [[ "${BAN_DURATION:-0}" =~ $int_pattern ]]; then
		echo "error: BAN_DURATION must be a non-negative integer (got '${BAN_DURATION:-}')."
		exit $EXIT_CONFIG_ERROR
	fi
	if ! [[ "${BAN_PERMANENT_AFTER:-0}" =~ $int_pattern ]]; then
		echo "error: BAN_PERMANENT_AFTER must be a non-negative integer (got '${BAN_PERMANENT_AFTER:-}')."
		exit $EXIT_CONFIG_ERROR
	fi
	if ! [[ "${BAN_PERMANENT_WINDOW:-1}" =~ $int_pattern ]] || [ "${BAN_PERMANENT_WINDOW:-1}" -eq 0 ]; then
		echo "error: BAN_PERMANENT_WINDOW must be a positive integer (got '${BAN_PERMANENT_WINDOW:-}')."
		exit $EXIT_CONFIG_ERROR
	fi
	if [ "${BAN_DURATION:-0}" -gt 0 ] && [ -z "${UNBAN_COMMAND_TEMPLATE:-}" ]; then
		echo "warning: BAN_DURATION>0 but UNBAN_COMMAND is empty; auto-unban will only remove state, not firewall rules."
	fi
	if [ "$EMAIL_ALERTS" != "0" ] && [ "$EMAIL_ALERTS" != "1" ]; then
		echo "error: EMAIL_ALERTS must be 0 or 1 (got '$EMAIL_ALERTS')."
		exit $EXIT_CONFIG_ERROR
	fi
	if ! [[ "$LOCK_FILE_TIMEOUT" =~ $int_pattern ]] || [ "$LOCK_FILE_TIMEOUT" -eq 0 ]; then
		echo "error: LOCK_FILE_TIMEOUT must be a positive integer (got '$LOCK_FILE_TIMEOUT')."
		exit $EXIT_CONFIG_ERROR
	fi
	if [ -z "$BAN_COMMAND_TEMPLATE" ]; then
		echo "error: BAN_COMMAND must not be empty."
		exit $EXIT_CONFIG_ERROR
	fi
	if [ ! -d "$INSTALL_PATH" ]; then
		echo "error: INSTALL_PATH '$INSTALL_PATH' does not exist."
		exit $EXIT_CONFIG_ERROR
	fi
	if [ -n "${LOG_SOURCE:-}" ] && \
	   [ "$LOG_SOURCE" != "auto" ] && \
	   [ "$LOG_SOURCE" != "file" ] && \
	   [ "$LOG_SOURCE" != "journal" ]; then
		echo "error: LOG_SOURCE must be auto, file, or journal (got '$LOG_SOURCE')."
		exit $EXIT_CONFIG_ERROR
	fi
	local _wi="${WATCH_INTERVAL-10}"
	if ! [[ "$_wi" =~ $int_pattern ]] || [ "$_wi" -eq 0 ]; then
		echo "error: WATCH_INTERVAL must be a positive integer (got '${WATCH_INTERVAL:-}')."
		exit $EXIT_CONFIG_ERROR
	fi
}

# detect_log_paths requires: AUTH_LOG_PATH, KERNEL_LOG_PATH, MAIL_LOG_PATH,
#   OUTPUT_SYSLOG_FILE
detect_log_paths() {
	# auto-detect log paths if configured paths don't exist
	# user overrides in conf.bfd always take priority
	if [ ! -f "$AUTH_LOG_PATH" ]; then
		if [ -f "/var/log/auth.log" ]; then
			AUTH_LOG_PATH="/var/log/auth.log"
		fi
	fi
	if [ ! -f "$KERNEL_LOG_PATH" ]; then
		if [ -f "/var/log/syslog" ]; then
			KERNEL_LOG_PATH="/var/log/syslog"
			OUTPUT_SYSLOG_FILE="$KERNEL_LOG_PATH"
		fi
	fi
	if [ ! -f "$MAIL_LOG_PATH" ]; then
		if [ -f "/var/log/mail.log" ]; then
			MAIL_LOG_PATH="/var/log/mail.log"
		fi
	fi
}

format_table() {
	if command -v column >/dev/null 2>&1; then
		column -s '|' -t
	else
		tr '|' '\t'
	fi
}

# tlog_read file tlog_name baserun — read new content from a log file
# Implements the same byte-offset tracking as files/tlog but as a function,
# avoiding subprocess overhead when called from bfd.
# Outputs new content to stdout; returns 0 on success, 1 on error.
tlog_read() {
	local file="$1" tlog_name="$2" baserun="$3"
	# Journal dispatch: use journal when file is missing (auto or journal mode)
	if [ "${LOG_SOURCE:-auto}" != "file" ] && [ ! -f "$file" ]; then
		if command -v journalctl >/dev/null 2>&1 && \
		   tlog_journal_filter "$tlog_name" >/dev/null 2>&1; then
			tlog_journal_read "$tlog_name" "$baserun"
			return $?
		fi
	fi
	if [ ! -f "$file" ]; then
		echo "$file is not a valid file, aborting" >&2
		return 1
	fi
	if [ ! -d "$baserun" ]; then
		echo "$baserun is not a valid operating path, aborting." >&2
		return 1
	fi
	local tsize size newsize
	if [ -f "$baserun/$tlog_name" ]; then
		tsize=$(cat "$baserun/$tlog_name" 2>/dev/null)
	else
		tsize=""
	fi
	local _tlog_file_size
	_tlog_file_size() { stat -c %s "$1" 2>/dev/null || wc -c < "$1"; }
	if [ -z "$tsize" ] || [ "$tsize" = "0" ]; then
		# first run or reset — record current size, output nothing
		size=$(_tlog_file_size "$file")
		echo "$size" > "$baserun/$tlog_name"
		return 0
	fi
	size="$tsize"
	newsize=$(_tlog_file_size "$file")
	if [ "$newsize" -gt "$size" ]; then
		# file grew — output new content
		tail -c $((newsize - size)) "$file"
		echo "$newsize" > "$baserun/$tlog_name"
	elif [ "$newsize" -lt "$size" ]; then
		# log rotated — output remainder from old file
		if [ -f "$file.1" ]; then
			local rtsize
			rtsize=$(_tlog_file_size "$file.1")
			if [ "$rtsize" -ge "$size" ]; then
				tail -c $((rtsize - size)) "$file.1"
			fi
		elif [ -f "$file.1.gz" ]; then
			local rtsize
			rtsize=$(zcat "$file.1.gz" | wc -c)
			if [ "$rtsize" -ge "$size" ]; then
				zcat "$file.1.gz" | tail -c $((rtsize - size))
			fi
		fi
		# output all of current file (new content since rotation)
		if [ "$newsize" -gt 0 ]; then
			cat "$file"
		fi
		echo "$newsize" > "$baserun/$tlog_name"
	fi
	# newsize == size — no change, output nothing
	return 0
}

# tlog_journal_filter tlog_name — map TLOG_TF to journalctl filter argument
# Returns 0 with filter on stdout, or 1 if no mapping exists (not journal-capable).
tlog_journal_filter() {
	local tlog_name="$1"
	case "$tlog_name" in
		sshd)       echo "SYSLOG_IDENTIFIER=sshd" ;;
		dropbear)   echo "SYSLOG_IDENTIFIER=dropbear" ;;
		dovecot)    echo "SYSLOG_IDENTIFIER=dovecot" ;;
		postfix)    echo "SYSLOG_IDENTIFIER=postfix" ;;
		courier)    echo "SYSLOG_IDENTIFIER=couriertcpd" ;;
		sendmail)   echo "SYSLOG_IDENTIFIER=sm-mta" ;;
		vpopmail)   echo "SYSLOG_IDENTIFIER=vpopmail" ;;
		cyrus)      echo "SYSLOG_IDENTIFIER=cyrus" ;;
		pure-ftpd)  echo "SYSLOG_IDENTIFIER=pure-ftpd" ;;
		proftpd)    echo "SYSLOG_IDENTIFIER=proftpd" ;;
		vsftpd)     echo "SYSLOG_IDENTIFIER=vsftpd" ;;
		webmin)     echo "SYSLOG_IDENTIFIER=webmin" ;;
		wordpress)  echo "SYSLOG_IDENTIFIER=wordpress" ;;
		rh_imapd)   echo "SYSLOG_IDENTIFIER=imapd" ;;
		rh_ipop3)   echo "SYSLOG_IDENTIFIER=ipop3d" ;;
		named)      echo "SYSLOG_IDENTIFIER=named" ;;
		*) return 1 ;;
	esac
	return 0
}

# tlog_journal_read tlog_name baserun — read new journal entries for a syslog identifier
# Uses cursor-based tracking with timestamp fallback.
# First run saves cursor and outputs nothing (matches tlog first-run behavior).
# Outputs new journal lines to stdout; returns 0 on success, 1 on error.
tlog_journal_read() {
	local tlog_name="$1" baserun="$2"
	local jfilter cursor_file ts_file
	jfilter=$(tlog_journal_filter "$tlog_name") || return 1
	cursor_file="$baserun/${tlog_name}.cursor"
	ts_file="$baserun/${tlog_name}.jts"

	if [ ! -d "$baserun" ]; then
		echo "$baserun is not a valid operating path, aborting." >&2
		return 1
	fi

	if ! command -v journalctl >/dev/null 2>&1; then
		echo "journalctl not available" >&2
		return 1
	fi

	local jctl_out cursor_line new_cursor now_ts

	if [ -f "$cursor_file" ]; then
		local saved_cursor
		saved_cursor=$(cat "$cursor_file" 2>/dev/null)
		# try cursor-based read; fall back to timestamp if cursor invalid
		jctl_out=$(timeout 30 journalctl "$jfilter" --after-cursor="$saved_cursor" \
			--output=short --show-cursor --no-pager -q 2>/dev/null) || {
			# cursor invalid (journal vacuumed?) — fall back to timestamp
			if [ -f "$ts_file" ]; then
				local saved_ts
				saved_ts=$(cat "$ts_file" 2>/dev/null)
				jctl_out=$(timeout 30 journalctl "$jfilter" --since="@${saved_ts}" \
					--output=short --show-cursor --no-pager -q 2>/dev/null) || return 1
			else
				# no fallback available; treat as first run
				jctl_out=$(timeout 30 journalctl "$jfilter" -n 0 \
					--output=short --show-cursor --no-pager -q 2>/dev/null) || return 1
			fi
		}
	elif [ -f "$ts_file" ]; then
		local saved_ts
		saved_ts=$(cat "$ts_file" 2>/dev/null)
		jctl_out=$(timeout 30 journalctl "$jfilter" --since="@${saved_ts}" \
			--output=short --show-cursor --no-pager -q 2>/dev/null) || return 1
	else
		# first run: get current cursor, output nothing
		jctl_out=$(timeout 30 journalctl "$jfilter" -n 0 \
			--output=short --show-cursor --no-pager -q 2>/dev/null) || return 1
		# extract cursor from output
		cursor_line=$(echo "$jctl_out" | grep '^-- cursor:' | tail -1)
		if [ -n "$cursor_line" ]; then
			new_cursor="${cursor_line#-- cursor: }"
			echo "$new_cursor" > "$cursor_file"
		fi
		now_ts=$(date +"%s")
		echo "$now_ts" > "$ts_file"
		return 0
	fi

	# extract and save new cursor
	cursor_line=$(echo "$jctl_out" | grep '^-- cursor:' | tail -1)
	if [ -n "$cursor_line" ]; then
		new_cursor="${cursor_line#-- cursor: }"
		echo "$new_cursor" > "$cursor_file"
		# output log lines (everything except the cursor line)
		echo "$jctl_out" | grep -v '^-- cursor:'
	else
		# no cursor in output — no new entries
		:
	fi

	# update timestamp on every successful read
	now_ts=$(date +"%s")
	echo "$now_ts" > "$ts_file"
	return 0
}

# extract_hosts pattern1 [pattern2 ...] — extract IPs from tlog output on stdin
# Each pattern is a grep -E regex with <HOST> marking the IP position.
# <HOST> is replaced with an IP-matching capture group for sed -r.
# Outputs one validated IP per line.
#
# Rules must NOT use () groups before <HOST> in a pattern.
# For alternation before <HOST>, use multiple patterns instead.
#
# Global IGNOREREGEX: if set by rule, lines matching this ERE pattern are
# excluded before extraction (fail2ban-compatible ignoreregex).
extract_hosts() {
	local ip4_re='[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
	local ip6_re='[0-9a-fA-F]{0,4}(:[0-9a-fA-F]{0,4}){1,7}'
	local tlog_input
	tlog_input=$(sed 's/::ffff://g')
	[ -z "$tlog_input" ] && return 0

	# apply IGNOREREGEX exclusion if set by rule
	if [ -n "${IGNOREREGEX:-}" ]; then
		tlog_input=$(echo "$tlog_input" | grep -Ev "$IGNOREREGEX")
		[ -z "$tlog_input" ] && return 0
	fi

	local pattern sed_pat
	for pattern in "$@"; do
		# IPv4 extraction
		sed_pat="${pattern//<HOST>/($ip4_re)}"
		# (^|.*[^0-9.]) boundary prevents greedy .* from consuming
		# leading digits of the IP address; IP capture becomes \2
		echo "$tlog_input" | sed -rn "s#(^|.*[^0-9.])${sed_pat}.*#\2#p"
		# IPv6 extraction — inner group in ip6_re pushes IP to \2
		sed_pat="${pattern//<HOST>/($ip6_re)}"
		echo "$tlog_input" | sed -rn "s#(^|.*[^0-9a-fA-F:])${sed_pat}.*#\2#p"
	done | tr -d '[]' | while IFS= read -r ip; do
		[ -z "$ip" ] && continue
		validate_ip_any "$ip" 2>/dev/null || true
	done
}

# validate_rule rule_name — check that a sourced rule set required variables
# requires: LP, TLOG_TF, ARG_VAL to be set by the rule file
# returns 0 on success, 1 on skip
validate_rule() {
	local rule_name="$1"
	if [ -z "${LP:-}" ]; then
		eout "rule $rule_name: LP not set (prerequisite not installed?), skipping" le
		return 1
	fi
	if [ ! -f "$LP" ]; then
		# allow rule if journal fallback is possible
		if [ "${LOG_SOURCE:-auto}" != "file" ] && \
		   command -v journalctl >/dev/null 2>&1 && \
		   tlog_journal_filter "${TLOG_TF:-}" >/dev/null 2>&1; then
			: # journal-capable, continue validation
		else
			eout "rule $rule_name: log file '$LP' does not exist, skipping" le
			return 1
		fi
	fi
	if [ -z "${TLOG_TF:-}" ]; then
		eout "rule $rule_name: TLOG_TF not set, skipping" le
		return 1
	fi
	if [ -z "${ARG_VAL:-}" ]; then
		return 1
	fi
	return 0
}

# filter_host host ignore_host_files lo_hosts — check if host should be processed
# returns 0 if host should be processed, 1 if ignored
filter_host() {
	local host="$1" ignore_host_files="$2" lo_hosts="$3"
	# check ignore lists
	if [ -f "$ignore_host_files" ]; then
		local file
		while IFS= read -r file; do
			[ -z "$file" ] && continue
			if [ -f "$file" ]; then
				if grep -v "#" "$file" | grep -qFx "$host"; then
					return 1
				fi
			fi
		done < <(grep -v "#" "$ignore_host_files")
	fi
	# check local addresses
	if [ -f "$lo_hosts" ]; then
		local localnet
		while IFS= read -r localnet; do
			[ -z "$localnet" ] && continue
			if [ "$host" = "$localnet" ]; then
				return 2
			fi
		done < "$lo_hosts"
	fi
	return 0
}

# execute_ban host mod ban_cmd_template dry_run [ports] [ban_cmd_v6_template]
# execute or log ban command; selects V6 template for IPv6 hosts
# retries on failure with exponential backoff (BAN_RETRY_COUNT, default 2)
# returns 0 on success, ban command exit code on failure
execute_ban() {
	local host="$1" mod="$2" ban_cmd_template="$3" dry_run="$4"
	local ports="${5:-all}" ban_cmd_v6="${6:-}"
	# select V6 command for IPv6 hosts when available
	if [ -n "$ban_cmd_v6" ] && [[ "$host" == *:* ]]; then
		ban_cmd_template="$ban_cmd_v6"
	fi
	# set globals needed by alert.bfd template and command expansion
	ATTACK_HOST="$host"
	MOD="$mod"
	PORTS="$ports"
	BAN_COMMAND="$ban_cmd_template"
	if [ "$dry_run" = "1" ]; then
		eout "{$mod} [dry-run] would ban $host with command '$BAN_COMMAND'." le
		return 0
	fi
	eout "{$mod} $host exceeded login failures; executed ban command '$BAN_COMMAND'." le
	local max_retries="${BAN_RETRY_COUNT:-2}"
	local retry_delay=1 attempt=0 ban_rc=1
	while [ "$attempt" -le "$max_retries" ] && [ "$ban_rc" -ne 0 ]; do
		eval "$BAN_COMMAND" >/dev/null 2>&1
		ban_rc=$?
		if [ "$ban_rc" -ne 0 ] && [ "$attempt" -lt "$max_retries" ]; then
			eout "{$mod} ban command for $host failed (attempt $((attempt + 1))), retrying in ${retry_delay}s." le
			sleep "$retry_delay"
			retry_delay=$((retry_delay * 2))
		fi
		attempt=$((attempt + 1))
	done
	if [ "$ban_rc" -ne 0 ]; then
		eout "{$mod} ban command for $host exited with code $ban_rc after $attempt attempt(s)." le
	fi
	return $ban_rc
}

# execute_unban host mod unban_cmd_template [ports] [unban_cmd_v6_template]
# execute unban command; selects V6 template for IPv6 hosts
# retries on failure with exponential backoff (BAN_RETRY_COUNT, default 2)
# returns 0 on success, unban command exit code on failure
execute_unban() {
	local host="$1" mod="$2" unban_cmd_template="$3"
	local ports="${4:-all}" unban_cmd_v6="${5:-}"
	# select V6 command for IPv6 hosts when available
	if [ -n "$unban_cmd_v6" ] && [[ "$host" == *:* ]]; then
		unban_cmd_template="$unban_cmd_v6"
	fi
	ATTACK_HOST="$host"
	MOD="$mod"
	PORTS="$ports"
	eout "{$mod} $host ban expired; executing unban command." le
	local max_retries="${BAN_RETRY_COUNT:-2}"
	local retry_delay=1 attempt=0 unban_rc=1
	while [ "$attempt" -le "$max_retries" ] && [ "$unban_rc" -ne 0 ]; do
		eval "$unban_cmd_template" >/dev/null 2>&1
		unban_rc=$?
		if [ "$unban_rc" -ne 0 ] && [ "$attempt" -lt "$max_retries" ]; then
			eout "{$mod} unban command for $host failed (attempt $((attempt + 1))), retrying in ${retry_delay}s." le
			sleep "$retry_delay"
			retry_delay=$((retry_delay * 2))
		fi
		attempt=$((attempt + 1))
	done
	if [ "$unban_rc" -ne 0 ]; then
		eout "{$mod} unban command for $host exited with code $unban_rc after $attempt attempt(s)." le
	fi
	return $unban_rc
}

# process_unbans install_path now unban_cmd_template [unban_cmd_v6_template]
process_unbans() {
	local install_path="$1" now="$2" unban_cmd_template="$3"
	local unban_cmd_v6="${4:-}"
	local expired_line ts expiry host mod ports
	while IFS=' ' read -r ts expiry host mod ports; do
		[ -z "$ts" ] && continue
		if [ -n "$unban_cmd_template" ]; then
			execute_unban "$host" "$mod" "$unban_cmd_template" "$ports" "$unban_cmd_v6"
		else
			eout "{$mod} $host ban expired; no UNBAN_COMMAND configured, removing state only." le
		fi
		state_bans_active_remove "$install_path" "$host"
		state_bans_history_append "$install_path" "$now" "$expiry" "$host" "$mod" "unban"
	done < <(state_bans_active_expired "$install_path" "$now")
}

# check_recidivism install_path host permanent_window now permanent_after
# returns 0 if host should be escalated to permanent ban, 1 otherwise
check_recidivism() {
	local install_path="$1" host="$2" permanent_window="$3"
	local now="$4" permanent_after="$5"
	if [ "$permanent_after" -eq 0 ]; then
		return 1
	fi
	local recent_count
	recent_count=$(state_bans_count_recent "$install_path" "$host" "$permanent_window" "$now")
	if [ "$recent_count" -ge "$permanent_after" ]; then
		return 0
	fi
	return 1
}

# list_bans install_path — display formatted active ban list
list_bans() {
	local install_path="$1"
	state_init "$install_path"
	local listing
	listing=$(state_bans_active_list "$install_path")
	if [ -z "$listing" ]; then
		echo "No active bans."
		return 0
	fi
	echo "[+] Active bans" && echo
	printf "IP|SERVICE|PORTS|BANNED|EXPIRES\n%s\n" "$listing" | format_table
}

# manual_unban install_path ip utime unban_cmd_template [unban_cmd_v6_template]
manual_unban() {
	local install_path="$1" ip="$2" utime="$3" unban_cmd_template="$4"
	local unban_cmd_v6="${5:-}"
	ip=$(validate_ip_any "$ip") || { echo "error: invalid IP address '$2'."; return 1; }
	state_init "$install_path"
	if ! state_bans_active_check "$install_path" "$ip"; then
		echo "error: $ip is not in the active ban list."
		return 1
	fi
	local ban_mod ban_ports
	ban_mod=$(awk -v ip="$ip" '$3 == ip {print $4; exit}' "$install_path/tmp/bans.active")
	ban_ports=$(awk -v ip="$ip" '$3 == ip {print $5; exit}' "$install_path/tmp/bans.active")
	if [ -n "$unban_cmd_template" ]; then
		execute_unban "$ip" "${ban_mod:-unknown}" "$unban_cmd_template" "${ban_ports:-all}" "$unban_cmd_v6"
	fi
	state_bans_active_remove "$install_path" "$ip"
	state_bans_history_append "$install_path" "$utime" "0" "$ip" "${ban_mod:-unknown}" "unban"
	echo "$ip unbanned successfully."
}

# manual_ban install_path ip utime ban_cmd_template [mod] [ports] [ban_cmd_v6_template]
manual_ban() {
	local install_path="$1" ip="$2" utime="$3" ban_cmd_template="$4"
	local mod="${5:-manual}"
	local ports="${6:-all}" ban_cmd_v6="${7:-}"
	ip=$(validate_ip_any "$ip") || { echo "error: invalid IP address '$2'."; return 1; }
	mod=$(sanitize_mod "$mod") || { echo "error: invalid service name '$mod'."; return 1; }
	state_init "$install_path"
	if state_bans_active_check "$install_path" "$ip"; then
		echo "error: $ip is already banned."
		return 1
	fi
	execute_ban "$ip" "$mod" "$ban_cmd_template" "0" "$ports" "$ban_cmd_v6"
	state_bans_active_append "$install_path" "$utime" "0" "$ip" "$mod" "$ports"
	state_bans_history_append "$install_path" "$utime" "0" "$ip" "$mod" "ban"
	echo "$ip banned permanently."
}

# --- State file I/O functions ---
# State file formats:
#   attack.pool:  "UTIME IP MOD" — persistent attack history

# state_init install_path — ensure state dirs/files exist with correct perms
state_init() {
	local install_path="$1"
	if [ ! -d "$install_path/tmp" ]; then
		mkdir -p "$install_path/tmp"
	fi
	if [ ! -d "$install_path/stats" ]; then
		mkdir -p "$install_path/stats"
	fi
	local f
	for f in "$install_path/tmp/events.dat" "$install_path/tmp/bans.active" \
		 "$install_path/tmp/bans.history"; do
		if [ ! -f "$f" ]; then
			touch "$f"
			chmod 600 "$f"
		fi
	done
	if [ ! -f "$install_path/stats/attack.pool" ]; then
		touch "$install_path/stats/attack.pool"
		chmod 600 "$install_path/stats/attack.pool"
	fi
}

# state_pool_append install_path utime host mod — append to attack.pool
state_pool_append() {
	local install_path="$1" utime="$2" host="$3" mod="$4"
	local pool_file="$install_path/stats/attack.pool"
	(
		flock -x 200
		echo "$utime $host $mod" >> "$pool_file"
	) 200>>"$pool_file"
}

# --- Ban state I/O functions ---
# State file formats:
#   bans.active:  "TIMESTAMP EXPIRY IP MOD PORTS" — currently active bans
#   bans.history: "TIMESTAMP EXPIRY IP MOD ACTION" — append-only ban event log

# state_bans_active_append install_path timestamp expiry host mod ports
# Append ban entry to bans.active. Skips if host already has active entry.
state_bans_active_append() {
	local install_path="$1" timestamp="$2" expiry="$3"
	local host="$4" mod="$5" ports="$6"
	local bans_file="$install_path/tmp/bans.active"
	(
		flock -x 200
		if awk -v ip="$host" '$3 == ip {found=1; exit} END {exit !found}' "$bans_file" 2>/dev/null; then
			return 0
		fi
		echo "$timestamp $expiry $host $mod $ports" >> "$bans_file"
	) 200>>"$bans_file"
}

# state_bans_active_remove install_path host — remove all entries for host
state_bans_active_remove() {
	local install_path="$1" host="$2"
	local bans_file="$install_path/tmp/bans.active"
	if [ ! -f "$bans_file" ] || [ ! -s "$bans_file" ]; then
		return 0
	fi
	awk -v ip="$host" '$3 != ip' "$bans_file" > "$bans_file.new" || true
	mv "$bans_file.new" "$bans_file"
}

# state_bans_active_check install_path host — return 0 if host has active ban
state_bans_active_check() {
	local install_path="$1" host="$2"
	if awk -v ip="$host" '$3 == ip {found=1; exit} END {exit !found}' "$install_path/tmp/bans.active" 2>/dev/null; then
		return 0
	fi
	return 1
}

# state_bans_active_list install_path — output formatted active ban lines
state_bans_active_list() {
	local install_path="$1"
	local bans_file="$install_path/tmp/bans.active"
	if [ ! -f "$bans_file" ] || [ ! -s "$bans_file" ]; then
		return 0
	fi
	local ts expiry host mod ports banned_fmt expiry_fmt
	while IFS=' ' read -r ts expiry host mod ports; do
		[ -z "$ts" ] && continue
		banned_fmt=$(date -d "@${ts}" +"%D %H:%M:%S" 2>/dev/null || echo "$ts")
		if [ "$expiry" = "0" ]; then
			expiry_fmt="permanent"
		else
			expiry_fmt=$(date -d "@${expiry}" +"%D %H:%M:%S" 2>/dev/null || echo "$expiry")
		fi
		echo "$host|$mod|$ports|$banned_fmt|$expiry_fmt"
	done < "$bans_file"
}

# state_bans_active_expired install_path now — output entries where EXPIRY>0 and EXPIRY<=now
state_bans_active_expired() {
	local install_path="$1" now="$2"
	local bans_file="$install_path/tmp/bans.active"
	if [ ! -f "$bans_file" ] || [ ! -s "$bans_file" ]; then
		return 0
	fi
	awk -v now="$now" '$2+0 > 0 && $2+0 <= now+0' "$bans_file"
}

# state_bans_history_append install_path timestamp expiry host mod action
state_bans_history_append() {
	local install_path="$1" timestamp="$2" expiry="$3"
	local host="$4" mod="$5" action="$6"
	local history_file="$install_path/tmp/bans.history"
	(
		flock -x 200
		echo "$timestamp $expiry $host $mod $action" >> "$history_file"
	) 200>>"$history_file"
}

# state_bans_count_recent install_path host window now — count ban/escalate events in window
state_bans_count_recent() {
	local install_path="$1" host="$2" window="$3" now="$4"
	local history_file="$install_path/tmp/bans.history"
	local cutoff=$((now - window))
	if [ ! -f "$history_file" ] || [ ! -s "$history_file" ]; then
		echo "0"
		return 0
	fi
	awk -v cutoff="$cutoff" -v host="$host" \
		'$1+0 >= cutoff && $3 == host && ($5 == "ban" || $5 == "escalate") { c++ } END { print c+0 }' \
		"$history_file"
}

# --- Event state I/O functions ---
# State file format:
#   events.dat: "TIMESTAMP IP MOD" — timestamped failure events

# state_events_append install_path timestamp host mod [count] — append events
# Appends count timestamped event lines (default 1) to events.dat
state_events_append() {
	local install_path="$1" timestamp="$2" host="$3" mod="$4"
	local count="${5:-1}"
	local events_file="$install_path/tmp/events.dat"
	(
		flock -x 200
		local i
		for ((i = 0; i < count; i++)); do
			echo "$timestamp $host $mod"
		done >> "$events_file"
	) 200>>"$events_file"
}

# state_events_count install_path host window now [mod] — count events in window
# Counts events for host within window seconds of now.
# If mod specified, counts only that service. Outputs count to stdout.
state_events_count() {
	local install_path="$1" host="$2" window="$3" now="$4"
	local mod="${5:-}"
	local events_file="$install_path/tmp/events.dat"
	local cutoff=$((now - window))
	if [ ! -f "$events_file" ] || [ ! -s "$events_file" ]; then
		echo "0"
		return 0
	fi
	if [ -n "$mod" ]; then
		awk -v cutoff="$cutoff" -v host="$host" -v mod="$mod" \
			'$1+0 >= cutoff && $2 == host && $3 == mod { c++ } END { print c+0 }' \
			"$events_file"
	else
		awk -v cutoff="$cutoff" -v host="$host" \
			'$1+0 >= cutoff && $2 == host { c++ } END { print c+0 }' \
			"$events_file"
	fi
}

# state_events_prune install_path window now [max_lines] — remove old events
# Removes events older than window. Safety cap at max_lines (default 5000).
state_events_prune() {
	local install_path="$1" window="$2" now="$3"
	local max_lines="${4:-5000}"
	local events_file="$install_path/tmp/events.dat"
	if [ ! -f "$events_file" ] || [ ! -s "$events_file" ]; then
		return 0
	fi
	local cutoff=$((now - window))
	awk -v cutoff="$cutoff" '$1+0 >= cutoff' "$events_file" | tail -n "$max_lines" > "$events_file.new"
	mv "$events_file.new" "$events_file"
}

# count_failures host hosts_parsed install_path window now mod — count windowed failures
# Replacement for count_attacks():
#   1. Count host occurrences in hosts_parsed (grep -cxF)
#   2. Append that many timestamped events
#   3. Count per-service events within window
#   4. Return the windowed count
count_failures() {
	local host="$1" hosts_parsed="$2" install_path="$3"
	local window="$4" now="$5" mod="$6"
	local count
	count=$(echo "$hosts_parsed" | grep -cxF "$host")
	if [ "$count" -gt 0 ]; then
		state_events_append "$install_path" "$now" "$host" "$mod" "$count"
	fi
	state_events_count "$install_path" "$host" "$window" "$now" "$mod"
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
		eval "log_path=\${$log_name:-}"
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

# _hc_binaries — validate ban/unban command binaries
_hc_binaries() {
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

	if [ "${BAN_DURATION:-0}" -gt 0 ] && [ -z "${UNBAN_COMMAND_TEMPLATE:-}" ]; then
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
			local _saved_REQ="${REQ:-}" _saved_LP="${LP:-}" _saved_TRIG="${TRIG:-}"
			local _saved_TLOG_TF="${TLOG_TF:-}" _saved_PORTS="${PORTS:-}"
			REQ="" LP="" TRIG="" TLOG_TF="" PORTS=""
			if safe_source "$rule_file" "rule:$rule_name" 2>/dev/null; then
				if [ -n "$REQ" ] && [ -f "$REQ" ]; then
					local rule_trig="${TRIG:-${GLOB_TRIG:-15}}"
					if [ -n "${LP:-}" ] && [ ! -f "$LP" ] && [ "$_hc_has_journalctl" -eq 1 ] && \
					   [ "$log_source" != "file" ] && \
					   tlog_journal_filter "${TLOG_TF:-}" >/dev/null 2>&1; then
						rules_active=$((rules_active + 1))
						echo "  [PASS] $rule_name: active via journal (TRIG=$rule_trig, PORTS=${PORTS:-all})"
					else
						rules_active=$((rules_active + 1))
						echo "  [PASS] $rule_name: active (TRIG=$rule_trig, PORTS=${PORTS:-all}, LOG=${LP:-n/a})"
					fi
				else
					rules_inactive=$((rules_inactive + 1))
					echo "  [SKIP] $rule_name: inactive (REQ ${REQ:-unset} not found)"
				fi
			else
				rules_inactive=$((rules_inactive + 1))
				echo "  [SKIP] $rule_name: failed to source"
			fi
			REQ="$_saved_REQ" LP="$_saved_LP" TRIG="$_saved_TRIG"
			TLOG_TF="$_saved_TLOG_TF" PORTS="$_saved_PORTS"
		done
		echo "[PASS] Rules: $rules_active active, $rules_inactive inactive ($rules_total total)"
		_hc_pass=$((_hc_pass + 1))
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

	if [ -d "$install_path/tmp" ] && [ -d "$install_path/stats" ]; then
		echo "[PASS] State: tmp/ and stats/ exist"
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
	if [ "$EMAIL_ALERTS" = "1" ]; then
		if command -v mail >/dev/null 2>&1; then
			echo "[PASS] Email alerts: enabled (mail command found)"
			_hc_pass=$((_hc_pass + 1))
		else
			echo "[WARN] Email alerts: enabled but 'mail' command not found"
			_hc_warn=$((_hc_warn + 1))
		fi
	else
		echo "[PASS] Email alerts: disabled"
		_hc_pass=$((_hc_pass + 1))
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

# format_alert_entry n total host mod ports count expiry action recent trig trig_window
# Format a single ban's detail block for email alerts.
# Sets ATTACK_HOST, MOD, PORTS globals so $BAN_COMMAND_TEMPLATE expands correctly.
format_alert_entry() {
	local n="$1" total="$2" host="$3" mod="$4" ports="$5"
	local count="$6" expiry="$7" action="$8" recent="$9"
	shift 9
	local trig="$1" trig_window="$2"

	if [ "$total" -gt 1 ]; then
		echo "--- Ban $n of $total ---"
		echo ""
	fi

	# set globals for BAN_COMMAND_TEMPLATE expansion
	ATTACK_HOST="$host"
	MOD="$mod"
	PORTS="$ports"

	local ban_type ban_detail=""
	if [ "$action" = "escalate" ]; then
		ban_type="Permanent (escalated from repeat offenses)"
	elif [ "$expiry" = "0" ]; then
		ban_type="Permanent"
	else
		local duration=$((expiry - UTIME))
		if [ "$duration" -lt 0 ]; then
			duration=0
		fi
		ban_type="Temporary ($(format_duration "$duration"))"
		ban_detail=$(date -d "@${expiry}" +"%Y-%m-%d %H:%M:%S %Z" 2>/dev/null || echo "$expiry")
	fi

	local port_display="$ports"
	if [ "$port_display" = "all" ]; then
		port_display="all ports"
	else
		port_display="port $port_display"
	fi

	echo "  Host:       $host"
	echo "  Service:    $mod ($port_display)"
	echo "  Failures:   $count in ${trig_window}s window (threshold: $trig)"
	if [ -n "$ban_detail" ]; then
		echo "  Ban:        $ban_type, expires $ban_detail"
	else
		echo "  Ban:        $ban_type"
	fi
	if [ "${BAN_PERMANENT_AFTER:-0}" -gt 0 ]; then
		echo "  History:    $recent previous ban(s) in ${BAN_PERMANENT_WINDOW:-86400}s (permanent at ${BAN_PERMANENT_AFTER})"
	fi
	# reconstruct ban command display via template expansion
	local display_cmd
	display_cmd=$(eval echo "$BAN_COMMAND_TEMPLATE" 2>/dev/null) || display_cmd="$BAN_COMMAND_TEMPLATE"
	echo "  Command:    $display_cmd"
	echo ""
}

# format_alert_body alerts_file loglines — full email body content
# Reads alerts_file, formats entries and log excerpts.
# Output goes to stdout.
format_alert_body() {
	local alerts_file="$1" loglines="${2:-50}"
	local entry_count=0

	if [ ! -f "$alerts_file" ] || [ ! -s "$alerts_file" ]; then
		return 0
	fi

	entry_count=$(wc -l < "$alerts_file")

	if [ "$entry_count" -gt 1 ]; then
		echo "$entry_count hosts banned in this check cycle."
	fi
	echo ""

	# format each entry
	local n=0
	local host mod ports count expiry action recent lp recipient trig trig_window
	while IFS='|' read -r host mod ports count expiry action recent lp recipient trig trig_window; do
		[ -z "$host" ] && continue
		n=$((n + 1))
		format_alert_entry "$n" "$entry_count" "$host" "$mod" "$ports" \
			"$count" "$expiry" "$action" "$recent" "$trig" "$trig_window"
	done < "$alerts_file"

	# log section
	local has_logs=0
	n=0
	while IFS='|' read -r host mod ports count expiry action recent lp recipient trig trig_window; do
		[ -z "$host" ] && continue
		n=$((n + 1))
		if [ -z "$lp" ] || [ ! -f "$lp" ]; then
			if [ "$has_logs" -eq 0 ]; then
				echo "  Source logs: not available (logs via systemd journal)"
				has_logs=1
			fi
			continue
		fi
		has_logs=1
		if [ "$entry_count" -gt 1 ]; then
			echo "  Source logs from '$mod' [$host]:"
		else
			echo "  Source logs from '$mod':"
		fi
		tail -n 5000 "$lp" | grep -Fw "$host" | tail -n "$loglines" | sed 's/^/  /'
		echo ""
	done < "$alerts_file"
}

# send_alerts alerts_file subject template loglines — orchestrate batched alert emails
# Groups entries by RECIPIENT field, calls format_alert_body per recipient,
# sources template and pipes to mail.
send_alerts() {
	local alerts_file="$1" subject="$2" template="$3" loglines="${4:-50}"

	if [ ! -f "$alerts_file" ] || [ ! -s "$alerts_file" ]; then
		return 0
	fi

	# get unique recipients (field 9)
	local recipients
	recipients=$(awk -F'|' '{print $9}' "$alerts_file" | sort -u)

	local recip
	while IFS= read -r recip; do
		[ -z "$recip" ] && continue
		# create per-recipient temp file
		local recip_file
		recip_file=$(mktemp "${alerts_file}.recip.XXXXXX")
		awk -F'|' -v r="$recip" '$9 == r' "$alerts_file" > "$recip_file"

		local alert_count
		alert_count=$(wc -l < "$recip_file")

		# set ALERT_COUNT and ALERT_ENTRIES for template
		ALERT_COUNT="$alert_count"
		ALERT_ENTRIES=$(format_alert_body "$recip_file" "$loglines")

		# set backward-compat globals for single-ban case
		if [ "$alert_count" -eq 1 ]; then
			local _host _mod _ports _count _expiry _action _recent _lp _recip _trig _tw
			IFS='|' read -r _host _mod _ports _count _expiry _action _recent _lp _recip _trig _tw < "$recip_file"
			ATTACK_HOST="$_host"
			MOD="$_mod"
			ATTACK_COUNT="$_count"
			LP="$_lp"
			PORTS="$_ports"
			BAN_COMMAND=$(eval echo "$BAN_COMMAND_TEMPLATE" 2>/dev/null) || BAN_COMMAND="$BAN_COMMAND_TEMPLATE"
		fi

		# augment subject for multi-ban
		local mail_subject="$subject"
		if [ "$alert_count" -gt 1 ]; then
			mail_subject="$subject ($alert_count bans)"
		fi

		# source template and pipe to mail
		if ! (. "$template") | mail -s "$mail_subject" "$recip" 2>/dev/null; then
			eout "alert email to $recip failed (mail command returned non-zero)." le
		fi

		rm -f "$recip_file"
	done <<< "$recipients"
}

# --- Phase 18: CLI Evolution functions ---

# show_status install_path — display global system status
show_status() {
	local install_path="$1"
	local now
	now=$(date +"%s")

	echo "BFD Status ($(date +"%Y-%m-%d %H:%M:%S"))"
	echo ""

	# Mode detection
	local mode="unknown"
	local watch_pid=""
	watch_pid=$(pgrep -f "bfd.*--watch" 2>/dev/null | head -1) || true
	if [ -z "$watch_pid" ]; then
		watch_pid=$(pgrep -f "bfd.*-w " 2>/dev/null | head -1) || true
	fi
	if [ -n "$watch_pid" ] && [ "$watch_pid" != "$$" ]; then
		local uptime_secs
		uptime_secs=$(ps -o etimes= -p "$watch_pid" 2>/dev/null | tr -d ' ') || uptime_secs=""
		if [ -n "$uptime_secs" ]; then
			mode="watch (pid $watch_pid, uptime $(format_duration "$uptime_secs"))"
		else
			mode="watch (pid $watch_pid)"
		fi
	elif crontab -l 2>/dev/null | grep -q 'bfd' || [ -f /etc/cron.d/bfd ]; then
		mode="cron"
	fi
	echo "  Mode:           $mode"

	# Active bans
	local bans_file="$install_path/tmp/bans.active"
	local total_bans=0 temp_bans=0 perm_bans=0
	if [ -f "$bans_file" ] && [ -s "$bans_file" ]; then
		total_bans=$(wc -l < "$bans_file")
		perm_bans=$(awk '$2+0 == 0' "$bans_file" | wc -l)
		temp_bans=$((total_bans - perm_bans))
	fi
	echo "  Active bans:    $total_bans ($temp_bans temporary, $perm_bans permanent)"

	# Events (24h) from events.dat
	local events_file="$install_path/tmp/events.dat"
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
			local _sv_REQ="${REQ:-}" _sv_LP="${LP:-}" _sv_TF="${TLOG_TF:-}"
			REQ="" LP="" TLOG_TF=""
			if safe_source "$rule_file" "rule:$rule_name" 2>/dev/null; then
				if [ -n "$REQ" ] && [ -f "$REQ" ]; then
					rules_active=$((rules_active + 1))
				fi
			fi
			REQ="$_sv_REQ" LP="$_sv_LP" TLOG_TF="$_sv_TF"
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
	local _sv_REQ="${REQ:-}" _sv_LP="${LP:-}" _sv_TRIG="${TRIG:-}"
	local _sv_TF="${TLOG_TF:-}" _sv_PORTS="${PORTS:-}"
	REQ="" LP="" TRIG="" TLOG_TF="" PORTS=""
	safe_source "$rule_file" "rule:$service" 2>/dev/null

	local rule_trig="${TRIG:-${GLOB_TRIG:-15}}"
	local rule_ports="${PORTS:-all}"

	# Log source
	if [ -n "${LP:-}" ] && [ -f "$LP" ]; then
		echo "  Log:            $LP (file)"
	elif command -v journalctl >/dev/null 2>&1 && \
	     tlog_journal_filter "${TLOG_TF:-}" >/dev/null 2>&1; then
		echo "  Log:            journal (${TLOG_TF:-})"
	else
		echo "  Log:            not available"
	fi

	echo "  Threshold:      $rule_trig failures in ${TRIG_WINDOW:-300}s"
	echo "  Ports:          $rule_ports"

	# Events (24h) for this service
	local events_file="$install_path/tmp/events.dat"
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
	REQ="$_sv_REQ" LP="$_sv_LP" TRIG="$_sv_TRIG"
	TLOG_TF="$_sv_TF" PORTS="$_sv_PORTS"
}

# show_config [var] — dump active config or single variable value
show_config() {
	local var="${1:-}"
	if [ -n "$var" ]; then
		# single variable lookup — only allow known config vars
		local val
		eval "val=\${$var:-}" 2>/dev/null || { echo "error: invalid variable name."; return 1; }
		echo "$val"
	else
		# dump all active config variables
		local config_vars="TRIG TRIG_WINDOW TRIG_GLOBAL BAN_DURATION BAN_PERMANENT_AFTER BAN_PERMANENT_WINDOW BAN_RETRY_COUNT EMAIL_ALERTS EMAIL_ADDRESS EMAIL_SUBJECT EMAIL_LOGLINES LOG_SOURCE AUTH_LOG_PATH KERNEL_LOG_PATH MAIL_LOG_PATH BFD_LOG_PATH OUTPUT_SYSLOG LOCK_FILE_TIMEOUT WATCH_INTERVAL"
		local v val
		for v in $config_vars; do
			eval "val=\${$v:-}"
			echo "$v=$val"
		done
	fi
}

# flush_bans install_path mode utime unban_cmd_template [unban_cmd_v6_template]
# mode: "temp" — unban temporary bans only; "all" — unban everything
flush_bans() {
	local install_path="$1" mode="$2" utime="$3"
	local unban_cmd_template="$4" unban_cmd_v6="${5:-}"
	local bans_file="$install_path/tmp/bans.active"
	local count=0

	if [ ! -f "$bans_file" ] || [ ! -s "$bans_file" ]; then
		echo "No active bans."
		return 0
	fi

	# Read all entries first (avoid modifying file while reading)
	local entries
	entries=$(cat "$bans_file")

	local ts expiry host mod ports
	while IFS=' ' read -r ts expiry host mod ports; do
		[ -z "$ts" ] && continue
		if [ "$mode" = "all" ] || { [ "$expiry" != "0" ] && [ "$expiry" -gt 0 ]; }; then
			if [ -n "$unban_cmd_template" ]; then
				execute_unban "$host" "$mod" "$unban_cmd_template" "$ports" "$unban_cmd_v6"
			fi
			state_bans_active_remove "$install_path" "$host"
			state_bans_history_append "$install_path" "$utime" "$expiry" "$host" "$mod" "unban"
			count=$((count + 1))
		fi
	done <<< "$entries"

	echo "$count bans removed."
}

# search_ip install_path ip — unified IP search across all state files
search_ip() {
	local install_path="$1" ip="$2"
	local now
	now=$(date +"%s")

	ip=$(validate_ip_any "$ip") || { echo "error: invalid IP address '$2'."; return 1; }

	echo "IP Report: $ip"
	echo ""

	# Ban status
	local bans_file="$install_path/tmp/bans.active"
	if [ -f "$bans_file" ] && [ -s "$bans_file" ]; then
		local ban_line
		ban_line=$(awk -v ip="$ip" '$3 == ip' "$bans_file" | head -1)
		if [ -n "$ban_line" ]; then
			local b_ts b_expiry
			b_ts=$(echo "$ban_line" | awk '{print $1}')
			b_expiry=$(echo "$ban_line" | awk '{print $2}')
			local ban_since
			ban_since=$(date -d "@${b_ts}" +"%Y-%m-%d %H:%M:%S" 2>/dev/null || echo "$b_ts")
			if [ "$b_expiry" = "0" ]; then
				echo "  Status:         BANNED (permanent since $ban_since)"
			else
				local remain=$(( (b_expiry - now) / 60 ))
				[ "$remain" -lt 0 ] && remain=0
				echo "  Status:         BANNED (temporary, ${remain}m remaining)"
			fi
		else
			echo "  Status:         not banned"
		fi
	else
		echo "  Status:         not banned"
	fi

	# Ban history
	local history_file="$install_path/tmp/bans.history"
	local cutoff_24h=$((now - 86400))
	if [ -f "$history_file" ] && [ -s "$history_file" ]; then
		local hist_bans hist_total
		hist_bans=$(awk -v ip="$ip" -v cutoff="$cutoff_24h" \
			'$3 == ip && $1+0 >= cutoff && ($5 == "ban" || $5 == "escalate") {c++} END {print c+0}' \
			"$history_file")
		hist_total=$(awk -v ip="$ip" \
			'$3 == ip && ($5 == "ban" || $5 == "escalate") {c++} END {print c+0}' \
			"$history_file")
		echo "  Ban history:    $hist_bans bans in 24h ($hist_total total)"
	else
		echo "  Ban history:    none"
	fi

	# Events
	local events_file="$install_path/tmp/events.dat"
	if [ -f "$events_file" ] && [ -s "$events_file" ]; then
		local evt_count evt_svcs
		evt_count=$(awk -v ip="$ip" -v cutoff="$cutoff_24h" \
			'$1+0 >= cutoff && $2 == ip' "$events_file" | wc -l)
		evt_svcs=$(awk -v ip="$ip" -v cutoff="$cutoff_24h" \
			'$1+0 >= cutoff && $2 == ip {s[$3]++} END {for(k in s) printf "%s(%s) ", k, s[k]}' \
			"$events_file")
		echo "  Events (24h):   $evt_count failures across $evt_svcs"

		# First/last seen
		local first_seen last_seen
		first_seen=$(awk -v ip="$ip" '$2 == ip {print $1; exit}' "$events_file")
		last_seen=$(awk -v ip="$ip" '$2 == ip {ts=$1} END {print ts+0}' "$events_file")
		if [ -n "$first_seen" ] && [ "$first_seen" -gt 0 ] 2>/dev/null; then
			echo "  First seen:     $(date -d "@${first_seen}" +"%Y-%m-%d %H:%M:%S" 2>/dev/null || echo "$first_seen")"
		fi
		if [ -n "$last_seen" ] && [ "$last_seen" -gt 0 ] 2>/dev/null; then
			echo "  Last seen:      $(date -d "@${last_seen}" +"%Y-%m-%d %H:%M:%S" 2>/dev/null || echo "$last_seen")"
		fi
	else
		echo "  Events (24h):   0"
	fi

	# Attack pool
	local pool_file="$install_path/stats/attack.pool"
	if [ -f "$pool_file" ] && [ -s "$pool_file" ]; then
		local pool_count
		pool_count=$(awk -v ip="$ip" '$2 == ip {c++} END {print c+0}' "$pool_file")
		echo "  Attack pool:    $pool_count total triggers"
	fi
}

# list_rules install_path — list all rules with status in table format
list_rules() {
	local install_path="$1"
	local rules_dir="${RULES_PATH:-$install_path/rules}"
	local log_source="${LOG_SOURCE:-auto}"

	if [ ! -d "$rules_dir" ]; then
		echo "error: rules directory not found."
		return 1
	fi

	local atmp
	atmp=$(mktemp "$install_path/tmp/.rules.XXXXXX")
	echo "RULE|STATUS|TRIG|PORTS|LOG SOURCE" > "$atmp"

	local active=0 inactive=0 total=0
	local rule_file rule_name
	for rule_file in "$rules_dir"/*; do
		[ ! -f "$rule_file" ] && continue
		rule_name=$(basename "$rule_file")
		total=$((total + 1))

		local _sv_REQ="${REQ:-}" _sv_LP="${LP:-}" _sv_TRIG="${TRIG:-}"
		local _sv_TF="${TLOG_TF:-}" _sv_PORTS="${PORTS:-}"
		REQ="" LP="" TRIG="" TLOG_TF="" PORTS=""

		if safe_source "$rule_file" "rule:$rule_name" 2>/dev/null; then
			local rule_trig="${TRIG:-${GLOB_TRIG:-15}}"
			local rule_ports="${PORTS:-all}"
			if [ -n "$REQ" ] && [ -f "$REQ" ]; then
				active=$((active + 1))
				local log_info
				if [ -n "${LP:-}" ] && [ -f "$LP" ]; then
					log_info="$LP (file)"
				elif [ "$log_source" != "file" ] && \
				     command -v journalctl >/dev/null 2>&1 && \
				     tlog_journal_filter "${TLOG_TF:-}" >/dev/null 2>&1; then
					log_info="journal"
				else
					log_info="${LP:-n/a}"
				fi
				echo "$rule_name|active|$rule_trig|$rule_ports|$log_info" >> "$atmp"
			else
				inactive=$((inactive + 1))
				echo "$rule_name|inactive|-|-|(no prereq)" >> "$atmp"
			fi
		else
			inactive=$((inactive + 1))
			echo "$rule_name|error|-|-|(source failed)" >> "$atmp"
		fi

		REQ="$_sv_REQ" LP="$_sv_LP" TRIG="$_sv_TRIG"
		TLOG_TF="$_sv_TF" PORTS="$_sv_PORTS"
	done

	format_table < "$atmp"
	echo ""
	echo "$active active, $inactive inactive ($total total)"
	rm -f "$atmp"
}

# show_rule install_path rule_name — show detailed rule info
show_rule() {
	local install_path="$1" rule_name="$2"
	local rule_file="${RULES_PATH:-$install_path/rules}/$rule_name"
	local log_source="${LOG_SOURCE:-auto}"

	if [ ! -f "$rule_file" ]; then
		echo "error: rule '$rule_name' not found."
		return 1
	fi

	echo "Rule: $rule_name"

	local _sv_REQ="${REQ:-}" _sv_LP="${LP:-}" _sv_TRIG="${TRIG:-}"
	local _sv_TF="${TLOG_TF:-}" _sv_PORTS="${PORTS:-}"
	REQ="" LP="" TRIG="" TLOG_TF="" PORTS=""

	if ! safe_source "$rule_file" "rule:$rule_name" 2>/dev/null; then
		echo "  Status:     error (failed to source)"
		REQ="$_sv_REQ" LP="$_sv_LP" TRIG="$_sv_TRIG"
		TLOG_TF="$_sv_TF" PORTS="$_sv_PORTS"
		return 1
	fi

	if [ -n "$REQ" ] && [ -f "$REQ" ]; then
		echo "  Status:     active"
	else
		echo "  Status:     inactive (${REQ:-unset} not found)"
	fi

	echo "  Threshold:  ${TRIG:-${GLOB_TRIG:-15}} failures in ${TRIG_WINDOW:-300}s"
	echo "  Ports:      ${PORTS:-all}"

	if [ -n "${LP:-}" ] && [ -f "$LP" ]; then
		echo "  Log:        $LP (file mode)"
	elif [ "$log_source" != "file" ] && \
	     command -v journalctl >/dev/null 2>&1 && \
	     tlog_journal_filter "${TLOG_TF:-}" >/dev/null 2>&1; then
		echo "  Log:        journal (${TLOG_TF:-})"
	else
		echo "  Log:        ${LP:-not configured}"
	fi

	REQ="$_sv_REQ" LP="$_sv_LP" TRIG="$_sv_TRIG"
	TLOG_TF="$_sv_TF" PORTS="$_sv_PORTS"
}

# --- Structured output formatters ---

# _json_escape str — escape string for JSON output
_json_escape() {
	local s="$1"
	s="${s//\\/\\\\}"
	s="${s//\"/\\\"}"
	echo "$s"
}

# list_bans_json install_path — JSON formatted active ban list
list_bans_json() {
	local install_path="$1"
	local bans_file="$install_path/tmp/bans.active"
	echo "["
	if [ -f "$bans_file" ] && [ -s "$bans_file" ]; then
		local first=1
		local ts expiry host mod ports
		while IFS=' ' read -r ts expiry host mod ports; do
			[ -z "$ts" ] && continue
			local banned_fmt expiry_fmt
			banned_fmt=$(date -d "@${ts}" +"%Y-%m-%dT%H:%M:%S" 2>/dev/null || echo "$ts")
			if [ "$expiry" = "0" ]; then
				expiry_fmt="permanent"
			else
				expiry_fmt=$(date -d "@${expiry}" +"%Y-%m-%dT%H:%M:%S" 2>/dev/null || echo "$expiry")
			fi
			if [ "$first" -eq 1 ]; then
				first=0
			else
				echo ","
			fi
			printf '  {"ip": "%s", "service": "%s", "ports": "%s", "banned": "%s", "expires": "%s"}' \
				"$(_json_escape "$host")" "$(_json_escape "$mod")" "$(_json_escape "$ports")" \
				"$banned_fmt" "$expiry_fmt"
		done < "$bans_file"
	fi
	echo ""
	echo "]"
}

# list_bans_csv install_path — CSV formatted active ban list
list_bans_csv() {
	local install_path="$1"
	local bans_file="$install_path/tmp/bans.active"
	echo "ip,service,ports,banned,expires"
	if [ -f "$bans_file" ] && [ -s "$bans_file" ]; then
		local ts expiry host mod ports
		while IFS=' ' read -r ts expiry host mod ports; do
			[ -z "$ts" ] && continue
			local banned_fmt expiry_fmt
			banned_fmt=$(date -d "@${ts}" +"%Y-%m-%dT%H:%M:%S" 2>/dev/null || echo "$ts")
			if [ "$expiry" = "0" ]; then
				expiry_fmt="permanent"
			else
				expiry_fmt=$(date -d "@${expiry}" +"%Y-%m-%dT%H:%M:%S" 2>/dev/null || echo "$expiry")
			fi
			echo "$host,$mod,$ports,$banned_fmt,$expiry_fmt"
		done < "$bans_file"
	fi
}
