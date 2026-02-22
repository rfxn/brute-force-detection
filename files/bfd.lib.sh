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

# count_attacks host hosts_parsed install_path trig — count attacks for host
# Counts occurrences in hosts_parsed, appends to track.attack, and if under
# trig threshold, adds accumulated track.attack counts. Outputs total to stdout.
count_attacks() {
	local host="$1" hosts_parsed="$2" install_path="$3" trig="$4"
	local count
	count=$(echo "$hosts_parsed" | grep -cFw "$host")
	state_track_append "$install_path" "$host" "$count" "${MOD:-unknown}"
	if [ "$count" -lt "$trig" ]; then
		state_track_trim "$install_path" 50
		local accumulated
		accumulated=$(state_track_count "$install_path" "$host")
		count=$((accumulated + count))
	fi
	echo "$count"
}

# execute_ban host mod ban_cmd_template dry_run [ports] [ban_cmd_v6_template]
# execute or log ban command; selects V6 template for IPv6 hosts
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
	eval "$BAN_COMMAND" >/dev/null 2>&1
	local ban_rc=$?
	if [ "$ban_rc" -ne 0 ]; then
		eout "{$mod} ban command for $host exited with code $ban_rc." le
	fi
	return $ban_rc
}

# execute_unban host mod unban_cmd_template [ports] [unban_cmd_v6_template]
# execute unban command; selects V6 template for IPv6 hosts
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
	eval "$unban_cmd_template" >/dev/null 2>&1
	local unban_rc=$?
	if [ "$unban_rc" -ne 0 ]; then
		eout "{$mod} unban command for $host exited with code $unban_rc." le
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
#   track.attack: "IP COUNT MOD" — per-run failure accumulator, line-capped
#   ban.list:     "IP" — recently banned IPs for dedup, line-capped
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
	for f in "$install_path/tmp/track.attack" "$install_path/tmp/ban.list" \
		 "$install_path/tmp/events.dat" "$install_path/tmp/bans.active" \
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

# state_track_append install_path host count mod — append to track.attack
state_track_append() {
	local install_path="$1" host="$2" count="$3" mod="$4"
	echo "$host $count $mod" >> "$install_path/tmp/track.attack"
}

# state_track_count install_path host — sum counts for host in track.attack
# outputs the total count to stdout
state_track_count() {
	local install_path="$1" host="$2"
	local total=0
	local i
	while IFS= read -r i; do
		if [ -n "$i" ]; then
			total=$((total + i))
		fi
	done < <(awk -v h="$host" '$1 == h {print $2}' "$install_path/tmp/track.attack" 2>/dev/null)
	echo "$total"
}

# state_track_trim install_path max_lines — trim track.attack to max_lines
state_track_trim() {
	local install_path="$1" max_lines="$2"
	local track_file="$install_path/tmp/track.attack"
	local cur_lines
	cur_lines=$(wc -l < "$track_file" 2>/dev/null || echo "0")
	if [ "$cur_lines" -gt "$max_lines" ]; then
		tail -n "$max_lines" "$track_file" > "$track_file.new"
		mv "$track_file.new" "$track_file"
	fi
}

# state_ban_check install_path host — return 0 if host is in ban.list, 1 if not
state_ban_check() {
	local install_path="$1" host="$2"
	if grep -qFx "$host" "$install_path/tmp/ban.list" 2>/dev/null; then
		return 0
	fi
	return 1
}

# state_ban_append install_path host max_lines — append host to ban.list, trim
state_ban_append() {
	local install_path="$1" host="$2" max_lines="$3"
	local ban_file="$install_path/tmp/ban.list"
	# trim before appending
	tail -n "$max_lines" "$ban_file" > "$ban_file.new"
	mv "$ban_file.new" "$ban_file"
	if ! grep -qFx "$host" "$ban_file" 2>/dev/null; then
		echo "$host" >> "$ban_file"
	fi
}

# state_pool_append install_path utime host mod — append to attack.pool
state_pool_append() {
	local install_path="$1" utime="$2" host="$3" mod="$4"
	echo "$utime $host $mod" >> "$install_path/stats/attack.pool"
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
	if awk -v ip="$host" '$3 == ip {found=1; exit} END {exit !found}' "$bans_file" 2>/dev/null; then
		return 0
	fi
	echo "$timestamp $expiry $host $mod $ports" >> "$bans_file"
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
	echo "$timestamp $expiry $host $mod $action" >> "$install_path/tmp/bans.history"
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
	local i
	for ((i = 0; i < count; i++)); do
		echo "$timestamp $host $mod"
	done >> "$events_file"
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

# health_check install_path — non-destructive diagnostic report
# Validates configuration, paths, rules, state, and reports status.
# Each check prints [PASS], [WARN], [FAIL], or [SKIP] with description.
health_check() {
	local install_path="$1"
	local pass_count=0 warn_count=0 fail_count=0

	# 1. Config validation — capture errors from validate_config
	local config_out config_rc=0
	config_out=$(validate_config 2>&1) || config_rc=$?
	if [ "$config_rc" -ne 0 ]; then
		echo "[FAIL] Configuration: $config_out"
		fail_count=$((fail_count + 1))
	else
		if [ -n "$config_out" ]; then
			# warnings from validate_config (e.g. UNBAN_COMMAND empty)
			echo "[WARN] Configuration: $config_out"
			warn_count=$((warn_count + 1))
		else
			echo "[PASS] Configuration validated"
			pass_count=$((pass_count + 1))
		fi
	fi

	# 2. Log paths
	local log_name log_path
	for log_name in AUTH_LOG_PATH KERNEL_LOG_PATH MAIL_LOG_PATH; do
		eval "log_path=\${$log_name:-}"
		if [ -z "$log_path" ]; then
			echo "[WARN] $log_name: not configured"
			warn_count=$((warn_count + 1))
		elif [ -f "$log_path" ] && [ -r "$log_path" ]; then
			echo "[PASS] $log_name: $log_path (exists, readable)"
			pass_count=$((pass_count + 1))
		else
			echo "[WARN] $log_name: $log_path (not found)"
			warn_count=$((warn_count + 1))
		fi
	done

	# 3. BAN_COMMAND binary
	local ban_bin
	ban_bin=$(echo "$BAN_COMMAND_TEMPLATE" | awk '{print $1}')
	if [ -z "$ban_bin" ]; then
		echo "[FAIL] BAN_COMMAND: not configured"
		fail_count=$((fail_count + 1))
	elif [ -x "$ban_bin" ]; then
		echo "[PASS] BAN_COMMAND binary: $ban_bin (found)"
		pass_count=$((pass_count + 1))
	else
		echo "[WARN] BAN_COMMAND binary: $ban_bin (not found)"
		warn_count=$((warn_count + 1))
	fi

	# 4. UNBAN_COMMAND consistency
	if [ "${BAN_DURATION:-0}" -gt 0 ] && [ -z "${UNBAN_COMMAND_TEMPLATE:-}" ]; then
		echo "[WARN] UNBAN_COMMAND is empty; temp bans won't auto-unban firewall rules"
		warn_count=$((warn_count + 1))
	fi

	# 5. BAN_COMMAND_V6 binary
	if [ -n "${BAN_COMMAND_V6_TEMPLATE:-}" ]; then
		local ban_v6_bin
		ban_v6_bin=$(echo "$BAN_COMMAND_V6_TEMPLATE" | awk '{print $1}')
		if [ -x "$ban_v6_bin" ]; then
			echo "[PASS] BAN_COMMAND_V6 binary: $ban_v6_bin (found)"
			pass_count=$((pass_count + 1))
		else
			echo "[WARN] BAN_COMMAND_V6 binary: $ban_v6_bin (not found)"
			warn_count=$((warn_count + 1))
		fi
	else
		echo "[PASS] BAN_COMMAND_V6: not configured (will use BAN_COMMAND for IPv6)"
		pass_count=$((pass_count + 1))
	fi

	# 6. journalctl availability
	local has_journalctl=0
	if command -v journalctl >/dev/null 2>&1; then
		local jctl_bin
		jctl_bin=$(command -v journalctl)
		echo "[PASS] journalctl: available ($jctl_bin)"
		pass_count=$((pass_count + 1))
		has_journalctl=1
	else
		echo "[SKIP] journalctl: not available (file-only mode)"
		pass_count=$((pass_count + 1))
	fi

	# 7. LOG_SOURCE setting
	local log_source="${LOG_SOURCE:-auto}"
	if [ "$log_source" = "auto" ]; then
		echo "[PASS] LOG_SOURCE: auto (journal fallback enabled)"
	elif [ "$log_source" = "journal" ]; then
		echo "[PASS] LOG_SOURCE: journal (prefer journal for syslog rules)"
	else
		echo "[PASS] LOG_SOURCE: file (journal disabled)"
	fi
	pass_count=$((pass_count + 1))

	# 8. Rule scan
	local rules_active=0 rules_inactive=0 rules_total=0
	if [ -d "${RULES_PATH:-$install_path/rules}" ]; then
		local rule_file rule_name
		for rule_file in "${RULES_PATH:-$install_path/rules}"/*; do
			[ ! -f "$rule_file" ] && continue
			rule_name=$(basename "$rule_file")
			rules_total=$((rules_total + 1))
			# save/restore rule variables to avoid pollution
			local _saved_REQ="${REQ:-}" _saved_LP="${LP:-}" _saved_TRIG="${TRIG:-}"
			local _saved_TLOG_TF="${TLOG_TF:-}" _saved_PORTS="${PORTS:-}"
			REQ="" LP="" TRIG="" TLOG_TF="" PORTS=""
			if safe_source "$rule_file" "rule:$rule_name" 2>/dev/null; then
				if [ -n "$REQ" ] && [ -f "$REQ" ]; then
					local rule_trig="${TRIG:-${GLOB_TRIG:-15}}"
					# check if rule would use journal (LP missing but journal-capable)
					if [ -n "${LP:-}" ] && [ ! -f "$LP" ] && [ "$has_journalctl" -eq 1 ] && \
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
		pass_count=$((pass_count + 1))
	else
		echo "[FAIL] Rules directory not found: ${RULES_PATH:-$install_path/rules}"
		fail_count=$((fail_count + 1))
	fi

	# 9. tlog tracking
	local tlog="${TLOG_PATH:-$install_path/tlog}"
	if [ -f "$tlog" ] && [ -x "$tlog" ]; then
		echo "[PASS] tlog: $tlog (executable)"
		pass_count=$((pass_count + 1))
	elif [ -f "$tlog" ]; then
		echo "[WARN] tlog: $tlog (exists but not executable)"
		warn_count=$((warn_count + 1))
	else
		echo "[WARN] tlog: $tlog (not found)"
		warn_count=$((warn_count + 1))
	fi

	# 10. State directories
	if [ -d "$install_path/tmp" ] && [ -d "$install_path/stats" ]; then
		echo "[PASS] State: tmp/ and stats/ exist"
		pass_count=$((pass_count + 1))
	else
		echo "[WARN] State: missing tmp/ or stats/ directory"
		warn_count=$((warn_count + 1))
	fi

	# 11. Lock file
	local lock="${LOCK_FILE:-$install_path/lock.utime}"
	if [ -f "$lock" ]; then
		echo "[WARN] Lock: active lock file exists ($lock)"
		warn_count=$((warn_count + 1))
	else
		echo "[PASS] Lock: no active lock"
		pass_count=$((pass_count + 1))
	fi

	# 12. Active bans
	local bans_file="$install_path/tmp/bans.active"
	local ban_count=0
	if [ -f "$bans_file" ] && [ -s "$bans_file" ]; then
		ban_count=$(wc -l < "$bans_file")
	fi
	echo "[PASS] Active bans: $ban_count"
	pass_count=$((pass_count + 1))

	echo
	echo "Summary: $pass_count passed, $warn_count warnings, $fail_count failures"
}
