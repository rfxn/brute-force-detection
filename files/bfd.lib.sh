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

# validate_config requires: TRIG, EMAIL_ALERTS, LOCK_FILE_TIMEOUT,
#   BAN_COMMAND_TEMPLATE, INSTALL_PATH, EXIT_CONFIG_ERROR
validate_config() {
	local int_pattern='^[0-9]+$'
	if ! [[ "$TRIG" =~ $int_pattern ]] || [ "$TRIG" -eq 0 ]; then
		echo "error: TRIG must be a positive integer (got '$TRIG')."
		exit $EXIT_CONFIG_ERROR
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
		eout "rule $rule_name: log file '$LP' does not exist, skipping" le
		return 1
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
				if grep -v "#" "$file" | grep -qFw "$host"; then
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

# execute_ban host mod ban_cmd_template dry_run — execute or log ban command
# returns 0 on success, ban command exit code on failure
execute_ban() {
	local host="$1" mod="$2" ban_cmd_template="$3" dry_run="$4"
	# set globals needed by alert.bfd template
	ATTACK_HOST="$host"
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
	for f in "$install_path/tmp/track.attack" "$install_path/tmp/ban.list"; do
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
	done < <(grep -Fw "$host" "$install_path/tmp/track.attack" 2>/dev/null | awk '{print$2}')
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
	if grep -qFw "$host" "$install_path/tmp/ban.list" 2>/dev/null; then
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
	if ! grep -qFw "$host" "$ban_file" 2>/dev/null; then
		echo "$host" >> "$ban_file"
	fi
}

# state_pool_append install_path utime host mod — append to attack.pool
state_pool_append() {
	local install_path="$1" utime="$2" host="$3" mod="$4"
	echo "$utime $host $mod" >> "$install_path/stats/attack.pool"
}
