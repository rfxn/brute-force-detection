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

# Source shared tlog library
_tlog_lib_path="${INSTALL_PATH:-/usr/local/bfd}/tlog_lib.sh"
if [ -f "$_tlog_lib_path" ]; then
	# shellcheck disable=SC1091 source=files/tlog_lib.sh
	. "$_tlog_lib_path"
else
	# Fallback for test environments: try relative to this script
	_tlog_lib_dir="${BASH_SOURCE[0]%/*}"
	if [ -f "$_tlog_lib_dir/tlog_lib.sh" ]; then
		# shellcheck disable=SC1091 source=files/tlog_lib.sh
		. "$_tlog_lib_dir/tlog_lib.sh"
	fi
fi
unset _tlog_lib_path _tlog_lib_dir

# Source shared elog library
_elog_lib_path="${INSTALL_PATH:-/usr/local/bfd}/elog_lib.sh"
if [ -f "$_elog_lib_path" ]; then
	# shellcheck disable=SC1090,SC1091
	. "$_elog_lib_path"
else
	_elog_lib_dir="${BASH_SOURCE[0]%/*}"
	if [ -f "$_elog_lib_dir/elog_lib.sh" ]; then
		# shellcheck disable=SC1091
		. "$_elog_lib_dir/elog_lib.sh"
	fi
fi
unset _elog_lib_path _elog_lib_dir

# Source alert library (template engine, formatting, delivery)
_alert_lib_path="${INSTALL_PATH:-/usr/local/bfd}/alert_lib.sh"
if [ -f "$_alert_lib_path" ]; then
	# shellcheck disable=SC1090,SC1091
	. "$_alert_lib_path"
else
	_alert_lib_dir="${BASH_SOURCE[0]%/*}"
	if [ -f "$_alert_lib_dir/alert_lib.sh" ]; then
		# shellcheck disable=SC1091
		. "$_alert_lib_dir/alert_lib.sh"
	fi
fi
unset _alert_lib_path _alert_lib_dir

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
	tlog_journal_register "xrdp" "SYSLOG_IDENTIFIER=xrdp-sesman"
	tlog_journal_register "asterisk" "SYSLOG_IDENTIFIER=asterisk"
	tlog_journal_register "asterisk.iax" "SYSLOG_IDENTIFIER=asterisk"
	tlog_journal_register "asterisk_nopeer" "SYSLOG_IDENTIFIER=asterisk"
}
# Register at module load
_bfd_journal_register_all

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

# validate_cidr input — validate IPv4 CIDR notation
# Returns 0 and echoes normalized addr/mask on success. IPv4 only, mask 8-32.
validate_cidr() {
	local input="$1"
	local addr mask
	addr="${input%/*}"
	mask="${input#*/}"
	if [ "$addr" = "$input" ] || [ -z "$mask" ]; then
		return 1
	fi
	# validate mask is numeric 8-32
	case "$mask" in
		*[!0-9]*) return 1 ;;
	esac
	if [ "$mask" -lt 8 ] || [ "$mask" -gt 32 ]; then
		return 1
	fi
	# validate IP portion
	addr=$(validate_ip "$addr") || return 1
	echo "$addr/$mask"
	return 0
}

# ip_to_subnet ip mask — compute the network address for an IP and prefix length
# Library utility exercised by tests and available for external callers;
# production subnet math is inline in count_subnet_attackers() for performance.
# IPv4: bit-shift arithmetic for any mask 8-32
# IPv6: group-aligned mask (must be multiple of 16); expands :: then truncates
ip_to_subnet() {
	local ip="$1" mask="$2"
	if [[ "$ip" == *:* ]]; then
		# IPv6: group-aligned mask (multiple of 16)
		local groups_to_keep=$((mask / 16))
		local full_groups=() left_count=0 right_count=0
		if [[ "$ip" == *::* ]]; then
			local left_part="${ip%%::*}" right_part="${ip#*::}"
			if [ -n "$left_part" ]; then
				IFS=':' read -ra _left <<< "$left_part"
				left_count=${#_left[@]}
			fi
			if [ -n "$right_part" ]; then
				IFS=':' read -ra _right <<< "$right_part"
				right_count=${#_right[@]}
			fi
			local zero_fill=$((8 - left_count - right_count))
			local i
			for ((i = 0; i < left_count; i++)); do
				full_groups+=("${_left[$i]}")
			done
			for ((i = 0; i < zero_fill; i++)); do
				full_groups+=("0")
			done
			for ((i = 0; i < right_count; i++)); do
				full_groups+=("${_right[$i]}")
			done
		else
			IFS=':' read -ra full_groups <<< "$ip"
		fi
		local subnet="" i
		for ((i = 0; i < groups_to_keep; i++)); do
			[ "$i" -gt 0 ] && subnet="${subnet}:"
			subnet="${subnet}${full_groups[$i]}"
		done
		echo "${subnet}::/${mask}"
		return 0
	fi
	# IPv4
	local o1 o2 o3 o4
	IFS='.' read -r o1 o2 o3 o4 <<< "$ip"
	if [ "$mask" -lt 8 ]; then
		echo "${ip}/${mask}"
		return 0
	fi
	if [ "$mask" -ge 24 ]; then
		local shift=$((32 - mask))
		o4=$(( (o4 >> shift) << shift ))
		echo "${o1}.${o2}.${o3}.${o4}/${mask}"
	elif [ "$mask" -ge 16 ]; then
		local shift=$((24 - mask))
		o3=$(( (o3 >> shift) << shift ))
		echo "${o1}.${o2}.${o3}.0/${mask}"
	elif [ "$mask" -ge 8 ]; then
		local shift=$((16 - mask))
		o2=$(( (o2 >> shift) << shift ))
		echo "${o1}.${o2}.0.0/${mask}"
	fi
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

sanitize_ports() {
	local ports="$1"
	local ports_pattern='^(all|[0-9]+(,[0-9]+)*)$'
	if [[ "$ports" =~ $ports_pattern ]]; then
		echo "$ports"
		return 0
	fi
	return 1
}

# _save_rule_vars / _restore_rule_vars / _clear_rule_vars
# Save, restore, and clear the per-rule variables that rule files set.
# Used by functions that source rules but must not clobber the caller's state.
_save_rule_vars() {
	_SV_PREREQ="${PREREQ:-}"; _SV_LOG_FILE="${LOG_FILE:-}"; _SV_TRIG="${TRIG:-}"
	_SV_LOG_TAG="${LOG_TAG:-}"; _SV_PORTS="${PORTS:-}"
	_SV_MATCHED_HOSTS="${MATCHED_HOSTS:-}"; _SV_IGNOREREGEX="${IGNOREREGEX:-}"
	_SV_SKIP_ALERT="${SKIP_ALERT:-}"; _SV_RULE_EMAIL="${RULE_EMAIL:-}"
	_SV_PRESSURE_WEIGHT="${PRESSURE_WEIGHT:-}"
	_SV_PRESSURE_TRIP="${PRESSURE_TRIP:-}"
}
_restore_rule_vars() {
	PREREQ="$_SV_PREREQ"; LOG_FILE="$_SV_LOG_FILE"; TRIG="$_SV_TRIG"
	LOG_TAG="$_SV_LOG_TAG"; PORTS="$_SV_PORTS"
	MATCHED_HOSTS="$_SV_MATCHED_HOSTS"; IGNOREREGEX="$_SV_IGNOREREGEX"
	SKIP_ALERT="$_SV_SKIP_ALERT"; RULE_EMAIL="$_SV_RULE_EMAIL"
	PRESSURE_WEIGHT="$_SV_PRESSURE_WEIGHT"
	PRESSURE_TRIP="$_SV_PRESSURE_TRIP"
}
_clear_rule_vars() {
	PREREQ="" LOG_FILE="" TRIG="" LOG_TAG="" PORTS=""
	MATCHED_HOSTS="" IGNOREREGEX="" SKIP_ALERT="" RULE_EMAIL=""
	PRESSURE_WEIGHT="" PRESSURE_TRIP=""
	# legacy names cleared for backward compat (custom rules may use them)
	REQ="" LP="" TLOG_TF="" ARG_VAL=""
}

# _compat_rule_vars — map legacy rule variable names to canonical names.
# Called after sourcing a rule file so custom rules using old names still work.
_compat_rule_vars() {
	: "${PREREQ:=${REQ:-}}"
	: "${LOG_FILE:=${LP:-}}"
	: "${LOG_TAG:=${TLOG_TF:-}}"
	: "${MATCHED_HOSTS:=${ARG_VAL:-}}"
}

# DEPRECATED: use _load_pressure_conf() — retained for backward compat callers.
# _load_thresholds conf_file — parse thresholds.conf into associative arrays
# Populates _THRESH_TRIG[], _THRESH_SKIP_ALERT[], _THRESH_RULE_EMAIL[].
# Skips comments, blank lines, and unknown keys. Validates file safety.
# Returns 0 even if file is missing (graceful degradation).
_load_thresholds() {
	local conf_file="${1:-}"
	# clear arrays (caller must have declared them)
	_THRESH_TRIG=()
	_THRESH_SKIP_ALERT=()
	_THRESH_RULE_EMAIL=()

	[ -z "$conf_file" ] && return 0
	[ ! -f "$conf_file" ] && return 0

	# validate ownership and permissions
	if ! _check_file_safety "$conf_file"; then
		elog warn "thresholds.conf has unsafe ownership (uid=$_CSAF_UID) or permissions ($_CSAF_PERMS), skipping"
		return 0
	fi

	local line rule_name fields key val pair
	while IFS= read -r line; do
		# skip comments and blank lines
		case "$line" in
			''|\#*) continue ;;
		esac
		# extract rule name (before first colon)
		rule_name="${line%%:*}"
		[ -z "$rule_name" ] && continue
		# extract fields (after first colon)
		fields="${line#*:}"
		[ -z "$fields" ] && continue
		# parse colon-delimited KEY=value pairs
		while [ -n "$fields" ]; do
			# extract next field
			case "$fields" in
				*:*) pair="${fields%%:*}"; fields="${fields#*:}" ;;
				*)   pair="$fields"; fields="" ;;
			esac
			key="${pair%%=*}"
			val="${pair#*=}"
			case "$key" in
				TRIG)       _THRESH_TRIG["$rule_name"]="$val" ;;
				SKIP_ALERT) _THRESH_SKIP_ALERT["$rule_name"]="$val" ;;
				RULE_EMAIL)
					if validate_email "$val"; then
						_THRESH_RULE_EMAIL["$rule_name"]="$val"
					else
						elog warn "thresholds.conf: $rule_name RULE_EMAIL='$val' invalid, skipping"
					fi
					;;
			esac
		done
	done < "$conf_file"
}

# DEPRECATED: use _apply_pressure() — retained for backward compat callers.
# _apply_thresholds rule_name — fill empty threshold vars from _THRESH arrays
# Called after safe_source of a rule file. Only sets variables the rule left
# empty, preserving rule-file precedence (rule > thresholds.conf > conf.bfd).
_apply_thresholds() {
	local rule_name="$1"
	if [ -z "$TRIG" ] && [ "${_THRESH_TRIG[$rule_name]+x}" = "x" ]; then
		TRIG="${_THRESH_TRIG[$rule_name]}"
	fi
	if [ -z "$SKIP_ALERT" ] && [ "${_THRESH_SKIP_ALERT[$rule_name]+x}" = "x" ]; then
		SKIP_ALERT="${_THRESH_SKIP_ALERT[$rule_name]}"
	fi
	if [ -z "$RULE_EMAIL" ] && [ "${_THRESH_RULE_EMAIL[$rule_name]+x}" = "x" ]; then
		RULE_EMAIL="${_THRESH_RULE_EMAIL[$rule_name]}"
	fi
}

# _load_pressure_conf conf_file — parse pressure.conf into associative arrays
# Populates _PRESS_WEIGHT[], _PRESS_TRIP[], _PRESS_SKIP_ALERT[], _PRESS_RULE_EMAIL[].
# Recognizes both new keys (PRESSURE_WEIGHT, PRESSURE_TRIP) and legacy TRIG key.
# Skips comments, blank lines, and unknown keys. Validates file safety.
# Returns 0 even if file is missing (graceful degradation).
_load_pressure_conf() {
	local conf_file="${1:-}"
	# clear arrays (caller must have declared them)
	_PRESS_WEIGHT=()
	_PRESS_TRIP=()
	_PRESS_SKIP_ALERT=()
	_PRESS_RULE_EMAIL=()

	[ -z "$conf_file" ] && return 0
	[ ! -f "$conf_file" ] && return 0

	# validate ownership and permissions
	if ! _check_file_safety "$conf_file"; then
		elog warn "pressure.conf has unsafe ownership (uid=$_CSAF_UID) or permissions ($_CSAF_PERMS), skipping"
		return 0
	fi

	local line rule_name fields key val pair
	while IFS= read -r line; do
		# skip comments and blank lines
		case "$line" in
			''|\#*) continue ;;
		esac
		# extract rule name (before first colon)
		rule_name="${line%%:*}"
		[ -z "$rule_name" ] && continue
		# extract fields (after first colon)
		fields="${line#*:}"
		[ -z "$fields" ] && continue
		# parse colon-delimited KEY=value pairs
		while [ -n "$fields" ]; do
			# extract next field
			case "$fields" in
				*:*) pair="${fields%%:*}"; fields="${fields#*:}" ;;
				*)   pair="$fields"; fields="" ;;
			esac
			key="${pair%%=*}"
			val="${pair#*=}"
			case "$key" in
				PRESSURE_WEIGHT)
					if [[ "$val" =~ ^[0-9]+$ ]] && [ "$val" -gt 0 ]; then
						_PRESS_WEIGHT["$rule_name"]="$val"
					else
						elog warn "pressure.conf: $rule_name PRESSURE_WEIGHT='$val' invalid (must be positive integer), skipping"
					fi
					;;
				PRESSURE_TRIP|TRIG)
					if [[ "$val" =~ ^[0-9]+$ ]] && [ "$val" -gt 0 ]; then
						_PRESS_TRIP["$rule_name"]="$val"
					else
						elog warn "pressure.conf: $rule_name PRESSURE_TRIP='$val' invalid (must be positive integer), skipping"
					fi
					;;
				SKIP_ALERT)       _PRESS_SKIP_ALERT["$rule_name"]="$val" ;;
				RULE_EMAIL)
					if validate_email "$val"; then
						_PRESS_RULE_EMAIL["$rule_name"]="$val"
					else
						elog warn "pressure.conf: $rule_name RULE_EMAIL='$val' invalid, skipping"
					fi
					;;
			esac
		done
	done < "$conf_file"
}

# _apply_pressure rule_name — fill empty pressure vars from _PRESS_* arrays
# Called after safe_source of a rule file. Only sets variables the rule left
# empty, preserving rule-file precedence (rule > pressure.conf > conf.bfd).
# Also fills TRIG from PRESSURE_TRIP for backward compat with display code.
_apply_pressure() {
	local rule_name="$1"
	# backward compat: old rule files set TRIG, treat as PRESSURE_TRIP
	if [ -z "$PRESSURE_TRIP" ] && [ -n "$TRIG" ]; then
		PRESSURE_TRIP="$TRIG"
	fi
	if [ -z "$PRESSURE_WEIGHT" ] && [ "${_PRESS_WEIGHT[$rule_name]+x}" = "x" ]; then
		PRESSURE_WEIGHT="${_PRESS_WEIGHT[$rule_name]}"
	fi
	if [ -z "$PRESSURE_TRIP" ] && [ "${_PRESS_TRIP[$rule_name]+x}" = "x" ]; then
		PRESSURE_TRIP="${_PRESS_TRIP[$rule_name]}"
	fi
	if [ -z "$SKIP_ALERT" ] && [ "${_PRESS_SKIP_ALERT[$rule_name]+x}" = "x" ]; then
		SKIP_ALERT="${_PRESS_SKIP_ALERT[$rule_name]}"
	fi
	if [ -z "$RULE_EMAIL" ] && [ "${_PRESS_RULE_EMAIL[$rule_name]+x}" = "x" ]; then
		RULE_EMAIL="${_PRESS_RULE_EMAIL[$rule_name]}"
	fi
	# backward compat: also fill TRIG from PRESSURE_TRIP for old display code
	if [ -z "$TRIG" ] && [ -n "$PRESSURE_TRIP" ]; then
		TRIG="$PRESSURE_TRIP"
	fi
}

# _rule_is_active — true when the rule's prerequisite binary/file exists
_rule_is_active() {
	[ -n "${PREREQ:-}" ] && [ -f "$PREREQ" ]
}

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

# _check_file_safety file — validate root ownership and non-group/world-writable perms
# Returns 0 (safe) or 1 (unsafe). Sets _CSAF_UID and _CSAF_PERMS for caller
# error messages. Does NOT check file existence — caller must verify first.
_check_file_safety() {
	local file="$1"
	_CSAF_UID=$(stat -L -c '%u' "$file")
	_CSAF_PERMS=$(stat -L -c '%a' "$file")
	local group_digit="${_CSAF_PERMS:1:1}"
	local world_digit="${_CSAF_PERMS: -1}"
	if [ "$_CSAF_UID" != "0" ] || [ "$((group_digit & 2))" -ne 0 ] || [ "$((world_digit & 2))" -ne 0 ]; then
		return 1
	fi
	return 0
}

# safe_source requires: eout() to be functional
safe_source() {
	local file="$1"
	local label="${2:-$file}"
	if [ ! -f "$file" ]; then
		elog error "safe_source: $label does not exist."
		return 1
	fi
	if ! _check_file_safety "$file"; then
		if [ "$_CSAF_UID" != "0" ]; then
			elog error "safe_source: $label is not owned by root (uid=$_CSAF_UID)."
		else
			elog error "safe_source: $label is group- or world-writable (perms=$_CSAF_PERMS)."
		fi
		return 1
	fi
	# shellcheck disable=SC1090
	. "$file"
}

# validate_email addr — check basic email format (user@domain)
# Returns 0 if valid, 1 if invalid. Rejects empty, missing @, semicolons,
# pipes, backticks, spaces, and other shell-unsafe characters.
validate_email() {
	local addr="$1"
	local email_p='^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$'
	[[ "$addr" =~ $email_p ]]
}

# extract_command_template config_file var_name — extract raw template value
# Reads the last occurrence of VAR_NAME="value" from config_file without
# shell expansion (preserves $ATTACK_HOST, $MOD, $PORTS as literals).
extract_command_template() {
	local config_file="$1" var_name="$2"
	grep "^${var_name}=" "$config_file" | tail -1 | sed "s/^${var_name}=//;s/^\"//;s/\"$//"
}

# expand_command_template template — expand $ATTACK_HOST, $MOD, $PORTS
# in a BAN_COMMAND template string without eval. Uses safe ${var//pat/rep}.
expand_command_template() {
	local cmd="$1"
	cmd="${cmd//\$ATTACK_HOST/$ATTACK_HOST}"
	cmd="${cmd//\$MOD/$MOD}"
	cmd="${cmd//\$PORTS/$PORTS}"
	echo "$cmd"
}

# validate_config requires: PRESSURE_TRIP, PRESSURE_HALF_LIFE, PRESSURE_TRIP_GLOBAL,
#   SUBNET_TRIG, SUBNET_MASK, SUBNET_MASK_V6,
#   BAN_TTL, BAN_ESCALATE_AFTER, BAN_ESCALATE_WINDOW, BAN_ESCALATION
#   (none/linear/double), BAN_ESCALATION_CAP, BAN_RETRY_COUNT, FIREWALL,
#   BAN_COMMAND_TEMPLATE, EMAIL_ALERTS, EMAIL_ADDRESS (when EMAIL_ALERTS=1),
#   EMAIL_LOGLINES, OUTPUT_SYSLOG, BFD_LOG_PATH, LOG_SOURCE, LOCK_FILE_TIMEOUT,
#   WATCH_INTERVAL, SCAN_MAX_LINES, SCAN_TIMEOUT, INSTALL_PATH, EXIT_CONFIG_ERROR
validate_config() {
	local int_pattern='^[0-9]+$'
	# Use ${VAR-default} (no colon) so explicit empty is validated, not skipped
	local _pt="${PRESSURE_TRIP-${TRIG:-20}}"
	if [ -z "$_pt" ] || ! [[ "$_pt" =~ $int_pattern ]] || [ "$_pt" -eq 0 ]; then
		echo "error: PRESSURE_TRIP must be a positive integer (got '${PRESSURE_TRIP:-${TRIG:-}}')." >&2
		return $EXIT_CONFIG_ERROR
	fi
	local _phl="${PRESSURE_HALF_LIFE-${TRIG_WINDOW:-300}}"
	if [ -z "$_phl" ] || ! [[ "$_phl" =~ $int_pattern ]] || [ "$_phl" -eq 0 ]; then
		echo "error: PRESSURE_HALF_LIFE must be a positive integer (got '${PRESSURE_HALF_LIFE:-${TRIG_WINDOW:-}}')." >&2
		return $EXIT_CONFIG_ERROR
	fi
	local _ptg="${PRESSURE_TRIP_GLOBAL-${TRIG_GLOBAL:-0}}"
	if [ -z "$_ptg" ] || ! [[ "$_ptg" =~ $int_pattern ]]; then
		echo "error: PRESSURE_TRIP_GLOBAL must be a non-negative integer (got '${PRESSURE_TRIP_GLOBAL:-${TRIG_GLOBAL:-}}')." >&2
		return $EXIT_CONFIG_ERROR
	fi
	local _st="${SUBNET_TRIG:-0}"
	if ! [[ "$_st" =~ $int_pattern ]]; then
		echo "error: SUBNET_TRIG must be a non-negative integer (got '${SUBNET_TRIG:-}')." >&2
		return $EXIT_CONFIG_ERROR
	fi
	local _sm="${SUBNET_MASK:-24}"
	if ! [[ "$_sm" =~ $int_pattern ]] || [ "$_sm" -lt 8 ] || [ "$_sm" -gt 32 ]; then
		echo "error: SUBNET_MASK must be an integer between 8 and 32 (got '${SUBNET_MASK:-}')." >&2
		return $EXIT_CONFIG_ERROR
	fi
	local _sm6="${SUBNET_MASK_V6:-48}"
	if ! [[ "$_sm6" =~ $int_pattern ]] || [ "$_sm6" -lt 16 ] || [ "$_sm6" -gt 128 ] || [ $((_sm6 % 16)) -ne 0 ]; then
		echo "error: SUBNET_MASK_V6 must be a multiple of 16 between 16 and 128 (got '${SUBNET_MASK_V6:-}')." >&2
		return $EXIT_CONFIG_ERROR
	fi
	if ! [[ "${BAN_TTL:-${BAN_DURATION:-0}}" =~ $int_pattern ]]; then
		echo "error: BAN_TTL must be a non-negative integer (got '${BAN_TTL:-${BAN_DURATION:-}}')." >&2
		return $EXIT_CONFIG_ERROR
	fi
	if ! [[ "${BAN_ESCALATE_AFTER:-${BAN_PERMANENT_AFTER:-0}}" =~ $int_pattern ]]; then
		echo "error: BAN_ESCALATE_AFTER must be a non-negative integer (got '${BAN_ESCALATE_AFTER:-${BAN_PERMANENT_AFTER:-}}')." >&2
		return $EXIT_CONFIG_ERROR
	fi
	if ! [[ "${BAN_ESCALATE_WINDOW:-${BAN_PERMANENT_WINDOW:-1}}" =~ $int_pattern ]] || [ "${BAN_ESCALATE_WINDOW:-${BAN_PERMANENT_WINDOW:-1}}" -eq 0 ]; then
		echo "error: BAN_ESCALATE_WINDOW must be a positive integer (got '${BAN_ESCALATE_WINDOW:-${BAN_PERMANENT_WINDOW:-}}')." >&2
		return $EXIT_CONFIG_ERROR
	fi
	if [ "${FIREWALL:-auto}" = "custom" ] && [ "${BAN_TTL:-${BAN_DURATION:-0}}" -gt 0 ] && [ -z "${UNBAN_COMMAND_TEMPLATE:-}" ]; then
		echo "warning: BAN_TTL>0 but UNBAN_COMMAND is empty; auto-unban will only remove state, not firewall rules." >&2
	fi
	if [ "$EMAIL_ALERTS" != "0" ] && [ "$EMAIL_ALERTS" != "1" ]; then
		echo "error: EMAIL_ALERTS must be 0 or 1 (got '$EMAIL_ALERTS')." >&2
		return $EXIT_CONFIG_ERROR
	fi
	if [ "$EMAIL_ALERTS" = "1" ] && [ -z "${EMAIL_ADDRESS:-}" ]; then
		echo "error: EMAIL_ADDRESS must be set when EMAIL_ALERTS=1." >&2
		return $EXIT_CONFIG_ERROR
	fi
	if [ "$EMAIL_ALERTS" = "1" ] && [ -n "${EMAIL_ADDRESS:-}" ]; then
		local _ea _ifs_save="$IFS"
		IFS=','
		for _ea in $EMAIL_ADDRESS; do
			IFS="$_ifs_save"
			_ea="${_ea## }"
			_ea="${_ea%% }"
			if [ -n "$_ea" ] && ! validate_email "$_ea"; then
				echo "warning: EMAIL_ADDRESS contains invalid address '$_ea'." >&2
			fi
		done
		IFS="$_ifs_save"
	fi
	local _os="${OUTPUT_SYSLOG:-0}"
	if [ "$_os" != "0" ] && [ "$_os" != "1" ]; then
		echo "error: OUTPUT_SYSLOG must be 0 or 1 (got '${OUTPUT_SYSLOG:-}')." >&2
		return $EXIT_CONFIG_ERROR
	fi
	if ! [[ "$LOCK_FILE_TIMEOUT" =~ $int_pattern ]] || [ "$LOCK_FILE_TIMEOUT" -eq 0 ]; then
		echo "error: LOCK_FILE_TIMEOUT must be a positive integer (got '$LOCK_FILE_TIMEOUT')." >&2
		return $EXIT_CONFIG_ERROR
	fi
	local valid_fw="auto apf csf firewalld ufw nftables iptables route custom"
	if [ -n "${FIREWALL:-}" ]; then
		local _fw_valid=0 _fw
		for _fw in $valid_fw; do
			if [ "$FIREWALL" = "$_fw" ]; then
				_fw_valid=1
				break
			fi
		done
		if [ "$_fw_valid" -eq 0 ]; then
			echo "error: FIREWALL must be one of: $valid_fw (got '$FIREWALL')." >&2
			return $EXIT_CONFIG_ERROR
		fi
	fi
	if [ "${FIREWALL:-auto}" = "custom" ] && [ -z "$BAN_COMMAND_TEMPLATE" ]; then
		echo "error: BAN_COMMAND must not be empty when FIREWALL=custom." >&2
		return $EXIT_CONFIG_ERROR
	fi
	if [ ! -d "$INSTALL_PATH" ]; then
		echo "error: INSTALL_PATH '$INSTALL_PATH' does not exist." >&2
		return $EXIT_CONFIG_ERROR
	fi
	if [ -z "${BFD_LOG_PATH:-}" ]; then
		echo "error: BFD_LOG_PATH must not be empty." >&2
		return $EXIT_CONFIG_ERROR
	fi
	if [ -n "${LOG_SOURCE:-}" ] && \
	   [ "$LOG_SOURCE" != "auto" ] && \
	   [ "$LOG_SOURCE" != "file" ] && \
	   [ "$LOG_SOURCE" != "journal" ]; then
		echo "error: LOG_SOURCE must be auto, file, or journal (got '$LOG_SOURCE')." >&2
		return $EXIT_CONFIG_ERROR
	fi
	local _wi="${WATCH_INTERVAL:-10}"
	if ! [[ "$_wi" =~ $int_pattern ]] || [ "$_wi" -eq 0 ]; then
		echo "error: WATCH_INTERVAL must be a positive integer (got '${WATCH_INTERVAL:-}')." >&2
		return $EXIT_CONFIG_ERROR
	fi
	if [ -n "${SCAN_MAX_LINES:-}" ] && ! [[ "${SCAN_MAX_LINES:-0}" =~ $int_pattern ]]; then
		echo "error: SCAN_MAX_LINES must be a non-negative integer (got '${SCAN_MAX_LINES:-}')." >&2
		return $EXIT_CONFIG_ERROR
	fi
	if [ -n "${SCAN_TIMEOUT:-}" ] && { ! [[ "${SCAN_TIMEOUT:-120}" =~ $int_pattern ]] || [ "${SCAN_TIMEOUT:-120}" -eq 0 ]; }; then
		echo "error: SCAN_TIMEOUT must be a positive integer (got '${SCAN_TIMEOUT:-}')." >&2
		return $EXIT_CONFIG_ERROR
	fi
	local _esc="${BAN_ESCALATION:-none}"
	if [ "$_esc" != "none" ] && [ "$_esc" != "linear" ] && [ "$_esc" != "double" ] && [ "$_esc" != "exponential" ]; then
		echo "error: BAN_ESCALATION must be none, linear, or double (got '$_esc'; 'exponential' is accepted as deprecated alias for 'double')." >&2
		return $EXIT_CONFIG_ERROR
	fi
	if ! [[ "${BAN_ESCALATION_CAP:-0}" =~ $int_pattern ]]; then
		echo "error: BAN_ESCALATION_CAP must be a non-negative integer (got '${BAN_ESCALATION_CAP:-}')." >&2
		return $EXIT_CONFIG_ERROR
	fi
	if ! [[ "${BAN_RETRY_COUNT:-0}" =~ $int_pattern ]]; then
		echo "error: BAN_RETRY_COUNT must be a non-negative integer (got '${BAN_RETRY_COUNT:-}')." >&2
		return $EXIT_CONFIG_ERROR
	fi
	if ! [[ "${EMAIL_LOGLINES:-50}" =~ $int_pattern ]] || [ "${EMAIL_LOGLINES:-50}" -eq 0 ]; then
		echo "error: EMAIL_LOGLINES must be a positive integer (got '${EMAIL_LOGLINES:-}')." >&2
		return $EXIT_CONFIG_ERROR
	fi
	# EMAIL_FORMAT: must be "text", "html", or "both"
	local _ef="${EMAIL_FORMAT:-text}"
	if [ "$_ef" != "text" ] && [ "$_ef" != "html" ] && [ "$_ef" != "both" ]; then
		echo "error: EMAIL_FORMAT must be text, html, or both (got '${EMAIL_FORMAT:-}')." >&2
		return $EXIT_CONFIG_ERROR
	fi
	# EMAIL_DIGEST: must be "cycle" or "timed"
	local _ed="${EMAIL_DIGEST:-cycle}"
	if [ "$_ed" != "cycle" ] && [ "$_ed" != "timed" ]; then
		echo "error: EMAIL_DIGEST must be cycle or timed (got '${EMAIL_DIGEST:-}')." >&2
		return $EXIT_CONFIG_ERROR
	fi
	# EMAIL_DIGEST_INTERVAL: positive integer when EMAIL_DIGEST=timed
	if [ "$_ed" = "timed" ]; then
		if ! [[ "${EMAIL_DIGEST_INTERVAL:-900}" =~ $int_pattern ]] || [ "${EMAIL_DIGEST_INTERVAL:-900}" -eq 0 ]; then
			echo "error: EMAIL_DIGEST_INTERVAL must be a positive integer (got '${EMAIL_DIGEST_INTERVAL:-}')." >&2
			return $EXIT_CONFIG_ERROR
		fi
	fi
	# EMAIL_REPUTATION_LINKS: comma-separated keys from known set (warning only)
	if [ -n "${EMAIL_REPUTATION_LINKS:-}" ]; then
		local _rl _rl_ifs_save="$IFS" _rl_known="abuseipdb shodan virustotal ipinfo greynoise"
		IFS=','
		for _rl in $EMAIL_REPUTATION_LINKS; do
			IFS="$_rl_ifs_save"
			_rl="${_rl## }"
			_rl="${_rl%% }"
			if [ -n "$_rl" ]; then
				local _rl_valid=0 _rl_k
				for _rl_k in $_rl_known; do
					if [ "$_rl" = "$_rl_k" ]; then
						_rl_valid=1
						break
					fi
				done
				if [ "$_rl_valid" -eq 0 ]; then
					echo "warning: EMAIL_REPUTATION_LINKS contains unknown provider '$_rl'." >&2
				fi
			fi
		done
		IFS="$_rl_ifs_save"
	fi
	# SMTP_RELAY: must contain "://" when set
	if [ -n "${SMTP_RELAY:-}" ]; then
		case "$SMTP_RELAY" in
			*"://"*) ;;
			*)
				echo "error: SMTP_RELAY must be a URL with protocol (got '$SMTP_RELAY')." >&2
				return $EXIT_CONFIG_ERROR
				;;
		esac
		# SMTP_FROM: required when SMTP_RELAY is set
		if [ -z "${SMTP_FROM:-}" ]; then
			echo "error: SMTP_FROM must be set when SMTP_RELAY is configured." >&2
			return $EXIT_CONFIG_ERROR
		fi
		if ! validate_email "$SMTP_FROM"; then
			echo "error: SMTP_FROM is not a valid email address (got '$SMTP_FROM')." >&2
			return $EXIT_CONFIG_ERROR
		fi
		# SMTP_USER/SMTP_PASS: warn if not set (some relays are auth-free)
		if [ -z "${SMTP_USER:-}" ] || [ -z "${SMTP_PASS:-}" ]; then
			echo "warning: SMTP_USER/SMTP_PASS not set; relay may fail if authentication is required." >&2
		fi
	fi
	# LOG_FORMAT: must be "classic" or "json"
	local _lf="${LOG_FORMAT:-classic}"
	if [ "$_lf" != "classic" ] && [ "$_lf" != "json" ]; then
		echo "error: LOG_FORMAT must be classic or json (got '${LOG_FORMAT:-}')." >&2
		return $EXIT_CONFIG_ERROR
	fi
	# LOG_LEVEL: must be 0-3 integer
	local _ll="${LOG_LEVEL:-1}"
	if ! [[ "$_ll" =~ $int_pattern ]] || [ "$_ll" -gt 3 ]; then
		echo "error: LOG_LEVEL must be 0, 1, 2, or 3 (got '${LOG_LEVEL:-}')." >&2
		return $EXIT_CONFIG_ERROR
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

# _rule_tlog log_file log_tag — in-process tlog for rule execution.
# Replaces the subprocess call: $("$TLOG_PATH" "$LOG_FILE" "$LOG_TAG")
# When _TLOG_PASSTHROUGH is set, outputs the entire file instead of a delta
# (used by test_rule() to feed full test data through the rule pipeline).
# Requires: TLOG_BASERUN (set in internals.conf / files/bfd fallback).
_rule_tlog() {
	local lp="$1" tlog_tf="$2"
	if [ -n "${_TLOG_PASSTHROUGH:-}" ]; then
		# test mode: output entire file (or specific file)
		if [ "$_TLOG_PASSTHROUGH" = "1" ]; then
			cat "$lp"
		else
			cat "$_TLOG_PASSTHROUGH"
		fi
		return 0
	fi
	# scan mode: read full file without cursor tracking
	if [ "${_SCAN_MODE:-}" = "1" ]; then
		# journal dispatch (mirrors tlog_read journal check)
		if [ "${LOG_SOURCE:-auto}" != "file" ] && [ ! -f "$lp" ]; then
			if command -v journalctl >/dev/null 2>&1 && \
			   tlog_journal_filter "$tlog_tf" >/dev/null 2>&1; then
				tlog_journal_read_full "$tlog_tf" "${SCAN_TIMEOUT:-120}" "${SCAN_MAX_LINES:-50000}"
				return $?
			fi
		fi
		tlog_read_full "$lp" "${SCAN_MAX_LINES:-50000}"
		return $?
	fi
	tlog_read "$lp" "$tlog_tf" "${TLOG_BASERUN:-$INSTALL_PATH/tmp}"
}

# extract_hosts pattern1 [pattern2 ...] — extract IPs from tlog output on stdin
# Each pattern is a grep -E regex with <HOST> marking the IP position.
# <HOST> is replaced with an IP-matching capture group for sed -E.
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
		# validate regex: grep -E returns 2 for invalid patterns
		local ign_rc=0
		grep -E "$IGNOREREGEX" /dev/null >/dev/null 2>&1 || ign_rc=$?
		if [ "$ign_rc" -eq 2 ]; then
			elog warn "invalid IGNOREREGEX pattern '$IGNOREREGEX', ignoring" >&2
			IGNOREREGEX=""
		else
			tlog_input=$(echo "$tlog_input" | grep -Ev "$IGNOREREGEX")
			[ -z "$tlog_input" ] && return 0
		fi
	fi

	local pattern sed_pat
	for pattern in "$@"; do
		# IPv4 extraction
		sed_pat="${pattern//<HOST>/($ip4_re)}"
		# (^|.*[^0-9.]) boundary prevents greedy .* from consuming
		# leading digits of the IP address; IP capture becomes \2
		echo "$tlog_input" | sed -En "s#(^|.*[^0-9.])${sed_pat}.*#\2#p"
		# IPv6 extraction — inner group in ip6_re pushes IP to \2
		sed_pat="${pattern//<HOST>/($ip6_re)}"
		echo "$tlog_input" | sed -En "s#(^|.*[^0-9a-fA-F:])${sed_pat}.*#\2#p"
	done | tr -d '[]' | while IFS= read -r ip; do
		[ -z "$ip" ] && continue
		validate_ip_any "$ip" 2>/dev/null || true
	done
}

# validate_rule rule_name — check that a sourced rule set required variables.
# Distinguishes three cases:
#   1. Service not installed (PREREQ set but missing) — silent skip
#   2. File-detection rule with no match (PREREQ+LOG_FILE both empty) — silent skip
#   3. Genuine misconfiguration (LOG_FILE/LOG_TAG missing despite PREREQ existing) — logged
# MATCHED_HOSTS check is NOT here — caller handles it after counting active rules.
# returns 0 on success (rule is active), 1 on skip
validate_rule() {
	local rule_name="$1"
	# 1. Service not installed (binary set but missing) — silent skip
	if [ -n "${PREREQ:-}" ] && [ ! -f "$PREREQ" ]; then
		return 1
	fi
	# 2. File-detection rules with no match — silent skip
	if [ -z "${PREREQ:-}" ] && [ -z "${LOG_FILE:-}" ]; then
		return 1
	fi
	# 3. LOG_FILE not set despite PREREQ existing — genuine misconfiguration
	if [ -z "${LOG_FILE:-}" ]; then
		elog warn "rule $rule_name: LOG_FILE not set (service found but log path missing), skipping"
		return 1
	fi
	# 4. LOG_FILE missing — check journal fallback
	if [ ! -f "$LOG_FILE" ]; then
		if [ "${LOG_SOURCE:-auto}" != "file" ] && \
		   command -v journalctl >/dev/null 2>&1 && \
		   tlog_journal_filter "${LOG_TAG:-}" >/dev/null 2>&1; then
			: # journal-capable, continue
		else
			elog warn "rule $rule_name: log file '$LOG_FILE' does not exist, skipping"
			return 1
		fi
	fi
	# 5. LOG_TAG not set
	if [ -z "${LOG_TAG:-}" ]; then
		elog warn "rule $rule_name: LOG_TAG not set, skipping"
		return 1
	fi
	# Rule is ACTIVE — MATCHED_HOSTS check moves to caller
	return 0
}

# filter_host host ignore_host_files lo_hosts — check if host should be excluded
# returns: 0 = not filtered (proceed), 1 = ignored (in ignore list), 2 = local address
# When _IGNORE_CACHE_FILE is set, uses the pre-built merged ignore list for O(1)
# grep lookups instead of re-reading and stripping every ignore file per IP.
filter_host() {
	local host="$1" ignore_host_files="$2" lo_hosts="$3"
	# check ignore lists — use pre-built cache if available
	if [ -n "${_IGNORE_CACHE_FILE:-}" ] && [ -f "$_IGNORE_CACHE_FILE" ]; then
		if grep -qFx "$host" "$_IGNORE_CACHE_FILE" 2>/dev/null; then
			return 1
		fi
	elif [ -f "$ignore_host_files" ]; then
		local file
		while IFS= read -r file; do
			[ -z "$file" ] && continue
			if [ -f "$file" ]; then
				if sed 's/[[:space:]]*#.*//' "$file" | grep -v '^[[:space:]]*$' | grep -qFx "$host"; then
					return 1
				fi
			fi
		done < <(sed 's/[[:space:]]*#.*//' "$ignore_host_files" | grep -v '^[[:space:]]*$')
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

# _build_ignore_cache ignore_host_files cache_file — pre-load all ignore lists
# into a single merged file (comment-stripped, blank-stripped, one IP per line).
# Used by check() to avoid repeated file reads in the per-IP inner loop.
_build_ignore_cache() {
	local ignore_host_files="$1" cache_file="$2"
	if [ ! -f "$ignore_host_files" ]; then
		return 0
	fi
	local _igf
	while IFS= read -r _igf; do
		[ -z "$_igf" ] && continue
		if [ -f "$_igf" ]; then
			sed 's/[[:space:]]*#.*//' "$_igf" | grep -v '^[[:space:]]*$'
		fi
	done < <(sed 's/[[:space:]]*#.*//' "$ignore_host_files" | grep -v '^[[:space:]]*$') > "$cache_file"
}

# --- Firewall backend system ---
# Auto-detects or uses configured firewall for ban/unban operations.
# Each backend implements: _fw_BACKEND_{ban,unban,setup,status}
# Dispatch layer: fw_resolve_backend, fw_setup, fw_ban, fw_unban, fw_status

# detect_firewall — auto-detect available firewall tool
# returns backend name on stdout: apf, csf, firewalld, ufw, nftables, iptables, route
detect_firewall() {
	if command -v apf >/dev/null 2>&1; then echo "apf"; return; fi
	if command -v csf >/dev/null 2>&1; then echo "csf"; return; fi
	if command -v firewall-cmd >/dev/null 2>&1 && \
	   firewall-cmd --state >/dev/null 2>&1; then echo "firewalld"; return; fi
	if command -v ufw >/dev/null 2>&1 && \
	   ufw status 2>/dev/null | grep -q "Status: active"; then echo "ufw"; return; fi
	if command -v nft >/dev/null 2>&1 && \
	   nft list tables >/dev/null 2>&1; then echo "nftables"; return; fi
	if command -v iptables >/dev/null 2>&1 && \
	   iptables -V >/dev/null 2>&1; then echo "iptables"; return; fi
	echo "route"
}

# --- APF backend ---
_fw_apf_setup() {
	_FW_APF_BIN=$(command -v apf 2>/dev/null) || _FW_APF_BIN=""
	if [ -z "$_FW_APF_BIN" ]; then
		elog error "{glob} apf binary not found"
		return 1
	fi
}

_fw_apf_ban() {
	local host="$1" mod="${2:-}"
	"$_FW_APF_BIN" -d "$host" "{bfd.$mod}" >/dev/null 2>&1
}

_fw_apf_unban() {
	local host="$1"
	"$_FW_APF_BIN" -u "$host" >/dev/null 2>&1
}

_fw_apf_status() {
	echo "apf (Advanced Policy Firewall)"
}

# --- CSF backend ---
_fw_csf_setup() {
	_FW_CSF_BIN=$(command -v csf 2>/dev/null) || _FW_CSF_BIN=""
	if [ -z "$_FW_CSF_BIN" ]; then
		elog error "{glob} csf binary not found"
		return 1
	fi
}

_fw_csf_ban() {
	local host="$1" mod="${2:-}"
	"$_FW_CSF_BIN" -d "$host" "bfd.$mod" >/dev/null 2>&1
}

_fw_csf_unban() {
	local host="$1"
	"$_FW_CSF_BIN" -dr "$host" >/dev/null 2>&1
}

_fw_csf_status() {
	echo "csf (ConfigServer Security & Firewall)"
}

# --- firewalld backend (runtime-only rich rules, no --permanent) ---
_fw_firewalld_setup() { :; }

_fw_firewalld_ban() {
	local host="$1" family="ipv4"
	[[ "$host" == *:* ]] && family="ipv6"
	firewall-cmd --add-rich-rule="rule family=$family source address=$host drop" >/dev/null 2>&1
}

_fw_firewalld_unban() {
	local host="$1" family="ipv4"
	[[ "$host" == *:* ]] && family="ipv6"
	firewall-cmd --remove-rich-rule="rule family=$family source address=$host drop" >/dev/null 2>&1
}

_fw_firewalld_status() {
	local count=0
	count=$(firewall-cmd --list-rich-rules 2>/dev/null | grep -c "drop") || count=0
	echo "firewalld ($count rich rules, runtime-only)"
}

# --- UFW backend ---
_fw_ufw_setup() { :; }

_fw_ufw_ban() {
	local host="$1"
	# try with comment marker for identification; fall back for old UFW (<0.35)
	ufw insert 1 deny from "$host" comment "bfd" >/dev/null 2>&1 \
		|| ufw insert 1 deny from "$host" >/dev/null 2>&1
}

_fw_ufw_unban() {
	local host="$1"
	ufw delete deny from "$host" >/dev/null 2>&1
}

_fw_ufw_status() {
	local count=0
	# count BFD-commented rules; fall back to all deny rules if no comments found
	count=$(ufw status 2>/dev/null | grep -c "# bfd") || count=0
	if [ "$count" -eq 0 ]; then
		count=$(ufw status 2>/dev/null | grep -c "DENY") || count=0
	fi
	echo "ufw ($count deny rules)"
}

# --- nftables backend (dedicated inet bfd table with IP sets) ---
_fw_nftables_setup() {
	# idempotent: skip if table already exists
	nft list table inet bfd >/dev/null 2>&1 && return 0
	nft add table inet bfd || return 1
	nft add set inet bfd blocked4 '{ type ipv4_addr; flags interval; }' || return 1
	nft add set inet bfd blocked6 '{ type ipv6_addr; flags interval; }' || return 1
	nft add chain inet bfd input '{ type filter hook input priority -1; policy accept; }' || return 1
	nft add rule inet bfd input ip saddr @blocked4 drop || return 1
	nft add rule inet bfd input ip6 saddr @blocked6 drop || return 1
}

_fw_nftables_ban() {
	local host="$1"
	if [[ "$host" == *:* ]]; then
		nft add element inet bfd blocked6 "{ $host }" >/dev/null 2>&1
	else
		nft add element inet bfd blocked4 "{ $host }" >/dev/null 2>&1
	fi
}

_fw_nftables_unban() {
	local host="$1"
	if [[ "$host" == *:* ]]; then
		nft delete element inet bfd blocked6 "{ $host }" >/dev/null 2>&1
	else
		nft delete element inet bfd blocked4 "{ $host }" >/dev/null 2>&1
	fi
}

# _fw_nftables_count_elements set_name — count elements in an nft set
# Parses "elements = { ip1, ip2, ... }" from nft output; handles multiline.
_fw_nftables_count_elements() {
	local set_name="$1"
	nft list set inet bfd "$set_name" 2>/dev/null | awk '
		/elements/ { found = 1 }
		found {
			for (i = 1; i <= length($0); i++)
				if (substr($0, i, 1) == ",") commas++
			if (/\}/) exit
		}
		END { print found ? commas + 1 : 0 }
	' || echo "0"
}

_fw_nftables_status() {
	local v4_count=0 v6_count=0
	# count actual set elements (comma-delimited), not lines containing "elements"
	v4_count=$(_fw_nftables_count_elements "blocked4")
	v6_count=$(_fw_nftables_count_elements "blocked6")
	echo "nftables (inet bfd table, $v4_count v4 + $v6_count v6 blocked)"
}

# --- iptables backend (dedicated bfd chain) ---
_fw_iptables_setup() {
	_FW_IPT_BIN=$(command -v iptables 2>/dev/null) || _FW_IPT_BIN=""
	_FW_IP6T_BIN=$(command -v ip6tables 2>/dev/null) || _FW_IP6T_BIN=""
	if [ -z "$_FW_IPT_BIN" ]; then
		elog error "{glob} iptables binary not found"
		return 1
	fi
	"$_FW_IPT_BIN" -N bfd 2>/dev/null || true
	"$_FW_IPT_BIN" -C INPUT -j bfd 2>/dev/null || "$_FW_IPT_BIN" -I INPUT -j bfd
	if [ -n "$_FW_IP6T_BIN" ]; then
		"$_FW_IP6T_BIN" -N bfd 2>/dev/null || true
		"$_FW_IP6T_BIN" -C INPUT -j bfd 2>/dev/null || "$_FW_IP6T_BIN" -I INPUT -j bfd
	else
		elog warn "{glob} ip6tables not found — IPv6 bans will be skipped"
	fi
}

_fw_iptables_ban() {
	local host="$1"
	if [[ "$host" == *:* ]]; then
		if [ -z "$_FW_IP6T_BIN" ]; then
			elog warn "{iptables} IPv6 ban skipped — ip6tables not found"
			return 1
		fi
		"$_FW_IP6T_BIN" -A bfd -s "$host" -j DROP 2>/dev/null
	else
		"$_FW_IPT_BIN" -A bfd -s "$host" -j DROP
	fi
}

_fw_iptables_unban() {
	local host="$1"
	if [[ "$host" == *:* ]]; then
		if [ -z "$_FW_IP6T_BIN" ]; then
			elog warn "{iptables} IPv6 unban skipped — ip6tables not found"
			return 1
		fi
		"$_FW_IP6T_BIN" -D bfd -s "$host" -j DROP 2>/dev/null
	else
		"$_FW_IPT_BIN" -D bfd -s "$host" -j DROP 2>/dev/null
	fi
}

_fw_iptables_status() {
	local v4_count=0 v6_count=0
	v4_count=$("$_FW_IPT_BIN" -L bfd -n 2>/dev/null | grep -c "DROP") || v4_count=0
	if [ -n "$_FW_IP6T_BIN" ]; then
		v6_count=$("$_FW_IP6T_BIN" -L bfd -n 2>/dev/null | grep -c "DROP") || v6_count=0
	fi
	echo "iptables (bfd chain, $v4_count v4 + $v6_count v6 rules)"
}

# --- route backend (ip route null-route / blackhole) ---
_fw_route_setup() {
	_FW_ROUTE_IP_BIN=$(command -v ip 2>/dev/null) || _FW_ROUTE_IP_BIN=""
	if [ -z "$_FW_ROUTE_IP_BIN" ]; then
		elog error "{glob} ip binary not found"
		return 1
	fi
}

_fw_route_ban() {
	local host="$1"
	if [[ "$host" == */* ]]; then
		"$_FW_ROUTE_IP_BIN" route add blackhole "$host" 2>/dev/null
	elif [[ "$host" == *:* ]]; then
		"$_FW_ROUTE_IP_BIN" route add blackhole "$host/128" 2>/dev/null
	else
		"$_FW_ROUTE_IP_BIN" route add blackhole "$host/32" 2>/dev/null
	fi
}

_fw_route_unban() {
	local host="$1"
	if [[ "$host" == */* ]]; then
		"$_FW_ROUTE_IP_BIN" route del blackhole "$host" 2>/dev/null
	elif [[ "$host" == *:* ]]; then
		"$_FW_ROUTE_IP_BIN" route del blackhole "$host/128" 2>/dev/null
	else
		"$_FW_ROUTE_IP_BIN" route del blackhole "$host/32" 2>/dev/null
	fi
}

_fw_route_status() {
	local count=0
	count=$("$_FW_ROUTE_IP_BIN" route list type blackhole 2>/dev/null | wc -l) || count=0
	echo "route ($count blackhole routes)"
}

# --- custom backend (backward-compatible eval of BAN_COMMAND templates) ---
_fw_custom_setup() { :; }

_fw_custom_ban() {
	local host="$1" mod="$2" ports="$3"
	ports=$(sanitize_ports "$ports") || { elog error "invalid PORTS value '$3'" "le"; return 1; }
	local cmd="$BAN_COMMAND_TEMPLATE"
	if [ -n "${BAN_COMMAND_V6_TEMPLATE:-}" ] && [[ "$host" == *:* ]]; then
		cmd="$BAN_COMMAND_V6_TEMPLATE"
	fi
	ATTACK_HOST="$host"; MOD="$mod"; PORTS="$ports"
	# Security: $cmd is from BAN_COMMAND_TEMPLATE, extracted raw from conf.bfd
	# by extract_command_template(). $host is validated by validate_ip_any(),
	# $mod by sanitize_mod(), $ports by sanitize_ports(). conf.bfd is root-owned
	# and verified by safe_source(). This eval is intentional for user-defined
	# firewall commands.
	eval "$cmd" >/dev/null 2>&1
}

_fw_custom_unban() {
	local host="$1" mod="$2" ports="$3"
	ports=$(sanitize_ports "$ports") || { elog error "invalid PORTS value '$3'" "le"; return 1; }
	local cmd="$UNBAN_COMMAND_TEMPLATE"
	if [ -n "${UNBAN_COMMAND_V6_TEMPLATE:-}" ] && [[ "$host" == *:* ]]; then
		cmd="$UNBAN_COMMAND_V6_TEMPLATE"
	fi
	ATTACK_HOST="$host"; MOD="$mod"; PORTS="$ports"
	# Security: same mitigation chain as _fw_custom_ban() — see comment there.
	eval "$cmd" >/dev/null 2>&1
}

_fw_custom_status() {
	echo "custom (BAN_COMMAND template)"
}

# --- Dispatch layer ---

# fw_resolve_backend — set _FW_BACKEND from FIREWALL config or auto-detect
fw_resolve_backend() {
	local configured="${FIREWALL:-auto}"
	if [ "$configured" = "auto" ]; then
		_FW_BACKEND=$(detect_firewall)
	else
		_FW_BACKEND="$configured"
	fi
}

# fw_setup — initialize firewall backend (create chains/tables/sets as needed)
fw_setup() {
	case "$_FW_BACKEND" in
		apf)       _fw_apf_setup ;;
		csf)       _fw_csf_setup ;;
		firewalld) _fw_firewalld_setup ;;
		ufw)       _fw_ufw_setup ;;
		nftables)  _fw_nftables_setup ;;
		iptables)  _fw_iptables_setup ;;
		route)     _fw_route_setup ;;
		custom)    _fw_custom_setup ;;
	esac
}

# fw_ban host [mod] [ports] — ban a host via the active backend
fw_ban() {
	local host="$1" mod="${2:-}" ports="${3:-all}"
	case "$_FW_BACKEND" in
		apf)       _fw_apf_ban "$host" "$mod" ;;
		csf)       _fw_csf_ban "$host" "$mod" ;;
		firewalld) _fw_firewalld_ban "$host" ;;
		ufw)       _fw_ufw_ban "$host" ;;
		nftables)  _fw_nftables_ban "$host" ;;
		iptables)  _fw_iptables_ban "$host" ;;
		route)     _fw_route_ban "$host" ;;
		custom)    _fw_custom_ban "$host" "$mod" "$ports" ;;
	esac
}

# fw_unban host [mod] [ports] — unban a host via the active backend
fw_unban() {
	local host="$1" mod="${2:-}" ports="${3:-all}"
	case "$_FW_BACKEND" in
		apf)       _fw_apf_unban "$host" ;;
		csf)       _fw_csf_unban "$host" ;;
		firewalld) _fw_firewalld_unban "$host" ;;
		ufw)       _fw_ufw_unban "$host" ;;
		nftables)  _fw_nftables_unban "$host" ;;
		iptables)  _fw_iptables_unban "$host" ;;
		route)     _fw_route_unban "$host" ;;
		custom)    _fw_custom_unban "$host" "$mod" "$ports" ;;
	esac
}

# fw_status — return human-readable status of the active backend
fw_status() {
	case "$_FW_BACKEND" in
		apf)       _fw_apf_status ;;
		csf)       _fw_csf_status ;;
		firewalld) _fw_firewalld_status ;;
		ufw)       _fw_ufw_status ;;
		nftables)  _fw_nftables_status ;;
		iptables)  _fw_iptables_status ;;
		route)     _fw_route_status ;;
		custom)    _fw_custom_status ;;
	esac
}

# _execute_fw_with_retry action host mod ports
# Shared retry loop for fw_ban/fw_unban with exponential backoff.
# action: "ban" or "unban" — dispatches to fw_ban() or fw_unban().
# Retries up to BAN_RETRY_COUNT (default 2) on failure.
# Returns 0 on success, fw command exit code on failure.
_execute_fw_with_retry() {
	local action="$1" host="$2" mod="$3" ports="$4"
	local max_retries="${BAN_RETRY_COUNT:-2}"
	local retry_delay=1 attempt=0 rc=1
	while [ "$attempt" -le "$max_retries" ] && [ "$rc" -ne 0 ]; do
		"fw_${action}" "$host" "$mod" "$ports"
		rc=$?
		if [ "$rc" -ne 0 ] && [ "$attempt" -lt "$max_retries" ]; then
			elog error "{$mod} $action for $host failed (attempt $((attempt + 1))), retrying in ${retry_delay}s."
			sleep "$retry_delay"
			retry_delay=$((retry_delay * 2))
		fi
		attempt=$((attempt + 1))
	done
	if [ "$rc" -ne 0 ]; then
		elog error "{$mod} $action for $host failed after $attempt attempt(s) via $_FW_BACKEND."
	fi
	return $rc
}

# execute_ban host mod dry_run [ports]
# execute or log ban command via firewall backend
# retries on failure with exponential backoff (BAN_RETRY_COUNT, default 2)
# returns 0 on success, ban command exit code on failure
execute_ban() {
	local host="$1" mod="$2" dry_run="$3" ports="${4:-all}"
	# set globals needed by alert templates and custom backend
	ATTACK_HOST="$host"
	MOD="$mod"
	PORTS="$ports"
	if [ "$_FW_BACKEND" = "custom" ]; then
		BAN_COMMAND="$BAN_COMMAND_TEMPLATE"
		if [ -n "${BAN_COMMAND_V6_TEMPLATE:-}" ] && [[ "$host" == *:* ]]; then
			BAN_COMMAND="$BAN_COMMAND_V6_TEMPLATE"
		fi
	else
		BAN_COMMAND="fw_ban $host ($_FW_BACKEND)"
	fi
	if [ "$dry_run" = "1" ]; then
		eout "{$mod} [dry-run] would ban $host via $_FW_BACKEND." le
		return 0
	fi
	eout "{$mod} $host exceeded login failures; banning via $_FW_BACKEND." le
	_execute_fw_with_retry "ban" "$host" "$mod" "$ports"
}

# execute_unban host mod [ports]
# execute unban command via firewall backend
# retries on failure with exponential backoff (BAN_RETRY_COUNT, default 2)
# returns 0 on success, unban command exit code on failure
execute_unban() {
	local host="$1" mod="$2" ports="${3:-all}"
	ATTACK_HOST="$host"
	MOD="$mod"
	PORTS="$ports"
	eout "{$mod} $host ban expired; executing unban via $_FW_BACKEND." le
	_execute_fw_with_retry "unban" "$host" "$mod" "$ports"
}

# process_unbans install_path now — expire and unban via firewall backend
process_unbans() {
	local install_path="$1" now="$2"
	local ts expiry host mod ports
	while IFS=' ' read -r ts expiry host mod ports; do
		[ -z "$ts" ] && continue
		if [ "$_FW_BACKEND" = "custom" ] && [ -z "${UNBAN_COMMAND_TEMPLATE:-}" ]; then
			eout "{$mod} $host ban expired; no UNBAN_COMMAND configured, removing state only." le
		else
			execute_unban "$host" "$mod" "$ports"
		fi
		vout "  unban: $host expired ($mod)"
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

# record_ban install_path utime host mod ports ban_action
# Computes ban expiry, records in bans.active + bans.history.
# Echoes "ban_expiry|ban_action|recent_bans" to stdout.
# Reads globals: BAN_TTL (fallback BAN_DURATION), BAN_ESCALATE_WINDOW
#   (fallback BAN_PERMANENT_WINDOW), BAN_ESCALATE_AFTER (fallback
#   BAN_PERMANENT_AFTER), BAN_ESCALATION, BAN_ESCALATION_CAP
record_ban() {
	local install_path="$1" utime="$2" host="$3" mod="$4"
	local ports="$5" ban_action="$6"
	local ban_ttl="${BAN_TTL:-${BAN_DURATION:-0}}"
	local esc_window="${BAN_ESCALATE_WINDOW:-${BAN_PERMANENT_WINDOW:-86400}}"
	local esc_after="${BAN_ESCALATE_AFTER:-${BAN_PERMANENT_AFTER:-0}}"
	local recent_bans
	recent_bans=$(state_bans_count_recent "$install_path" "$host" \
		"$esc_window" "$utime")
	local ban_expiry
	if [ "$ban_ttl" -eq 0 ]; then
		ban_expiry=0
	elif check_recidivism "$install_path" "$host" \
		"$esc_window" "$utime" "$esc_after"; then
		ban_expiry=0
		ban_action="escalate"
		elog warn "{$mod} $host escalated to permanent ban (repeat offender)."
	else
		local computed_duration
		computed_duration=$(compute_ban_duration "$ban_ttl" "$recent_bans" \
			"${BAN_ESCALATION:-none}" "${BAN_ESCALATION_CAP:-0}")
		ban_expiry=$((utime + computed_duration))
	fi
	state_bans_active_append "$install_path" "$utime" "$ban_expiry" "$host" "$mod" "$ports"
	state_bans_history_append "$install_path" "$utime" "$ban_expiry" "$host" "$mod" "$ban_action"
	echo "${ban_expiry}|${ban_action}|${recent_bans}"
}

# compute_ban_duration base_duration ban_count mode cap
# Computes escalated ban duration based on repeat offense count.
# ban_count = previous bans (0 for first offense)
# mode: none (fixed), linear (base * n), double (base * 2^(n-1))
# cap: maximum duration (0 = no cap)
compute_ban_duration() {
	local base_duration="$1" ban_count="$2" mode="$3" cap="$4"
	local effective_count=$((ban_count + 1))
	local d="$base_duration"
	case "$mode" in
		linear)
			d=$((base_duration * effective_count))
			;;
		double|exponential)
			local shift=$((effective_count - 1))
			[ "$shift" -gt 30 ] && shift=30
			d=$((base_duration * (1 << shift)))
			;;
	esac
	if [ "${cap:-0}" -gt 0 ] && [ "$d" -gt "$cap" ]; then
		d="$cap"
	fi
	echo "$d"
}

# _list_bans_data install_path — output raw pipe-delimited active ban data
# Outputs: ts|expiry|host|mod|ports (one line per ban, raw timestamps)
# Returns 1 if no active bans.
_list_bans_data() {
	local install_path="$1"
	local bans_file="$install_path/tmp/bans.active"
	if [ ! -f "$bans_file" ] || [ ! -s "$bans_file" ]; then
		return 1
	fi
	local ts expiry host mod ports
	while IFS=' ' read -r ts expiry host mod ports; do
		[ -z "$ts" ] && continue
		echo "$ts|$expiry|$host|$mod|$ports"
	done < "$bans_file"
}

# list_bans install_path — display formatted active ban list
list_bans() {
	local install_path="$1"
	state_init "$install_path"
	local raw
	raw=$(_list_bans_data "$install_path") || { echo "No active bans."; return 0; }
	echo "[+] Active bans" && echo
	local atmp
	atmp=$(mktemp "$install_path/tmp/.lbans.XXXXXX")
	echo "IP|SERVICE|PORTS|BANNED|EXPIRES" > "$atmp"
	local ts expiry host mod ports banned_fmt expiry_fmt
	while IFS='|' read -r ts expiry host mod ports; do
		banned_fmt=$(_fmt_ts "$ts")
		if [ "$expiry" = "0" ]; then
			expiry_fmt="permanent"
		else
			expiry_fmt=$(_fmt_ts "$expiry")
		fi
		echo "$host|$mod|$ports|$banned_fmt|$expiry_fmt"
	done <<< "$raw" >> "$atmp"
	format_table < "$atmp"
	rm -f "$atmp"
}

# manual_unban install_path ip utime — manually unban an IP via firewall backend
manual_unban() {
	local install_path="$1" ip="$2" utime="$3"
	ip=$(validate_ip_any "$ip") || { echo "error: invalid IP address '$2'." >&2; return 1; }
	state_init "$install_path"
	if ! state_bans_active_check "$install_path" "$ip"; then
		echo "error: $ip is not in the active ban list." >&2
		return 1
	fi
	local ban_mod ban_ports
	ban_mod=$(awk -v ip="$ip" '$3 == ip {print $4; exit}' "$install_path/tmp/bans.active")
	ban_ports=$(awk -v ip="$ip" '$3 == ip {print $5; exit}' "$install_path/tmp/bans.active")
	execute_unban "$ip" "${ban_mod:-unknown}" "${ban_ports:-all}"
	state_bans_active_remove "$install_path" "$ip"
	state_bans_history_append "$install_path" "$utime" "0" "$ip" "${ban_mod:-unknown}" "unban"
	echo "$ip unbanned successfully."
}

# manual_ban install_path ip utime [mod] [ports] — manually ban an IP via firewall backend
manual_ban() {
	local install_path="$1" ip="$2" utime="$3"
	local mod="${4:-manual}"
	local ports="${5:-all}"
	ip=$(validate_ip_any "$ip") || { echo "error: invalid IP address '$2'." >&2; return 1; }
	mod=$(sanitize_mod "$mod") || { echo "error: invalid service name '$mod'." >&2; return 1; }
	state_init "$install_path"
	if state_bans_active_check "$install_path" "$ip"; then
		echo "error: $ip is already banned." >&2
		return 1
	fi
	execute_ban "$ip" "$mod" "0" "$ports"
	state_bans_active_append "$install_path" "$utime" "0" "$ip" "$mod" "$ports"
	state_bans_history_append "$install_path" "$utime" "0" "$ip" "$mod" "ban"
	echo "$ip banned permanently."
}

# --- State file I/O functions ---
# State file formats:
#   attack.pool:  "UTIME IP MOD COUNT CC ACTION DURATION PORTS PRESSURE TRIP_TYPE"
#     10-field enriched format — backward compatible (old 3-field entries read as:
#     COUNT=1, CC=--, ACTION=ban, DURATION=0, PORTS=all, PRESSURE=0, TRIP_TYPE=service)

# state_init install_path — ensure state dirs/files exist with correct perms
state_init() {
	local install_path="$1"
	if [ ! -d "$install_path/tmp" ]; then
		# shellcheck disable=SC2174  # parent always exists; -m applies to leaf
		mkdir -m 750 -p "$install_path/tmp"
	fi
	if [ ! -d "$install_path/stats" ]; then
		# shellcheck disable=SC2174  # parent always exists; -m applies to leaf
		mkdir -m 750 -p "$install_path/stats"
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

# state_pool_append install_path utime host mod [count cc action duration ports pressure trip_type]
state_pool_append() {
	local install_path="$1" utime="$2" host="$3" mod="$4"
	local count="${5:-1}" cc="${6:---}" action="${7:-ban}"
	local duration="${8:-0}" ports="${9:-all}" pressure="${10:-0}"
	local trip_type="${11:-service}"
	local pool_file="$install_path/stats/attack.pool"
	(
		flock -x 200
		echo "$utime $host $mod $count $cc $action $duration $ports $pressure $trip_type" >> "$pool_file"
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
	(
		flock -x 200
		awk -v ip="$host" '$3 != ip' "$bans_file" > "$bans_file.new" || true
		mv "$bans_file.new" "$bans_file"
		chmod 600 "$bans_file"
	) 200>>"$bans_file"
}

# state_bans_active_check install_path host — return 0 if host has active ban
state_bans_active_check() {
	local install_path="$1" host="$2"
	if awk -v ip="$host" '$3 == ip {found=1; exit} END {exit !found}' "$install_path/tmp/bans.active" 2>/dev/null; then
		return 0
	fi
	return 1
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
#   events.dat: "TIMESTAMP IP MOD [WEIGHT]" — timestamped failure events
#   Field 4 (WEIGHT) is optional; older events without it default to weight 1.

# state_events_append install_path timestamp host mod [count] [weight] — append events
# Appends count timestamped event lines (default 1) to events.dat.
# weight (default "1") is stored as field 4 for pressure scoring.
state_events_append() {
	local install_path="$1" timestamp="$2" host="$3" mod="$4"
	local count="${5:-1}" weight="${6:-1}"
	local events_file="$install_path/tmp/events.dat"
	(
		flock -x 200
		local i
		for ((i = 0; i < count; i++)); do
			echo "$timestamp $host $mod $weight"
		done >> "$events_file"
	) 200>>"$events_file"
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
	(
		flock -x 200
		awk -v cutoff="$cutoff" '$1+0 >= cutoff' "$events_file" \
			| tail -n "$max_lines" > "$events_file.new"
		mv "$events_file.new" "$events_file"
		chmod 600 "$events_file"
	) 200>>"$events_file"
}

# state_pool_prune install_path [retention_days] [max_lines] — age-based pool pruning
# Removes entries older than retention_days. Safety cap at max_lines.
# Preserves file inode via cat-overwrite (important for flock handles).
state_pool_prune() {
	local install_path="$1" retention_days="${2:-365}" max_lines="${3:-500000}"
	local pool_file="$install_path/stats/attack.pool"
	[ ! -f "$pool_file" ] || [ ! -s "$pool_file" ] && return 0
	local cutoff=0
	if [ "$retention_days" -gt 0 ] 2>/dev/null; then
		cutoff=$(( $(date +%s) - (retention_days * 86400) ))
	fi
	(
		flock -x 200
		if [ "$cutoff" -gt 0 ]; then
			awk -v cutoff="$cutoff" '$1+0 >= cutoff' "$pool_file" \
				| tail -n "$max_lines" > "$pool_file.new"
		else
			tail -n "$max_lines" "$pool_file" > "$pool_file.new"
		fi
		cat "$pool_file.new" > "$pool_file"   # preserves inode for flock
		rm -f "$pool_file.new"
	) 200>>"$pool_file"
}

# --- Pressure scoring functions ---

# pressure_compute install_path host half_life now [mod] — compute decayed pressure
# Single-pass awk over events.dat: sums weight * 2^(-(now-ts)/half_life) for each
# event matching host (and optionally mod). Returns pressure * 1000 as integer.
# Handles both 3-field (old, weight=1) and 4-field (new) event lines.
pressure_compute() {
	local install_path="$1" host="$2" half_life="$3" now="$4"
	local mod="${5:-}"
	local events_file="$install_path/tmp/events.dat"
	if [ ! -f "$events_file" ] || [ ! -s "$events_file" ]; then
		echo "0"
		return 0
	fi
	local cutoff=$((now - half_life * 10))
	if [ -n "$mod" ]; then
		awk -v cutoff="$cutoff" -v host="$host" -v hl="$half_life" \
			-v now="$now" -v mod="$mod" '
		BEGIN { p = 0 }
		$1+0 >= cutoff && $2 == host && $3 == mod {
			w = ($4+0 > 0) ? $4+0 : 1
			age = now - ($1+0)
			p += w * exp(-0.693147180559945 * age / hl)
		}
		END { printf "%d\n", p * 1000 }' "$events_file"
	else
		awk -v cutoff="$cutoff" -v host="$host" -v hl="$half_life" \
			-v now="$now" '
		BEGIN { p = 0 }
		$1+0 >= cutoff && $2 == host {
			w = ($4+0 > 0) ? $4+0 : 1
			age = now - ($1+0)
			p += w * exp(-0.693147180559945 * age / hl)
		}
		END { printf "%d\n", p * 1000 }' "$events_file"
	fi
}

# pressure_format scaled_pressure — format scaled integer as decimal string
# Example: 18400 -> "18.4", 0 -> "0.0", 500 -> "0.5"
pressure_format() {
	local scaled="$1"
	local whole=$((scaled / 1000))
	local frac=$(( (scaled % 1000 + 50) / 100 ))
	if [ "$frac" -ge 10 ]; then
		whole=$((whole + 1))
		frac=0
	fi
	echo "${whole}.${frac}"
}

# _pressure_aggregate_all events_file now half_life
# Single-pass AWK over events.dat: computes decayed pressure for ALL IPs.
# Outputs "scaled_pressure ip" lines sorted descending, filtered to >0.
# Used by show_status() for top-N pressure display.
_pressure_aggregate_all() {
	local events_file="$1" now="$2" half_life="$3"
	local cutoff=$((now - half_life * 10))
	awk -v now="$now" -v hl="$half_life" -v cutoff="$cutoff" \
		'BEGIN { ln2 = 0.693147180559945 }
		$1+0 >= cutoff {
			w = ($4+0 > 0) ? $4+0 : 1
			age = now - ($1+0)
			ip = $2
			p[ip] += w * exp(-ln2 * age / hl)
		}
		END {
			for (ip in p) {
				scaled = int(p[ip] * 1000)
				if (scaled > 0)
					printf "%d %s\n", scaled, ip
			}
		}' "$events_file" | sort -rn
}

# record_and_score host hosts_parsed install_path half_life now mod weight [count]
# Replacement for count_failures() using pressure scoring:
#   1. Count host occurrences in hosts_parsed (grep -cxF), or use pre-computed count
#   2. Append that many weighted events to events.dat
#   3. Compute per-service pressure (decayed sum)
#   4. Return pressure * 1000 as integer
# When count (arg 8) is provided, skips the O(n) grep scan — check() pre-computes
# counts via uniq -c to avoid O(n^2) repeated grep passes over HOSTS_PARSED.
record_and_score() {
	local host="$1" hosts_parsed="$2" install_path="$3"
	local half_life="$4" now="$5" mod="$6" weight="${7:-1}"
	local count="${8:-}"
	if [ -z "$count" ]; then
		count=$(echo "$hosts_parsed" | grep -cxF "$host")
	fi
	if [ "$count" -gt 0 ]; then
		state_events_append "$install_path" "$now" "$host" "$mod" "$count" "$weight"
	fi
	pressure_compute "$install_path" "$host" "$half_life" "$now" "$mod"
}

# --- Country multiplier functions ---

# ip_to_country ip db_file — look up 2-letter country code for an IPv4 address
# Uses awk linear scan on sorted integer ranges in ipcountry.dat.
# Returns CC to stdout, or empty string if not found or IPv6.
# When _COUNTRY_CACHE_FILE is set, caches lookups to avoid repeated scans of
# the 190K-line database (reduces O(IPs * DB_lines) to O(IPs + DB_lines)).
ip_to_country() {
	local ip="$1" db_file="$2"
	# IPv6 not supported in v1
	if [[ "$ip" == *:* ]]; then
		echo ""
		return 0
	fi
	if [ ! -f "$db_file" ] || [ ! -s "$db_file" ]; then
		echo ""
		return 0
	fi
	# per-cycle cache: check before expensive awk scan
	if [ -n "${_COUNTRY_CACHE_FILE:-}" ] && [ -f "$_COUNTRY_CACHE_FILE" ]; then
		local _cached_line
		_cached_line=$(grep -m1 "^${ip} " "$_COUNTRY_CACHE_FILE" 2>/dev/null) || true
		if [ -n "$_cached_line" ]; then
			local _cached_cc="${_cached_line#* }"
			if [ "$_cached_cc" = "-" ]; then echo ""; else echo "$_cached_cc"; fi
			return 0
		fi
	fi
	local cc
	cc=$(awk -v ip="$ip" '
	BEGIN {
		n = split(ip, p, ".")
		if (n != 4) { print ""; exit }
		target = (p[1]+0) * 16777216 + (p[2]+0) * 65536 + (p[3]+0) * 256 + (p[4]+0)
	}
	/^#/ { next }
	{
		if ($1+0 <= target && target <= $2+0) {
			print $3
			exit
		}
	}
	END {}' "$db_file")
	# populate cache (use "-" sentinel for empty results)
	if [ -n "${_COUNTRY_CACHE_FILE:-}" ]; then
		echo "$ip ${cc:--}" >> "$_COUNTRY_CACHE_FILE"
	fi
	echo "$cc"
}

# country_weight cc weights_file — look up pressure multiplier for a country code
# Returns integer multiplier (10 = 1.0x, 20 = 2.0x). Defaults to 10 if unlisted.
country_weight() {
	local cc="$1" weights_file="$2"
	if [ -z "$cc" ] || [ ! -f "$weights_file" ]; then
		echo "10"
		return 0
	fi
	awk -F= -v cc="$cc" '
	/^#/ { next }
	/^$/ { next }
	$1 == cc { print $2; found=1; exit }
	END { if (!found) print 10 }' "$weights_file"
}

# pressure_effective_weight rule_weight host install_path — apply country multiplier
# Auto-enabled when pressure-country.conf exists with entries; otherwise passthrough.
# Returns: rule_weight * country_mult / 10 (integer math, minimum 1).
pressure_effective_weight() {
	local rule_weight="$1" host="$2" install_path="$3"
	local db_file="$install_path/ipcountry.dat"
	local weights_file="$install_path/pressure-country.conf"
	if [ ! -f "$db_file" ] || [ ! -f "$weights_file" ]; then
		echo "$rule_weight"
		return 0
	fi
	local cc
	cc=$(ip_to_country "$host" "$db_file")
	if [ -z "$cc" ]; then
		echo "$rule_weight"
		return 0
	fi
	local mult
	mult=$(country_weight "$cc" "$weights_file")
	# integer math: weight * mult / 10, minimum 1
	local eff=$(( (rule_weight * mult + 5) / 10 ))
	if [ "$eff" -lt 1 ]; then
		eff=1
	fi
	echo "$eff"
}

# count_subnet_attackers install_path window now mask mask_v6 min_unique
# Single-pass awk over events.dat: groups events by subnet+service,
# outputs "subnet_cidr mod unique_count" for subnets meeting threshold.
# All subnet math done in awk (mawk-compatible) for O(n) performance.
count_subnet_attackers() {
	local install_path="$1" window="$2" now="$3"
	local mask="$4" mask_v6="$5" min_unique="$6"
	local events_file="$install_path/tmp/events.dat"
	local cutoff=$((now - window))
	if [ ! -f "$events_file" ] || [ ! -s "$events_file" ]; then
		return 0
	fi
	awk -v cutoff="$cutoff" -v mask="$mask" -v mask_v6="$mask_v6" \
		-v min_unique="$min_unique" '
	function pow2(n,    r, i) {
		r = 1; for (i = 0; i < n; i++) r = r * 2; return r
	}
	function ipv4_subnet(ip, m,    parts, n, o1, o2, o3, o4, sh, divisor) {
		n = split(ip, parts, ".")
		if (n != 4) return ""
		o1 = parts[1]+0; o2 = parts[2]+0; o3 = parts[3]+0; o4 = parts[4]+0
		if (m >= 24) {
			sh = 32 - m; divisor = pow2(sh)
			o4 = int(o4 / divisor) * divisor
			return o1 "." o2 "." o3 "." o4 "/" m
		} else if (m >= 16) {
			sh = 24 - m; divisor = pow2(sh)
			o3 = int(o3 / divisor) * divisor
			return o1 "." o2 "." o3 ".0/" m
		} else if (m >= 8) {
			sh = 16 - m; divisor = pow2(sh)
			o2 = int(o2 / divisor) * divisor
			return o1 "." o2 ".0.0/" m
		}
		return ""
	}
	function ipv6_subnet(ip, m,    n_keep, halves, lp, rp, nl, nr, \
								full, zf, i, result) {
		n_keep = int(m / 16)
		if (index(ip, "::") > 0) {
			split(ip, halves, "::")
			nl = split(halves[1], lp, ":")
			if (halves[1] == "") nl = 0
			nr = split(halves[2], rp, ":")
			if (halves[2] == "") nr = 0
			for (i = 1; i <= nl; i++) full[i] = lp[i]
			zf = 8 - nl - nr
			for (i = nl + 1; i <= nl + zf; i++) full[i] = "0"
			for (i = 1; i <= nr; i++) full[nl + zf + i] = rp[i]
		} else {
			if (split(ip, full, ":") != 8) return ""
		}
		result = ""
		for (i = 1; i <= n_keep; i++) {
			if (i > 1) result = result ":"
			result = result full[i]
		}
		return result "::/" m
	}
	{
		if ($1+0 < cutoff) next
		ip = $2; mod = $3
		if (index(ip, ":") > 0)
			subnet = ipv6_subnet(ip, mask_v6)
		else
			subnet = ipv4_subnet(ip, mask)
		if (subnet == "") next
		key = subnet SUBSEP mod
		ipkey = key SUBSEP ip
		if (!(ipkey in seen)) {
			seen[ipkey] = 1
			unique[key]++
		}
		snet[key] = subnet
		smod[key] = mod
	}
	END {
		for (key in unique)
			if (unique[key] >= min_unique)
				print snet[key] " " smod[key] " " unique[key]
	}' "$events_file"
}

# check_distributed install_path window now alerts_file
# Post-loop distributed attack detection: bans entire subnets when
# SUBNET_TRIG unique IPs from the same subnet attack the same service.
# Echoes the number of subnet bans executed.
check_distributed() {
	local install_path="$1" window="$2" now="$3" alerts_file="$4"
	local ban_count=0

	local subnet mod unique_count
	while IFS=' ' read -r subnet mod unique_count; do
		[ -z "$subnet" ] && continue
		if state_bans_active_check "$install_path" "$subnet"; then
			eout "{$mod} subnet $subnet already banned, skipping." le
			continue
		fi
		elog warn "{$mod} distributed attack detected: $unique_count unique IPs from $subnet."
		if execute_ban "$subnet" "$mod" "$DRY_RUN" "all"; then
			ban_count=$((ban_count + 1))
			local ban_result
			ban_result=$(record_ban "$install_path" "$now" "$subnet" "$mod" "all" "subnet")
			local ban_expiry ban_action recent_bans
			IFS='|' read -r ban_expiry ban_action recent_bans <<< "$ban_result"
			local _dist_duration="-1"
			if [ "$ban_expiry" = "0" ]; then
				_dist_duration="0"
			else
				_dist_duration=$((ban_expiry - now))
			fi
			state_pool_append "$install_path" "$now" "$subnet" "$mod" \
				"$unique_count" "--" "$ban_action" "$_dist_duration" "all" \
				"0" "subnet"
			if [ "$EMAIL_ALERTS" = "1" ] && [ "$DRY_RUN" != "1" ]; then
				echo "${subnet}|${mod}|all|${unique_count}|${ban_expiry}|${ban_action}|${recent_bans}||${EMAIL_ADDRESS}|${SUBNET_TRIG}|${window}|1" >> "$alerts_file"
			fi
		fi
	done < <(count_subnet_attackers "$install_path" "$window" "$now" \
		"$SUBNET_MASK" "$SUBNET_MASK_V6" "$SUBNET_TRIG")

	echo "$ban_count"
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

	local _tlog_lib="${INSTALL_PATH:-$install_path}/tlog_lib.sh"
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
		return
	fi
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
		else
			echo "[WARN] Alert templates: $_atd (not found)"
			_hc_warn=$((_hc_warn + 1))
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
			_alert_render_text "$recip_file" "$tpl_dir" "$loglines" > "$text_file"
		fi

		# render HTML body
		local html_file=""
		if [ "$format" = "html" ] || [ "$format" = "both" ]; then
			html_file=$(mktemp "${alerts_file}.html.XXXXXX")
			_alert_render_html "$recip_file" "$tpl_dir" "$loglines" > "$html_file"
		fi

		# for text-only: html_file needed by relay path, render it too
		if [ "$format" = "text" ] && [ -n "${SMTP_RELAY:-}" ]; then
			html_file=$(mktemp "${alerts_file}.html.XXXXXX")
			_alert_render_html "$recip_file" "$tpl_dir" "$loglines" > "$html_file"
		fi
		# for html-only: text_file needed as sendmail fallback
		if [ "$format" = "html" ] && [ -z "$text_file" ]; then
			text_file=$(mktemp "${alerts_file}.text.XXXXXX")
			_alert_render_text "$recip_file" "$tpl_dir" "$loglines" > "$text_file"
		fi

		if _alert_send "$recip" "$mail_subject" "$text_file" "$html_file" "$format"; then
			elog info "alert email sent to $recip ($alert_count ban(s), format=$format)."
		else
			elog error "alert email to $recip failed."
		fi

		# set backward-compat globals for single-ban case
		# (needed by custom hooks or external integrations that read these after send_alerts)
		if [ "$alert_count" -eq 1 ]; then
			local _host _mod _ports _count _expiry _action _recent _lp _recip _trig _tw _wt
			IFS='|' read -r _host _mod _ports _count _expiry _action _recent _lp _recip _trig _tw _wt < "$recip_file"
			ATTACK_HOST="$_host"
			MOD="$_mod"
			# backward compat: _count is pressure_scaled (e.g., 18400);
			# custom hooks expect a count, so use whole pressure units
			ATTACK_COUNT="$(( _count / 1000 ))"
			if [ "$ATTACK_COUNT" -lt 1 ]; then ATTACK_COUNT=1; fi
			LOG_FILE="$_lp"
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

		rm -f "$recip_file" "$text_file" "$html_file"
	done <<< "$recipients"
}

# --- Phase 18: CLI Evolution functions ---

# detect_run_mode — determine how BFD is being run.
# Outputs one of: watch/systemd, watch/init, watch/manual,
# timer/systemd, cron, unknown
detect_run_mode() {
	local watch_pid=""
	watch_pid=$(pgrep -f "bfd.*--watch" 2>/dev/null | head -1) || true
	if [ -z "$watch_pid" ]; then
		watch_pid=$(pgrep -f "bfd.*-w " 2>/dev/null | head -1) || true
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
			watch_pid=$(pgrep -f "bfd.*--watch" 2>/dev/null | head -1) || true
			if [ -z "$watch_pid" ]; then
				watch_pid=$(pgrep -f "bfd.*-w " 2>/dev/null | head -1) || true
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
	_restore_rule_vars
}

# show_config [var] — dump active config or single variable value
show_config() {
	local var="${1:-}"
	local config_vars="FIREWALL PRESSURE_TRIP PRESSURE_HALF_LIFE PRESSURE_TRIP_GLOBAL SUBNET_TRIG SUBNET_MASK SUBNET_MASK_V6 BAN_COMMAND BAN_COMMAND_V6 UNBAN_COMMAND UNBAN_COMMAND_V6 BAN_TTL BAN_ESCALATE_AFTER BAN_ESCALATE_WINDOW BAN_RETRY_COUNT BAN_ESCALATION BAN_ESCALATION_CAP EMAIL_ALERTS EMAIL_ADDRESS EMAIL_SUBJECT EMAIL_LOGLINES EMAIL_FORMAT EMAIL_DIGEST EMAIL_DIGEST_INTERVAL EMAIL_REPUTATION_LINKS SMTP_RELAY SMTP_FROM ALERT_TEMPLATE_DIR LOG_FORMAT LOG_LEVEL LOG_SOURCE AUTH_LOG_PATH KERNEL_LOG_PATH MAIL_LOG_PATH BFD_LOG_PATH OUTPUT_SYSLOG OUTPUT_SYSLOG_FILE LOCK_FILE_TIMEOUT WATCH_INTERVAL SCAN_MAX_LINES SCAN_TIMEOUT APOOL_RETENTION_DAYS APOOL_MAX_LINES PRESSURE_CONF"
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
			echo "$_display=$val"
		done
	fi
}

# flush_bans install_path mode utime — bulk unban via firewall backend
# mode: "temp" — unban temporary bans only; "all" — unban everything
flush_bans() {
	local install_path="$1" mode="$2" utime="$3"
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
			execute_unban "$host" "$mod" "$ports"
			state_bans_active_remove "$install_path" "$host"
			state_bans_history_append "$install_path" "$utime" "$expiry" "$host" "$mod" "unban"
			count=$((count + 1))
		fi
	done <<< "$entries"

	echo "$count bans removed."
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

	# Events (events.dat) — 24h event count and per-service counts
	local events_file="$install_path/tmp/events.dat"
	local evt_count=0 first_ts="" last_ts=""
	local _gp_fmt="0.0"
	local has_events=0
	if [ -f "$events_file" ] && [ -s "$events_file" ]; then
		# Single AWK: 24h count, per-service 24h counts, first/last seen
		local evt_raw
		evt_raw=$(awk -v ip="$ip" -v cutoff="$cutoff_24h" '
			$2 == ip {
				ts = $1+0
				if (!(first) || ts < first) first = ts
				if (ts > last) last = ts
				if (ts >= cutoff) {
					total++
					svc[$3]++
				}
			}
			END {
				printf "X|%d|%d|%d\n", total+0, first+0, last+0
				for (s in svc) printf "E|%s|%d\n", s, svc[s]
			}' "$events_file")
		if [ -n "$evt_raw" ]; then
			local x_line
			x_line=$(echo "$evt_raw" | grep '^X|')
			IFS='|' read -r _ evt_count first_ts last_ts <<< "$x_line"
			if [ "$first_ts" -gt 0 ] 2>/dev/null; then
				has_events=1
			fi
		fi

		# Pressure — reuse _events_ip_awk for single-pass computation
		if [ "$has_events" -eq 1 ]; then
			local ip_awk_raw
			ip_awk_raw=$(_events_ip_awk "$events_file" "$ip" "$now" "$half_life")
			if [ -n "$ip_awk_raw" ]; then
				# extract overall pressure from H line
				local h_line _gp
				h_line=$(echo "$ip_awk_raw" | grep '^H|')
				IFS='|' read -r _ _gp _ _ <<< "$h_line"
				_gp_fmt=$(pressure_format "$_gp")
			fi
		fi
	fi

	# Attack pool — sum failures (COUNT field) and count ban events (lines)
	local pool_file="$install_path/stats/attack.pool"
	local pool_triggers=0 pool_failures=0
	if [ -f "$pool_file" ] && [ -s "$pool_file" ]; then
		pool_triggers=$(awk -v ip="$ip" '$2 == ip {c++} END {print c+0}' "$pool_file")
		pool_failures=$(awk -v ip="$ip" '$2 == ip { c += ($4+0 > 0 ? $4+0 : 1) } END {print c+0}' "$pool_file")
	fi

	# Output: D line (core data)
	echo "D|$ban_ts|$ban_expiry|$hist_24h|$hist_total|$evt_count|$first_ts|$last_ts|$_gp_fmt|$trip|$half_life|$pool_triggers|$pool_failures"

	# Output: E lines (per-service 24h event counts)
	if [ -n "${evt_raw:-}" ]; then
		echo "$evt_raw" | grep '^E|'
	fi

	# Output: P lines (per-service pressure)
	if [ "$has_events" -eq 1 ] && [ -n "${ip_awk_raw:-}" ]; then
		local _type _svc _wt _cnt _sp
		while IFS='|' read -r _type _svc _wt _cnt _sp; do
			[ "$_type" != "S" ] && continue
			local _sp_fmt
			_sp_fmt=$(pressure_format "$_sp")
			echo "P|$_svc|$_sp_fmt"
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

	# Events
	if [ "$evt_count" -gt 0 ] 2>/dev/null; then
		# Build svc_summary from E lines: "sshd(5) dovecot(2)"
		local evt_svcs=""
		local _type _svc _cnt
		while IFS='|' read -r _type _svc _cnt; do
			[ "$_type" != "E" ] && continue
			evt_svcs="${evt_svcs}${_svc}(${_cnt}) "
		done <<< "$data"
		echo "  Failures (24h): $evt_count across $evt_svcs"

		# First/last seen
		if [ -n "$first_ts" ] && [ "$first_ts" -gt 0 ] 2>/dev/null; then
			echo "  First seen:     $(date -d "@${first_ts}" +"%Y-%m-%d %H:%M:%S" 2>/dev/null || echo "$first_ts")"
		fi
		if [ -n "$last_ts" ] && [ "$last_ts" -gt 0 ] 2>/dev/null; then
			echo "  Last seen:      $(date -d "@${last_ts}" +"%Y-%m-%d %H:%M:%S" 2>/dev/null || echo "$last_ts")"
		fi

		# Pressure
		echo "  Pressure:       ${_gp_fmt}/${trip} (half-life=${half_life}s)"
		# Per-service pressure from P lines
		local _ptype _psvc _pfmt
		while IFS='|' read -r _ptype _psvc _pfmt; do
			[ "$_ptype" != "P" ] && continue
			echo "                  ${_psvc}: ${_pfmt}/${trip}"
		done <<< "$data"
	else
		echo "  Failures (24h): 0"
	fi

	# Attack pool
	if [ "$pool_triggers" -gt 0 ] 2>/dev/null; then
		echo "  Attack pool:    $pool_failures failures across $pool_triggers bans"
	fi
}

# list_rules install_path — list all rules with status in table format
list_rules() {
	local install_path="$1"
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
				if [ -n "${LOG_FILE:-}" ] && [ -f "$LOG_FILE" ]; then
					log_info="$LOG_FILE (file)"
				elif [ "$log_source" != "file" ] && \
				     command -v journalctl >/dev/null 2>&1 && \
				     tlog_journal_filter "${LOG_TAG:-}" >/dev/null 2>&1; then
					log_info="journal"
				else
					log_info="${LOG_FILE:-n/a}"
				fi
				echo "$rule_name|active|$rule_weight|$rule_trip|$rule_ports|$log_info" >> "$atmp"
			else
				inactive=$((inactive + 1))
				echo "$rule_name|inactive|-|-|-|(no prereq)" >> "$atmp"
			fi
		else
			inactive=$((inactive + 1))
			echo "$rule_name|error|-|-|-|(source failed)" >> "$atmp"
		fi

		_restore_rule_vars
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

	if [ -n "${LOG_FILE:-}" ] && [ -f "$LOG_FILE" ]; then
		echo "  Log:        $LOG_FILE (file mode)"
	elif [ "$log_source" != "file" ] && \
	     command -v journalctl >/dev/null 2>&1 && \
	     tlog_journal_filter "${LOG_TAG:-}" >/dev/null 2>&1; then
		echo "  Log:        journal (${LOG_TAG:-})"
	else
		echo "  Log:        ${LOG_FILE:-not configured}"
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
		rm -f "$stdin_file"
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

	rm -f "$stdin_file"
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

# list_bans_json install_path — JSON formatted active ban list
list_bans_json() {
	local install_path="$1"
	echo "["
	local raw
	if raw=$(_list_bans_data "$install_path"); then
		local first=1
		local ts expiry host mod ports
		while IFS='|' read -r ts expiry host mod ports; do
			local banned_fmt expiry_fmt
			banned_fmt=$(_fmt_ts_iso "$ts")
			if [ "$expiry" = "0" ]; then
				expiry_fmt="permanent"
			else
				expiry_fmt=$(_fmt_ts_iso "$expiry")
			fi
			if [ "$first" -eq 1 ]; then
				first=0
			else
				echo ","
			fi
			printf '  {"ip": "%s", "service": "%s", "ports": "%s", "banned": "%s", "expires": "%s"}' \
				"$(_json_escape "$host")" "$(_json_escape "$mod")" "$(_json_escape "$ports")" \
				"$banned_fmt" "$expiry_fmt"
		done <<< "$raw"
	fi
	echo ""
	echo "]"
}

# list_bans_csv install_path — CSV formatted active ban list
list_bans_csv() {
	local install_path="$1"
	echo "ip,service,ports,banned,expires"
	local raw
	if raw=$(_list_bans_data "$install_path"); then
		local ts expiry host mod ports
		while IFS='|' read -r ts expiry host mod ports; do
			local banned_fmt expiry_fmt
			banned_fmt=$(_fmt_ts_iso "$ts")
			if [ "$expiry" = "0" ]; then
				expiry_fmt="permanent"
			else
				expiry_fmt=$(_fmt_ts_iso "$expiry")
			fi
			echo "$host,$mod,$ports,$banned_fmt,$expiry_fmt"
		done <<< "$raw"
	fi
}

# --- Events CLI functions ---

# _events_pressure_awk events_file now half_life trip [target_addr target_mask]
# Unified single-pass pressure computation over events.dat.
# Dashboard mode (no target_addr/target_mask): all IPs.
# CIDR mode (target_addr + target_mask set): IPv4 subnet filter.
# Outputs pipe-delimited raw data sorted by pressure descending:
# pv|ip|pw|pf|trip|cnt|svcs_csv|first_ts|last_ts
_events_pressure_awk() {
	local events_file="$1" now="$2" half_life="$3" trip="$4"
	local target_addr="${5:-}" target_mask="${6:-}"
	local cutoff=$((now - half_life * 10))
	local cidr_mode=0
	[ -n "$target_addr" ] && [ -n "$target_mask" ] && cidr_mode=1
	awk -v cutoff="$cutoff" -v now="$now" -v hl="$half_life" \
		-v trip="$trip" -v cidr_mode="$cidr_mode" \
		-v tmask="$target_mask" -v taddr="$target_addr" '
	function pow2(n,    r, i) {
		r = 1; for (i = 0; i < n; i++) r = r * 2; return r
	}
	function ipv4_subnet(ip, m,    parts, n, o1, o2, o3, o4, sh, divisor) {
		n = split(ip, parts, ".")
		if (n != 4) return ""
		o1 = parts[1]+0; o2 = parts[2]+0; o3 = parts[3]+0; o4 = parts[4]+0
		if (m >= 24) {
			sh = 32 - m; divisor = pow2(sh)
			o4 = int(o4 / divisor) * divisor
			return o1 "." o2 "." o3 "." o4
		} else if (m >= 16) {
			sh = 24 - m; divisor = pow2(sh)
			o3 = int(o3 / divisor) * divisor
			return o1 "." o2 "." o3 ".0"
		} else if (m >= 8) {
			sh = 16 - m; divisor = pow2(sh)
			o2 = int(o2 / divisor) * divisor
			return o1 "." o2 ".0.0"
		}
		return ""
	}
	BEGIN {
		ln2 = 0.693147180559945
		if (cidr_mode) target_net = ipv4_subnet(taddr, tmask)
	}
	$1+0 >= cutoff {
		ip = $2; mod = $3; ts = $1+0
		if (cidr_mode) {
			if (index(ip, ":") > 0) next
			if (ipv4_subnet(ip, tmask) != target_net) next
		}
		w = ($4+0 > 0) ? $4+0 : 1
		age = now - ts
		p[ip] += w * exp(-ln2 * age / hl)
		cnt[ip]++
		if (!(ip SUBSEP mod in sm)) { sm[ip SUBSEP mod] = 1; svcs[ip] = (svcs[ip] == "" ? mod : svcs[ip] "," mod) }
		if (!(ip in first) || ts < first[ip]) first[ip] = ts
		if (ts > last[ip]) last[ip] = ts
	}
	END {
		for (ip in p) {
			pv = int(p[ip] * 1000)
			pw = int(pv / 1000)
			pf = int((pv % 1000 + 50) / 100)
			if (pf >= 10) { pw++; pf = 0 }
			printf "%d|%s|%d|%d|%d|%d|%s|%d|%d\n", pv, ip, pw, pf, trip, cnt[ip], svcs[ip], first[ip], last[ip]
		}
	}' "$events_file" | sort -t'|' -k1 -nr
}

# _events_dashboard_awk events_file now half_life trip
# Thin wrapper: dashboard mode (all IPs) — delegates to _events_pressure_awk.
_events_dashboard_awk() {
	_events_pressure_awk "$@"
}

# events_dashboard install_path — show all IPs with active pressure
# Single-pass awk over events.dat computes per-IP pressure aggregates,
# outputs pipe-delimited table sorted by pressure descending.
events_dashboard() {
	local install_path="$1"
	local events_file="$install_path/tmp/events.dat"
	local now half_life trip
	now=$(date +"%s")
	half_life="${PRESSURE_HALF_LIFE:-300}"
	trip="${GLOB_PRESSURE_TRIP:-20}"

	if [ ! -f "$events_file" ] || [ ! -s "$events_file" ]; then
		echo "No active events."
		return 0
	fi

	local atmp
	atmp=$(mktemp "$install_path/tmp/.events.XXXXXX")
	echo "#IP|PRESSURE|COUNT|SERVICES|FIRST_SEEN|LAST_SEEN|STATUS" > "$atmp"
	_events_dashboard_awk "$events_file" "$now" "$half_life" "$trip" | \
	while IFS='|' read -r _sort_key ip pw pf _trip cnt svcs first_ts last_ts; do
		local first_fmt last_fmt ban_status
		first_fmt=$(_fmt_ts "$first_ts")
		last_fmt=$(_fmt_ts "$last_ts")
		ban_status=$(_apool_ban_status "$ip")
		echo "$ip|${pw}.${pf}/${_trip}|$cnt|$svcs|$first_fmt|$last_fmt|$ban_status"
	done >> "$atmp"
	format_table < "$atmp"
	rm -f "$atmp"
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
		if (w > wt[mod]) wt[mod] = w
		if (!(mod in sfirst) || ts < sfirst[mod]) sfirst[mod] = ts
		if (ts > slast[mod]) slast[mod] = ts
		if (gfirst == 0 || ts < gfirst) gfirst = ts
		if (ts > glast) glast = ts
	}
	END {
		if (length(cnt) == 0) exit
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
	local rule_file="${RULES_PATH:-}/rules/$rule"
	# if RULES_PATH already includes the project root, try both forms
	if [ ! -f "$rule_file" ]; then
		rule_file="${RULES_PATH:-}/$rule"
	fi
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

# _events_ip_data install_path ip — shared data gatherer for events_ip triplet
# Validates IP, checks for events, runs single-pass AWK, adds ban status.
# Outputs:
#   H|pressure_fmt|trip|half_life|first_ts|last_ts|ban_status
#   S|service|weight|count|pressure_fmt
# Returns 1 if invalid IP (with error on stderr).
# Returns 2 if no events for IP.
_events_ip_data() {
	local install_path="$1" ip="$2"
	local events_file="$install_path/tmp/events.dat"
	local now half_life trip
	now=$(date +"%s")
	half_life="${PRESSURE_HALF_LIFE:-300}"
	trip="${GLOB_PRESSURE_TRIP:-20}"

	ip=$(validate_ip_any "$ip") || { echo "error: invalid IP address '$2'." >&2; return 1; }

	if [ ! -f "$events_file" ] || [ ! -s "$events_file" ]; then
		return 2
	fi

	local raw
	raw=$(_events_ip_awk "$events_file" "$ip" "$now" "$half_life")
	if [ -z "$raw" ]; then
		return 2
	fi

	# extract header line
	local h_line _gp _gp_fmt first_ts last_ts
	h_line=$(echo "$raw" | grep '^H|')
	IFS='|' read -r _ _gp first_ts last_ts <<< "$h_line"
	_gp_fmt=$(pressure_format "$_gp")

	# ban status
	local ban_status
	ban_status=$(_apool_ban_status "$ip")
	[ -z "$ban_status" ] && ban_status="not banned"

	echo "H|$_gp_fmt|$trip|$half_life|$first_ts|$last_ts|$ban_status"

	# emit service lines with formatted pressure
	local _type _svc _wt _cnt _sp _sp_fmt
	while IFS='|' read -r _type _svc _wt _cnt _sp; do
		[ "$_type" != "S" ] && continue
		_sp_fmt=$(pressure_format "$_sp")
		echo "S|$_svc|$_wt|$_cnt|$_sp_fmt"
	done <<< "$raw"
}

# events_ip install_path ip — per-IP pressure detail with service breakdown
events_ip() {
	local install_path="$1" ip="$2"
	local half_life trip
	half_life="${PRESSURE_HALF_LIFE:-300}"
	trip="${GLOB_PRESSURE_TRIP:-20}"

	local data rc=0
	data=$(_events_ip_data "$install_path" "$ip") || rc=$?
	if [ "$rc" -eq 1 ]; then
		return 1
	fi
	if [ "$rc" -eq 2 ]; then
		ip=$(validate_ip_any "$ip" 2>/dev/null) || ip="$2"
		echo "No active events for $ip."
		return 0
	fi

	# parse header
	local h_line _gp_fmt _trip _hl first_ts last_ts ban_status
	h_line=$(echo "$data" | grep '^H|')
	IFS='|' read -r _ _gp_fmt _trip _hl first_ts last_ts ban_status <<< "$h_line"

	echo "IP:               $ip"
	echo "Pressure:         ${_gp_fmt}/${_trip} (half-life=${_hl}s)"
	echo ""

	# per-service table
	local atmp
	atmp=$(mktemp "$install_path/tmp/.evtip.XXXXXX")
	echo "#SERVICE|WEIGHT|COUNT|PRESSURE" > "$atmp"
	local _type _svc _wt _cnt _sp_fmt
	while IFS='|' read -r _type _svc _wt _cnt _sp_fmt; do
		[ "$_type" != "S" ] && continue
		echo "$_svc|$_wt|$_cnt|${_sp_fmt}/${_trip}" >> "$atmp"
	done <<< "$data"
	format_table < "$atmp"
	rm -f "$atmp"
	echo ""

	# first/last seen
	if [ -n "$first_ts" ] && [ "$first_ts" -gt 0 ] 2>/dev/null; then
		echo "First seen:       $(date -d "@${first_ts}" +"%Y-%m-%d %H:%M:%S" 2>/dev/null || echo "$first_ts")"
	fi
	if [ -n "$last_ts" ] && [ "$last_ts" -gt 0 ] 2>/dev/null; then
		echo "Last seen:        $(date -d "@${last_ts}" +"%Y-%m-%d %H:%M:%S" 2>/dev/null || echo "$last_ts")"
	fi

	# ban status
	if [ "$ban_status" != "not banned" ]; then
		echo "Status:           $ban_status"
	else
		echo "Status:           not banned"
	fi

	# log sample — extract recent log lines matching this IP
	echo ""
	echo "Recent log activity:"
	local _log_total=0 _log_cap=15
	local _seen_logs="" _log_file _log_lines
	local _type _svc _wt _cnt _sp_fmt
	while IFS='|' read -r _type _svc _wt _cnt _sp_fmt; do
		[ "$_type" != "S" ] && continue
		[ "$_log_total" -ge "$_log_cap" ] && break
		_log_file=$(_events_rule_log_file "$_svc") || continue
		# deduplicate log files (e.g., sshd + postfix both use AUTH_LOG_PATH)
		case ",$_seen_logs," in
			*",$_log_file,"*) continue ;;
		esac
		_seen_logs="${_seen_logs:+$_seen_logs,}$_log_file"
		local _remain=$((_log_cap - _log_total))
		_log_lines=$(_alert_sanitize_logs "$_log_file" "$ip" "$_remain") || continue
		echo "$_log_lines"
		_log_total=$((_log_total + $(echo "$_log_lines" | wc -l)))
	done <<< "$data"
	if [ "$_log_total" -eq 0 ]; then
		echo "  (no matching log entries found)"
	fi
}

# _events_cidr_awk events_file now half_life trip target_addr target_mask
# Thin wrapper: CIDR mode (subnet filter) — delegates to _events_pressure_awk.
_events_cidr_awk() {
	_events_pressure_awk "$@"
}

# events_cidr install_path cidr — subnet-scoped pressure report
# Uses mawk-compatible ipv4_subnet() for CIDR matching (IPv4 only, mask 8-32).
events_cidr() {
	local install_path="$1" cidr="$2"
	local events_file="$install_path/tmp/events.dat"
	local now half_life trip
	now=$(date +"%s")
	half_life="${PRESSURE_HALF_LIFE:-300}"
	trip="${GLOB_PRESSURE_TRIP:-20}"

	cidr=$(validate_cidr "$cidr") || { echo "error: invalid CIDR notation '$2' (IPv4, mask 8-32)." >&2; return 1; }
	local target_addr target_mask
	target_addr="${cidr%/*}"
	target_mask="${cidr#*/}"

	if [ ! -f "$events_file" ] || [ ! -s "$events_file" ]; then
		echo "No events found for $cidr."
		return 0
	fi

	local atmp
	atmp=$(mktemp "$install_path/tmp/.evtcidr.XXXXXX")
	echo "#IP|PRESSURE|COUNT|SERVICES|FIRST_SEEN|LAST_SEEN|STATUS" > "$atmp"
	local match_count=0 total_events=0 banned_count=0
	_events_cidr_awk "$events_file" "$now" "$half_life" "$trip" "$target_addr" "$target_mask" | \
	while IFS='|' read -r _sort_key ip pw pf _trip cnt svcs first_ts last_ts; do
		local first_fmt last_fmt ban_status
		first_fmt=$(_fmt_ts "$first_ts")
		last_fmt=$(_fmt_ts "$last_ts")
		ban_status=$(_apool_ban_status "$ip")
		echo "$ip|${pw}.${pf}/${_trip}|$cnt|$svcs|$first_fmt|$last_fmt|$ban_status"
		# counters for summary (write to fd 3)
		echo "M|$cnt|${ban_status:+1}" >&3
	done 3>"$atmp.summary" >> "$atmp"
	# compute summary from fd 3 output
	if [ -f "$atmp.summary" ] && [ -s "$atmp.summary" ]; then
		match_count=$(wc -l < "$atmp.summary")
		total_events=$(awk -F'|' '{s+=$2} END {print s+0}' "$atmp.summary")
		banned_count=$(awk -F'|' '$3 != "" {c++} END {print c+0}' "$atmp.summary")
	fi
	rm -f "$atmp.summary"
	if [ "$match_count" -eq 0 ]; then
		rm -f "$atmp"
		echo "No events found for $cidr."
		return 0
	fi
	format_table < "$atmp"
	echo ""
	echo "$match_count IPs, $total_events failures, $banned_count banned"
	rm -f "$atmp"
}

# --- Events structured output (JSON/CSV) ---

# events_dashboard_json install_path — JSON array of pressure dashboard entries
events_dashboard_json() {
	local install_path="$1"
	local events_file="$install_path/tmp/events.dat"
	local now half_life trip
	now=$(date +"%s")
	half_life="${PRESSURE_HALF_LIFE:-300}"
	trip="${GLOB_PRESSURE_TRIP:-20}"

	if [ ! -f "$events_file" ] || [ ! -s "$events_file" ]; then
		echo "[]"
		return 0
	fi

	echo "["
	local first=1
	_events_dashboard_awk "$events_file" "$now" "$half_life" "$trip" | \
	while IFS='|' read -r _ ip pw pf _trip cnt svcs first_ts last_ts; do
		local first_fmt last_fmt ban_status
		first_fmt=$(_fmt_ts_iso "$first_ts")
		last_fmt=$(_fmt_ts_iso "$last_ts")
		ban_status=$(_apool_ban_status "$ip")
		[ -z "$ban_status" ] && ban_status="not banned"
		if [ "$first" -eq 1 ]; then
			first=0
		else
			echo ","
		fi
		printf '  {"ip": "%s", "pressure": %s.%s, "pressure_trip": %s, "count": %s, "services": %s, "first_seen": "%s", "last_seen": "%s", "status": "%s"}' \
			"$(_json_escape "$ip")" "$pw" "$pf" "$_trip" "$cnt" \
			"$(_json_array_from_csv "$svcs")" "$first_fmt" "$last_fmt" \
			"$(_json_escape "$ban_status")"
	done
	echo ""
	echo "]"
}

# events_dashboard_csv install_path — CSV formatted pressure dashboard
events_dashboard_csv() {
	local install_path="$1"
	local events_file="$install_path/tmp/events.dat"
	local now half_life trip
	now=$(date +"%s")
	half_life="${PRESSURE_HALF_LIFE:-300}"
	trip="${GLOB_PRESSURE_TRIP:-20}"

	echo "ip,pressure,pressure_trip,count,services,first_seen,last_seen,status"
	if [ ! -f "$events_file" ] || [ ! -s "$events_file" ]; then
		return 0
	fi

	_events_dashboard_awk "$events_file" "$now" "$half_life" "$trip" | \
	while IFS='|' read -r _ ip pw pf _trip cnt svcs first_ts last_ts; do
		local first_fmt last_fmt ban_status
		first_fmt=$(_fmt_ts_iso "$first_ts")
		last_fmt=$(_fmt_ts_iso "$last_ts")
		ban_status=$(_apool_ban_status "$ip")
		[ -z "$ban_status" ] && ban_status="not banned"
		echo "$ip,${pw}.${pf},$_trip,$cnt,$svcs,$first_fmt,$last_fmt,$ban_status"
	done
}

# events_ip_json install_path ip — JSON object for per-IP pressure detail
events_ip_json() {
	local install_path="$1" ip="$2"
	local half_life trip
	half_life="${PRESSURE_HALF_LIFE:-300}"
	trip="${GLOB_PRESSURE_TRIP:-20}"

	local data rc=0
	data=$(_events_ip_data "$install_path" "$ip") || rc=$?
	if [ "$rc" -eq 1 ]; then
		return 1
	fi
	if [ "$rc" -eq 2 ]; then
		ip=$(validate_ip_any "$ip" 2>/dev/null) || ip="$2"
		printf '{"ip": "%s", "pressure": 0.0, "pressure_trip": %s, "half_life": %s, "services": [], "first_seen": null, "last_seen": null, "status": "not banned", "log_sample": []}\n' \
			"$(_json_escape "$ip")" "$trip" "$half_life"
		return 0
	fi

	# parse header
	local h_line _gp_fmt _trip _hl first_ts last_ts ban_status
	h_line=$(echo "$data" | grep '^H|')
	IFS='|' read -r _ _gp_fmt _trip _hl first_ts last_ts ban_status <<< "$h_line"

	# build services JSON array
	local svcs_json="["
	local svc_first=1
	local _type _svc _wt _cnt _sp_fmt
	while IFS='|' read -r _type _svc _wt _cnt _sp_fmt; do
		[ "$_type" != "S" ] && continue
		if [ "$svc_first" -eq 1 ]; then
			svc_first=0
		else
			svcs_json="$svcs_json, "
		fi
		svcs_json="$svcs_json{\"service\": \"$(_json_escape "$_svc")\", \"weight\": $_wt, \"count\": $_cnt, \"pressure\": $_sp_fmt}"
	done <<< "$data"
	svcs_json="$svcs_json]"

	# first/last seen
	local first_fmt="null" last_fmt="null"
	if [ -n "$first_ts" ] && [ "$first_ts" -gt 0 ] 2>/dev/null; then
		first_fmt="\"$(_fmt_ts_iso "$first_ts")\""
	fi
	if [ -n "$last_ts" ] && [ "$last_ts" -gt 0 ] 2>/dev/null; then
		last_fmt="\"$(_fmt_ts_iso "$last_ts")\""
	fi

	# build log_sample JSON array
	local log_json="[" _log_total=0 _log_cap=15
	local _seen_logs="" _log_file _log_lines _log_first=1
	while IFS='|' read -r _type _svc _wt _cnt _sp_fmt; do
		[ "$_type" != "S" ] && continue
		[ "$_log_total" -ge "$_log_cap" ] && break
		_log_file=$(_events_rule_log_file "$_svc") || continue
		case ",$_seen_logs," in
			*",$_log_file,"*) continue ;;
		esac
		_seen_logs="${_seen_logs:+$_seen_logs,}$_log_file"
		local _remain=$((_log_cap - _log_total))
		_log_lines=$(_alert_sanitize_logs "$_log_file" "$ip" "$_remain") || continue
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
	done <<< "$data"
	log_json="$log_json]"

	printf '{"ip": "%s", "pressure": %s, "pressure_trip": %s, "half_life": %s, "services": %s, "first_seen": %s, "last_seen": %s, "status": "%s", "log_sample": %s}\n' \
		"$(_json_escape "$ip")" "$_gp_fmt" "$_trip" "$_hl" \
		"$svcs_json" "$first_fmt" "$last_fmt" "$(_json_escape "$ban_status")" "$log_json"
}

# events_ip_csv install_path ip — CSV formatted per-IP pressure detail
# One row per service, IP repeated on each row.
events_ip_csv() {
	local install_path="$1" ip="$2"
	local half_life trip
	half_life="${PRESSURE_HALF_LIFE:-300}"
	trip="${GLOB_PRESSURE_TRIP:-20}"

	ip=$(validate_ip_any "$ip") || { echo "error: invalid IP address '$2'." >&2; return 1; }

	echo "ip,pressure,pressure_trip,half_life,service,weight,count,service_pressure,first_seen,last_seen,status"

	local data rc=0
	data=$(_events_ip_data "$install_path" "$ip") || rc=$?
	if [ "$rc" -ne 0 ]; then
		return 0
	fi

	# parse header
	local h_line _gp_fmt _trip _hl first_ts last_ts ban_status
	h_line=$(echo "$data" | grep '^H|')
	IFS='|' read -r _ _gp_fmt _trip _hl first_ts last_ts ban_status <<< "$h_line"

	# first/last seen
	local first_fmt="" last_fmt=""
	if [ -n "$first_ts" ] && [ "$first_ts" -gt 0 ] 2>/dev/null; then
		first_fmt=$(_fmt_ts_iso "$first_ts")
	fi
	if [ -n "$last_ts" ] && [ "$last_ts" -gt 0 ] 2>/dev/null; then
		last_fmt=$(_fmt_ts_iso "$last_ts")
	fi

	# per-service rows
	local _type _svc _wt _cnt _sp_fmt
	while IFS='|' read -r _type _svc _wt _cnt _sp_fmt; do
		[ "$_type" != "S" ] && continue
		echo "$ip,$_gp_fmt,$_trip,$_hl,$_svc,$_wt,$_cnt,$_sp_fmt,$first_fmt,$last_fmt,$ban_status"
	done <<< "$data"
}

# events_cidr_json install_path cidr — JSON object with CIDR summary and IP list
events_cidr_json() {
	local install_path="$1" cidr="$2"
	local events_file="$install_path/tmp/events.dat"
	local now half_life trip
	now=$(date +"%s")
	half_life="${PRESSURE_HALF_LIFE:-300}"
	trip="${GLOB_PRESSURE_TRIP:-20}"

	cidr=$(validate_cidr "$cidr") || { echo "error: invalid CIDR notation '$2' (IPv4, mask 8-32)." >&2; return 1; }
	local target_addr target_mask
	target_addr="${cidr%/*}"
	target_mask="${cidr#*/}"

	if [ ! -f "$events_file" ] || [ ! -s "$events_file" ]; then
		printf '{"cidr": "%s", "summary": {"match_count": 0, "total_count": 0, "banned_count": 0}, "ips": []}\n' \
			"$(_json_escape "$cidr")"
		return 0
	fi

	local match_count=0 total_events=0 banned_count=0
	local first=1
	local _cidr_summary _cidr_ips
	_cidr_summary=$(mktemp "$install_path/tmp/.cidr_json_summary.XXXXXX")
	_cidr_ips=$(mktemp "$install_path/tmp/.cidr_json_ips.XXXXXX")

	_events_cidr_awk "$events_file" "$now" "$half_life" "$trip" "$target_addr" "$target_mask" | \
	while IFS='|' read -r _ ip pw pf _trip cnt svcs first_ts last_ts; do
		local first_fmt last_fmt ban_status
		first_fmt=$(_fmt_ts_iso "$first_ts")
		last_fmt=$(_fmt_ts_iso "$last_ts")
		ban_status=$(_apool_ban_status "$ip")
		[ -z "$ban_status" ] && ban_status="not banned"
		if [ "$first" -eq 1 ]; then
			first=0
		else
			echo ","
		fi
		printf '    {"ip": "%s", "pressure": %s.%s, "pressure_trip": %s, "count": %s, "services": %s, "first_seen": "%s", "last_seen": "%s", "status": "%s"}' \
			"$(_json_escape "$ip")" "$pw" "$pf" "$_trip" "$cnt" \
			"$(_json_array_from_csv "$svcs")" "$first_fmt" "$last_fmt" \
			"$(_json_escape "$ban_status")"
		# summary counters to fd 3
		echo "$cnt|${ban_status}" >&3
	done 3>"$_cidr_summary" > "$_cidr_ips"

	# compute summary
	if [ -f "$_cidr_summary" ] && [ -s "$_cidr_summary" ]; then
		match_count=$(wc -l < "$_cidr_summary")
		total_events=$(awk -F'|' '{s+=$1} END {print s+0}' "$_cidr_summary")
		banned_count=$(awk -F'|' '$2 != "not banned" && $2 != "" {c++} END {print c+0}' "$_cidr_summary")
	fi

	printf '{"cidr": "%s", "summary": {"match_count": %d, "total_count": %d, "banned_count": %d}, "ips": [\n' \
		"$(_json_escape "$cidr")" "$match_count" "$total_events" "$banned_count"
	cat "$_cidr_ips" 2>/dev/null
	echo ""
	echo "]}"
	rm -f "$_cidr_summary" "$_cidr_ips"
}

# events_cidr_csv install_path cidr — CSV formatted CIDR pressure report
events_cidr_csv() {
	local install_path="$1" cidr="$2"
	local events_file="$install_path/tmp/events.dat"
	local now half_life trip
	now=$(date +"%s")
	half_life="${PRESSURE_HALF_LIFE:-300}"
	trip="${GLOB_PRESSURE_TRIP:-20}"

	cidr=$(validate_cidr "$cidr") || { echo "error: invalid CIDR notation '$2' (IPv4, mask 8-32)." >&2; return 1; }
	local target_addr target_mask
	target_addr="${cidr%/*}"
	target_mask="${cidr#*/}"

	echo "ip,pressure,pressure_trip,count,services,first_seen,last_seen,status"
	if [ ! -f "$events_file" ] || [ ! -s "$events_file" ]; then
		return 0
	fi

	_events_cidr_awk "$events_file" "$now" "$half_life" "$trip" "$target_addr" "$target_mask" | \
	while IFS='|' read -r _ ip pw pf _trip cnt svcs first_ts last_ts; do
		local first_fmt last_fmt ban_status
		first_fmt=$(_fmt_ts_iso "$first_ts")
		last_fmt=$(_fmt_ts_iso "$last_ts")
		ban_status=$(_apool_ban_status "$ip")
		[ -z "$ban_status" ] && ban_status="not banned"
		echo "$ip,${pw}.${pf},$_trip,$cnt,$svcs,$first_fmt,$last_fmt,$ban_status"
	done
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
