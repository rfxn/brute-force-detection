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
unset _internals_dir

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
						if [ "$val" -gt 200 ]; then
							elog warn "pressure.conf: $rule_name PRESSURE_TRIP=$val exceeds maximum (200), clamping"
							val=200
						fi
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
	if [ "$_pt" -gt 200 ]; then
		echo "error: PRESSURE_TRIP=$_pt exceeds maximum (200). Values above 200 effectively disable detection." >&2
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
	if [ "$_ptg" -gt 200 ]; then
		echo "error: PRESSURE_TRIP_GLOBAL=$_ptg exceeds maximum (200). Values above 200 effectively disable detection." >&2
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
	local _lis="${LOG_IDLE_SUPPRESS:-1}"
	if [ "$_lis" != "0" ] && [ "$_lis" != "1" ]; then
		echo "error: LOG_IDLE_SUPPRESS must be 0 or 1 (got '${LOG_IDLE_SUPPRESS:-}')." >&2
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
	if ! [[ "${EMAIL_LOGLINES:-5}" =~ $int_pattern ]] || [ "${EMAIL_LOGLINES:-5}" -eq 0 ]; then
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
					echo "warning: EMAIL_REPUTATION_LINKS contains unknown provider '$_rl'; known: $_rl_known." >&2
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
	# write tlog output to temp file once; sed reads from file per pattern
	# instead of echo-piping multi-MB $tlog_input variable for each pattern
	local _tlog_file
	_tlog_file=$(mktemp "${TMPDIR:-/tmp}/.bfd_extract.XXXXXX")
	sed 's/::ffff://g' > "$_tlog_file"
	if [ ! -s "$_tlog_file" ]; then
		command rm -f "$_tlog_file"
		return 0
	fi

	# apply IGNOREREGEX exclusion if set by rule
	if [ -n "${IGNOREREGEX:-}" ]; then
		# validate regex: grep -E returns 2 for invalid patterns
		local ign_rc=0
		grep -E "$IGNOREREGEX" /dev/null >/dev/null 2>&1 || ign_rc=$?
		if [ "$ign_rc" -eq 2 ]; then
			elog warn "invalid IGNOREREGEX pattern '$IGNOREREGEX', ignoring" >&2
			IGNOREREGEX=""
		else
			local _tlog_filtered
			_tlog_filtered=$(mktemp "${TMPDIR:-/tmp}/.bfd_extract.XXXXXX")
			grep -Ev "$IGNOREREGEX" "$_tlog_file" > "$_tlog_filtered" || true  # exit 1 = all lines match (valid)
			command mv -f "$_tlog_filtered" "$_tlog_file"
			if [ ! -s "$_tlog_file" ]; then
				command rm -f "$_tlog_file"
				return 0
			fi
		fi
	fi

	# Build combined sed scripts: one IPv4 pass, one IPv6 pass.
	# Uses sed 't' (test-and-branch) to skip remaining patterns on first
	# match — reduces 2N file reads to 2 for N-pattern rules (e.g. sshd
	# with 12 patterns: 24 sed processes → 2).  If a line matches >1
	# pattern, only the first fires; this is correct (one log line = one
	# event) and fixes incidental double-counting in cpanel/sendmail rules
	# where overlapping patterns previously inflated pressure scores.
	local sed_v4="" sed_v6="" pattern sed_pat
	for pattern in "$@"; do
		# (^|.*[^0-9.]) boundary prevents greedy .* from consuming
		# leading digits of the IP address; IP capture becomes \2
		sed_pat="${pattern//<HOST>/($ip4_re)}"
		sed_v4="${sed_v4}s#(^|.*[^0-9.])${sed_pat}.*#\2#p; t; "
		# IPv6 extraction — inner group in ip6_re pushes IP to \2
		sed_pat="${pattern//<HOST>/($ip6_re)}"
		sed_v6="${sed_v6}s#(^|.*[^0-9a-fA-F:])${sed_pat}.*#\2#p; t; "
	done
	{
		sed -En "$sed_v4" "$_tlog_file"
		sed -En "$sed_v6" "$_tlog_file"
	} | awk '{
		gsub(/[\[\]]/, "")
		if ($0 == "") next
		ip = $0
		# IPv4: exactly 4 dot-separated groups, each 0-255
		n = split(ip, o, ".")
		if (n == 4) {
			valid = 1
			for (i = 1; i <= 4; i++) {
				if (o[i] ~ /[^0-9]/ || o[i] == "" || length(o[i]) > 3 || o[i]+0 > 255) {
					valid = 0; break
				}
			}
			if (valid) { print ip; next }
		}
		# IPv6: strip zone ID, validate hex:colon structure
		sub(/%.*$/, "", ip)
		if (ip == "") next
		if (ip !~ /^[0-9a-fA-F:]+$/) next
		if (ip !~ /:/) next
		if (ip ~ /:::/) next
		if (ip ~ /^:[^:]/) next
		if (ip ~ /[^:]:$/) next
		tmp = ip; dc = gsub(/::/, "::", tmp)
		if (dc > 1) next
		n = split(ip, g, ":")
		ne = 0; valid = 1
		for (i = 1; i <= n; i++) {
			if (g[i] != "") {
				ne++
				if (length(g[i]) > 4) { valid = 0; break }
			}
		}
		if (!valid) next
		if (dc == 1) {
			if (ne <= 7) print ip
		} else {
			if (ne == 8) print ip
		}
	}'
	command rm -f "$_tlog_file"
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
	"$_FW_IPT_BIN" -N bfd 2>/dev/null || true  # chain may already exist
	"$_FW_IPT_BIN" -C INPUT -j bfd 2>/dev/null || "$_FW_IPT_BIN" -I INPUT -j bfd
	if [ -n "$_FW_IP6T_BIN" ]; then
		"$_FW_IP6T_BIN" -N bfd 2>/dev/null || true  # chain may already exist
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
	# by extract_command_template(). $host is validated by validate_ip_any()
	# (check() loop + CLI callers), $mod by sanitize_mod(), $ports by
	# sanitize_ports(). conf.bfd is root-owned and verified by safe_source().
	# This eval is intentional for user-defined firewall commands.
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
	elog_event "block_added" "warn" "{$mod} banned $host via $_FW_BACKEND" \
		"ip=$host" "mod=$mod" "backend=$_FW_BACKEND" "ports=${ports:-all}"
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
	elog_event "block_removed" "info" "{$mod} $host ban expired" \
		"ip=$host" "mod=$mod" "backend=$_FW_BACKEND"
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
	local _ts_numeric='^[0-9]+$'
	while IFS='|' read -r ts expiry host mod ports; do
		[[ "$ts" =~ $_ts_numeric ]] || continue
		[ -n "$host" ] || continue
		banned_fmt=$(_fmt_ts "$ts")
		if [ "$expiry" = "0" ]; then
			expiry_fmt="permanent"
		else
			expiry_fmt=$(_fmt_ts "$expiry")
		fi
		echo "$host|$mod|$ports|$banned_fmt|$expiry_fmt"
	done <<< "$raw" >> "$atmp"
	format_table < "$atmp"
	command rm -f "$atmp"
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
	for f in "$install_path/tmp/pressure.dat" "$install_path/tmp/bans.active" \
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
		awk -v ip="$host" '$3 != ip' "$bans_file" > "$bans_file.new" || true  # empty result is valid (last entry removed)
		command mv "$bans_file.new" "$bans_file"
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

# --- Pressure state I/O functions ---
# State file format:
#   pressure.dat: "TIMESTAMP IP MOD [WEIGHT]" — timestamped pressure events
#   Field 4 (WEIGHT) is optional; older events without it default to weight 1.
#   Pruned aggressively (~10 half-lives); used only for exponential-decay scoring.

# state_pressure_append install_path timestamp host mod [count] [weight] — append events
# Appends count timestamped event lines (default 1) to pressure.dat.
# weight (default "1") is stored as field 4 for pressure scoring.
state_pressure_append() {
	local install_path="$1" timestamp="$2" host="$3" mod="$4"
	local count="${5:-1}" weight="${6:-1}"
	local events_file="$install_path/tmp/pressure.dat"
	(
		flock -x 200
		local i
		for ((i = 0; i < count; i++)); do
			echo "$timestamp $host $mod $weight"
		done >> "$events_file"
	) 200>>"$events_file"
}

# state_pressure_prune install_path window now [max_lines] — remove old events
# Removes events older than window. Safety cap at max_lines (default 5000).
state_pressure_prune() {
	local install_path="$1" window="$2" now="$3"
	local max_lines="${4:-5000}"
	local events_file="$install_path/tmp/pressure.dat"
	if [ ! -f "$events_file" ] || [ ! -s "$events_file" ]; then
		return 0
	fi
	local cutoff=$((now - window))
	(
		flock -x 200
		awk -v cutoff="$cutoff" '$1+0 >= cutoff' "$events_file" \
			| tail -n "$max_lines" > "$events_file.new"
		command mv "$events_file.new" "$events_file"
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
		command rm -f "$pool_file.new"
	) 200>>"$pool_file"
}

# --- Pressure scoring functions ---

# pressure_compute install_path host half_life now [mod] — compute decayed pressure
# Single-pass awk over pressure.dat: sums weight * 2^(-(now-ts)/half_life) for each
# event matching host (and optionally mod). Returns pressure * 1000 as integer.
# Handles both 3-field (old, weight=1) and 4-field (new) event lines.
pressure_compute() {
	local install_path="$1" host="$2" half_life="$3" now="$4"
	local mod="${5:-}"
	local events_file="$install_path/tmp/pressure.dat"
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

# _resolve_trip service — return per-rule trip threshold for a service
# Falls back to GLOB_PRESSURE_TRIP when no per-rule override exists.
_resolve_trip() {
	local svc="$1"
	if [ "${_PRESS_TRIP[$svc]+x}" = "x" ]; then
		echo "${_PRESS_TRIP[$svc]}"
	else
		echo "${GLOB_PRESSURE_TRIP:-20}"
	fi
}

# _resolve_min_trip csv_services — return minimum per-rule trip across services
# Input: comma-separated service list (e.g., "sshd,dovecot,postfix").
# Returns the lowest per-rule trip found (or GLOB_PRESSURE_TRIP if none set).
_resolve_min_trip() {
	local csv="$1"
	local min_trip="${GLOB_PRESSURE_TRIP:-20}" svc val
	local IFS=','
	for svc in $csv; do
		if [ "${_PRESS_TRIP[$svc]+x}" = "x" ]; then
			val="${_PRESS_TRIP[$svc]}"
			if [ "$val" -lt "$min_trip" ]; then
				min_trip="$val"
			fi
		fi
	done
	echo "$min_trip"
}

# _pressure_aggregate_all events_file now half_life
# Single-pass AWK over pressure.dat: computes decayed pressure for ALL IPs.
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
#   2. Append that many weighted events to pressure.dat
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
		state_pressure_append "$install_path" "$now" "$host" "$mod" "$count" "$weight"
	fi
	pressure_compute "$install_path" "$host" "$half_life" "$now" "$mod"
}

# --- Country multiplier functions ---

# ip_to_country ip db_file — look up 2-letter country code for an IP address
# IPv4: awk linear scan on sorted integer ranges in ipcountry.dat.
# IPv6: geoip_ip6_lookup on hex-range database (ipcountry6.dat).
# Returns CC to stdout, or empty string if not found.
# When _COUNTRY_CACHE_FILE is set, caches lookups to avoid repeated scans of
# the 190K-line database (reduces O(IPs * DB_lines) to O(IPs + DB_lines)).
ip_to_country() {
	local ip="$1" db_file="$2"
	# per-cycle cache: check before expensive awk/hex scan (both families)
	if [ -n "${_COUNTRY_CACHE_FILE:-}" ] && [ -f "$_COUNTRY_CACHE_FILE" ]; then
		local _cached_line
		_cached_line=$(grep -m1 "^${ip} " "$_COUNTRY_CACHE_FILE" 2>/dev/null) || true  # no match is normal (cache miss)
		if [ -n "$_cached_line" ]; then
			local _cached_cc="${_cached_line#* }"
			if [ "$_cached_cc" = "-" ]; then echo ""; else echo "$_cached_cc"; fi
			return 0
		fi
	fi
	# IPv6: derive db6 path from db_file (ipcountry.dat -> ipcountry6.dat)
	if [[ "$ip" == *:* ]]; then
		local db6_file="${db_file%.*}6.${db_file##*.}"
		# Format guard: verify hex-range format before calling lookup.
		# Protects upgrade path where old raw-CIDR ipcountry6.dat may persist
		# if network was unavailable at first run after upgrade.
		if [ -f "$db6_file" ] && [ -s "$db6_file" ]; then
			local _hdr
			_hdr=$(head -1 "$db6_file")
			# hex-range format: two 32-char hex fields + 2-char CC (no colons)
			# raw-CIDR format: starts with hex:hex (contains colons)
			if [[ "$_hdr" == *:* ]]; then
				# old raw-CIDR format — skip IPv6 lookup silently
				echo ""
				return 0
			fi
			if declare -f geoip_ip6_lookup >/dev/null 2>&1; then
				local v6cc
				v6cc=$(geoip_ip6_lookup "$ip" "$db6_file") || true  # no-match returns 1; empty v6cc is valid
				# populate cache (use "-" sentinel for empty results)
				if [ -n "${_COUNTRY_CACHE_FILE:-}" ]; then
					echo "$ip ${v6cc:--}" >> "$_COUNTRY_CACHE_FILE"
				fi
				echo "$v6cc"
				return 0
			fi
		fi
		echo ""
		return 0
	fi
	if [ ! -f "$db_file" ] || [ ! -s "$db_file" ]; then
		echo ""
		return 0
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

# _resolve_cidr_cc ip cc — resolve country code for CIDR entries missing CC.
# If cc is already set (non-empty, not "--"), echoes it unchanged.
# For CIDR IPs (containing "/"), strips the mask and looks up the network
# address via ip_to_country. Falls back to "--" if lookup fails.
_resolve_cidr_cc() {
	local ip="$1" cc="$2"
	if [ -n "$cc" ] && [ "$cc" != "--" ]; then
		echo "$cc"
		return
	fi
	if [[ "$ip" == */* ]] && [ -f "$INSTALL_PATH/ipcountry.dat" ]; then
		cc=$(ip_to_country "${ip%%/*}" "$INSTALL_PATH/ipcountry.dat" 2>/dev/null)  # 2>/dev/null: ipcountry.dat may not exist
	fi
	echo "${cc:---}"
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

# --- Batch pre-computation functions for check() performance ---
# These functions perform single-pass computation over all IPs at once,
# replacing per-IP subprocess calls with O(1) associative array lookups.

# _batch_pressure_compute events_file now half_life mod
# Single awk pass over pressure.dat computing BOTH per-mod and global decayed
# pressure for all IPs. Output: "IP mod_p global_p" (pressures scaled *1000).
_batch_pressure_compute() {
	local events_file="$1" now="$2" half_life="$3" mod="$4"
	if [ ! -f "$events_file" ] || [ ! -s "$events_file" ]; then
		return 0
	fi
	local cutoff=$((now - half_life * 10))
	awk -v now="$now" -v hl="$half_life" -v cutoff="$cutoff" -v mod="$mod" \
		'BEGIN { ln2 = 0.693147180559945 }
		$1+0 >= cutoff {
			w = ($4+0 > 0) ? $4+0 : 1
			age = now - ($1+0)
			d = w * exp(-ln2 * age / hl)
			global[$2] += d
			if ($3 == mod) per_mod[$2] += d
		}
		END {
			for (ip in global)
				printf "%s %d %d\n", ip, int((ip in per_mod ? per_mod[ip] : 0) * 1000), int(global[ip] * 1000)
		}' "$events_file"
}

# _batch_ip_to_country db_file < ip_list
# Dual-stack batch lookup. IPv4: binary search on integer-range DB (pass 1 load,
# pass 2 search). IPv6: hex-range DB lookup via awk lexicographic comparison.
# Output: "IP CC" (or "IP -"). Order not guaranteed when both families present.
# O(M + N*log(M)) for IPv4 where M=db entries (~256K) and N=unique IPs (~500).
_batch_ip_to_country() {
	local db_file="$1"
	if [ ! -f "$db_file" ] || [ ! -s "$db_file" ]; then
		# no IPv4 db — output "IP -" for each input IP (both families)
		while IFS= read -r _ip; do
			[ -n "$_ip" ] && echo "$_ip -"
		done
		return 0
	fi

	# Check if IPv6 DB is available and in hex-range format
	local db6_file="${db_file%.*}6.${db_file##*.}"
	local _have_v6=0
	if [ -f "$db6_file" ] && [ -s "$db6_file" ] && \
	   declare -f geoip_ip6_lookup >/dev/null 2>&1; then
		local _hdr
		_hdr=$(head -1 "$db6_file")
		[[ "$_hdr" != *:* ]] && _have_v6=1
	fi

	if [ "$_have_v6" -eq 0 ]; then
		# No IPv6 DB — existing behavior: IPv4 binary search, IPv6 gets "-"
		awk 'NR==FNR {
			if (/^#/) next
			lo[++n] = $1+0; hi[n] = $2+0; cc[n] = $3
			next
		}
		/:/ { print $0, "-"; next }
		{
			split($0, p, ".")
			t = (p[1]+0) * 16777216 + (p[2]+0) * 65536 + (p[3]+0) * 256 + (p[4]+0)
			l = 1; r = n; f = ""
			while (l <= r) {
				m = int((l + r) / 2)
				if (t < lo[m]) r = m - 1
				else if (t > hi[m]) l = m + 1
				else { f = cc[m]; break }
			}
			print $0, (f != "" ? f : "-")
		}' "$db_file" /dev/stdin
		return 0
	fi

	# Dual-stack: partition stdin, run each DB lookup, merge
	local _tmpdir
	_tmpdir=$(mktemp -d /tmp/bfd-batch.XXXXXX)
	# shellcheck disable=SC2064
	trap "command rm -rf '$_tmpdir'" RETURN
	local _v4="$_tmpdir/v4" _v6="$_tmpdir/v6"

	# Split input: IPv4 to one file, IPv6 to another
	while IFS= read -r _ip; do
		[ -z "$_ip" ] && continue
		if [[ "$_ip" == *:* ]]; then
			echo "$_ip" >> "$_v6"
		else
			echo "$_ip" >> "$_v4"
		fi
	done

	# IPv4 batch: binary-search awk
	if [ -f "$_v4" ]; then
		awk 'NR==FNR {
			if (/^#/) next
			lo[++n] = $1+0; hi[n] = $2+0; cc[n] = $3
			next
		}
		{
			split($0, p, ".")
			t = (p[1]+0) * 16777216 + (p[2]+0) * 65536 + (p[3]+0) * 256 + (p[4]+0)
			l = 1; r = n; f = ""
			while (l <= r) {
				m = int((l + r) / 2)
				if (t < lo[m]) r = m - 1
				else if (t > hi[m]) l = m + 1
				else { f = cc[m]; break }
			}
			print $0, (f != "" ? f : "-")
		}' "$db_file" "$_v4"
	fi

	# IPv6 batch: hex-range lookup via awk
	if [ -f "$_v6" ]; then
		"$GEOIP_AWK_BIN" -v db="$db6_file" \
		"${_GEOIP_V6_AWK}"'
		BEGIN {
			while ((getline line < db) > 0) {
				if (line ~ /^#/) continue
				n = split(line, f, " ")
				if (n >= 3) { lo[++m] = f[1]; hi[m] = f[2]; cc[m] = f[3] }
			}
			close(db)
		}
		{
			ip = $0
			hex = v6hex(ip)
			if (hex == "") { print ip, "-"; next }
			found = ""
			for (i = 1; i <= m; i++) {
				if (hex >= lo[i] && hex <= hi[i]) { found = cc[i]; break }
			}
			print ip, (found != "" ? found : "-")
		}' "$_v6"
	fi

	# trap RETURN handles cleanup; explicit rm as belt-and-suspenders
	command rm -rf "$_tmpdir"
}

# count_subnet_attackers install_path window now mask mask_v6 min_unique
# Single-pass awk over pressure.dat: groups events by subnet+service,
# outputs "subnet_cidr mod unique_count" for subnets meeting threshold.
# All subnet math done in awk (mawk-compatible) for O(n) performance.
count_subnet_attackers() {
	local install_path="$1" window="$2" now="$3"
	local mask="$4" mask_v6="$5" min_unique="$6"
	local detail_file="${7:-}"
	local events_file="$install_path/tmp/pressure.dat"
	local cutoff=$((now - window))
	if [ ! -f "$events_file" ] || [ ! -s "$events_file" ]; then
		return 0
	fi
	awk -v cutoff="$cutoff" -v mask="$mask" -v mask_v6="$mask_v6" \
		-v min_unique="$min_unique" -v detail_file="$detail_file" '
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
		w = ($4+0 > 0) ? $4+0 : 1
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
		# per-IP detail tracking
		ip_fail[ipkey]++
		ip_wsum[ipkey] += w
		ip_addr[ipkey] = ip
	}
	END {
		for (key in unique) {
			if (unique[key] >= min_unique) {
				print snet[key] " " smod[key] " " unique[key]
				if (detail_file != "") {
					for (ipkey in ip_addr) {
						split(ipkey, kp, SUBSEP)
						if (kp[1] SUBSEP kp[2] == key) {
							print snet[key] " " smod[key] " " ip_addr[ipkey] " " ip_fail[ipkey] " " ip_wsum[ipkey] > detail_file
						}
					}
				}
			}
		}
	}' "$events_file"
}

# check_distributed install_path window now alerts_file
# Post-loop distributed attack detection: bans entire subnets when
# SUBNET_TRIG unique IPs from the same subnet attack the same service.
# Writes sidecar files for alert enrichment with per-IP breakdown.
# Echoes the number of subnet bans executed.
check_distributed() {
	local install_path="$1" window="$2" now="$3" alerts_file="$4"
	local ban_count=0

	# detail file for per-IP data from count_subnet_attackers
	local detail_file
	detail_file=$(mktemp "$install_path/tmp/.cidr_detail_raw.XXXXXX")

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
			ban_result=$(record_ban "$install_path" "$now" "$subnet" "$mod" "all" "ban")
			local ban_expiry ban_action recent_bans
			IFS='|' read -r ban_expiry ban_action recent_bans <<< "$ban_result"
			local _dist_duration="-1"
			if [ "$ban_expiry" = "0" ]; then
				_dist_duration="0"
			else
				_dist_duration=$((ban_expiry - now))
			fi

			# compute aggregates from detail file
			local total_failures=0 total_pressure_raw=0
			local _d_ip _d_mod _d_fc _d_ws _d_sn
			while IFS=' ' read -r _d_sn _d_mod _d_ip _d_fc _d_ws; do
				[ "$_d_sn" = "$subnet" ] || continue
				total_failures=$((total_failures + _d_fc))
				total_pressure_raw=$((total_pressure_raw + _d_ws))
			done < "$detail_file"
			local pressure_scaled=$((total_pressure_raw * 1000))

			# write sidecar file for alert renderer
			if [ "$EMAIL_ALERTS" = "1" ] && [ "$DRY_RUN" != "1" ]; then
				local _san_subnet
				_san_subnet=$(printf '%s' "$subnet" | tr ':' '-' | tr '/' '_')
				local sidecar="$install_path/tmp/.cidr_detail_${_san_subnet}"
				# header: subnet unique_count total_failures total_pressure_raw_scaled
				echo "HEADER $subnet $unique_count $total_failures $pressure_scaled" > "$sidecar"
				# per-IP rows sorted by weighted sum descending, capped at TOP_N
				local _top_n="${SUBNET_ALERT_TOP_N:-5}"
				local _ip_count=0 _overflow=0
				while IFS=' ' read -r _d_sn _d_mod _d_ip _d_fc _d_ws; do
					_ip_count=$((_ip_count + 1))
					if [ "$_ip_count" -le "$_top_n" ]; then
						echo "$_d_ip $_d_mod $_d_fc $((_d_ws * 1000))" >> "$sidecar"
					fi
				done < <(awk -v sn="$subnet" '$1 == sn { print }' "$detail_file" | sort -k5 -rn)
				_overflow=$((_ip_count - _top_n))
				if [ "$_overflow" -gt 0 ]; then
					echo "OVERFLOW $_overflow" >> "$sidecar"
				fi

				echo "${subnet}|${mod}|all|${pressure_scaled}|${ban_expiry}|${ban_action}|${recent_bans}|(multiple)|${EMAIL_ADDRESS}|${SUBNET_TRIG}|${window}|1|${total_failures}" >> "$alerts_file"
			fi

			local _dist_cc
			_dist_cc=$(_resolve_cidr_cc "$subnet" "--")
			state_pool_append "$install_path" "$now" "$subnet" "$mod" \
				"$unique_count" "$_dist_cc" "$ban_action" "$_dist_duration" "all" \
				"0" "subnet"
		fi
	done < <(count_subnet_attackers "$install_path" "$window" "$now" \
		"$SUBNET_MASK" "$SUBNET_MASK_V6" "$SUBNET_TRIG" "$detail_file")

	command rm -f "$detail_file"
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

	if _bfd_dispatch_messaging "$alerts_file" "$subject" "${EMAIL_LOGLINES:-5}" "$tpl_dir"; then
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

# list_bans_json install_path — JSON formatted active ban list
list_bans_json() {
	local install_path="$1"
	local raw
	if ! raw=$(_list_bans_data "$install_path"); then
		echo "[]"
		return 0
	fi
	echo "["
	local first=1
	local ts expiry host mod ports
	local _ts_numeric='^[0-9]+$'
	while IFS='|' read -r ts expiry host mod ports; do
		[[ "$ts" =~ $_ts_numeric ]] || continue
		[ -n "$host" ] || continue
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
		local _ts_numeric='^[0-9]+$'
		while IFS='|' read -r ts expiry host mod ports; do
			[[ "$ts" =~ $_ts_numeric ]] || continue
			[ -n "$host" ] || continue
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

# _events_rule_patterns rule — extract detection patterns from a rule file
# Sources the rule in a subshell with a custom extract_hosts() that prints the
# pattern arguments (one per line) instead of processing log data.
# Returns 1 if the rule file does not exist or no patterns are found.
_events_rule_patterns() {
	local rule="$1"
	local rule_file="${RULES_PATH:-}/rules/$rule"
	if [ ! -f "$rule_file" ]; then
		rule_file="${RULES_PATH:-}/$rule"
	fi
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
