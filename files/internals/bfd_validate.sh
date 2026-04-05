#!/bin/bash
#
# Brute Force Detection 2.0.2 - Input and Config Validation
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
# Sourced by bfd.lib.sh. Provides input validation, config validation, file safety checks, and log path detection.

# Source guard — prevent double-sourcing
[[ -n "${_BFD_VALIDATE_LOADED:-}" ]] && return 0 2>/dev/null
_BFD_VALIDATE_LOADED=1

# shellcheck disable=SC2034
BFD_VALIDATE_VERSION="1.0.0"

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

# _require_valid_ip ip raw_arg — validate IP or print error and return 1
# Outputs cleaned IP on stdout. Usage: ip=$(_require_valid_ip "$ip" "$2") || return 1
_require_valid_ip() {
	validate_ip_any "$1" || { echo "error: invalid IP address '$2'." >&2; return 1; }
}

# _require_valid_cidr cidr raw_arg — validate CIDR or print error and return 1
# Outputs cleaned CIDR on stdout. Usage: cidr=$(_require_valid_cidr "$cidr" "$2") || return 1
_require_valid_cidr() {
	validate_cidr "$1" || { echo "error: invalid CIDR notation '$2' (IPv4, mask 8-32)." >&2; return 1; }
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

# _check_file_safety file — validate root ownership and non-group/world-writable perms
# Returns 0 (safe) or 1 (unsafe). Sets _CSAF_UID and _CSAF_PERMS for caller
# error messages. Does NOT check file existence — caller must verify first.
_check_file_safety() {
	local file="$1"
	_CSAF_UID=$(stat -L -c '%u' "$file")
	_CSAF_PERMS=$(stat -L -c '%04a' "$file")
	local group_digit="${_CSAF_PERMS:2:1}"
	local world_digit="${_CSAF_PERMS:3:1}"
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
	# periodic report config
	case "${REPORT_ENABLED:-0}" in
		0|1) ;;
		*) echo "error: REPORT_ENABLED must be 0 or 1 (got '${REPORT_ENABLED}')." >&2
		   return "$EXIT_CONFIG_ERROR" ;;
	esac
	if [ -n "${REPORT_TOP_N:-}" ] && ! [ "${REPORT_TOP_N}" -gt 0 ] 2>/dev/null; then  # integer > 0 check
		echo "error: REPORT_TOP_N must be a positive integer (got '${REPORT_TOP_N}')." >&2
		return "$EXIT_CONFIG_ERROR"
	fi
	# REPORT_CHANNELS: comma-separated list from known set
	if [ -n "${REPORT_CHANNELS:-}" ]; then
		local _rc _rc_ifs_save="$IFS" _rc_valid=1
		IFS=','
		for _rc in $REPORT_CHANNELS; do
			IFS="$_rc_ifs_save"
			_rc="${_rc## }"; _rc="${_rc%% }"
			[ -z "$_rc" ] && continue
			case "$_rc" in
				email|slack|telegram|discord) ;;
				*) echo "error: REPORT_CHANNELS contains unknown channel '$_rc' (must be email, slack, telegram, or discord)." >&2
				   _rc_valid=0 ;;
			esac
		done
		IFS="$_rc_ifs_save"
		[ "$_rc_valid" -eq 0 ] && return "$EXIT_CONFIG_ERROR"
	fi
	# CDN config
	case "${CDN_ENABLE:-0}" in
		0|1) ;;
		*) echo "error: CDN_ENABLE must be 0 or 1 (got '${CDN_ENABLE}')." >&2
		   return "$EXIT_CONFIG_ERROR" ;;
	esac
	if [ -n "${CDN_UPDATE_DAYS:-}" ]; then
		if ! [[ "${CDN_UPDATE_DAYS}" =~ $int_pattern ]]; then
			echo "error: CDN_UPDATE_DAYS must be a non-negative integer (got '${CDN_UPDATE_DAYS}')." >&2
			return "$EXIT_CONFIG_ERROR"
		fi
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
			# shellcheck disable=SC2034  # consumed by caller (config_init)
			OUTPUT_SYSLOG_FILE="$KERNEL_LOG_PATH"
		fi
	fi
	if [ ! -f "$MAIL_LOG_PATH" ]; then
		if [ -f "/var/log/mail.log" ]; then
			MAIL_LOG_PATH="/var/log/mail.log"
		fi
	fi
}

# --- Ignore list management functions ---

# ignore_add install_path entry [comment] — add IP/CIDR to ignore.hosts
# Validates entry, normalizes CIDR to network address, checks duplicates, appends with flock.
# Returns: 0=added, 1=invalid input, 2=duplicate
ignore_add() {
	local install_path="$1" entry="$2" comment="${3:-}"
	local ignore_file="$install_path/ignore.hosts"

	# Validate: try IP first, then CIDR
	local validated
	if validated=$(validate_ip_any "$entry" 2>/dev/null); then
		entry="$validated"
	elif validated=$(validate_cidr "$entry" 2>/dev/null); then
		# Normalize CIDR to network address
		local _addr="${validated%/*}" _mask="${validated#*/}"
		entry=$(ip_to_subnet "$_addr" "$_mask")
	else
		echo "error: invalid IP or CIDR '$entry'." >&2
		return 1
	fi

	# Ensure file exists
	[ -f "$ignore_file" ] || command touch "$ignore_file"

	(
		flock -x 200
		# Check for duplicate (strip inline comments for comparison)
		if awk -v entry="$entry" '
			{ line=$0; sub(/#.*/, "", line); gsub(/^[[:space:]]+|[[:space:]]+$/, "", line) }
			line == entry { found=1; exit }
			END { exit !found }
		' "$ignore_file" 2>/dev/null; then
			echo "$entry: already in ignore list" >&2
			exit 2
		fi
		# Append
		if [ -n "$comment" ]; then
			printf '%s  # %s\n' "$entry" "$comment" >> "$ignore_file"
		else
			printf '%s\n' "$entry" >> "$ignore_file"
		fi
	) 200>>"$ignore_file"
	local rc=$?
	[ "$rc" -ne 0 ] && return "$rc"
	echo "$entry: added to ignore list"
	return 0
}

# ignore_remove install_path entry — remove IP/CIDR from ignore.hosts
# Returns: 0=removed, 1=not found
ignore_remove() {
	local install_path="$1" entry="$2"
	local ignore_file="$install_path/ignore.hosts"

	if [ ! -f "$ignore_file" ]; then
		echo "$entry: not in ignore list" >&2
		return 1
	fi

	(
		flock -x 200
		# Check entry exists (strip inline comments for matching)
		if ! awk -v entry="$entry" '
			{ line=$0; sub(/#.*/, "", line); gsub(/^[[:space:]]+|[[:space:]]+$/, "", line) }
			line == entry { found=1; exit }
			END { exit !found }
		' "$ignore_file" 2>/dev/null; then
			echo "$entry: not in ignore list" >&2
			exit 1
		fi
		# Remove: exclude lines where stripped entry matches
		awk -v entry="$entry" '
			{ line=$0; sub(/#.*/, "", line); gsub(/^[[:space:]]+|[[:space:]]+$/, "", line) }
			line != entry
		' "$ignore_file" > "$ignore_file.new"
		command mv "$ignore_file.new" "$ignore_file"
		command chmod 600 "$ignore_file"
	) 200>>"$ignore_file"
	local rc=$?
	[ "$rc" -ne 0 ] && return "$rc"
	echo "$entry: removed from ignore list"
	return 0
}

# ignore_list install_path — display ignore.hosts entries (skip comments and blanks)
ignore_list() {
	local install_path="$1"
	local ignore_file="$install_path/ignore.hosts"

	if [ ! -f "$ignore_file" ] || [ ! -s "$ignore_file" ]; then
		echo "no entries" >&2
		return 0
	fi

	# Print non-blank, non-comment-only lines (preserves inline comments)
	awk '!/^[[:space:]]*$/ && !/^[[:space:]]*#/' "$ignore_file"
}

# ignore_check install_path ip — check if IP is ignored (exact match + CIDR containment)
# Returns: 0 + message if ignored, 1 (silent) if not ignored
ignore_check() {
	local install_path="$1" query_ip="$2"
	local ignore_file="$install_path/ignore.hosts"

	query_ip=$(validate_ip_any "$query_ip") || {
		echo "error: invalid IP address '$2'." >&2
		return 1
	}

	if [ ! -f "$ignore_file" ]; then
		return 1
	fi

	local entry stripped
	while IFS= read -r entry; do
		# Skip comment-only lines
		[[ "$entry" =~ ^[[:space:]]*# ]] && continue
		# Strip inline comments and whitespace
		stripped="${entry%%#*}"
		stripped=$(printf '%s' "$stripped" | awk '{gsub(/^[[:space:]]+|[[:space:]]+$/, ""); print}')
		[ -z "$stripped" ] && continue

		if [[ "$stripped" == */* ]]; then
			# CIDR entry — compute network address of query IP with this mask
			local _mask="${stripped#*/}"
			local computed
			computed=$(ip_to_subnet "$query_ip" "$_mask" 2>/dev/null) || continue
			if [ "$computed" = "$stripped" ]; then
				echo "$query_ip: ignored (matched $stripped)"
				return 0
			fi
		else
			# Exact IP match
			if [ "$stripped" = "$query_ip" ]; then
				echo "$query_ip: ignored"
				return 0
			fi
		fi
	done < "$ignore_file"

	return 1
}
