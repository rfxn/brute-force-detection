#!/bin/bash
#
# Brute Force Detection 2.0.2 - Pressure Model and Rule Infrastructure
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
# Sourced by bfd.lib.sh. Provides the pressure scoring model, rule variable
# management, rule activation/validation, geolocation lookups, and batch
# optimization helpers.

# Source guard — prevent double-sourcing
[[ -n "${_BFD_PRESSURE_LOADED:-}" ]] && return 0 2>/dev/null
_BFD_PRESSURE_LOADED=1

# shellcheck disable=SC2034
BFD_PRESSURE_VERSION="1.0.0"

# --- Rule variable management ---

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

# --- Pressure config loading ---

# _load_pressure_conf conf_file — parse pressure.conf into associative arrays
# Populates _PRESS_WEIGHT[], _PRESS_TRIP[], _PRESS_SKIP_ALERT[], _PRESS_RULE_EMAIL[].
# Dual-format: per-line detection of old colon format and new whitespace format.
# Old format: rule:PRESSURE_WEIGHT=N:PRESSURE_TRIP=N[:SKIP_ALERT=N][:RULE_EMAIL=addr]
# New format: rule  weight=N  trip=N  [skip_alert=N]  [rule_email=addr]
# Skips comments, blank lines, and unknown keys. Validates file safety.
# Returns 0 even if file is missing (graceful degradation).
_load_pressure_conf() {
	local conf_file="${1:-}"
	_PRESS_WEIGHT=()
	_PRESS_TRIP=()
	_PRESS_SKIP_ALERT=()
	_PRESS_RULE_EMAIL=()

	[ -z "$conf_file" ] && return 0
	[ ! -f "$conf_file" ] && return 0

	if ! _check_file_safety "$conf_file"; then
		elog warn "pressure.conf has unsafe ownership (uid=$_CSAF_UID) or permissions ($_CSAF_PERMS), skipping"
		return 0
	fi

	local line rule_name _first fields pair key val _fields _pair _key _val
	while IFS= read -r line; do
		case "$line" in
			''|\#*) continue ;;
		esac
		_first="${line%%[[:space:]]*}"
		case "$_first" in
			*:*)
				# OLD FORMAT: colon-delimited rule:KEY=VAL:KEY=VAL
				rule_name="${line%%:*}"
				[ -z "$rule_name" ] && continue
				fields="${line#*:}"
				[ -z "$fields" ] && continue
				while [ -n "$fields" ]; do
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
						PRESSURE_TRIP)
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
				;;
			*)
				# NEW FORMAT: whitespace-delimited rule key=val [key=val ...]
				# shellcheck disable=SC2162
				read rule_name _fields <<< "$line"
				[ -z "$rule_name" ] && continue
				# shellcheck disable=SC2086  # intentional word splitting
				for _pair in $_fields; do
					_key="${_pair%%=*}"
					_val="${_pair#*=}"
					[ "$_key" = "$_pair" ] && continue  # no = sign, skip
					case "$_key" in
						weight)
							if [[ "$_val" =~ ^[0-9]+$ ]] && [ "$_val" -gt 0 ]; then
								_PRESS_WEIGHT["$rule_name"]="$_val"
							else
								elog warn "pressure.conf: $rule_name weight='$_val' invalid (must be positive integer), skipping"
							fi
							;;
						trip)
							if [[ "$_val" =~ ^[0-9]+$ ]] && [ "$_val" -gt 0 ]; then
								if [ "$_val" -gt 200 ]; then
									elog warn "pressure.conf: $rule_name trip=$_val exceeds maximum (200), clamping"
									_val=200
								fi
								_PRESS_TRIP["$rule_name"]="$_val"
							else
								elog warn "pressure.conf: $rule_name trip='$_val' invalid (must be positive integer), skipping"
							fi
							;;
						skip_alert)       _PRESS_SKIP_ALERT["$rule_name"]="$_val" ;;
						rule_email)
							if validate_email "$_val"; then
								_PRESS_RULE_EMAIL["$rule_name"]="$_val"
							else
								elog warn "pressure.conf: $rule_name rule_email='$_val' invalid, skipping"
							fi
							;;
					esac
				done
				;;
		esac
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

# --- Rule activation ---

# _rule_is_active — true when the rule's prerequisite binary/file exists
_rule_is_active() {
	[ -n "${PREREQ:-}" ] && [ -f "$PREREQ" ]
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
	if [[ "$ip" == */* ]] && [ -f "$DATA_PATH/ipcountry.dat" ]; then
		cc=$(ip_to_country "${ip%%/*}" "$DATA_PATH/ipcountry.dat" 2>/dev/null)  # 2>/dev/null: ipcountry.dat may not exist
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
	awk -v cc="$cc" '
	/^#/ || /^$/ { next }
	index($0,"=") { split($0,a,"="); if (a[1]==cc) { print a[2]; found=1; exit }; next }
	$1 == cc { print $2; found=1; exit }
	END { if (!found) print 10 }' "$weights_file"
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
	_tmpdir=$(mktemp -d "$INSTALL_PATH/tmp/bfd-batch.XXXXXX")
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
