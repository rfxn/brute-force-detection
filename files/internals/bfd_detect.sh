#!/bin/bash
#
# Brute Force Detection 2.0.2 - Detection Pipeline
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
# Sourced by bfd.lib.sh. Provides IP extraction from log lines,
# ignore-list filtering, tlog wrapper for incremental log reading,
# and subnet/CIDR attack detection.

# Source guard — prevent double-sourcing
[[ -n "${_BFD_DETECT_LOADED:-}" ]] && return 0 2>/dev/null
_BFD_DETECT_LOADED=1

# shellcheck disable=SC2034
BFD_DETECT_VERSION="1.0.0"

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
	_tlog_file=$(mktemp "$INSTALL_PATH/tmp/.bfd_extract.XXXXXX")
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
			_tlog_filtered=$(mktemp "$INSTALL_PATH/tmp/.bfd_extract.XXXXXX")
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
		elog_event "threat_detected" "warn" "{$mod} distributed attack from $subnet" \
			"subnet=$subnet" "mod=$mod" "unique_ips=$unique_count" "trip_type=subnet"
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
