#!/bin/bash
#
# Brute Force Detection 2.0.2 - Event Queries and Attack Pool
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
# Sourced by bfd.lib.sh. Provides event list/search/CIDR queries, attack pool
# aggregation and reporting (text/JSON/CSV), and batch ban status optimization.

# Source guard — prevent double-sourcing
[[ -n "${_BFD_EVENTS_LOADED:-}" ]] && return 0 2>/dev/null
_BFD_EVENTS_LOADED=1

# shellcheck disable=SC2034
BFD_EVENTS_VERSION="1.0.0"

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

	ip=$(_require_valid_ip "$ip" "$2") || return 1

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

	# Ban history (bans.history + rotated archives) — single AWK pass
	local hist_24h=0 hist_total=0
	local cutoff_24h=$((now - 86400))
	local _hist_files=()
	local _hf
	for _hf in "$install_path/tmp"/bans.history*; do
		[ -f "$_hf" ] && [ -s "$_hf" ] && _hist_files+=("$_hf")
	done
	if [ ${#_hist_files[@]} -gt 0 ]; then
		local hist_raw
		hist_raw=$(awk -v ip="$ip" -v cutoff="$cutoff_24h" '
			$3 == ip && ($5 == "ban" || $5 == "escalate") {
				total++
				if ($1+0 >= cutoff) recent++
			}
			END { print recent+0 "|" total+0 }' "${_hist_files[@]}")
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

	# CDN provider annotation (only when CDN active and cdn.dat exists)
	if [ "${_CDN_ACTIVE:-0}" = "1" ]; then
		local _cdn_db="$install_path/cdn.dat"
		if [ -f "$_cdn_db" ] && [ -s "$_cdn_db" ]; then
			local _cdn_result
			if _cdn_result=$(_cdn_lookup "$ip" "$_cdn_db"); then
				local _cdn_prov _cdn_treat _cdn_mult
				read -r _cdn_prov _cdn_treat _cdn_mult <<< "$_cdn_result"
				echo "  CDN provider:   $_cdn_prov (treatment: $_cdn_treat)"
			fi
		fi
	fi
}

# _resolve_log_source_label log_source has_journalctl
# Determines the display label for a rule's log source based on:
#   - LOG_FILE existence, LOG_TAG, journal filter registration
# Uses rule variables (LOG_FILE, LOG_TAG) from the caller's scope.
_resolve_log_source_label() {
	# shellcheck disable=SC2034 # log_source is a documented parameter for callers; function uses LOG_FILE/LOG_TAG from caller scope
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

	ip=$(_require_valid_ip "$ip" "$2") || return 1

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

	cidr=$(_require_valid_cidr "$cidr" "$2") || return 1
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

	ip=$(_require_valid_ip "$ip" "$2") || return 1

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

	ip=$(_require_valid_ip "$ip" "$2") || return 1

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

	cidr=$(_require_valid_cidr "$cidr" "$2") || return 1
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
	command cat "$_cidr_ips" 2>/dev/null
	echo ""
	echo "]}"
	command rm -f "$_cidr_summary" "$_cidr_ips"
}

# events_list_cidr_csv install_path cidr [sort_mode] [limit] — CSV CIDR event search
events_list_cidr_csv() {
	local install_path="$1" cidr="$2" sort_mode="${3:-count}" limit="${4:-100}"
	local pool_file="$install_path/stats/attack.pool"
	local cutoff="${_EVENTS_CUTOFF:-0}"

	cidr=$(_require_valid_cidr "$cidr" "$2") || return 1
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

# _apool_ban_status ip — return ban status string for an IP
_apool_ban_status() {
	local aip="$1"
	local bans_active="$INSTALL_PATH/tmp/bans.active"
	if awk -v ip="$aip" '$3 == ip {found=1; exit} END {exit !found}' "$bans_active" 2>/dev/null; then
		local ban_expiry
		ban_expiry=$(awk -v ip="$aip" '$3 == ip {print $2; exit}' "$bans_active")
		if [ "$ban_expiry" = "0" ]; then
			echo "BANNED(perm)"
		else
			local now remain
			now=$(date +"%s")
			remain=$(( (ban_expiry - now) / 60 ))
			if [ "$remain" -lt 0 ]; then
				remain=0
			fi
			echo "BANNED(${remain}m)"
		fi
	else
		local _hist_files=()
		local _hf
		for _hf in "$INSTALL_PATH/tmp"/bans.history*; do
			[ -f "$_hf" ] && [ -s "$_hf" ] && _hist_files+=("$_hf")
		done
		if [ ${#_hist_files[@]} -gt 0 ]; then
			local hist_count
			hist_count=$(awk -v ip="$aip" '$3 == ip && ($5 == "ban" || $5 == "escalate") {c++} END {print c+0}' \
				"${_hist_files[@]}")
			if [ "$hist_count" -gt 0 ]; then
				echo "prev:$hist_count"
			fi
		fi
	fi
}

# _batch_ban_status_init install_path — pre-compute ban status for all IPs into a lookup file.
# Creates _BAN_STATUS_FILE (caller must clean up) with lines: ip|status
# One awk pass over bans.active + one over bans.history (incl. rotated archives)
# instead of 2-3 awk spawns per IP. Use with _batch_ban_status_lookup in loops.
_batch_ban_status_init() {
	local install_path="$1"
	local bans_active="$install_path/tmp/bans.active"
	_BAN_STATUS_FILE=$(mktemp "$install_path/tmp/.banstat.XXXXXX")
	local now
	now=$(date +"%s")
	# Active bans: compute BANNED(perm) or BANNED(Nm) per IP
	if [ -f "$bans_active" ] && [ -s "$bans_active" ]; then
		awk -v now="$now" '{
			ip = $3; expiry = $2
			if (expiry == "0") {
				print ip "|BANNED(perm)"
			} else {
				remain = int((expiry - now) / 60)
				if (remain < 0) remain = 0
				print ip "|BANNED(" remain "m)"
			}
		}' "$bans_active" >> "$_BAN_STATUS_FILE"
	fi
	# History: count prior bans from current + rotated archives
	local _hist_files=()
	local _hf
	for _hf in "$install_path/tmp"/bans.history*; do
		[ -f "$_hf" ] && [ -s "$_hf" ] && _hist_files+=("$_hf")
	done
	if [ ${#_hist_files[@]} -gt 0 ]; then
		awk '($5 == "ban" || $5 == "escalate") { hist[$3]++ }
		END { for (ip in hist) print ip "|prev:" hist[ip] }' \
			"${_hist_files[@]}" >> "$_BAN_STATUS_FILE"
	fi
}

# _batch_ban_status_lookup ip — look up pre-computed ban status (requires _batch_ban_status_init)
# Returns the status string, preferring active ban over history.
_batch_ban_status_lookup() {
	local aip="$1"
	# File format: ip|status — use awk for exact field match (grep -F "${ip}|"
	# would substring-match 192.0.2.1 against 192.0.2.10). -m1 stops at first
	# match; active bans precede history so active takes priority.
	local line
	line=$(awk -F'|' -v ip="$aip" '$1 == ip { print; exit }' "$_BAN_STATUS_FILE" 2>/dev/null) || true  # 2>/dev/null: file may not exist if no bans; || true: no match is normal (IP has no ban state)
	echo "${line#*|}"
}

# _batch_ban_status_cleanup — remove the lookup file
_batch_ban_status_cleanup() {
	command rm -f "${_BAN_STATUS_FILE:-}"
}

# _apool_service_dual_awk source_file cutoff_24h cutoff_7d — dual-interval per-service AWK
# Outputs pipe-delimited: service|count_24h|count_7d|uniq_24h|uniq_7d|top_cc
# mawk-compatible: string-concatenated keys, no multi-dimensional arrays.
_apool_service_dual_awk() {
	local source_file="$1"
	local cutoff_24h="$2"
	local cutoff_7d="$3"
	awk -v c24="$cutoff_24h" -v c7d="$cutoff_7d" '{
		ts = $1 + 0
		if (ts < c7d) next
		svc = $3; ip = $2
		cnt = ($4+0 > 0) ? $4+0 : 1
		cc = ($5 != "" && $5 != "--") ? $5 : ""
		c7[svc] += cnt
		k7 = svc " " ip
		if (!(k7 in s7)) { s7[k7] = 1; u7[svc]++ }
		if (cc != "") {
			ck7 = svc " " cc
			ccf7[ck7]++
		}
		if (ts >= c24) {
			c24a[svc] += cnt
			k24 = svc " " ip
			if (!(k24 in s24)) { s24[k24] = 1; u24[svc]++ }
		}
	}
	END {
		for (svc in c7) {
			# find top country for this service (7d window)
			top_cc = "--"; top_n = 0
			for (ck in ccf7) {
				if (index(ck, svc " ") == 1) {
					cc_name = substr(ck, length(svc) + 2)
					if (ccf7[ck] > top_n) {
						top_n = ccf7[ck]
						top_cc = cc_name
					}
				}
			}
			print svc "|" c24a[svc]+0 "|" c7[svc]+0 "|" u24[svc]+0 "|" u7[svc]+0 "|" top_cc
		}
	}' "$source_file" | sort -t'|' -k3 -nr
}

# _apool_service_dual source_file cutoff_24h cutoff_7d — text per-service dual-interval breakdown
_apool_service_dual() {
	local source_file="$1"
	local cutoff_24h="$2"
	local cutoff_7d="$3"
	if [ ! -f "$source_file" ] || [ ! -s "$source_file" ]; then
		return 0
	fi
	local atmp
	atmp=$(mktemp "$INSTALL_PATH/tmp/.svcdual.XXXXXX")
	echo "[+] Per-service threat breakdown (24h / 7d)" && echo
	echo "SERVICE|24H_COUNT|7D_COUNT|24H_IPS|7D_IPS|TOP_COUNTRY" > "$atmp"
	_apool_service_dual_awk "$source_file" "$cutoff_24h" "$cutoff_7d" >> "$atmp"
	format_table < "$atmp"
	command rm -f "$atmp"
}

# _apool_service_dual_json source_file cutoff_24h cutoff_7d — JSON dual-interval services
_apool_service_dual_json() {
	local source_file="$1"
	local cutoff_24h="$2"
	local cutoff_7d="$3"
	echo "["
	if [ -f "$source_file" ] && [ -s "$source_file" ]; then
		local first=1
		_apool_service_dual_awk "$source_file" "$cutoff_24h" "$cutoff_7d" | \
		while IFS='|' read -r svc c24 c7d u24 u7d top_cc; do
			[ -z "$svc" ] && continue
			if [ "$first" -eq 1 ]; then
				first=0
			else
				echo ","
			fi
			printf '    {"service": "%s", "count_24h": %s, "count_7d": %s, "unique_ips_24h": %s, "unique_ips_7d": %s, "top_country": "%s"}' \
				"$(_json_escape "$svc")" "$c24" "$c7d" "$u24" "$u7d" "$(_json_escape "$top_cc")"
		done
	fi
	echo ""
	echo "  ]"
}

# _apool_service_dual_csv source_file cutoff_24h cutoff_7d — CSV dual-interval services
_apool_service_dual_csv() {
	local source_file="$1"
	local cutoff_24h="$2"
	local cutoff_7d="$3"
	echo "service,count_24h,count_7d,unique_ips_24h,unique_ips_7d,top_country"
	if [ -f "$source_file" ] && [ -s "$source_file" ]; then
		_apool_service_dual_awk "$source_file" "$cutoff_24h" "$cutoff_7d" | \
		while IFS='|' read -r svc c24 c7d u24 u7d top_cc; do
			[ -z "$svc" ] && continue
			echo "$svc,$c24,$c7d,$u24,$u7d,$top_cc"
		done
	fi
}

# _apool_summary_awk source_file cutoff_24h cutoff_7d — single-pass AWK for summary stats
# Outputs: uniq_24h|total_24h|uniq_7d|total_7d
_apool_summary_awk() {
	local source_file="$1"
	local cutoff_24h="$2"
	local cutoff_7d="$3"
	awk -v c24="$cutoff_24h" -v c7d="$cutoff_7d" '{
		ts = $1 + 0
		cnt = ($4+0 > 0) ? $4+0 : 1
		if (ts >= c7d) {
			t7 += cnt
			if (!s7[$2]++) u7++
			if (ts >= c24) {
				t24 += cnt
				if (!s24[$2]++) u24++
			}
		}
	}
	END {
		print u24+0 "|" t24+0 "|" u7+0 "|" t7+0
	}' "$source_file"
}

# _apool_summary source_file cutoff_24h cutoff_7d — text summary header
_apool_summary() {
	local source_file="$1"
	local cutoff_24h="$2"
	local cutoff_7d="$3"
	if [ ! -f "$source_file" ] || [ ! -s "$source_file" ]; then
		local active_bans=0
		local bans_active="$INSTALL_PATH/tmp/bans.active"
		if [ -f "$bans_active" ] && [ -s "$bans_active" ]; then
			active_bans=$(wc -l < "$bans_active")
		fi
		echo "[+] Threat Activity Summary" && echo
		echo "  Unique IPs:   0 (24h) / 0 (7d)"
		echo "  Total Count:  0 (24h) / 0 (7d)"
		printf "  Active Bans:  %s\n" "$active_bans"
		return 0
	fi
	local stats
	stats=$(_apool_summary_awk "$source_file" "$cutoff_24h" "$cutoff_7d")
	local u24 t24 u7d t7d
	IFS='|' read -r u24 t24 u7d t7d <<< "$stats"
	local active_bans=0
	local bans_active="$INSTALL_PATH/tmp/bans.active"
	if [ -f "$bans_active" ] && [ -s "$bans_active" ]; then
		active_bans=$(wc -l < "$bans_active")
	fi
	echo "[+] Threat Activity Summary" && echo
	printf "  Unique IPs:   %s (24h) / %s (7d)\n" "$u24" "$u7d"
	printf "  Total Count:  %s (24h) / %s (7d)\n" "$t24" "$t7d"
	printf "  Active Bans:  %s\n" "$active_bans"
}

# _apool_summary_json source_file cutoff_24h cutoff_7d — JSON summary object (no braces)
_apool_summary_json() {
	local source_file="$1"
	local cutoff_24h="$2"
	local cutoff_7d="$3"
	local u24=0 t24=0 u7d=0 t7d=0 active_bans=0
	if [ -f "$source_file" ] && [ -s "$source_file" ]; then
		local stats
		stats=$(_apool_summary_awk "$source_file" "$cutoff_24h" "$cutoff_7d")
		IFS='|' read -r u24 t24 u7d t7d <<< "$stats"
	fi
	local bans_active="$INSTALL_PATH/tmp/bans.active"
	if [ -f "$bans_active" ] && [ -s "$bans_active" ]; then
		active_bans=$(wc -l < "$bans_active")
	fi
	printf '{"unique_ips_24h": %s, "unique_ips_7d": %s, "total_count_24h": %s, "total_count_7d": %s, "active_bans": %s}' \
		"$u24" "$u7d" "$t24" "$t7d" "$active_bans"
}

# _apool_summary_csv source_file cutoff_24h cutoff_7d — CSV summary
_apool_summary_csv() {
	local source_file="$1"
	local cutoff_24h="$2"
	local cutoff_7d="$3"
	local u24=0 t24=0 u7d=0 t7d=0 active_bans=0
	if [ -f "$source_file" ] && [ -s "$source_file" ]; then
		local stats
		stats=$(_apool_summary_awk "$source_file" "$cutoff_24h" "$cutoff_7d")
		IFS='|' read -r u24 t24 u7d t7d <<< "$stats"
	fi
	local bans_active="$INSTALL_PATH/tmp/bans.active"
	if [ -f "$bans_active" ] && [ -s "$bans_active" ]; then
		active_bans=$(wc -l < "$bans_active")
	fi
	echo "unique_ips_24h,unique_ips_7d,total_count_24h,total_count_7d,active_bans"
	echo "$u24,$u7d,$t24,$t7d,$active_bans"
}

apool_list() {
	local ahost="${1:-}"
	local now cutoff_24h cutoff_7d
	now=$(date +"%s")
	cutoff_24h=$((now - 86400))
	cutoff_7d=$((now - 604800))
	if [ -n "$ahost" ]; then
		_apool_report "$APOOL_LIST" "Matching entries for \"$ahost\" (7d)" "$ahost" "$cutoff_7d"
	elif [ -f "$APOOL_LIST" ] && [ -s "$APOOL_LIST" ]; then
		_apool_summary "$APOOL_LIST" "$cutoff_24h" "$cutoff_7d"
		echo
		_apool_report "$APOOL_LIST" "Top 25 threat IPs (24h)" "" "$cutoff_24h"
		echo
		_apool_report "$APOOL_LIST" "Top 25 threat IPs (7d)" "" "$cutoff_7d"
		echo
		_apool_service_dual "$APOOL_LIST" "$cutoff_24h" "$cutoff_7d"
	else
		echo "No attack pool data."
	fi
}

# --- Structured output for attack pool ---

# _apool_awk source_file [search] [cutoff] [sort_mode] [limit] [cidr_addr] [cidr_mask]
# Shared aggregation pipeline for attack pool.
# Outputs pipe-delimited: cnt|ip|first_ts|last_ts|rules_csv|country_code
# cutoff: epoch timestamp — entries older than cutoff are skipped (0 = no filter)
# sort_mode: count (default), time (last_seen desc), ip (version sort asc)
# limit: max rows (default 25, 0 = unlimited)
# cidr_addr/cidr_mask: optional CIDR filter (IPv4 only, mask 8-32)
_apool_awk() {
	local source_file="$1"
	local search="${2:-}"
	local cutoff="${3:-0}"
	local sort_mode="${4:-count}"
	local limit="${5:-25}"
	local cidr_addr="${6:-}" cidr_mask="${7:-}"
	local cidr_mode=0
	[ -n "$cidr_addr" ] && [ -n "$cidr_mask" ] && cidr_mode=1
	{
		if [ -n "$search" ]; then
			grep -F "$search" "$source_file"
		else
			command cat "$source_file"
		fi | awk -v cutoff="$cutoff" -v cidr_mode="$cidr_mode" \
			-v taddr="$cidr_addr" -v tmask="$cidr_mask" '
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
			if (cidr_mode) target_net = ipv4_subnet(taddr, tmask)
		}
		{
			ts = $1 + 0
			if (cutoff > 0 && ts < cutoff) next
			ip = $2; rule = $3
			if (cidr_mode) {
				if (index(ip, ":") > 0) next
				if (ipv4_subnet(ip, tmask) != target_net) next
			}
			cnt = ($4+0 > 0) ? $4+0 : 1
			cc_val = ($5 != "" && $5 != "--") ? $5 : ""
			count[ip] += cnt
			if (cc_val != "" && cc[ip] == "") cc[ip] = cc_val
			if (!(ip in first) || ts < first[ip]) first[ip] = ts
			if (!(ip in last) || ts > last[ip]) last[ip] = ts
			if (rules[ip] == "") rules[ip] = rule
			else if (index("," rules[ip] ",", "," rule ",") == 0) rules[ip] = rules[ip] "," rule
		}
		END {
			for (ip in count)
				print count[ip] "|" ip "|" first[ip] "|" last[ip] "|" rules[ip] "|" cc[ip]
		}'
	} | {
		case "$sort_mode" in
			time) sort -t'|' -k4 -nr ;;
			ip)   sort -t'|' -k2 -V ;;
			*)    sort -t'|' -k1 -nr ;;
		esac
	} | if [ "$limit" -gt 0 ] 2>/dev/null; then head -n "$limit"; else command cat; fi  # suppress non-numeric $limit comparison error (defaults to unlimited)
}

_apool_report() {
	local source_file="$1"
	local title="$2"
	local search="${3:-}"
	local cutoff="${4:-0}"
	local atmp
	atmp=$(mktemp "$INSTALL_PATH/tmp/.alist.XXXXXX")
	echo "[+] $title" && echo
	echo "#COUNT|IP|PRESSURE|COUNTRY|FIRST_SEEN|LAST_SEEN|RULES|STATUS" > "$atmp"
	local now half_life trip
	now=$(date +"%s")
	half_life="${PRESSURE_HALF_LIFE:-300}"
	local cnt aip first_ts last_ts mods aip_cc first_fmt last_fmt ban_status _gp _gp_fmt
	_batch_ban_status_init "$INSTALL_PATH"
	while IFS='|' read -r cnt aip first_ts last_ts mods aip_cc; do
		[ -z "$cnt" ] && continue
		aip_cc=$(_resolve_cidr_cc "$aip" "$aip_cc")
		first_fmt=$(_fmt_ts "$first_ts")
		last_fmt=$(_fmt_ts "$last_ts")
		ban_status=$(_batch_ban_status_lookup "$aip")
		_gp=$(pressure_compute "$INSTALL_PATH" "$aip" "$half_life" "$now")
		_gp_fmt=$(pressure_format "$_gp")
		trip=$(_resolve_min_trip "$mods")
		echo "$cnt|$aip|${_gp_fmt}/${trip}|${aip_cc:---}|$first_fmt|$last_fmt|$mods|$ban_status" >> "$atmp"
	done < <(_apool_awk "$source_file" "$search" "$cutoff")
	_batch_ban_status_cleanup
	format_table < "$atmp"
	command rm -f "$atmp"
}

# _apool_report_json source_file [search] [cutoff] — JSON array of attack pool entries
_apool_report_json() {
	local source_file="$1"
	local search="${2:-}"
	local cutoff="${3:-0}"
	local now half_life trip
	now=$(date +"%s")
	half_life="${PRESSURE_HALF_LIFE:-300}"
	echo "["
	if [ -f "$source_file" ] && [ -s "$source_file" ]; then
		local first=1
		local cnt aip first_ts last_ts mods aip_cc
		_batch_ban_status_init "$INSTALL_PATH"
		_apool_awk "$source_file" "$search" "$cutoff" | \
		while IFS='|' read -r cnt aip first_ts last_ts mods aip_cc; do
			[ -z "$cnt" ] && continue
			aip_cc=$(_resolve_cidr_cc "$aip" "$aip_cc")
			local first_fmt last_fmt ban_status _gp _gp_fmt
			first_fmt=$(_fmt_ts_iso "$first_ts")
			last_fmt=$(_fmt_ts_iso "$last_ts")
			ban_status=$(_batch_ban_status_lookup "$aip")
			[ -z "$ban_status" ] && ban_status="not banned"
			_gp=$(pressure_compute "$INSTALL_PATH" "$aip" "$half_life" "$now")
			_gp_fmt=$(pressure_format "$_gp")
			trip=$(_resolve_min_trip "$mods")
			if [ "$first" -eq 1 ]; then
				first=0
			else
				echo ","
			fi
			printf '    {"count": %s, "ip": "%s", "pressure": %s, "pressure_trip": %s, "country": "%s", "first_seen": "%s", "last_seen": "%s", "rules": %s, "status": "%s"}' \
				"$cnt" "$(_json_escape "$aip")" "$_gp_fmt" "$trip" \
				"$(_json_escape "${aip_cc:---}")" "$first_fmt" "$last_fmt" \
				"$(_json_array_from_csv "$mods")" "$(_json_escape "$ban_status")"
		done
		_batch_ban_status_cleanup
	fi
	echo ""
	echo "  ]"
}

# _apool_report_csv source_file [search] [cutoff] — CSV formatted attack pool entries
_apool_report_csv() {
	local source_file="$1"
	local search="${2:-}"
	local cutoff="${3:-0}"
	local now half_life trip
	now=$(date +"%s")
	half_life="${PRESSURE_HALF_LIFE:-300}"
	echo "count,ip,pressure,pressure_trip,country,first_seen,last_seen,rules,status"
	if [ -f "$source_file" ] && [ -s "$source_file" ]; then
		local cnt aip first_ts last_ts mods aip_cc
		_batch_ban_status_init "$INSTALL_PATH"
		_apool_awk "$source_file" "$search" "$cutoff" | \
		while IFS='|' read -r cnt aip first_ts last_ts mods aip_cc; do
			[ -z "$cnt" ] && continue
			aip_cc=$(_resolve_cidr_cc "$aip" "$aip_cc")
			local first_fmt last_fmt ban_status _gp _gp_fmt
			first_fmt=$(_fmt_ts_iso "$first_ts")
			last_fmt=$(_fmt_ts_iso "$last_ts")
			ban_status=$(_batch_ban_status_lookup "$aip")
			[ -z "$ban_status" ] && ban_status="not banned"
			_gp=$(pressure_compute "$INSTALL_PATH" "$aip" "$half_life" "$now")
			_gp_fmt=$(pressure_format "$_gp")
			trip=$(_resolve_min_trip "$mods")
			echo "$cnt,$aip,$_gp_fmt,$trip,${aip_cc:---},$first_fmt,$last_fmt,$mods,$ban_status"
		done
		_batch_ban_status_cleanup
	fi
}

# apool_list_json [search] — JSON formatted attack pool report
apool_list_json() {
	local ahost="${1:-}"
	local now cutoff_24h cutoff_7d
	now=$(date +"%s")
	cutoff_24h=$((now - 86400))
	cutoff_7d=$((now - 604800))
	if [ -n "$ahost" ]; then
		printf '{"search": "%s", "results": ' "$(_json_escape "$ahost")"
		_apool_report_json "$APOOL_LIST" "$ahost" "$cutoff_7d"
		echo "}"
	elif [ -f "$APOOL_LIST" ] && [ -s "$APOOL_LIST" ]; then
		printf '{"summary": '
		_apool_summary_json "$APOOL_LIST" "$cutoff_24h" "$cutoff_7d"
		printf ', "last_24h": '
		_apool_report_json "$APOOL_LIST" "" "$cutoff_24h"
		printf ', "last_7d": '
		_apool_report_json "$APOOL_LIST" "" "$cutoff_7d"
		printf ', "services": '
		_apool_service_dual_json "$APOOL_LIST" "$cutoff_24h" "$cutoff_7d"
		echo "}"
	else
		echo "{}"
	fi
}

# apool_list_csv [search] — CSV formatted attack pool report
apool_list_csv() {
	local ahost="${1:-}"
	local now cutoff_24h cutoff_7d
	now=$(date +"%s")
	cutoff_24h=$((now - 86400))
	cutoff_7d=$((now - 604800))
	if [ -n "$ahost" ]; then
		echo "# search: $ahost"
		_apool_report_csv "$APOOL_LIST" "$ahost" "$cutoff_7d"
	elif [ -f "$APOOL_LIST" ] && [ -s "$APOOL_LIST" ]; then
		echo "# summary"
		_apool_summary_csv "$APOOL_LIST" "$cutoff_24h" "$cutoff_7d"
		echo ""
		echo "# last_24h"
		_apool_report_csv "$APOOL_LIST" "" "$cutoff_24h"
		echo ""
		echo "# last_7d"
		_apool_report_csv "$APOOL_LIST" "" "$cutoff_7d"
		echo ""
		echo "# services"
		_apool_service_dual_csv "$APOOL_LIST" "$cutoff_24h" "$cutoff_7d"
	fi
}
