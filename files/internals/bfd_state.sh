#!/bin/bash
#
# Brute Force Detection 2.0.2 - State I/O and Ban Execution
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
# Sourced by bfd.lib.sh. Provides state file operations (attack pool, active bans, ban history, pressure), ban execution/lifecycle, and ban management CLI operations.

# Source guard — prevent double-sourcing
[[ -n "${_BFD_STATE_LOADED:-}" ]] && return 0 2>/dev/null
_BFD_STATE_LOADED=1

# shellcheck disable=SC2034
BFD_STATE_VERSION="1.0.0"

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
		command mkdir -m 750 -p "$install_path/tmp"
	fi
	if [ ! -d "$install_path/stats" ]; then
		# shellcheck disable=SC2174  # parent always exists; -m applies to leaf
		command mkdir -m 750 -p "$install_path/stats"
	fi
	local f
	for f in "$install_path/tmp/pressure.dat" "$install_path/tmp/bans.active" \
		 "$install_path/tmp/bans.history"; do
		if [ ! -f "$f" ]; then
			command touch "$f"
			command chmod 600 "$f"
		fi
	done
	if [ ! -f "$install_path/stats/attack.pool" ]; then
		command touch "$install_path/stats/attack.pool"
		command chmod 600 "$install_path/stats/attack.pool"
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
		command chmod 600 "$bans_file"
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
		command chmod 600 "$events_file"
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
		command cat "$pool_file.new" > "$pool_file"   # preserves inode for flock
		command rm -f "$pool_file.new"
	) 200>>"$pool_file"
}

# execute_ban host mod dry_run [ports]
# execute or log ban command via firewall backend
# retries on failure with exponential backoff (BAN_RETRY_COUNT, default 2)
# returns 0 on success, ban command exit code on failure
execute_ban() {
	local host="$1" mod="$2" dry_run="$3" ports="${4:-all}"
	# set globals needed by alert templates and custom backend
	# shellcheck disable=SC2034  # consumed by eval'd BAN_COMMAND_TEMPLATE and alert templates
	ATTACK_HOST="$host"
	# shellcheck disable=SC2034  # consumed by alert templates cross-file
	MOD="$mod"
	# shellcheck disable=SC2034  # consumed by alert templates cross-file
	PORTS="$ports"
	if [ "$_FW_BACKEND" = "custom" ]; then
		# shellcheck disable=SC2034  # consumed by eval'd BAN_COMMAND_TEMPLATE
		BAN_COMMAND="$BAN_COMMAND_TEMPLATE"
		if [ -n "${BAN_COMMAND_V6_TEMPLATE:-}" ] && [[ "$host" == *:* ]]; then
			# shellcheck disable=SC2034  # consumed by eval'd BAN_COMMAND_V6_TEMPLATE
			BAN_COMMAND="$BAN_COMMAND_V6_TEMPLATE"
		fi
	else
		# shellcheck disable=SC2034  # diagnostic string for alert templates
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
	# shellcheck disable=SC2034  # consumed by eval'd UNBAN_COMMAND_TEMPLATE and alert templates
	ATTACK_HOST="$host"
	# shellcheck disable=SC2034  # consumed by alert templates cross-file
	MOD="$mod"
	# shellcheck disable=SC2034  # consumed by alert templates cross-file
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
		elog_event "block_escalated" "warn" "{$mod} $host escalated to permanent ban" \
			"ip=$host" "mod=$mod" "recent_bans=$recent_bans"
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

# manual_unban install_path ip utime — manually unban an IP via firewall backend
manual_unban() {
	local install_path="$1" ip="$2" utime="$3"
	ip=$(_require_valid_ip "$ip" "$2") || return 1
	state_init "$install_path"
	if ! state_bans_active_check "$install_path" "$ip"; then
		echo "error: $ip is not in the active ban list." >&2
		echo "hint: if the IP is blocked in the firewall but not tracked by BFD," >&2
		echo "      remove it directly with your firewall tool (iptables/nft/apf/csf)." >&2
		return 1
	fi
	local ban_mod ban_ports
	ban_mod=$(awk -v ip="$ip" '$3 == ip {print $4; exit}' "$install_path/tmp/bans.active")
	ban_ports=$(awk -v ip="$ip" '$3 == ip {print $5; exit}' "$install_path/tmp/bans.active")
	execute_unban "$ip" "${ban_mod:-unknown}" "${ban_ports:-all}"
	# CLI provenance event — execute_unban already emits block_removed with backend context
	elog_event "block_removed" "info" "{${ban_mod:-unknown}} manual unban $ip via CLI" \
		"ip=$ip" "mod=${ban_mod:-unknown}" "source=cli"
	state_bans_active_remove "$install_path" "$ip"
	state_bans_history_append "$install_path" "$utime" "0" "$ip" "${ban_mod:-unknown}" "unban"
	echo "$ip unbanned successfully."
}

# manual_ban install_path ip utime [mod] [ports] — manually ban an IP via firewall backend
manual_ban() {
	local install_path="$1" ip="$2" utime="$3"
	local mod="${4:-manual}"
	local ports="${5:-all}"
	ip=$(_require_valid_ip "$ip" "$2") || return 1
	mod=$(sanitize_mod "$mod") || { echo "error: invalid service name '$mod'." >&2; return 1; }
	state_init "$install_path"
	if state_bans_active_check "$install_path" "$ip"; then
		echo "error: $ip is already banned." >&2
		return 1
	fi
	execute_ban "$ip" "$mod" "0" "$ports"
	# CLI provenance event — execute_ban already emits block_added with backend context
	elog_event "block_added" "warn" "{$mod} manual ban $ip via CLI" \
		"ip=$ip" "mod=$mod" "source=cli" "ports=$ports"
	state_bans_active_append "$install_path" "$utime" "0" "$ip" "$mod" "$ports"
	state_bans_history_append "$install_path" "$utime" "0" "$ip" "$mod" "ban"
	echo "$ip banned permanently."
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
	entries=$(command cat "$bans_file")

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

	if [ "$count" -gt 0 ]; then
		elog_event "block_removed" "warn" "flush: $count bans removed (mode=$mode)" \
			"count=$count" "mode=$mode" "source=cli"
	fi
	echo "$count bans removed."
}
