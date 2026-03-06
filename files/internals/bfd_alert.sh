#!/bin/bash
#
# Brute Force Detection 2.0.1 - BFD Alert Functions
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
# This file is sourced by bfd.lib.sh after the shared alert_lib.sh.
# It provides BFD-specific alert functions: content helpers, data preparation,
# rendering pipeline, and wrappers for the shared library's digest/delivery API.

# Source guard — prevent double-sourcing
[[ -n "${_BFD_ALERT_LOADED:-}" ]] && return 0 2>/dev/null
_BFD_ALERT_LOADED=1

# shellcheck disable=SC2034  # version checked by health_check and show_config
BFD_ALERT_VERSION="1.0.0"

# ---------------------------------------------------------------------------
# IP Reputation Link Registry
# ---------------------------------------------------------------------------
# Parallel indexed arrays (bash 4.1 compatible — no declare -A).
# Used by _alert_build_reputation_links() to generate text and HTML links.

_REPLINK_KEYS=("abuseipdb" "shodan" "virustotal" "ipinfo" "greynoise")
_REPLINK_LABELS=("AbuseIPDB" "Shodan" "VirusTotal" "IPinfo" "GreyNoise")
_REPLINK_URLS=(
	"https://www.abuseipdb.com/check/"
	"https://www.shodan.io/host/"
	"https://www.virustotal.com/gui/ip-address/"
	"https://ipinfo.io/"
	"https://viz.greynoise.io/ip/"
)

# ---------------------------------------------------------------------------
# Unicode Regional Indicator Symbol Letter UTF-8 byte sequences (A-Z)
# Used by _alert_country_flag() to render flag emoji from 2-letter CC.
# U+1F1E6 (A) = F0 9F 87 A6 through U+1F1FF (Z) = F0 9F 87 BF
# ---------------------------------------------------------------------------
_RI_BYTES=(
	$'\xf0\x9f\x87\xa6' $'\xf0\x9f\x87\xa7' $'\xf0\x9f\x87\xa8'
	$'\xf0\x9f\x87\xa9' $'\xf0\x9f\x87\xaa' $'\xf0\x9f\x87\xab'
	$'\xf0\x9f\x87\xac' $'\xf0\x9f\x87\xad' $'\xf0\x9f\x87\xae'
	$'\xf0\x9f\x87\xaf' $'\xf0\x9f\x87\xb0' $'\xf0\x9f\x87\xb1'
	$'\xf0\x9f\x87\xb2' $'\xf0\x9f\x87\xb3' $'\xf0\x9f\x87\xb4'
	$'\xf0\x9f\x87\xb5' $'\xf0\x9f\x87\xb6' $'\xf0\x9f\x87\xb7'
	$'\xf0\x9f\x87\xb8' $'\xf0\x9f\x87\xb9' $'\xf0\x9f\x87\xba'
	$'\xf0\x9f\x87\xbb' $'\xf0\x9f\x87\xbc' $'\xf0\x9f\x87\xbd'
	$'\xf0\x9f\x87\xbe' $'\xf0\x9f\x87\xbf'
)

# ---------------------------------------------------------------------------
# Content Helpers
# ---------------------------------------------------------------------------

# _alert_sanitize_logs log_file host loglines [patterns] — extract and redact log lines
# Extracts up to $loglines lines matching $host from $log_file, redacts
# passwords and authorization headers. Output goes to stdout.
# If $patterns (newline-delimited detection patterns with <HOST> placeholders)
# is provided, filters by rule patterns instead of blanket IP grep.
# Returns 1 if log_file missing or empty match.
_alert_sanitize_logs() {
	local log_file="$1" host="$2" loglines="${3:-5}" patterns="${4:-}"
	if [ -z "$log_file" ] || [ ! -f "$log_file" ]; then
		return 1
	fi
	local lines
	if [ -n "$patterns" ]; then
		# escape IP dots for grep -E (IPv4); colons (IPv6) are safe
		local escaped_ip
		escaped_ip=$(echo "$host" | sed 's/[.]/\\./g')
		# replace <HOST> in each pattern with the escaped IP, join with |
		local filter="" _pat
		while IFS= read -r _pat; do
			[ -z "$_pat" ] && continue
			_pat="${_pat//<HOST>/$escaped_ip}"
			filter="${filter:+$filter|}$_pat"
		done <<< "$patterns"
		if [ -n "$filter" ]; then
			lines=$(tail -n 5000 "$log_file" | grep -E "$filter" | tail -n "$loglines" | \
				sed -e 's/\([Pp]ass[a-z]*\)[=:][[:space:]]*[^ ]*/\1=<REDACTED>/g' \
				    -e 's/\([Aa]uthorization:[[:space:]]*\).*/\1<REDACTED>/')
		else
			# patterns were all empty — fall back to IP grep
			lines=$(tail -n 5000 "$log_file" | grep -Fw "$host" | tail -n "$loglines" | \
				sed -e 's/\([Pp]ass[a-z]*\)[=:][[:space:]]*[^ ]*/\1=<REDACTED>/g' \
				    -e 's/\([Aa]uthorization:[[:space:]]*\).*/\1<REDACTED>/')
		fi
	else
		lines=$(tail -n 5000 "$log_file" | grep -Fw "$host" | tail -n "$loglines" | \
			sed -e 's/\([Pp]ass[a-z]*\)[=:][[:space:]]*[^ ]*/\1=<REDACTED>/g' \
			    -e 's/\([Aa]uthorization:[[:space:]]*\).*/\1<REDACTED>/')
	fi
	if [ -z "$lines" ]; then
		return 1
	fi
	echo "$lines"
}

# _alert_country_flag cc — convert 2-letter country code to Unicode flag emoji
# Uses pre-computed Regional Indicator Symbol byte sequences from _RI_BYTES[].
# Returns empty string for invalid or empty input.
# Output goes to stdout.
_alert_country_flag() {
	local cc
	cc=$(echo "$1" | tr '[:lower:]' '[:upper:]')
	if [ ${#cc} -ne 2 ]; then
		echo ""
		return 0
	fi
	# convert each letter to index (A=0, B=1, ... Z=25)
	local i1 i2
	i1=$(( $(printf '%d' "'${cc:0:1}") - 65 ))
	i2=$(( $(printf '%d' "'${cc:1:1}") - 65 ))
	if [ "$i1" -lt 0 ] || [ "$i1" -gt 25 ] || [ "$i2" -lt 0 ] || [ "$i2" -gt 25 ]; then
		echo ""
		return 0
	fi
	echo "${_RI_BYTES[$i1]}${_RI_BYTES[$i2]}"
}

# _alert_build_reputation_links ip config_value — build text and HTML reputation links
# Reads $config_value (comma-separated keys like "abuseipdb,ipinfo") and builds
# link strings for the matching services. Sets two exported variables:
#   REPUTATION_LINKS_TEXT — newline-separated "    Label: URL" lines
#   REPUTATION_LINKS_HTML — HTML anchor tags separated by middot
# Returns 1 if no valid keys found.
_alert_build_reputation_links() {
	local ip="$1" config_value="$2"
	REPUTATION_LINKS_TEXT=""
	REPUTATION_LINKS_HTML=""
	export REPUTATION_LINKS_TEXT REPUTATION_LINKS_HTML

	if [ -z "$ip" ] || [ -z "$config_value" ]; then
		return 1
	fi

	local text_lines="" html_parts="" found=0
	# split config_value on comma
	local IFS=','
	# shellcheck disable=SC2086  # intentional word-splitting on comma-separated keys
	set -- $config_value
	unset IFS

	local requested_key
	for requested_key in "$@"; do
		# trim whitespace
		requested_key=$(echo "$requested_key" | tr -d '[:space:]')
		[ -z "$requested_key" ] && continue
		# look up in registry
		local i
		for i in "${!_REPLINK_KEYS[@]}"; do
			if [ "${_REPLINK_KEYS[$i]}" = "$requested_key" ]; then
				local label="${_REPLINK_LABELS[$i]}"
				local url="${_REPLINK_URLS[$i]}${ip}"
				if [ "$found" -gt 0 ]; then
					text_lines="${text_lines}
"
					html_parts="${html_parts} &middot; "
				fi
				text_lines="${text_lines}    ${label}: ${url}"
				local _link
				# shellcheck disable=SC2089  # literal quotes are intentional HTML output
				printf -v _link '<a href="%s" style="color:#0891b2;text-decoration:none;">%s</a>' "$url" "$label"
				html_parts="${html_parts}${_link}"
				found=$((found + 1))
				break
			fi
		done
	done

	if [ "$found" -eq 0 ]; then
		return 1
	fi

	REPUTATION_LINKS_TEXT="$text_lines"
	REPUTATION_LINKS_HTML="$html_parts"
	# shellcheck disable=SC2090  # variable contains HTML with literal quotes, not shell quoting
	export REPUTATION_LINKS_TEXT REPUTATION_LINKS_HTML
	return 0
}

# _alert_pressure_bar pct — build ASCII pressure bar from percentage
# Bar is 20 chars wide. Fill proportional to pct, capped at 20 for display
# but shows actual percentage value. Output: "[====        ] 85%"
_alert_pressure_bar() {
	local pct="${1:-0}"
	local filled
	if [ "$pct" -gt 100 ]; then
		filled=20
	else
		filled=$(( pct * 20 / 100 ))
	fi
	local bar="" i
	for (( i = 0; i < 20; i++ )); do
		if [ "$i" -lt "$filled" ]; then
			bar="${bar}="
		else
			bar="${bar} "
		fi
	done
	echo "[${bar}] ${pct}%"
}

# _alert_pressure_color pct — return HTML hex color for pressure percentage
# 0-69%: green (#16a34a), 70-99%: amber (#d97706), 100%+: red (#dc2626)
_alert_pressure_color() {
	local pct="${1:-0}"
	if [ "$pct" -ge 100 ]; then
		echo "#dc2626"
	elif [ "$pct" -ge 70 ]; then
		echo "#d97706"
	else
		echo "#16a34a"
	fi
}

# _alert_ban_type_color action expiry — return HTML hex color for ban severity
# escalated: amber (#d97706), permanent: red (#dc2626), temporary: teal (#0891b2)
_alert_ban_type_color() {
	local action="$1" expiry="$2"
	if [ "$action" = "escalate" ]; then
		echo "#d97706"
	elif [ "$expiry" = "0" ]; then
		echo "#dc2626"
	else
		echo "#0891b2"
	fi
}

# ---------------------------------------------------------------------------
# Data Preparation
# ---------------------------------------------------------------------------

# _alert_set_global_vars alert_count — export global template variables
# Sets: HOSTNAME, TIMESTAMP, TIMESTAMP_ISO, TIME_ZONE, ALERT_COUNT, BFD_VERSION
# Must be called once before rendering begins.
_alert_set_global_vars() {
	local alert_count="${1:-0}"
	# HOSTNAME is typically already set by the shell; export to ensure ENVIRON visibility
	export HOSTNAME="${HOSTNAME:-$(hostname)}"
	export TIMESTAMP
	TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
	export TIMESTAMP_ISO
	TIMESTAMP_ISO=$(date +"%Y-%m-%dT%H:%M:%S%z")
	# TIME_ZONE set by internals.conf; fallback to date
	export TIME_ZONE="${TIME_ZONE:-$(date +"%z")}"
	export ALERT_COUNT="$alert_count"
	# V is the version variable set in files/bfd; fall back to ALERT_LIB_VERSION
	export BFD_VERSION="${V:-${BFD_VERSION:-$ALERT_LIB_VERSION}}"
}

# _alert_set_entry_vars pipe_line entry_num entry_total — parse alert line, export entry variables
# Input: pipe-delimited line with 12 fields:
#   host|mod|ports|pressure_scaled|expiry|action|recent|log_path|recipient|trip|half_life|weight
# Sets all per-entry template variables into exported environment for _alert_tpl_render.
# Requires: format_duration(), pressure_format(), ip_to_country(), expand_command_template(),
#   _alert_build_reputation_links(), _alert_pressure_bar(), _alert_pressure_color(),
#   _alert_ban_type_color(), _alert_country_flag(), _alert_html_escape(), _alert_sanitize_logs()
#   (all from bfd.lib.sh, alert_lib.sh, or bfd_alert.sh)
_alert_set_entry_vars() {
	local pipe_line="$1" entry_num="$2" entry_total="$3"
	local loglines="${4:-5}"

	# parse pipe-delimited fields
	local host mod ports pressure_scaled expiry action recent lp recipient trip half_life weight
	IFS='|' read -r host mod ports pressure_scaled expiry action recent lp recipient trip half_life weight <<< "$pipe_line"

	export ENTRY_NUM="$entry_num"
	export ENTRY_TOTAL="$entry_total"
	export HOST="$host"

	# host version: IPv6 contains ':'
	if [[ "$host" == *:* ]]; then
		export HOST_VERSION="IPv6"
	else
		export HOST_VERSION="IPv4"
	fi

	export SERVICE="$mod"

	# port display
	if [ "$ports" = "all" ]; then
		export PORTS="all ports"
	else
		export PORTS="port $ports"
	fi

	# pressure formatting (pressure_scaled is in thousandths, e.g. 18400 = 18.4)
	local p_fmt t_fmt
	p_fmt=$(pressure_format "$pressure_scaled")
	t_fmt=$(pressure_format $((trip * 1000)))
	export PRESSURE="$p_fmt"
	export PRESSURE_TRIP="$t_fmt"

	# percentage of trip
	local pct=0
	if [ "$trip" -gt 0 ]; then
		pct=$(( (pressure_scaled * 100) / (trip * 1000) ))
	fi
	export PRESSURE_PCT="$pct"
	local pct_clamped="$pct"
	if [ "$pct_clamped" -gt 100 ]; then
		pct_clamped=100
	fi
	export PRESSURE_PCT_CLAMPED="$pct_clamped"

	# pressure bar and colors
	export PRESSURE_BAR
	PRESSURE_BAR=$(_alert_pressure_bar "$pct")
	export PRESSURE_COLOR
	PRESSURE_COLOR=$(_alert_pressure_color "$pct")

	export WEIGHT="${weight:-1}"

	# half-life: format seconds to human-readable
	export HALF_LIFE_FMT
	HALF_LIFE_FMT=$(format_duration "${half_life:-300}")

	# ban type
	local ban_type ban_duration_detail=""
	if [ "$action" = "escalate" ]; then
		ban_type="Permanent (escalated)"
	elif [ "$expiry" = "0" ]; then
		ban_type="Permanent"
	else
		local duration=$(( expiry - $(date +"%s") ))
		if [ "$duration" -lt 0 ]; then
			duration=0
		fi
		ban_type="Temporary"
		local dur_fmt
		dur_fmt=$(format_duration "$duration")
		local exp_str
		exp_str=$(date -d "@${expiry}" +"%Y-%m-%d %H:%M:%S %Z" 2>/dev/null || echo "$expiry")
		ban_duration_detail=" ($dur_fmt), expires $exp_str"
	fi
	export BAN_TYPE="$ban_type"
	export BAN_DURATION_DETAIL="$ban_duration_detail"
	export BAN_TYPE_COLOR
	BAN_TYPE_COLOR=$(_alert_ban_type_color "$action" "$expiry")

	# history and escalation lines (pre-computed with label or empty)
	local esc_after="${BAN_ESCALATE_AFTER:-${BAN_PERMANENT_AFTER:-0}}"
	local esc_window="${BAN_ESCALATE_WINDOW:-${BAN_PERMANENT_WINDOW:-86400}}"
	if [ "${esc_after:-0}" -gt 0 ] && [ "${recent:-0}" -gt 0 ]; then
		local _esc_dur
		_esc_dur=$(format_duration "$esc_window")
		HISTORY_LINE="  History:     $recent previous ban(s) in $_esc_dur (permanent at $esc_after)"
		export HISTORY_LINE
		HISTORY_ROW_HTML=$(printf '<tr>\n<td style="padding:4px 16px;color:#71717a;vertical-align:top;">History</td>\n<td style="padding:4px 16px;color:#09090b;">%s previous ban(s) in %s (permanent at %s)</td>\n</tr>' \
			"$recent" "$_esc_dur" "$esc_after")
		export HISTORY_ROW_HTML
	else
		export HISTORY_LINE=""
		export HISTORY_ROW_HTML=""
	fi

	if [ "$action" = "escalate" ]; then
		export ESCALATION_LINE="  Escalation:  permanent after $esc_after offenses"
		export ESCALATION_ROW_HTML
		ESCALATION_ROW_HTML=$(printf '<tr>\n<td style="padding:4px 16px;color:#71717a;vertical-align:top;">Escalation</td>\n<td style="padding:4px 16px;color:#dc2626;font-weight:bold;">Permanent after %s offenses</td>\n</tr>' \
			"$esc_after")
	elif [ "${BAN_ESCALATION:-none}" != "none" ] && [ "${recent:-0}" -gt 0 ]; then
		export ESCALATION_LINE="  Escalation:  ${BAN_ESCALATION}, step $((recent + 1))"
		export ESCALATION_ROW_HTML
		ESCALATION_ROW_HTML=$(printf '<tr>\n<td style="padding:4px 16px;color:#71717a;vertical-align:top;">Escalation</td>\n<td style="padding:4px 16px;color:#09090b;">%s, step %s</td>\n</tr>' \
			"${BAN_ESCALATION}" "$((recent + 1))")
	else
		export ESCALATION_LINE=""
		export ESCALATION_ROW_HTML=""
	fi

	# ban command display
	# expand_command_template uses globals ATTACK_HOST, MOD, PORTS (raw values)
	local _saved_ports="$PORTS"
	ATTACK_HOST="$host"
	MOD="$mod"
	PORTS="$ports"
	local display_cmd
	if [ "${_FW_BACKEND:-custom}" = "custom" ]; then
		display_cmd=$(expand_command_template "${BAN_COMMAND_TEMPLATE:-}")
	else
		display_cmd="fw_ban $host ($_FW_BACKEND)"
	fi
	export BAN_COMMAND="$display_cmd"
	# restore formatted PORTS for template rendering
	PORTS="$_saved_ports"
	export PORTS

	# country lookup
	local cc=""
	if [ -n "${INSTALL_PATH:-}" ] && [ -f "${INSTALL_PATH}/ipcountry.dat" ]; then
		cc=$(ip_to_country "$host" "$INSTALL_PATH/ipcountry.dat")
	fi
	export COUNTRY_CODE="${cc:---}"
	export COUNTRY_FLAG
	if [ -n "$cc" ]; then
		COUNTRY_FLAG=$(_alert_country_flag "$cc")
	else
		COUNTRY_FLAG=""
	fi

	# reputation links
	local rep_config="${EMAIL_REPUTATION_LINKS:-}"
	if [ -n "$rep_config" ]; then
		_alert_build_reputation_links "$host" "$rep_config"
		export REPUTATION_SECTION_TEXT=""
		export REPUTATION_SECTION_HTML=""
		if [ -n "$REPUTATION_LINKS_TEXT" ]; then
			REPUTATION_SECTION_TEXT="  Reputation:
$REPUTATION_LINKS_TEXT"
			export REPUTATION_SECTION_TEXT
			local _esc_html="$REPUTATION_LINKS_HTML"
			REPUTATION_SECTION_HTML=$(printf '<tr>\n<td style="padding:4px 16px 8px;color:#71717a;vertical-align:top;">Reputation</td>\n<td style="padding:4px 16px 8px;">%s</td>\n</tr>' "$_esc_html")
			export REPUTATION_SECTION_HTML
		fi
	else
		export REPUTATION_LINKS_TEXT="" REPUTATION_LINKS_HTML=""
		export REPUTATION_SECTION_TEXT="" REPUTATION_SECTION_HTML=""
	fi

	# source logs — filter by rule detection patterns when available
	export SOURCE_LOGS="" SOURCE_LOGS_HTML=""
	export SOURCE_LOGS_SECTION_TEXT="" SOURCE_LOGS_SECTION_HTML=""
	if [ -n "$lp" ] && [ -f "$lp" ]; then
		local _patterns raw_logs
		_patterns=$(_events_rule_patterns "$mod") || _patterns=""
		raw_logs=$(_alert_sanitize_logs "$lp" "$host" "$loglines" "$_patterns") || true
		if [ -n "$raw_logs" ]; then
			export SOURCE_LOGS="$raw_logs"
			# indent for text display
			local indented_logs
			indented_logs=$(echo "$raw_logs" | sed 's/^/    /')
			# shellcheck disable=SC2089  # single quotes are literal output, not shell quoting
			if [ "$entry_total" -gt 1 ]; then
				SOURCE_LOGS_SECTION_TEXT="  Source logs from '${mod}' [${host}]:
${indented_logs}"
			else
				SOURCE_LOGS_SECTION_TEXT="  Source logs from '${mod}':
${indented_logs}"
			fi
			# shellcheck disable=SC2090  # variable contains literal quotes for template output
			export SOURCE_LOGS_SECTION_TEXT

			# HTML: escape log content
			local html_logs
			html_logs=$(_alert_html_escape "$raw_logs")
			export SOURCE_LOGS_HTML="$html_logs"
			SOURCE_LOGS_SECTION_HTML=$(printf '<tr>\n<td colspan="2" style="padding:8px 16px;">\n<div style="background-color:#f4f4f5;border:1px solid #d4d4d8;border-radius:6px;padding:10px;font-family:&apos;Courier New&apos;,Courier,monospace;font-size:11px;color:#09090b;white-space:pre-wrap;word-break:break-all;max-height:300px;overflow-y:auto;">%s</div>\n</td>\n</tr>' "$html_logs")
			export SOURCE_LOGS_SECTION_HTML
		fi
	elif [ -z "$lp" ] || [ ! -f "${lp:-/dev/null}" ]; then
		# journal-based logs: no log file path available
		SOURCE_LOGS_SECTION_TEXT="  Source logs: not available (logs via systemd journal)"
		export SOURCE_LOGS_SECTION_TEXT
		# shellcheck disable=SC2089  # variable contains HTML with literal quotes, not shell quoting
		SOURCE_LOGS_SECTION_HTML='<tr><td colspan="2" style="padding:8px 16px;color:#71717a;font-style:italic;">Source logs not available (systemd journal)</td></tr>'
		# shellcheck disable=SC2090  # variable contains HTML output
		export SOURCE_LOGS_SECTION_HTML
	fi
}

# _alert_compute_summary alerts_file — compute summary variables from alerts file
# Single awk pass to compute: total bans, unique IPs, per-service counts,
# per-country counts, ban type counts (temporary/escalated/permanent),
# repeat offender count. Exports SUMMARY_* variables.
_alert_compute_summary() {
	local alerts_file="$1"
	if [ ! -f "$alerts_file" ] || [ ! -s "$alerts_file" ]; then
		return 1
	fi

	# single awk pass: field layout host|mod|ports|pressure|expiry|action|recent|lp|recip|trip|hl|weight
	local summary
	summary=$(awk -F'|' '
	{
		total++
		ips[$1]++
		services[$2]++
		if ($6 == "escalate") { escalated++ }
		else if ($5 == "0") { permanent++ }
		else { temporary++ }
		if ($7 + 0 > 0) { repeats++ }
	}
	END {
		unique = 0; for (i in ips) unique++
		# build service string: "sshd(3), dovecot(2)"
		svc = ""
		for (s in services) {
			if (svc != "") svc = svc ", "
			svc = svc s "(" services[s] ")"
		}
		printf "%d\n%d\n%s\n%d\n%d\n%d\n%d\n",
			total, unique, svc,
			temporary + 0, escalated + 0, permanent + 0, repeats + 0
	}' "$alerts_file")

	local line_num=0
	local s_total s_unique s_services s_temp s_esc s_perm s_repeats
	while IFS= read -r _line; do
		line_num=$((line_num + 1))
		case $line_num in
			1) s_total="$_line" ;;
			2) s_unique="$_line" ;;
			3) s_services="$_line" ;;
			4) s_temp="$_line" ;;
			5) s_esc="$_line" ;;
			6) s_perm="$_line" ;;
			7) s_repeats="$_line" ;;
		esac
	done <<< "$summary"

	export SUMMARY_TOTAL_BANS="${s_total:-0}"
	export SUMMARY_UNIQUE_IPS="${s_unique:-0}"
	export SUMMARY_SERVICES="${s_services:-}"
	export SUMMARY_TEMPORARY="${s_temp:-0}"
	export SUMMARY_ESCALATED="${s_esc:-0}"
	export SUMMARY_PERMANENT="${s_perm:-0}"
	export SUMMARY_REPEAT_OFFENDERS="${s_repeats:-0}"

	# repeat percentage
	local repeat_pct=0
	if [ "${s_total:-0}" -gt 0 ]; then
		repeat_pct=$(( (${s_repeats:-0} * 100) / s_total ))
	fi
	export SUMMARY_REPEAT_PCT="$repeat_pct"

	# country breakdown: need ip_to_country for each unique IP
	local countries_str=""
	if [ -n "${INSTALL_PATH:-}" ] && [ -f "${INSTALL_PATH}/ipcountry.dat" ]; then
		# collect unique IPs and look up countries
		local _ip _cc
		local -a _cc_counts=()
		local _cc_list=""
		while IFS='|' read -r _ip _ _ _ _ _ _ _ _ _ _ _; do
			[ -z "$_ip" ] && continue
			_cc=$(ip_to_country "$_ip" "$INSTALL_PATH/ipcountry.dat")
			_cc="${_cc:---}"
			_cc_list="${_cc_list}${_cc}
"
		done < "$alerts_file"
		# count and format
		countries_str=$(echo "$_cc_list" | grep -v '^$' | sort | uniq -c | sort -rn | \
			awk '{printf "%s(%d), ", $2, $1}' | sed 's/, $//')
	fi
	export SUMMARY_COUNTRIES="${countries_str:---}"
}

# ---------------------------------------------------------------------------
# Rendering Pipeline
# ---------------------------------------------------------------------------

# _alert_render_text alerts_file template_dir [loglines] — render full text email
# Orchestrates: header → N×entry → [summary] → footer
# Output goes to stdout.
_alert_render_text() {
	local alerts_file="$1" template_dir="$2" loglines="${3:-5}"
	if [ ! -f "$alerts_file" ] || [ ! -s "$alerts_file" ]; then
		return 1
	fi

	local entry_total
	entry_total=$(wc -l < "$alerts_file")

	# global vars
	_alert_set_global_vars "$entry_total"

	# header
	_alert_tpl_resolve "$template_dir" "text.header.tpl"
	_alert_tpl_render "$_ALERT_TPL_RESOLVED"

	# entries
	local n=0 line
	while IFS= read -r line; do
		[ -z "$line" ] && continue
		n=$((n + 1))
		_alert_set_entry_vars "$line" "$n" "$entry_total" "$loglines"
		_alert_tpl_resolve "$template_dir" "text.entry.tpl"
		_alert_tpl_render "$_ALERT_TPL_RESOLVED"
	done < "$alerts_file"

	# summary (multi-ban only)
	if [ "$entry_total" -gt 1 ]; then
		_alert_compute_summary "$alerts_file"
		_alert_tpl_resolve "$template_dir" "text.summary.tpl"
		_alert_tpl_render "$_ALERT_TPL_RESOLVED"
	fi

	# footer
	_alert_tpl_resolve "$template_dir" "text.footer.tpl"
	_alert_tpl_render "$_ALERT_TPL_RESOLVED"
}

# _alert_render_html alerts_file template_dir [loglines] — render full HTML email
# Same flow as text but with HTML partials and HTML-escaped values.
# Output goes to stdout.
_alert_render_html() {
	local alerts_file="$1" template_dir="$2" loglines="${3:-5}"
	if [ ! -f "$alerts_file" ] || [ ! -s "$alerts_file" ]; then
		return 1
	fi

	local entry_total
	entry_total=$(wc -l < "$alerts_file")

	# global vars
	_alert_set_global_vars "$entry_total"

	# header
	_alert_tpl_resolve "$template_dir" "html.header.tpl"
	_alert_tpl_render "$_ALERT_TPL_RESOLVED"

	# entries
	local n=0 line
	while IFS= read -r line; do
		[ -z "$line" ] && continue
		n=$((n + 1))
		_alert_set_entry_vars "$line" "$n" "$entry_total" "$loglines"
		_alert_tpl_resolve "$template_dir" "html.entry.tpl"
		_alert_tpl_render "$_ALERT_TPL_RESOLVED"
	done < "$alerts_file"

	# summary (multi-ban only)
	if [ "$entry_total" -gt 1 ]; then
		_alert_compute_summary "$alerts_file"
		_alert_tpl_resolve "$template_dir" "html.summary.tpl"
		_alert_tpl_render "$_ALERT_TPL_RESOLVED"
	fi

	# footer
	_alert_tpl_resolve "$template_dir" "html.footer.tpl"
	_alert_tpl_render "$_ALERT_TPL_RESOLVED"
}

# ---------------------------------------------------------------------------
# BFD Alert Init — map BFD config to shared alert_lib env vars
# ---------------------------------------------------------------------------

# _bfd_alert_init — export BFD config variables as ALERT_* env vars for shared alert_lib
# Maps BFD's SMTP_* and messaging variables to the shared library's ALERT_* names.
# Enables/disables channels in the shared lib's channel registry.
# Called from config_init() after sourcing conf.bfd.
_bfd_alert_init() {
	# Map SMTP config for email delivery
	export ALERT_SMTP_RELAY="${SMTP_RELAY:-}"
	export ALERT_SMTP_FROM="${SMTP_FROM:-}"
	export ALERT_SMTP_USER="${SMTP_USER:-}"
	export ALERT_SMTP_PASS="${SMTP_PASS:-}"
	# Set temp dir for shared lib
	export ALERT_TMPDIR="${TMPDIR:-/tmp}"

	# Map Slack config
	export ALERT_SLACK_MODE="${SLACK_MODE:-webhook}"
	export ALERT_SLACK_WEBHOOK_URL="${SLACK_WEBHOOK_URL:-}"
	export ALERT_SLACK_TOKEN="${SLACK_TOKEN:-}"
	export ALERT_SLACK_CHANNEL="${SLACK_CHANNEL:-}"

	# Map Telegram config
	export ALERT_TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
	export ALERT_TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID:-}"

	# Map Discord config
	export ALERT_DISCORD_WEBHOOK_URL="${DISCORD_WEBHOOK_URL:-}"

	# Enable/disable channels in registry (email NOT registered — BFD handles email directly)
	if [ "${SLACK_ALERTS:-0}" = "1" ]; then
		alert_channel_enable "slack"
	else
		alert_channel_disable "slack"
	fi
	if [ "${TELEGRAM_ALERTS:-0}" = "1" ]; then
		alert_channel_enable "telegram"
	else
		alert_channel_disable "telegram"
	fi
	if [ "${DISCORD_ALERTS:-0}" = "1" ]; then
		alert_channel_enable "discord"
	else
		alert_channel_disable "discord"
	fi
}

# ---------------------------------------------------------------------------
# BFD Messaging Dispatch — multi-channel alerting via shared alert_lib
# ---------------------------------------------------------------------------

# _bfd_dispatch_messaging alerts_file subject loglines tpl_dir — dispatch to messaging channels
# Sends alerts to enabled messaging channels (Slack, Telegram, Discord) via
# the shared alert_lib channel registry. Email is NOT dispatched here (handled
# by send_alerts() directly). Renders per-entry blocks using channel-specific
# templates and exports ENTRY_BLOCKS/ENTRY_FIELDS as template variables for
# the outer message template.
# No-op if no messaging channel is enabled.
_bfd_dispatch_messaging() {
	local alerts_file="$1" subject="$2" loglines="${3:-5}" tpl_dir="$4"

	# Early exit if no messaging channels enabled
	if ! alert_channel_enabled "slack" && \
	   ! alert_channel_enabled "telegram" && \
	   ! alert_channel_enabled "discord"; then
		return 0
	fi

	if [ ! -f "$alerts_file" ] || [ ! -s "$alerts_file" ]; then
		return 0
	fi

	# Set global template variables (hostname, version, timestamp, etc.)
	_alert_set_global_vars

	# Build per-entry blocks for each enabled channel
	local slack_blocks="" telegram_blocks="" discord_fields=""
	local pipe_line
	while IFS= read -r pipe_line; do
		[ -z "$pipe_line" ] && continue

		# Set per-entry template variables (HOST, MOD, PORTS, etc.)
		_alert_set_entry_vars "$pipe_line" "$loglines"

		if alert_channel_enabled "slack"; then
			_alert_tpl_resolve "$tpl_dir" "slack.entry.tpl"
			if [ -f "$_ALERT_TPL_RESOLVED" ]; then
				local _se
				_se=$(_alert_tpl_render "$_ALERT_TPL_RESOLVED")
				slack_blocks="${slack_blocks}${_se}"
			fi
		fi

		if alert_channel_enabled "telegram"; then
			_alert_tpl_resolve "$tpl_dir" "telegram.entry.tpl"
			if [ -f "$_ALERT_TPL_RESOLVED" ]; then
				local _te
				_te=$(_alert_tpl_render "$_ALERT_TPL_RESOLVED")
				telegram_blocks="${telegram_blocks}${_te}"
			fi
		fi

		if alert_channel_enabled "discord"; then
			_alert_tpl_resolve "$tpl_dir" "discord.entry.tpl"
			if [ -f "$_ALERT_TPL_RESOLVED" ]; then
				local _de
				_de=$(_alert_tpl_render "$_ALERT_TPL_RESOLVED")
				discord_fields="${discord_fields}${_de}"
			fi
		fi
	done < "$alerts_file"

	# Compute summary for outer template
	_alert_compute_summary "$alerts_file"

	# Export accumulated entry blocks as template variables
	export ENTRY_BLOCKS="${slack_blocks}${telegram_blocks}"
	export ENTRY_FIELDS="$discord_fields"

	# Dispatch to all enabled channels (excluding email)
	alert_dispatch "$tpl_dir" "$subject" "slack,telegram,discord"
	local rc=$?

	# Clean up exported entry variables
	unset ENTRY_BLOCKS ENTRY_FIELDS
	return $rc
}

# ---------------------------------------------------------------------------
# BFD Digest Wrappers — bridge BFD's digest API to shared alert_lib
# ---------------------------------------------------------------------------

# _bfd_spool_append alerts_file — append to BFD's digest spool via shared lib
# Wraps _alert_spool_append() with BFD's ALERT_SPOOL_FILE global.
_bfd_spool_append() {
	local alerts_file="$1"
	local spool="${ALERT_SPOOL_FILE:-}"
	if [ -z "$spool" ]; then
		elog error "ALERT_SPOOL_FILE not set, cannot spool digest alerts."
		return 1
	fi
	_alert_spool_append "$alerts_file" "$spool"
}

# _bfd_digest_check — flush BFD's digest spool if interval expired
# Wraps _alert_digest_check() with BFD's digest config variables.
# No-op if EMAIL_DIGEST != "timed".
_bfd_digest_check() {
	if [ "${EMAIL_DIGEST:-cycle}" != "timed" ]; then
		return 0
	fi
	local spool="${ALERT_SPOOL_FILE:-}"
	if [ -z "$spool" ]; then
		return 0
	fi
	local interval="${EMAIL_DIGEST_INTERVAL:-900}"
	_alert_digest_check "$spool" "$interval" "_bfd_digest_flush_callback"
}

# _bfd_digest_flush — force-flush BFD's digest spool
# Checks that at least one alert channel is enabled before flushing.
# This preserves the existing behavior where the spool is NOT truncated
# when alerting is disabled (entries accumulate until re-enabled).
_bfd_digest_flush() {
	# Check that at least one alert channel is enabled
	if [ "${EMAIL_ALERTS:-0}" != "1" ] && \
	   [ "${SLACK_ALERTS:-0}" != "1" ] && \
	   [ "${TELEGRAM_ALERTS:-0}" != "1" ] && \
	   [ "${DISCORD_ALERTS:-0}" != "1" ]; then
		return 0
	fi
	local spool="${ALERT_SPOOL_FILE:-}"
	if [ -z "$spool" ]; then
		return 0
	fi
	_alert_digest_flush "$spool" "_bfd_digest_flush_callback"
}

# _bfd_digest_flush_callback flush_file — callback invoked by _alert_digest_flush
# Receives the path to a temp file with flushed entries (epoch prefix stripped).
# Logs and calls send_alerts() for delivery.
_bfd_digest_flush_callback() {
	local flush_file="$1"
	local flush_count
	flush_count=$(wc -l < "$flush_file")
	eout "digest flush: sending $flush_count accumulated alert(s)." le
	send_alerts "$flush_file" "${EMAIL_SUBJECT:-BFD Alert}" "${EMAIL_LOGLINES:-5}"
}
