#!/bin/bash
#
# Brute Force Detection 2.0.1 - Alert Library
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
# This file is sourced by bfd.lib.sh and provides the email alert subsystem:
# template rendering engine, content formatting, and delivery mechanisms.

# shellcheck disable=SC2034  # version checked by health_check and show_config
ALERT_LIB_VERSION="1.0.0"

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
# Template Engine
# ---------------------------------------------------------------------------

# _tpl_render template_file — render template by replacing {{VAR}} tokens
# with values from exported environment variables. Single-pass awk using
# ENVIRON array. Unknown/unset tokens become empty strings.
# Safe: no shell code execution, no eval, mawk-compatible.
# Output goes to stdout.
_tpl_render() {
	local template_file="$1"
	if [ ! -f "$template_file" ]; then
		return 1
	fi
	awk '{
		line = $0
		while (match(line, /\{\{[A-Z_][A-Z0-9_]*\}\}/)) {
			token = substr(line, RSTART + 2, RLENGTH - 4)
			val = ENVIRON[token]
			line = substr(line, 1, RSTART - 1) val substr(line, RSTART + RLENGTH)
		}
		print line
	}' "$template_file"
}

# _html_escape str — escape HTML special characters for safe embedding
# Handles: & < > " ' (& first to avoid double-escaping)
# Uses sed for portable behavior across bash versions (bash 5.2 changed
# & semantics in ${var//pat/rep} to act as a backreference).
# Output goes to stdout.
_html_escape() {
	if [ -z "$1" ]; then
		echo ""
		return 0
	fi
	printf '%s\n' "$1" | sed \
		-e 's/&/\&amp;/g' \
		-e 's/</\&lt;/g' \
		-e 's/>/\&gt;/g' \
		-e 's/"/\&quot;/g' \
		-e "s/'/\\&#39;/g"
}

# ---------------------------------------------------------------------------
# Content Helpers
# ---------------------------------------------------------------------------

# _alert_sanitize_logs log_file host loglines — extract and redact log lines
# Extracts up to $loglines lines matching $host from $log_file, redacts
# passwords and authorization headers. Output goes to stdout.
# Returns 1 if log_file missing or empty match.
_alert_sanitize_logs() {
	local log_file="$1" host="$2" loglines="${3:-50}"
	if [ -z "$log_file" ] || [ ! -f "$log_file" ]; then
		return 1
	fi
	local lines
	lines=$(tail -n 5000 "$log_file" | grep -Fw "$host" | tail -n "$loglines" | \
		sed -e 's/\([Pp]ass[a-z]*\)[=:][[:space:]]*[^ ]*/\1=<REDACTED>/g' \
		    -e 's/\([Aa]uthorization:[[:space:]]*\).*/\1<REDACTED>/')
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
				printf -v _link '<a href="%s" style="color:#1976d2;text-decoration:none;">%s</a>' "$url" "$label"
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
# 0-69%: green (#4caf50), 70-99%: orange (#ff9800), 100%+: red (#d32f2f)
_alert_pressure_color() {
	local pct="${1:-0}"
	if [ "$pct" -ge 100 ]; then
		echo "#d32f2f"
	elif [ "$pct" -ge 70 ]; then
		echo "#ff9800"
	else
		echo "#4caf50"
	fi
}

# _alert_ban_type_color action expiry — return HTML hex color for ban severity
# escalated: orange (#f57c00), permanent: red (#d32f2f), temporary: amber (#f9a825)
_alert_ban_type_color() {
	local action="$1" expiry="$2"
	if [ "$action" = "escalate" ]; then
		echo "#f57c00"
	elif [ "$expiry" = "0" ]; then
		echo "#d32f2f"
	else
		echo "#f9a825"
	fi
}

# ---------------------------------------------------------------------------
# Data Preparation (Phase 3)
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
# Sets all per-entry template variables into exported environment for _tpl_render.
# Requires: format_duration(), pressure_format(), ip_to_country(), expand_command_template(),
#   _alert_build_reputation_links(), _alert_pressure_bar(), _alert_pressure_color(),
#   _alert_ban_type_color(), _alert_country_flag(), _html_escape(), _alert_sanitize_logs()
#   (all from bfd.lib.sh or alert_lib.sh)
_alert_set_entry_vars() {
	local pipe_line="$1" entry_num="$2" entry_total="$3"
	local loglines="${4:-50}"

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
		HISTORY_ROW_HTML=$(printf '<tr>\n<td style="padding:4px 14px;color:#757575;vertical-align:top;">History</td>\n<td style="padding:4px 14px;">%s previous ban(s) in %s (permanent at %s)</td>\n</tr>' \
			"$recent" "$_esc_dur" "$esc_after")
		export HISTORY_ROW_HTML
	else
		export HISTORY_LINE=""
		export HISTORY_ROW_HTML=""
	fi

	if [ "$action" = "escalate" ]; then
		export ESCALATION_LINE="  Escalation:  permanent after $esc_after offenses"
		export ESCALATION_ROW_HTML
		ESCALATION_ROW_HTML=$(printf '<tr>\n<td style="padding:4px 14px;color:#757575;vertical-align:top;">Escalation</td>\n<td style="padding:4px 14px;color:#d32f2f;font-weight:bold;">Permanent after %s offenses</td>\n</tr>' \
			"$esc_after")
	elif [ "${BAN_ESCALATION:-none}" != "none" ] && [ "${recent:-0}" -gt 0 ]; then
		export ESCALATION_LINE="  Escalation:  ${BAN_ESCALATION}, step $((recent + 1))"
		export ESCALATION_ROW_HTML
		ESCALATION_ROW_HTML=$(printf '<tr>\n<td style="padding:4px 14px;color:#757575;vertical-align:top;">Escalation</td>\n<td style="padding:4px 14px;">%s, step %s</td>\n</tr>' \
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
			REPUTATION_SECTION_HTML=$(printf '<tr>\n<td style="padding:4px 14px 8px;color:#757575;vertical-align:top;">Reputation</td>\n<td style="padding:4px 14px 8px;">%s</td>\n</tr>' "$_esc_html")
			export REPUTATION_SECTION_HTML
		fi
	else
		export REPUTATION_LINKS_TEXT="" REPUTATION_LINKS_HTML=""
		export REPUTATION_SECTION_TEXT="" REPUTATION_SECTION_HTML=""
	fi

	# source logs
	export SOURCE_LOGS="" SOURCE_LOGS_HTML=""
	export SOURCE_LOGS_SECTION_TEXT="" SOURCE_LOGS_SECTION_HTML=""
	if [ -n "$lp" ] && [ -f "$lp" ]; then
		local raw_logs
		raw_logs=$(_alert_sanitize_logs "$lp" "$host" "$loglines") || true
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
			html_logs=$(_html_escape "$raw_logs")
			export SOURCE_LOGS_HTML="$html_logs"
			SOURCE_LOGS_SECTION_HTML=$(printf '<tr>\n<td colspan="2" style="padding:8px 14px;">\n<div style="background-color:#f5f5f5;border:1px solid #e0e0e0;border-radius:3px;padding:8px;font-family:monospace,monospace;font-size:11px;white-space:pre-wrap;word-break:break-all;max-height:300px;overflow-y:auto;">%s</div>\n</td>\n</tr>' "$html_logs")
			export SOURCE_LOGS_SECTION_HTML
		fi
	elif [ -z "$lp" ] || [ ! -f "${lp:-/dev/null}" ]; then
		# journal-based logs: no log file path available
		SOURCE_LOGS_SECTION_TEXT="  Source logs: not available (logs via systemd journal)"
		export SOURCE_LOGS_SECTION_TEXT
		# shellcheck disable=SC2089  # variable contains HTML with literal quotes, not shell quoting
		SOURCE_LOGS_SECTION_HTML='<tr><td colspan="2" style="padding:8px 14px;color:#9e9e9e;font-style:italic;">Source logs not available (systemd journal)</td></tr>'
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
# Rendering Pipeline (Phase 3)
# ---------------------------------------------------------------------------

# _alert_render_text alerts_file template_dir [loglines] — render full text email
# Orchestrates: header → N×entry → [summary] → footer
# Output goes to stdout.
_alert_render_text() {
	local alerts_file="$1" template_dir="$2" loglines="${3:-50}"
	if [ ! -f "$alerts_file" ] || [ ! -s "$alerts_file" ]; then
		return 1
	fi

	local entry_total
	entry_total=$(wc -l < "$alerts_file")

	# global vars
	_alert_set_global_vars "$entry_total"

	# header
	_tpl_render "$template_dir/text.header.tpl"

	# entries
	local n=0 line
	while IFS= read -r line; do
		[ -z "$line" ] && continue
		n=$((n + 1))
		_alert_set_entry_vars "$line" "$n" "$entry_total" "$loglines"
		_tpl_render "$template_dir/text.entry.tpl"
	done < "$alerts_file"

	# summary (multi-ban only)
	if [ "$entry_total" -gt 1 ]; then
		_alert_compute_summary "$alerts_file"
		_tpl_render "$template_dir/text.summary.tpl"
	fi

	# footer
	_tpl_render "$template_dir/text.footer.tpl"
}

# _alert_render_html alerts_file template_dir [loglines] — render full HTML email
# Same flow as text but with HTML partials and HTML-escaped values.
# Output goes to stdout.
_alert_render_html() {
	local alerts_file="$1" template_dir="$2" loglines="${3:-50}"
	if [ ! -f "$alerts_file" ] || [ ! -s "$alerts_file" ]; then
		return 1
	fi

	local entry_total
	entry_total=$(wc -l < "$alerts_file")

	# global vars
	_alert_set_global_vars "$entry_total"

	# header
	_tpl_render "$template_dir/html.header.tpl"

	# entries
	local n=0 line
	while IFS= read -r line; do
		[ -z "$line" ] && continue
		n=$((n + 1))
		_alert_set_entry_vars "$line" "$n" "$entry_total" "$loglines"
		_tpl_render "$template_dir/html.entry.tpl"
	done < "$alerts_file"

	# summary (multi-ban only)
	if [ "$entry_total" -gt 1 ]; then
		_alert_compute_summary "$alerts_file"
		_tpl_render "$template_dir/html.summary.tpl"
	fi

	# footer
	_tpl_render "$template_dir/html.footer.tpl"
}

# _alert_build_mime text_body html_body — construct multipart/alternative MIME message
# Writes MIME headers and both text and HTML parts to stdout.
# Caller is responsible for adding Subject/To/From headers before this output.
# The boundary uses epoch+PID for uniqueness (sufficient for email context).
_alert_build_mime() {
	local text_body="$1" html_body="$2"
	local boundary
	boundary="BFD_$(date +%s)_$$"

	echo "MIME-Version: 1.0"
	echo "Content-Type: multipart/alternative; boundary=\"$boundary\""
	echo ""
	echo "--$boundary"
	echo "Content-Type: text/plain; charset=UTF-8"
	echo "Content-Transfer-Encoding: 8bit"
	echo ""
	echo "$text_body"
	echo ""
	echo "--$boundary"
	echo "Content-Type: text/html; charset=UTF-8"
	echo "Content-Transfer-Encoding: 8bit"
	echo ""
	echo "$html_body"
	echo ""
	echo "--${boundary}--"
}

# ---------------------------------------------------------------------------
# Delivery Functions (Phase 4)
# ---------------------------------------------------------------------------

# _alert_send_local recip subject text_file html_file format
# Send alert via local MTA (mail/sendmail). Format: text, html, or both.
# Returns 0 on success, 1 on failure.
_alert_send_local() {
	local recip="$1" subject="$2" text_file="$3" html_file="$4" format="${5:-text}"
	local from="${SMTP_FROM:-root@$(hostname -f 2>/dev/null || hostname)}"
	local sendmail_bin mail_bin
	sendmail_bin=$(command -v sendmail 2>/dev/null || true)
	mail_bin=$(command -v mail 2>/dev/null || true)

	case "$format" in
		text)
			if [ -z "$mail_bin" ]; then
				elog error "mail binary not found, cannot send alert to $recip."
				return 1
			fi
			"$mail_bin" -s "$subject" "$recip" < "$text_file"
			return $?
			;;
		html)
			if [ -n "$sendmail_bin" ]; then
				{
					echo "From: $from"
					echo "To: $recip"
					echo "Subject: $subject"
					echo "Content-Type: text/html; charset=UTF-8"
					echo "Content-Transfer-Encoding: 8bit"
					echo ""
					cat "$html_file"
				} | "$sendmail_bin" -t -oi
				return $?
			fi
			# sendmail not available — fall back to text via mail
			elog warn "sendmail not found, falling back to text-only alert for $recip."
			if [ -z "$mail_bin" ]; then
				elog error "mail binary not found, cannot send alert to $recip."
				return 1
			fi
			"$mail_bin" -s "$subject" "$recip" < "$text_file"
			return $?
			;;
		both)
			if [ -n "$sendmail_bin" ]; then
				local text_body html_body
				text_body=$(cat "$text_file")
				html_body=$(cat "$html_file")
				{
					echo "From: $from"
					echo "To: $recip"
					echo "Subject: $subject"
					_alert_build_mime "$text_body" "$html_body"
				} | "$sendmail_bin" -t -oi
				return $?
			fi
			# sendmail not available — fall back to text via mail
			elog warn "sendmail not found, falling back to text-only alert for $recip."
			if [ -z "$mail_bin" ]; then
				elog error "mail binary not found, cannot send alert to $recip."
				return 1
			fi
			"$mail_bin" -s "$subject" "$recip" < "$text_file"
			return $?
			;;
		*)
			elog error "unknown EMAIL_FORMAT '$format', cannot send alert."
			return 1
			;;
	esac
}

# _alert_send_relay recip subject msg_file — send via authenticated SMTP relay
# msg_file must be a complete RFC 822 message (headers + body).
# Returns 0 on success, 1 on failure.
_alert_send_relay() {
	local recip="$1" subject="$2" msg_file="$3"

	if [ -z "${SMTP_FROM:-}" ]; then
		elog error "SMTP_FROM not set, cannot send relay alert to $recip."
		return 1
	fi
	if [ -z "${SMTP_USER:-}" ] || [ -z "${SMTP_PASS:-}" ]; then
		elog error "SMTP_USER/SMTP_PASS not set, cannot send relay alert to $recip."
		return 1
	fi
	local curl_bin
	curl_bin=$(command -v curl 2>/dev/null || true)
	if [ -z "$curl_bin" ]; then
		elog error "curl not found, cannot send relay alert to $recip."
		return 1
	fi

	local rc=0
	"$curl_bin" --url "$SMTP_RELAY" --ssl-reqd \
		--mail-from "$SMTP_FROM" --mail-rcpt "$recip" \
		--user "$SMTP_USER:$SMTP_PASS" \
		--upload-file "$msg_file" 2>/dev/null || rc=$?
	if [ "$rc" -ne 0 ]; then
		elog error "SMTP relay to $recip failed (curl exit $rc)."
		return 1
	fi
	return 0
}

# _alert_send recip subject text_file html_file format
# Router: SMTP_RELAY set → relay path, else → local MTA.
# Returns 0 on success, 1 on failure.
_alert_send() {
	local recip="$1" subject="$2" text_file="$3" html_file="$4" format="${5:-text}"

	if [ -n "${SMTP_RELAY:-}" ]; then
		# relay path: always build full multipart MIME message
		local from="${SMTP_FROM:-root@$(hostname -f 2>/dev/null || hostname)}"
		local text_body html_body
		text_body=$(cat "$text_file")
		html_body=$(cat "$html_file")
		local msg_file
		msg_file=$(mktemp "${TMPDIR:-/tmp}/bfd_relay_msg.XXXXXX")
		{
			echo "From: $from"
			echo "To: $recip"
			echo "Subject: $subject"
			echo "Date: $(date -R 2>/dev/null || date)"
			_alert_build_mime "$text_body" "$html_body"
		} > "$msg_file"
		_alert_send_relay "$recip" "$subject" "$msg_file"
		local rc=$?
		rm -f "$msg_file"
		return $rc
	fi

	# local MTA path
	_alert_send_local "$recip" "$subject" "$text_file" "$html_file" "$format"
}

# ---------------------------------------------------------------------------
# Digest Mode (Phase 5)
# ---------------------------------------------------------------------------

# _alert_spool_append alerts_file — append timestamped entries to digest spool
# Prepends current epoch to each line of alerts_file and appends to
# $ALERT_SPOOL_FILE under exclusive flock (10s timeout).
# No-op if alerts_file is empty or missing.
_alert_spool_append() {
	local alerts_file="$1"
	if [ ! -f "$alerts_file" ] || [ ! -s "$alerts_file" ]; then
		return 0
	fi
	local spool="${ALERT_SPOOL_FILE:-}"
	if [ -z "$spool" ]; then
		elog error "ALERT_SPOOL_FILE not set, cannot spool digest alerts."
		return 1
	fi
	local now
	now=$(date +%s)
	local lock_file="${spool}.lock"
	(
		flock -x -w 10 200 || { elog error "digest spool lock timeout, skipping append."; exit 1; }
		while IFS= read -r _line; do
			[ -z "$_line" ] && continue
			echo "${now}|${_line}"
		done < "$alerts_file" >> "$spool"
	) 200>"$lock_file"
}

# _alert_digest_check — flush spool if EMAIL_DIGEST_INTERVAL has expired
# Returns immediately if EMAIL_DIGEST != "timed" or spool is empty/missing.
# Reads first line's epoch for age check (optimistic, no lock needed).
_alert_digest_check() {
	if [ "${EMAIL_DIGEST:-cycle}" != "timed" ]; then
		return 0
	fi
	local spool="${ALERT_SPOOL_FILE:-}"
	if [ -z "$spool" ] || [ ! -f "$spool" ] || [ ! -s "$spool" ]; then
		return 0
	fi
	local first_epoch
	IFS='|' read -r first_epoch _ < "$spool"
	if [ -z "$first_epoch" ]; then
		return 0
	fi
	local now interval
	now=$(date +%s)
	interval="${EMAIL_DIGEST_INTERVAL:-900}"
	if [ $((now - first_epoch)) -ge "$interval" ]; then
		_alert_digest_flush_now
	fi
}

# _alert_digest_flush_now — force-send accumulated digest alerts
# Under exclusive flock: strips epoch prefix, copies to temp flush file,
# truncates spool. Releases lock before calling send_alerts() to avoid
# holding flock during SMTP delivery. No-op if EMAIL_ALERTS!=1 or spool empty.
_alert_digest_flush_now() {
	if [ "${EMAIL_ALERTS:-0}" != "1" ]; then
		return 0
	fi
	local spool="${ALERT_SPOOL_FILE:-}"
	if [ -z "$spool" ] || [ ! -f "$spool" ] || [ ! -s "$spool" ]; then
		return 0
	fi
	local lock_file="${spool}.lock"
	local flush_file
	flush_file=$(mktemp "${spool}.flush.XXXXXX")
	local flush_count=0
	(
		flock -x -w 10 200 || { elog error "digest flush lock timeout, skipping flush."; exit 1; }
		# re-check spool non-empty under lock
		if [ ! -s "$spool" ]; then
			exit 0
		fi
		# strip epoch prefix (field 0) — send_alerts expects 12-field format
		cut -d'|' -f2- "$spool" > "$flush_file"
		# truncate spool
		: > "$spool"
	) 200>"$lock_file"
	# send outside lock to avoid holding flock during delivery
	if [ -s "$flush_file" ]; then
		flush_count=$(wc -l < "$flush_file")
		eout "digest flush: sending $flush_count accumulated alert(s)." le
		send_alerts "$flush_file" "${EMAIL_SUBJECT:-BFD Alert}" "${EMAIL_LOGLINES:-50}"
	fi
	rm -f "$flush_file"
}
