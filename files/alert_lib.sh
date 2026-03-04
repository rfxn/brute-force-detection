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
