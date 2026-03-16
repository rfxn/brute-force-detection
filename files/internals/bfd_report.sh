#!/bin/bash
#
# Brute Force Detection 2.0.1 - Periodic Report Functions
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
# This file is sourced by bfd.lib.sh after bfd_alert.sh and geoip_lib.sh.
# It provides periodic report functions: data gathering, rendering, and delivery.

# Source guard — prevent double-sourcing
[[ -n "${_BFD_REPORT_LOADED:-}" ]] && return 0 2>/dev/null
_BFD_REPORT_LOADED=1

# shellcheck disable=SC2034  # version checked by health_check and show_config
BFD_REPORT_VERSION="1.0.0"

# ---------------------------------------------------------------------------
# Init Layer — validate interval, compute time windows
# ---------------------------------------------------------------------------

# _report_init interval — validate and set window variables
# Sets: _RPT_LABEL, _RPT_WINDOW, _RPT_CUTOFF, _RPT_PREV_CUTOFF, _RPT_NOW
# Returns 1 on invalid interval.
_report_init() {
	local interval="$1"
	_RPT_NOW=$(date +%s)
	case "$interval" in
		daily)
			_RPT_LABEL="Daily"
			_RPT_WINDOW="24h"
			_RPT_CUTOFF=$((_RPT_NOW - 86400))
			_RPT_PREV_CUTOFF=$((_RPT_NOW - 172800))
			;;
		weekly)
			_RPT_LABEL="Weekly"
			_RPT_WINDOW="7d"
			_RPT_CUTOFF=$((_RPT_NOW - 604800))
			_RPT_PREV_CUTOFF=$((_RPT_NOW - 1209600))
			;;
		monthly)
			_RPT_LABEL="Monthly"
			_RPT_WINDOW="30d"
			_RPT_CUTOFF=$((_RPT_NOW - 2592000))
			_RPT_PREV_CUTOFF=$((_RPT_NOW - 5184000))
			;;
		*)
			echo "error: invalid report interval '$interval' (use daily, weekly, or monthly)." >&2
			return 1
			;;
	esac
	return 0
}

# ---------------------------------------------------------------------------
# Data Layer — AWK helpers and stat gathering
# ---------------------------------------------------------------------------

# _report_trend_awk pool_file current_cutoff prior_cutoff
# Single-pass AWK: counts events and unique IPs in two adjacent time windows.
# Output: current_total|current_uniq|prior_total|prior_uniq
_report_trend_awk() {
	local pool_file="$1" current_cutoff="$2" prior_cutoff="$3"
	if [ ! -f "$pool_file" ] || [ ! -s "$pool_file" ]; then
		echo "0|0|0|0"
		return 0
	fi
	awk -v cur="$current_cutoff" -v prev="$prior_cutoff" '
	{
		ts = $1 + 0
		ip = $2
		cnt = ($4+0 > 0) ? $4+0 : 1
		if (ts >= cur) {
			ct += cnt
			if (!ci[ip]++) cu++
		} else if (ts >= prev) {
			pt += cnt
			if (!pi[ip]++) pu++
		}
	}
	END {
		printf "%d|%d|%d|%d\n", ct+0, cu+0, pt+0, pu+0
	}' "$pool_file"
}

# _report_data pool_file — gather all report stats, export REPORT_* vars
# Requires: _RPT_* vars from _report_init(), INSTALL_PATH, APOOL_LIST
# Reuses: _apool_summary_awk, _apool_awk, _apool_service_dual_awk,
#         format_table, _batch_ban_status_init/lookup/cleanup, pressure_compute,
#         pressure_format, _resolve_min_trip, _alert_country_flag
_report_data() {
	local pool_file="$1"
	local top_n="${REPORT_TOP_N:-25}"

	# --- Summary stats ---
	local summary_line
	if [ -f "$pool_file" ] && [ -s "$pool_file" ]; then
		summary_line=$(_apool_summary_awk "$pool_file" "$_RPT_CUTOFF" "$((_RPT_CUTOFF - (_RPT_NOW - _RPT_CUTOFF)))")
	else
		summary_line="0|0|0|0"
	fi
	local u_cur t_cur u_prev t_prev
	# shellcheck disable=SC2034  # u_prev/t_prev: positional placeholders for pipe field ordering
	IFS='|' read -r u_cur t_cur u_prev t_prev <<< "$summary_line"

	export REPORT_UNIQUE_IPS="${u_cur:-0}"
	export REPORT_TOTAL_EVENTS="${t_cur:-0}"

	# Ban counts
	local bans_active="${INSTALL_PATH:-}/tmp/bans.active"
	local active_bans=0
	if [ -f "$bans_active" ] && [ -s "$bans_active" ]; then
		active_bans=$(wc -l < "$bans_active")
	fi
	export REPORT_ACTIVE_BANS="$active_bans"

	# Total bans in window (ACTION=ban or escalate)
	local total_bans=0
	if [ -f "$pool_file" ] && [ -s "$pool_file" ]; then
		total_bans=$(awk -v cutoff="$_RPT_CUTOFF" '
			$1+0 >= cutoff && ($6 == "ban" || $6 == "escalate") { c++ }
			END { print c+0 }' "$pool_file")
	fi
	export REPORT_TOTAL_BANS="$total_bans"

	# --- Interval metadata ---
	local interval_name
	case "$_RPT_WINDOW" in
		24h) interval_name="daily" ;;
		7d)  interval_name="weekly" ;;
		30d) interval_name="monthly" ;;
		*)   interval_name="daily" ;;
	esac
	export REPORT_INTERVAL="$interval_name"
	export REPORT_INTERVAL_LABEL="$_RPT_LABEL"
	export REPORT_WINDOW="$_RPT_WINDOW"

	# Date range
	local start_fmt end_fmt
	start_fmt=$(date -d "@$_RPT_CUTOFF" +"%Y-%m-%d %H:%M" 2>/dev/null || echo "$_RPT_CUTOFF")  # fallback for non-GNU date
	end_fmt=$(date -d "@$_RPT_NOW" +"%Y-%m-%d %H:%M" 2>/dev/null || echo "$_RPT_NOW")  # fallback for non-GNU date
	export REPORT_DATE_RANGE="$start_fmt -- $end_fmt"

	# --- Trend ---
	local trend_line
	trend_line=$(_report_trend_awk "$pool_file" "$_RPT_CUTOFF" "$_RPT_PREV_CUTOFF")
	local ct cu pt pu
	# shellcheck disable=SC2034  # cu/pu: positional placeholders for pipe field ordering
	IFS='|' read -r ct cu pt pu <<< "$trend_line"
	ct=${ct:-0}; pt=${pt:-0}

	if [ "$pt" -eq 0 ] && [ "$ct" -eq 0 ]; then
		export REPORT_TREND_DIRECTION="flat"
		export REPORT_TREND_PCT="0"
		export REPORT_TREND_LABEL="no activity in either period"
	elif [ "$pt" -eq 0 ]; then
		export REPORT_TREND_DIRECTION="up"
		export REPORT_TREND_PCT="100"
		export REPORT_TREND_LABEL="new activity ($ct events, none in prior $_RPT_WINDOW)"
	else
		local pct_change=$(( (ct - pt) * 100 / pt ))
		local abs_pct=${pct_change#-}
		if [ "$pct_change" -gt 5 ]; then
			export REPORT_TREND_DIRECTION="up"
			export REPORT_TREND_PCT="$abs_pct"
			export REPORT_TREND_LABEL="${abs_pct}% increase vs prior $_RPT_WINDOW ($ct vs $pt)"
		elif [ "$pct_change" -lt -5 ]; then
			export REPORT_TREND_DIRECTION="down"
			export REPORT_TREND_PCT="$abs_pct"
			export REPORT_TREND_LABEL="${abs_pct}% decrease vs prior $_RPT_WINDOW ($ct vs $pt)"
		else
			export REPORT_TREND_DIRECTION="flat"
			export REPORT_TREND_PCT="$abs_pct"
			export REPORT_TREND_LABEL="no significant change vs prior $_RPT_WINDOW ($ct vs $pt)"
		fi
	fi

	# --- Top IPs (text + HTML + brief) ---
	_report_format_top_ips "$pool_file" "$_RPT_CUTOFF" "$top_n"

	# --- Service breakdown (text + HTML + brief) ---
	_report_format_services "$pool_file" "$_RPT_CUTOFF" "$((_RPT_CUTOFF - (_RPT_NOW - _RPT_CUTOFF)))"
}

# _report_format_top_ips pool_file cutoff limit
# Exports: REPORT_TOP_IPS_TEXT, REPORT_TOP_IPS_HTML, REPORT_TOP_IPS_BRIEF
_report_format_top_ips() {
	local pool_file="$1" cutoff="$2" limit="$3"

	if [ ! -f "$pool_file" ] || [ ! -s "$pool_file" ]; then
		export REPORT_TOP_IPS_TEXT=""
		export REPORT_TOP_IPS_HTML=""
		export REPORT_TOP_IPS_BRIEF="No activity."
		return 0
	fi

	# Use _apool_awk to aggregate — outputs: cnt|ip|first_ts|last_ts|rules_csv|cc
	local agg_data
	agg_data=$(_apool_awk "$pool_file" "" "$cutoff" "count" "$limit")
	if [ -z "$agg_data" ]; then
		export REPORT_TOP_IPS_TEXT="No threat IPs in this period."
		export REPORT_TOP_IPS_HTML="<p>No threat IPs in this period.</p>"
		export REPORT_TOP_IPS_BRIEF="No threat IPs."
		return 0
	fi

	# Initialize ban status batch lookup
	_batch_ban_status_init "${INSTALL_PATH:-}"

	# Build text table, HTML table, and brief in a single pass
	local text_table="COUNT|IP|COUNTRY|PRESSURE|RULES|STATUS"
	local html_rows="" brief="" brief_count=0 flag=""
	local cnt ip first_ts last_ts rules_csv cc ban_status
	local pressure_scaled pressure_fmt trip_val esc_ip esc_cc esc_rules
	# shellcheck disable=SC2034  # first_ts/last_ts: positional placeholders for pipe field ordering
	while IFS='|' read -r cnt ip first_ts last_ts rules_csv cc; do
		[ -z "$ip" ] && continue
		ban_status=$(_batch_ban_status_lookup "$ip")
		# Compute live pressure
		pressure_scaled=$(pressure_compute "${INSTALL_PATH:-}" "$ip" \
			"${PRESSURE_HALF_LIFE:-300}" "$_RPT_NOW")
		pressure_fmt=$(pressure_format "$pressure_scaled")
		trip_val=$(_resolve_min_trip "$rules_csv")
		text_table="${text_table}
${cnt}|${ip}|${cc:---}|${pressure_fmt}/${trip_val}|${rules_csv}|${ban_status:---}"
		# HTML row with entity escaping (defense-in-depth)
		esc_ip="${ip//&/&amp;}"; esc_ip="${esc_ip//</&lt;}"; esc_ip="${esc_ip//>/&gt;}"
		esc_cc="${cc//&/&amp;}"; esc_cc="${esc_cc//</&lt;}"
		esc_rules="${rules_csv//&/&amp;}"; esc_rules="${esc_rules//</&lt;}"
		html_rows="${html_rows}<tr><td>${cnt}</td><td>${esc_ip}</td><td>${esc_cc:---}</td><td>${esc_rules}</td></tr>
"
		# Brief: top 5 for messaging
		if [ "$brief_count" -lt 5 ]; then
			flag=""
			if [ -n "$cc" ] && [ "$cc" != "--" ] && type _alert_country_flag >/dev/null 2>&1; then
				flag=$(_alert_country_flag "$cc")
				flag="${flag:+$flag }"
			fi
			brief="${brief}${flag}${ip} -- ${cc:---} -- ${cnt} hits (${rules_csv})${ban_status:+ $ban_status}
"
			brief_count=$((brief_count + 1))
		fi
	done <<< "$agg_data"

	_batch_ban_status_cleanup

	export REPORT_TOP_IPS_TEXT
	REPORT_TOP_IPS_TEXT=$(echo "$text_table" | format_table)
	export REPORT_TOP_IPS_BRIEF="${brief%
}"
	export REPORT_TOP_IPS_HTML="<table><tr><th>COUNT</th><th>IP</th><th>COUNTRY</th><th>RULES</th></tr>
${html_rows}</table>"
}

# _report_format_services pool_file cutoff_a cutoff_b
# Exports: REPORT_SERVICES_TEXT, REPORT_SERVICES_HTML, REPORT_SERVICES_BRIEF
_report_format_services() {
	local pool_file="$1" cutoff_a="$2" cutoff_b="$3"

	if [ ! -f "$pool_file" ] || [ ! -s "$pool_file" ]; then
		export REPORT_SERVICES_TEXT=""
		export REPORT_SERVICES_HTML=""
		export REPORT_SERVICES_BRIEF="No services."
		return 0
	fi

	# _apool_service_dual_awk outputs: service|count_a|count_b|uniq_a|uniq_b|top_cc
	local svc_data
	svc_data=$(_apool_service_dual_awk "$pool_file" "$cutoff_a" "$cutoff_b")
	if [ -z "$svc_data" ]; then
		export REPORT_SERVICES_TEXT="No service activity."
		export REPORT_SERVICES_HTML="<p>No service activity.</p>"
		export REPORT_SERVICES_BRIEF="No services."
		return 0
	fi

	local text_table="SERVICE|EVENTS|UNIQUE IPS|TOP COUNTRY"
	local brief="" html_rows="" flag=""
	local svc cnt_a cnt_b uq_a uq_b top_cc esc_svc esc_cc
	# shellcheck disable=SC2034  # cnt_b/uq_b: positional placeholders for pipe field ordering
	while IFS='|' read -r svc cnt_a cnt_b uq_a uq_b top_cc; do
		[ -z "$svc" ] && continue
		text_table="${text_table}
${svc}|${cnt_a}|${uq_a}|${top_cc:---}"
		flag=""
		if [ -n "$top_cc" ] && [ "$top_cc" != "--" ] && type _alert_country_flag >/dev/null 2>&1; then
			flag=$(_alert_country_flag "$top_cc")
			flag="${flag:+$flag }"
		fi
		brief="${brief}${svc} -- ${cnt_a} events . ${uq_a} IPs . ${flag}${top_cc:---}
"
		# HTML row with entity escaping (defense-in-depth)
		esc_svc="${svc//&/&amp;}"; esc_svc="${esc_svc//</&lt;}"
		esc_cc="${top_cc//&/&amp;}"; esc_cc="${esc_cc//</&lt;}"
		html_rows="${html_rows}<tr><td>${esc_svc}</td><td>${cnt_a}</td><td>${uq_a}</td><td>${esc_cc:---}</td></tr>
"
	done <<< "$svc_data"

	export REPORT_SERVICES_TEXT
	REPORT_SERVICES_TEXT=$(echo "$text_table" | format_table)
	export REPORT_SERVICES_BRIEF="${brief%
}"
	export REPORT_SERVICES_HTML="<table><tr><th>SERVICE</th><th>EVENTS</th><th>UNIQUE IPS</th><th>TOP COUNTRY</th></tr>
${html_rows}</table>"
}

# ---------------------------------------------------------------------------
# Render Layer — assemble templates into report bodies
# ---------------------------------------------------------------------------

# _report_render_text tpl_dir — render text report to stdout
# Requires: all REPORT_* vars exported by _report_data()
_report_render_text() {
	local tpl_dir="$1"
	_alert_tpl_resolve "$tpl_dir" "report.text.header.tpl"
	if [ -f "$_ALERT_TPL_RESOLVED" ]; then
		_alert_tpl_render "$_ALERT_TPL_RESOLVED"
	fi
	_alert_tpl_resolve "$tpl_dir" "report.text.body.tpl"
	if [ -f "$_ALERT_TPL_RESOLVED" ]; then
		_alert_tpl_render "$_ALERT_TPL_RESOLVED"
	fi
}

# _report_render_html tpl_dir — render HTML report to stdout
_report_render_html() {
	local tpl_dir="$1"
	_alert_tpl_resolve "$tpl_dir" "report.html.header.tpl"
	if [ -f "$_ALERT_TPL_RESOLVED" ]; then
		_alert_tpl_render "$_ALERT_TPL_RESOLVED"
	fi
	_alert_tpl_resolve "$tpl_dir" "report.html.body.tpl"
	if [ -f "$_ALERT_TPL_RESOLVED" ]; then
		_alert_tpl_render "$_ALERT_TPL_RESOLVED"
	fi
}

# ---------------------------------------------------------------------------
# Deliver Layer — send reports to configured channels
# ---------------------------------------------------------------------------

# _report_deliver_email subject text_file html_file
# Wraps _alert_deliver_email with report-specific recipient handling.
_report_deliver_email() {
	local subject="$1" text_file="$2" html_file="$3"
	local recipient="${REPORT_EMAIL_ADDRESS:-${EMAIL_ADDRESS:-root}}"
	local format="${EMAIL_FORMAT:-text}"
	_alert_deliver_email "$recipient" "$subject" "$text_file" "$html_file" "$format"
}

# _report_dispatch_messaging tpl_dir subject
# Sends report to enabled messaging channels by resolving report-prefixed
# templates (report.slack.message.tpl, etc.) and calling handlers directly.
# Cannot use alert_dispatch() because it constructs filenames as
# ${channel}.message.tpl, which resolves ban-alert templates, not report templates.
_report_dispatch_messaging() {
	local tpl_dir="$1" subject="$2"
	local rc=0

	# Early exit if no messaging channels enabled
	if ! alert_channel_enabled "slack" && \
	   ! alert_channel_enabled "telegram" && \
	   ! alert_channel_enabled "discord"; then
		return 0
	fi

	# handler_map_* used via ${!handler_var} indirect expansion below
	# shellcheck disable=SC2034
	local handler_map_slack="_alert_handle_slack"
	# shellcheck disable=SC2034
	local handler_map_telegram="_alert_handle_telegram"
	# shellcheck disable=SC2034
	local handler_map_discord="_alert_handle_discord"

	local ch
	for ch in slack telegram discord; do
		alert_channel_enabled "$ch" || continue

		# Resolve report-prefixed template
		_alert_tpl_resolve "$tpl_dir" "report.${ch}.message.tpl"
		if [ ! -f "$_ALERT_TPL_RESOLVED" ]; then
			continue
		fi

		local text_file
		text_file=$(mktemp "${ALERT_TMPDIR:-${TMPDIR:-/tmp}}/rpt_${ch}.XXXXXX")
		_alert_tpl_render "$_ALERT_TPL_RESOLVED" > "$text_file"

		# Create empty html placeholder (handlers expect both files)
		local html_file
		html_file=$(mktemp "${ALERT_TMPDIR:-${TMPDIR:-/tmp}}/rpt_${ch}_h.XXXXXX")

		# Call channel handler
		local handler_var="handler_map_${ch}"
		if ! "${!handler_var}" "$subject" "$text_file" "$html_file" ""; then
			rc=1
		fi
		command rm -f "$text_file" "$html_file"
	done

	return $rc
}

# _report_channel_override — temporarily override channel registry per REPORT_CHANNELS
# Saves current state, then enables only the channels listed in REPORT_CHANNELS.
# Call _report_channel_restore to undo.
_report_channel_override() {
	_RPT_SAVED_SLACK=$(alert_channel_enabled "slack" && echo 1 || echo 0)
	_RPT_SAVED_TELEGRAM=$(alert_channel_enabled "telegram" && echo 1 || echo 0)
	_RPT_SAVED_DISCORD=$(alert_channel_enabled "discord" && echo 1 || echo 0)

	local channels=",${REPORT_CHANNELS:-},"
	if [[ "$channels" == *",slack,"* ]]; then
		alert_channel_enable "slack"
	else
		alert_channel_disable "slack"
	fi
	if [[ "$channels" == *",telegram,"* ]]; then
		alert_channel_enable "telegram"
	else
		alert_channel_disable "telegram"
	fi
	if [[ "$channels" == *",discord,"* ]]; then
		alert_channel_enable "discord"
	else
		alert_channel_disable "discord"
	fi
}

# _report_channel_restore — restore channel registry to pre-override state
_report_channel_restore() {
	if [ "${_RPT_SAVED_SLACK:-0}" = "1" ]; then
		alert_channel_enable "slack"
	else
		alert_channel_disable "slack"
	fi
	if [ "${_RPT_SAVED_TELEGRAM:-0}" = "1" ]; then
		alert_channel_enable "telegram"
	else
		alert_channel_disable "telegram"
	fi
	if [ "${_RPT_SAVED_DISCORD:-0}" = "1" ]; then
		alert_channel_enable "discord"
	else
		alert_channel_disable "discord"
	fi
}

# _report_deliver interval tpl_dir — render and deliver report to all channels
_report_deliver() {
	local interval="$1" tpl_dir="$2"

	# Render subject from template
	local subject_tpl="${REPORT_EMAIL_SUBJECT:-BFD {{INTERVAL}} Threat Report for {{HOSTNAME}}}"
	local subject_file
	subject_file=$(mktemp "${ALERT_TMPDIR:-${TMPDIR:-/tmp}}/.bfd_rpt_subj.XXXXXX")
	echo "$subject_tpl" > "$subject_file"
	# Export INTERVAL for subject template rendering
	export INTERVAL="$_RPT_LABEL"
	local subject
	subject=$(_alert_tpl_render "$subject_file")
	command rm -f "$subject_file"

	# Override channels if REPORT_CHANNELS is set
	local channels_overridden=0
	if [ -n "${REPORT_CHANNELS:-}" ]; then
		_report_channel_override
		channels_overridden=1
	fi

	# Email delivery
	local send_email=0
	if [ -n "${REPORT_CHANNELS:-}" ]; then
		case ",${REPORT_CHANNELS}," in
			*",email,"*) send_email=1 ;;
		esac
	else
		[ "${EMAIL_ALERTS:-0}" = "1" ] && send_email=1
	fi

	if [ "$send_email" = "1" ]; then
		local text_file html_file
		text_file=$(mktemp "${ALERT_TMPDIR:-${TMPDIR:-/tmp}}/.bfd_rpt_text.XXXXXX")
		html_file=$(mktemp "${ALERT_TMPDIR:-${TMPDIR:-/tmp}}/.bfd_rpt_html.XXXXXX")
		_report_render_text "$tpl_dir" > "$text_file"
		_report_render_html "$tpl_dir" > "$html_file"
		_report_deliver_email "$subject" "$text_file" "$html_file"
		command rm -f "$text_file" "$html_file"
	fi

	# Messaging delivery
	_report_dispatch_messaging "$tpl_dir" "$subject"

	# Restore channels if overridden
	if [ "$channels_overridden" = "1" ]; then
		_report_channel_restore
	fi
}

# ---------------------------------------------------------------------------
# Public Entry Point
# ---------------------------------------------------------------------------

# report interval — generate and deliver periodic threat report
# Called from CLI: bfd --report [daily|weekly|monthly]
report() {
	local interval="${1:-daily}"

	# Init — validate interval, compute windows
	_report_init "$interval" || return $?

	local pool_file="${APOOL_LIST:-${INSTALL_PATH:-/usr/local/bfd}/stats/attack.pool}"
	local tpl_dir="${ALERT_TEMPLATE_DIR:-${INSTALL_PATH:-/usr/local/bfd}/alert}"

	# Set global template vars (HOSTNAME, TIMESTAMP, BFD_VERSION, etc.)
	_alert_set_global_vars 0

	# Empty pool — short-circuit with no-activity message
	if [ ! -f "$pool_file" ] || [ ! -s "$pool_file" ]; then
		echo "BFD $_RPT_LABEL Threat Report for ${HOSTNAME:-$(hostname)}"
		local start_fmt end_fmt
		start_fmt=$(date -d "@$_RPT_CUTOFF" +"%Y-%m-%d %H:%M" 2>/dev/null || echo "$_RPT_CUTOFF")  # fallback for non-GNU date
		end_fmt=$(date -d "@$_RPT_NOW" +"%Y-%m-%d %H:%M" 2>/dev/null || echo "$_RPT_NOW")  # fallback for non-GNU date
		echo "Period: $start_fmt -- $end_fmt ($_RPT_WINDOW)"
		echo ""
		echo "No threat activity recorded in this period."
		return 0
	fi

	# Gather data — export all REPORT_* vars
	_report_data "$pool_file"

	# Text output to stdout (always — CLI use)
	_report_render_text "$tpl_dir"

	# Deliver via email + messaging
	_report_deliver "$interval" "$tpl_dir"

	# Log report generation
	if type eout >/dev/null 2>&1; then
		eout "$_RPT_LABEL report generated: $REPORT_UNIQUE_IPS IPs, $REPORT_TOTAL_EVENTS events" le
	fi
}
