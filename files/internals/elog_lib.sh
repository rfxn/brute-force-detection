#!/bin/bash
#
# elog_lib.sh — Structured Logging Library 1.0.0
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
# Shared structured logging library for rfxn projects.
# Source this file after setting ELOG_* configuration variables.
# No project-specific code — all behavior controlled via variables.

# Source guard — safe for repeated sourcing
# shellcheck disable=SC2154
[[ -n "${_ELOG_LIB_LOADED:-}" ]] && return 0 2>/dev/null
_ELOG_LIB_LOADED=1
# shellcheck disable=SC2034 # version checked by consumers
ELOG_LIB_VERSION="1.0.0"

# --- Configuration variables (set by consumer before sourcing) ---
# All use ${VAR:-default} — safe when sourced from inside functions (BATS).
#
# ELOG_APP          — app name in log lines (default: basename $0)
# ELOG_LOG_FILE     — primary log file path (empty = no file logging)
# ELOG_SYSLOG_FILE  — secondary syslog output file (empty = disabled)
# ELOG_LEVEL        — minimum severity: 0=debug 1=info 2=warn 3=error 4=critical (default: 1)
# ELOG_VERBOSE      — when "1", debug-level messages emit to stdout (default: 0)
# ELOG_FORMAT       — "classic" or "json" (default: classic)
# ELOG_TS_FORMAT    — date strftime format (default: "%b %e %H:%M:%S")
# ELOG_STDOUT       — "always"|"never"|"flag" (default: always)
# ELOG_STDOUT_PREFIX — "full"|"short"|"none" (default: full)

# --- Internal functions ---

# _elog_level_num(name) — maps level name to numeric value
# Returns: 0=debug, 1=info, 2=warn, 3=error, 4=critical; unknown defaults to 1
_elog_level_num() {
	case "${1:-info}" in
		debug)    echo 0 ;;
		info)     echo 1 ;;
		warn)     echo 2 ;;
		error)    echo 3 ;;
		critical) echo 4 ;;
		*)        echo 1 ;;
	esac
}

# _elog_level_name(num) — maps numeric value to level name
_elog_level_name() {
	case "${1:-1}" in
		0) echo "debug" ;;
		1) echo "info" ;;
		2) echo "warn" ;;
		3) echo "error" ;;
		4) echo "critical" ;;
		*) echo "info" ;;
	esac
}

# _elog_json_escape(str) — escape string for safe JSON embedding
# Handles: backslash, double-quote, newline, tab, carriage return
_elog_json_escape() {
	local s="$1"
	s="${s//\\/\\\\}"
	s="${s//\"/\\\"}"
	s="${s//$'\n'/\\n}"
	s="${s//$'\t'/\\t}"
	s="${s//$'\r'/\\r}"
	echo "$s"
}

# _elog_extract_tag(msg) — extract {tag} prefix from message
# Returns the tag name (without braces), or empty if no tag found
_elog_extract_tag() {
	local msg="$1"
	local tag_pat='^\{([^}]+)\}'
	if [[ "$msg" =~ $tag_pat ]]; then
		echo "${BASH_REMATCH[1]}"
	fi
}

# _elog_strip_tag(msg) — strip {tag} prefix (and trailing space) from message
_elog_strip_tag() {
	local msg="$1"
	local tag_pat='^\{[^}]+\} '
	if [[ "$msg" =~ $tag_pat ]]; then
		echo "${msg#"${BASH_REMATCH[0]}"}"
	else
		echo "$msg"
	fi
}

# --- Public functions ---

# elog(level, message [, stdout_flag])
# Primary logging function.
#
# Levels: debug, info, warn, error, critical
# - debug: stdout only (bare text), gated by ELOG_VERBOSE=1, never writes to files
# - info+: formatted output to file, syslog, and/or stdout per configuration
#
# Returns 0 always (logging must never cause caller failure).
elog() {
	local _level="${1:-info}"
	local _msg="${2:-}"
	local _stdout_flag="${3:-}"

	# empty message — no output
	[ -z "$_msg" ] && return 0

	local _level_num
	_level_num=$(_elog_level_num "$_level")

	# debug level: stdout only (bare text), gated solely by ELOG_VERBOSE
	# (not subject to ELOG_LEVEL filtering — ELOG_VERBOSE is its own gate)
	if [ "$_level_num" -eq 0 ]; then
		if [ "${ELOG_VERBOSE:-0}" = "1" ]; then
			echo "$_msg"
		fi
		return 0
	fi

	local _min_level="${ELOG_LEVEL:-1}"

	# below minimum severity — suppress
	[ "$_level_num" -lt "$_min_level" ] && return 0

	# info+ levels: format and route
	local _ts _host _app _pid _line
	_ts=$(date +"${ELOG_TS_FORMAT:-%b %e %H:%M:%S}")
	_host=$(hostname -s)
	_app="${ELOG_APP:-${0##*/}}"
	_pid="$$"

	local _format="${ELOG_FORMAT:-classic}"

	if [ "$_format" = "json" ]; then
		# JSON format (JSONL — one object per line)
		local _esc_msg _tag _esc_tag _json_msg
		_tag=$(_elog_extract_tag "$_msg")
		if [ -n "$_tag" ]; then
			_json_msg=$(_elog_strip_tag "$_msg")
		else
			_json_msg="$_msg"
		fi
		_esc_msg=$(_elog_json_escape "$_json_msg")
		local _iso_ts
		_iso_ts=$(date +"%Y-%m-%dT%H:%M:%S%z")
		if [ -n "$_tag" ]; then
			_esc_tag=$(_elog_json_escape "$_tag")
			_line="{\"ts\":\"${_iso_ts}\",\"host\":\"${_host}\",\"app\":\"${_app}\",\"pid\":${_pid},\"level\":\"${_level}\",\"tag\":\"${_esc_tag}\",\"msg\":\"${_esc_msg}\"}"
		else
			_line="{\"ts\":\"${_iso_ts}\",\"host\":\"${_host}\",\"app\":\"${_app}\",\"pid\":${_pid},\"level\":\"${_level}\",\"msg\":\"${_esc_msg}\"}"
		fi
	else
		# Classic syslog-style format
		_line="$_ts $_host ${_app}(${_pid}): $_msg"
	fi

	# Write to primary log file
	if [ -n "${ELOG_LOG_FILE:-}" ]; then
		echo "$_line" >> "$ELOG_LOG_FILE"
	fi

	# Write to syslog file
	if [ -n "${ELOG_SYSLOG_FILE:-}" ]; then
		echo "$_line" >> "$ELOG_SYSLOG_FILE"
	fi

	# Stdout routing
	local _stdout="${ELOG_STDOUT:-always}"
	case "$_stdout" in
		always)
			;;
		never)
			return 0
			;;
		flag)
			[ -z "$_stdout_flag" ] && return 0
			;;
	esac

	# Stdout prefix handling
	local _prefix="${ELOG_STDOUT_PREFIX:-full}"
	case "$_prefix" in
		full)
			echo "$_line"
			;;
		short)
			echo "${_app}(${_pid}): $_msg"
			;;
		none)
			echo "$_msg"
			;;
	esac

	return 0
}

# Convenience wrappers
elog_debug() { elog debug "$@"; }
elog_info()  { elog info "$@"; }
elog_warn()  { elog warn "$@"; }
elog_error() { elog error "$@"; }
