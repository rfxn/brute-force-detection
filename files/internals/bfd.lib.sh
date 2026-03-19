#!/bin/bash
#
# Brute Force Detection 2.0.2 - Function Library
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
# This file is sourced by bfd and test scripts.
# Functions here are defined but not called; callers invoke as needed.

# Source sibling libraries (all co-located in internals/)
_internals_dir="${BASH_SOURCE[0]%/*}"

# Source shared tlog library
if [ -f "$_internals_dir/tlog_lib.sh" ]; then
	# shellcheck disable=SC1091
	. "$_internals_dir/tlog_lib.sh"
fi

# Source shared elog library
if [ -f "$_internals_dir/elog_lib.sh" ]; then
	# shellcheck disable=SC1091
	. "$_internals_dir/elog_lib.sh"
fi

# Source shared alert library (template engine, MIME, delivery, channel registry)
if [ -f "$_internals_dir/alert_lib.sh" ]; then
	# shellcheck disable=SC1091
	. "$_internals_dir/alert_lib.sh"
fi

# Source BFD-specific alert functions (content helpers, rendering, digest wrappers)
if [ -f "$_internals_dir/bfd_alert.sh" ]; then
	# shellcheck disable=SC1091
	. "$_internals_dir/bfd_alert.sh"
fi

# Source shared GeoIP metadata library (country names, continents, validation)
if [ -f "$_internals_dir/geoip_lib.sh" ]; then
	# shellcheck disable=SC1091
	. "$_internals_dir/geoip_lib.sh"
fi

# Source BFD report functions (periodic threat reports)
if [ -f "$_internals_dir/bfd_report.sh" ]; then
	# shellcheck disable=SC1091
	. "$_internals_dir/bfd_report.sh"
fi

# Source BFD input and config validation
if [ -f "$_internals_dir/bfd_validate.sh" ]; then
	# shellcheck disable=SC1091
	. "$_internals_dir/bfd_validate.sh"
fi

# Source BFD firewall backend abstraction
if [ -f "$_internals_dir/bfd_fw.sh" ]; then
	# shellcheck disable=SC1091
	. "$_internals_dir/bfd_fw.sh"
fi

# Source BFD state I/O and ban execution
if [ -f "$_internals_dir/bfd_state.sh" ]; then
	# shellcheck disable=SC1091
	. "$_internals_dir/bfd_state.sh"
fi

# Source BFD pressure model and rule infrastructure
if [ -f "$_internals_dir/bfd_pressure.sh" ]; then
	# shellcheck disable=SC1091
	. "$_internals_dir/bfd_pressure.sh"
fi

# Source BFD detection pipeline
if [ -f "$_internals_dir/bfd_detect.sh" ]; then
	# shellcheck disable=SC1091
	. "$_internals_dir/bfd_detect.sh"
fi

# Source BFD event queries and attack pool
if [ -f "$_internals_dir/bfd_events.sh" ]; then
	# shellcheck disable=SC1091
	. "$_internals_dir/bfd_events.sh"
fi

# Source BFD health check, status, and diagnostics
if [ -f "$_internals_dir/bfd_diag.sh" ]; then
	# shellcheck disable=SC1091
	. "$_internals_dir/bfd_diag.sh"
fi

# _bfd_journal_register_all: populate journal filter mappings for all BFD rules
# Wrapped in a function so reload_watch can re-register after clearing arrays
_bfd_journal_register_all() {
	tlog_journal_register "sshd" "SYSLOG_IDENTIFIER=sshd"
	tlog_journal_register "dropbear" "SYSLOG_IDENTIFIER=dropbear"
	tlog_journal_register "dovecot" "SYSLOG_IDENTIFIER=dovecot"
	tlog_journal_register "postfix" "SYSLOG_IDENTIFIER=postfix"
	tlog_journal_register "courier" "SYSLOG_IDENTIFIER=couriertcpd"
	tlog_journal_register "sendmail" "SYSLOG_IDENTIFIER=sm-mta"
	tlog_journal_register "vpopmail" "SYSLOG_IDENTIFIER=vpopmail"
	tlog_journal_register "cyrus" "SYSLOG_IDENTIFIER=cyrus"
	tlog_journal_register "pure-ftpd" "SYSLOG_IDENTIFIER=pure-ftpd"
	tlog_journal_register "proftpd" "SYSLOG_IDENTIFIER=proftpd"
	tlog_journal_register "vsftpd" "SYSLOG_IDENTIFIER=vsftpd"
	tlog_journal_register "webmin" "SYSLOG_IDENTIFIER=webmin"
	tlog_journal_register "wordpress" "SYSLOG_IDENTIFIER=wordpress"
	tlog_journal_register "rh_imapd" "SYSLOG_IDENTIFIER=imapd"
	tlog_journal_register "rh_ipop3" "SYSLOG_IDENTIFIER=ipop3d"
	tlog_journal_register "named" "SYSLOG_IDENTIFIER=named"
	tlog_journal_register "openvpn" "SYSLOG_IDENTIFIER=openvpn"
	tlog_journal_register "exim_authfail" "SYSLOG_IDENTIFIER=exim4 + SYSLOG_IDENTIFIER=exim"
	tlog_journal_register "exim_nxuser" "SYSLOG_IDENTIFIER=exim4 + SYSLOG_IDENTIFIER=exim"
	tlog_journal_register "cockpit" "SYSLOG_IDENTIFIER=cockpit-ws"
	tlog_journal_register "gitea" "SYSLOG_IDENTIFIER=gitea"
	tlog_journal_register "postscreen" "SYSLOG_IDENTIFIER=postfix/postscreen"
	tlog_journal_register "xrdp" "SYSLOG_IDENTIFIER=xrdp-sesman"
	tlog_journal_register "asterisk" "SYSLOG_IDENTIFIER=asterisk"
	tlog_journal_register "asterisk.iax" "SYSLOG_IDENTIFIER=asterisk"
	tlog_journal_register "asterisk_nopeer" "SYSLOG_IDENTIFIER=asterisk"
	tlog_journal_register "vaultwarden" "SYSLOG_IDENTIFIER=vaultwarden"
	tlog_journal_register "guacamole" "SYSLOG_IDENTIFIER=guacamole-client"
	tlog_journal_register "haproxy" "SYSLOG_IDENTIFIER=haproxy"
	tlog_journal_register "squid" "SYSLOG_IDENTIFIER=squid"
	tlog_journal_register "sogod" "SYSLOG_IDENTIFIER=sogod"
	tlog_journal_register "freeswitch" "SYSLOG_IDENTIFIER=freeswitch"
	tlog_journal_register "ejabberd" "SYSLOG_IDENTIFIER=ejabberd"
	tlog_journal_register "drupal" "SYSLOG_IDENTIFIER=drupal"
	tlog_journal_register "jellyfin" "SYSLOG_IDENTIFIER=jellyfin"
	tlog_journal_register "pdns" "SYSLOG_IDENTIFIER=pdns_server"
	tlog_journal_register "proxmox" "SYSLOG_IDENTIFIER=pvedaemon + SYSLOG_IDENTIFIER=pveproxy"
	tlog_journal_register "phpmyadmin" "SYSLOG_IDENTIFIER=phpmyadmin"
}
# Register at module load
_bfd_journal_register_all

# exit codes (used by bfd, exported for callers)
# shellcheck disable=SC2034
EXIT_OK=0
# shellcheck disable=SC2034
EXIT_CONFIG_ERROR=1
# shellcheck disable=SC2034
EXIT_LOCK_ERROR=2
# shellcheck disable=SC2034
EXIT_PREREQ_ERROR=3

# eout(message [, "le"])
# Backward-compatible wrapper delegating to elog().
# Contract: always echo to stdout; "le" = also write to log + syslog.
# Syncs BFD config vars (OUTPUT_SYSLOG, BFD_LOG_PATH) to ELOG at call time
# so tests that change these mid-flight still work.
eout() {
	local _msg="${1:-}"
	local _flag="${2:-}"
	[ -z "$_msg" ] && return 0
	if [ "$_flag" = "le" ]; then
		ELOG_LOG_FILE="${BFD_LOG_PATH:-}"
		if [ "${OUTPUT_SYSLOG:-0}" = "1" ]; then
			ELOG_SYSLOG_FILE="${OUTPUT_SYSLOG_FILE:-}"
		else
			ELOG_SYSLOG_FILE=""
		fi
		elog info "$_msg"
	elif [ "$_flag" = "l" ]; then
		# log-file-only: write to BFD log but skip syslog
		ELOG_LOG_FILE="${BFD_LOG_PATH:-}"
		ELOG_SYSLOG_FILE=""
		elog info "$_msg"
	else
		# stdout-only: bypass file logging
		local _saved_log="${ELOG_LOG_FILE:-}"
		local _saved_syslog="${ELOG_SYSLOG_FILE:-}"
		ELOG_LOG_FILE=""
		ELOG_SYSLOG_FILE=""
		elog info "$_msg"
		ELOG_LOG_FILE="$_saved_log"
		ELOG_SYSLOG_FILE="$_saved_syslog"
	fi
}

# vout — verbose-only output via elog debug level
# Syncs VERBOSE to ELOG_VERBOSE so callers setting VERBOSE=1 still work.
vout() {
	# shellcheck disable=SC2034
	ELOG_VERBOSE="${VERBOSE:-0}"
	elog debug "$*"
}

format_table() {
	if command -v column >/dev/null 2>&1; then
		column -s '|' -t
	else
		tr '|' '\t'
	fi
}

# _fmt_ts epoch — format epoch as short human-readable timestamp for text tables
# Returns "mm/dd/yy HH:MM:SS" or the raw epoch on failure.
_fmt_ts() {
	date -d "@$1" +"%D %H:%M:%S" 2>/dev/null || echo "$1"
}

# _fmt_ts_iso epoch — format epoch as ISO 8601 timestamp for JSON/CSV output
# Returns "YYYY-MM-DDTHH:MM:SS" or the raw epoch on failure.
_fmt_ts_iso() {
	date -d "@$1" +"%Y-%m-%dT%H:%M:%S" 2>/dev/null || echo "$1"
}

# --- Structured output formatters ---

# _json_escape str — escape string for JSON output (RFC 8259 §7)
_json_escape() {
	local s="$1"
	s="${s//\\/\\\\}"
	s="${s//\"/\\\"}"
	s="${s//$'\n'/\\n}"
	s="${s//$'\t'/\\t}"
	s="${s//$'\r'/\\r}"
	s="${s//$'\b'/\\b}"
	s="${s//$'\f'/\\f}"
	echo "$s"
}

# _json_array_from_csv csv_string — convert "sshd,dovecot" to ["sshd","dovecot"]
_json_array_from_csv() {
	local csv="$1"
	if [ -z "$csv" ]; then
		echo "[]"
		return
	fi
	local result="[" first=1
	local IFS=','
	local item
	for item in $csv; do
		if [ "$first" -eq 1 ]; then
			first=0
		else
			result="$result,"
		fi
		result="$result\"$(_json_escape "$item")\""
	done
	echo "${result}]"
}

