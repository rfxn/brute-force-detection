#!/bin/bash
#
# Brute Force Detection 2.0.2 - Core Orchestration
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
# Sourced by bfd.lib.sh. Provides config initialization, the main detection cycle,
# run/watch mode orchestration, journal registration, and cleanup handlers.

# Source guard — prevent double-sourcing
[[ -n "${_BFD_CORE_LOADED:-}" ]] && return 0 2>/dev/null
_BFD_CORE_LOADED=1

# shellcheck disable=SC2034
BFD_CORE_VERSION="1.0.0"

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
	# pam_generic: PAM logs under the calling service's SYSLOG_IDENTIFIER, not its
	# own — no single identifier captures all PAM auth failures. Use authpriv
	# facility (10) as the broadest correct filter; extract_hosts pattern is tight.
	tlog_journal_register "pam" "SYSLOG_FACILITY=10"
}

_cleanup_common() {
	command rm -rf "$LOCK_FILE.lk" 2>/dev/null
	command rm -f "$LOCK_FILE" 2>/dev/null
	command rm -f "${_IGNORE_CACHE_FILE:-}" 2>/dev/null
}

# shellcheck disable=SC2317 # called via trap
cleanup() {
	_cleanup_common
	# remove per-rule temp files that may remain after abnormal exit
	command rm -f "$INSTALL_PATH/tmp/.uniq_ips."* \
		"$INSTALL_PATH/tmp/.pressure_buf."* \
		"$INSTALL_PATH/tmp/.pool_buf."* 2>/dev/null  # safe if glob expands to nothing
}

# config_init [reload]
# Source config files, derive variables, load pressure arrays, validate,
# and set up firewall backend. When reload=1, unset all config variables
# first so removed settings revert to defaults. Returns non-zero on failure.
config_init() {
	local _reload="${1:-0}"

	# On reload: pre-validate syntax before unsetting anything
	if [ "$_reload" = "1" ]; then
		if ! bash -n "$CNF" 2>/dev/null; then
			echo "error: conf.bfd has syntax errors, reload aborted." >&2
			return "$EXIT_CONFIG_ERROR"
		fi
		if [ -f "$INTCNF" ] && ! bash -n "$INTCNF" 2>/dev/null; then
			echo "error: internals.conf has syntax errors, reload aborted." >&2
			return "$EXIT_CONFIG_ERROR"
		fi
		# Pre-check ownership/permissions before unsetting anything
		if ! _check_file_safety "$CNF"; then
			echo "error: conf.bfd has unsafe ownership (uid=$_CSAF_UID) or permissions ($_CSAF_PERMS), reload aborted." >&2
			return "$EXIT_CONFIG_ERROR"
		fi
		# Unset ALL config variables for clean re-read (F-010)
		# conf.bfd variables
		unset PRESSURE_TRIP PRESSURE_HALF_LIFE PRESSURE_TRIP_GLOBAL
		unset BAN_TTL BAN_ESCALATE_AFTER BAN_ESCALATE_WINDOW
		unset BAN_ESCALATION BAN_ESCALATION_CAP
		unset EMAIL_ALERTS EMAIL_ADDRESS EMAIL_SUBJECT EMAIL_LOGLINES
		unset EMAIL_FORMAT EMAIL_DIGEST EMAIL_DIGEST_INTERVAL
		unset EMAIL_REPUTATION_LINKS
		unset SMTP_RELAY SMTP_USER SMTP_PASS SMTP_FROM
		unset FIREWALL
		unset BAN_COMMAND UNBAN_COMMAND BAN_COMMAND_V6 UNBAN_COMMAND_V6
		unset AUTH_LOG_PATH KERNEL_LOG_PATH MAIL_LOG_PATH BFD_LOG_PATH
		unset OUTPUT_SYSLOG LOG_FORMAT LOG_LEVEL
		unset WATCH_INTERVAL SCAN_MAX_LINES SCAN_TIMEOUT
		unset SUBNET_TRIG SUBNET_MASK SUBNET_MASK_V6
		# legacy compat aliases
		unset TRIG TRIG_WINDOW TRIG_GLOBAL
		unset BAN_DURATION BAN_PERMANENT_AFTER BAN_PERMANENT_WINDOW
		unset APOOL_RETENTION_DAYS APOOL_MAX_LINES
		# elog_lib canonical vars
		unset ELOG_LOG_DIR ELOG_AUDIT_FILE ELOG_LOG_MAX_LINES
		# messaging config vars (new in conf.bfd)
		unset SLACK_ALERTS SLACK_MODE SLACK_WEBHOOK_URL SLACK_TOKEN SLACK_CHANNEL
		unset TELEGRAM_ALERTS TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID
		unset DISCORD_ALERTS DISCORD_WEBHOOK_URL
		# report config vars
		unset REPORT_ENABLED REPORT_INTERVALS REPORT_CHANNELS
		unset REPORT_EMAIL_ADDRESS REPORT_EMAIL_SUBJECT REPORT_TOP_N
		# log + internal overrides
		unset LOG_IDLE_SUPPRESS SUBNET_ALERT_TOP_N
		unset CDN_ENABLE CDN_UPDATE_DAYS
		# alert_lib mapped env vars (set by _bfd_alert_init)
		unset ALERT_SMTP_RELAY ALERT_SMTP_FROM ALERT_SMTP_USER ALERT_SMTP_PASS
		unset ALERT_SLACK_MODE ALERT_SLACK_WEBHOOK_URL ALERT_SLACK_TOKEN ALERT_SLACK_CHANNEL
		unset ALERT_TELEGRAM_BOT_TOKEN ALERT_TELEGRAM_CHAT_ID ALERT_DISCORD_WEBHOOK_URL
		# internals.conf variables
		unset RULES_PATH TLOG_PATH TLOG_BASERUN
		unset ALERT_TEMPLATE_DIR ALERT_SPOOL_FILE IGNORE_HOST_FILES LOCK_FILE
		unset PRESSURE_CONF TIME_ZONE
		unset LOCK_FILE_TIMEOUT OUTPUT_SYSLOG_FILE BAN_RETRY_COUNT LOG_SOURCE
	fi

	# Source conf.bfd (with safety checks)
	if [ ! -f "$CNF" ]; then
		echo "error: could not find $CNF." >&2
		return "$EXIT_CONFIG_ERROR"
	fi
	if ! _check_file_safety "$CNF"; then
		echo "error: conf.bfd has unsafe ownership (uid=$_CSAF_UID) or permissions ($_CSAF_PERMS)." >&2
		return "$EXIT_CONFIG_ERROR"
	fi
	# shellcheck disable=SC1090
	. "$CNF"

	# Source internals.conf
	if [ -f "$INTCNF" ]; then
		if _check_file_safety "$INTCNF"; then
			# shellcheck disable=SC1090
			. "$INTCNF"
		else
			echo "warning: internals.conf has unsafe ownership or permissions, using defaults." >&2
		fi
	fi

	# Fallbacks for internals.conf variables
	RULES_PATH="${RULES_PATH:-$INSTALL_PATH/rules}"
	TLOG_PATH="${TLOG_PATH:-$INSTALL_PATH/tlog}"
	TLOG_BASERUN="${TLOG_BASERUN:-$INSTALL_PATH/tmp}"
	ALERT_TEMPLATE_DIR="${ALERT_TEMPLATE_DIR:-$INSTALL_PATH/alert}"
	ALERT_SPOOL_FILE="${ALERT_SPOOL_FILE:-$INSTALL_PATH/tmp/.alert_spool}"
	IGNORE_HOST_FILES="${IGNORE_HOST_FILES:-$INSTALL_PATH/exclude.files}"
	LOCK_FILE="${LOCK_FILE:-$INSTALL_PATH/lock.utime}"
	TIME_ZONE="${TIME_ZONE:-$(date +"%z")}"
	LOCK_FILE_TIMEOUT="${LOCK_FILE_TIMEOUT:-300}"
	OUTPUT_SYSLOG_FILE="${OUTPUT_SYSLOG_FILE:-$KERNEL_LOG_PATH}"
	BAN_RETRY_COUNT="${BAN_RETRY_COUNT:-2}"
	LOG_SOURCE="${LOG_SOURCE:-auto}"
	export LOG_SOURCE

	# ELOG config derived from conf.bfd values — consumed by sourced elog_lib.sh
	# shellcheck disable=SC2034
	ELOG_LOG_FILE="$BFD_LOG_PATH"
	# Legacy log path — elog_init creates symlink if this path doesn't exist yet
	# shellcheck disable=SC2034
	ELOG_LEGACY_LOG="/var/log/bfd_log"
	# shellcheck disable=SC2034
	ELOG_SYSLOG_FILE=""
	# shellcheck disable=SC2034
	[ "${OUTPUT_SYSLOG:-0}" = "1" ] && ELOG_SYSLOG_FILE="$OUTPUT_SYSLOG_FILE"
	# shellcheck disable=SC2034
	ELOG_FORMAT="${LOG_FORMAT:-classic}"
	# shellcheck disable=SC2034
	ELOG_LEVEL="${LOG_LEVEL:-1}"

	# Structured logging: directory and audit trail (elog_lib canonical)
	ELOG_LOG_DIR="${ELOG_LOG_DIR:-/var/log/bfd}"
	# shellcheck disable=SC2034
	ELOG_AUDIT_FILE="${ELOG_AUDIT_FILE:-${ELOG_LOG_DIR}/audit.log}"
	# shellcheck disable=SC2034
	ELOG_LOG_MAX_LINES="${ELOG_LOG_MAX_LINES:-50000}"

	# Initialize log environment (creates dirs, files, enables output modules)
	if ! elog_init; then
		elog warn "elog_init: log directory setup failed; structured event logging may be unavailable"
	fi
	# Always enable syslog_file module — eout() dynamically sets ELOG_SYSLOG_FILE
	# per call; handler checks var at write time (empty = skip)
	# safe: "already enabled" stderr if elog_init() already enabled this module; no-op
	elog_output_enable "syslog_file" 2>/dev/null || true  # no-op if already enabled
	# Enable stdout module — eout() contract expects bare eout() to echo to stdout;
	# safe: stdout module pre-registered at elog_lib load, stderr if already enabled
	elog_output_enable "stdout" 2>/dev/null || true  # safe: no-op if already active

	# Symlink farm self-healing — verify sbin symlinks on every startup (pkg_lib v1.0.6)
	# Non-fatal: if BFD is already running, the invoking symlink works; log and continue
	pkg_fhs_verify_farm "$INSTALL_PATH/internals/.symlink-manifest" \
		|| elog warn "symlink farm verification failed; run install.sh to repair"

	# Backward compat mapping (old v1.5 names -> new names)
	PRESSURE_TRIP="${PRESSURE_TRIP:-${TRIG:-20}}"
	PRESSURE_HALF_LIFE="${PRESSURE_HALF_LIFE:-${TRIG_WINDOW:-300}}"
	PRESSURE_TRIP_GLOBAL="${PRESSURE_TRIP_GLOBAL:-${TRIG_GLOBAL:-0}}"
	BAN_TTL="${BAN_TTL:-${BAN_DURATION:-600}}"
	BAN_ESCALATE_AFTER="${BAN_ESCALATE_AFTER:-${BAN_PERMANENT_AFTER:-5}}"
	BAN_ESCALATE_WINDOW="${BAN_ESCALATE_WINDOW:-${BAN_PERMANENT_WINDOW:-86400}}"
	GLOB_PRESSURE_TRIP="$PRESSURE_TRIP"
	TRIG="${TRIG:-$PRESSURE_TRIP}"
	TRIG_WINDOW="${TRIG_WINDOW:-$PRESSURE_HALF_LIFE}"
	TRIG_GLOBAL="${TRIG_GLOBAL:-$PRESSURE_TRIP_GLOBAL}"
	BAN_DURATION="${BAN_DURATION:-$BAN_TTL}"
	BAN_PERMANENT_AFTER="${BAN_PERMANENT_AFTER:-$BAN_ESCALATE_AFTER}"
	BAN_PERMANENT_WINDOW="${BAN_PERMANENT_WINDOW:-$BAN_ESCALATE_WINDOW}"
	# shellcheck disable=SC2034 # GLOB_TRIG read by bfd_pressure.sh
	GLOB_TRIG="$TRIG"

	# Pressure arrays (clear + reload)
	_PRESS_WEIGHT=()
	_PRESS_TRIP=()
	_PRESS_SKIP_ALERT=()
	_PRESS_RULE_EMAIL=()
	if [ -f "${PRESSURE_CONF:-$INSTALL_PATH/pressure.conf}" ]; then
		_load_pressure_conf "${PRESSURE_CONF:-$INSTALL_PATH/pressure.conf}"
	fi

	# BAN_COMMAND templates — consumed by bfd_fw.sh and bfd_state.sh
	# shellcheck disable=SC2034 # BAN_COMMAND_TEMPLATE used by bfd_fw.sh
	BAN_COMMAND_TEMPLATE=$(extract_command_template "$CNF" "BAN_COMMAND")
	# shellcheck disable=SC2034
	UNBAN_COMMAND_TEMPLATE=$(extract_command_template "$CNF" "UNBAN_COMMAND")
	# shellcheck disable=SC2034 # BAN_COMMAND_V6_TEMPLATE used by bfd_fw.sh
	BAN_COMMAND_V6_TEMPLATE=$(extract_command_template "$CNF" "BAN_COMMAND_V6")
	# shellcheck disable=SC2034
	UNBAN_COMMAND_V6_TEMPLATE=$(extract_command_template "$CNF" "UNBAN_COMMAND_V6")

	# Validate and set up
	validate_config || return $?
	detect_log_paths
	fw_resolve_backend
	if ! fw_setup; then
		elog warn "firewall backend '$_FW_BACKEND' failed to initialize; bans will not work"
	fi

	# Initialize alert channel config mapping
	_bfd_alert_init

	# Re-register journal filters on reload (F-057)
	if [ "$_reload" = "1" ]; then
		_TLOG_JOURNAL_NAMES=()
		_TLOG_JOURNAL_FILTERS=()
		_bfd_journal_register_all
	fi

	return 0
}

pre() {
if [ ! -f "$TLOG_PATH" ]; then
	elog error "could not locate \$TLOG_PATH, aborting."
	exit "$EXIT_PREREQ_ERROR"
fi
if [ ! -f "$INSTALL_PATH/internals/tlog_lib.sh" ]; then
	elog error "could not locate tlog_lib.sh, aborting."
	exit "$EXIT_PREREQ_ERROR"
fi
if [ ! -d "$RULES_PATH" ]; then
	elog error "could not locate \$RULES_PATH, aborting."
	exit "$EXIT_PREREQ_ERROR"
fi
if [ ! -d "$TLOG_BASERUN" ]; then
	command mkdir -p "$TLOG_BASERUN"
	command chmod 750 "$TLOG_BASERUN"
fi
# one-time log path migration: /var/log/bfd_log → /var/log/bfd/bfd.log
# v1.x used a flat file; v2.x consolidates into the elog log directory.
# Moves content to new path and leaves a symlink at the old location so
# external log parsers, logrotate entries, and muscle memory still work.
_LEGACY_LOG="/var/log/bfd_log"
if [ -f "$_LEGACY_LOG" ] && [ ! -L "$_LEGACY_LOG" ] && [ "$BFD_LOG_PATH" = "/var/log/bfd/bfd.log" ]; then
	command mkdir -p /var/log/bfd
	command chmod 750 /var/log/bfd
	if [ -s "$BFD_LOG_PATH" ]; then
		# both exist with content — prepend old (chronologically earlier) before new
		command cat "$_LEGACY_LOG" "$BFD_LOG_PATH" > "${BFD_LOG_PATH}.mig"
		command mv -f "${BFD_LOG_PATH}.mig" "$BFD_LOG_PATH"
	else
		command mv -f "$_LEGACY_LOG" "$BFD_LOG_PATH"
	fi
	command chmod 640 "$BFD_LOG_PATH"
	command ln -sf "$BFD_LOG_PATH" "$_LEGACY_LOG"
fi

if [ ! -f "$BFD_LOG_PATH" ]; then
	command touch "$BFD_LOG_PATH"
	command chmod 640 "$BFD_LOG_PATH"
fi

if [ ! -d "$INSTALL_PATH/stats" ]; then
	command mkdir -p "$INSTALL_PATH/stats"
	command chmod 750 "$INSTALL_PATH/stats"
fi

APOOL_LIST="$INSTALL_PATH/stats/attack.pool"
if [ -f "$APOOL_LIST" ]; then
	command chmod 600 "$APOOL_LIST"
else
	command touch "$APOOL_LIST"
	command chmod 600 "$APOOL_LIST"
fi

state_init "$INSTALL_PATH"

LO_HOSTS="$INSTALL_PATH/ignore.hosts.local"
IP_BIN=$(command -v ip 2>/dev/null)
if [ -z "$IP_BIN" ]; then
	for _p in /sbin/ip /usr/sbin/ip /usr/bin/ip /bin/ip; do
		if [ -x "$_p" ]; then
			IP_BIN="$_p"
			break
		fi
	done
fi
if [ -n "$IP_BIN" ]; then
	"$IP_BIN" addr list | grep -E 'inet6? ' | tr '/' ' ' | awk '{print$2}' > "$LO_HOSTS"
else
	hostname -I | tr ' ' '\n' > "$LO_HOSTS"
fi
command chmod 640 "$LO_HOSTS"
}

get_state() {
if ! command mkdir "$LOCK_FILE.lk" 2>/dev/null; then
	# lock dir exists — check staleness
	if [ -f "$LOCK_FILE" ]; then
		OVAL=$(cat "$LOCK_FILE")
		# guard: treat non-numeric content as epoch 0 (always exceeds LOCK_FILE_TIMEOUT → stale)
		[[ "$OVAL" =~ ^[0-9]+$ ]] || OVAL=0
		DIFF=$((UTIME - OVAL))
		if [ "$DIFF" -gt "$LOCK_FILE_TIMEOUT" ]; then
			elog warn "cleared stale lock (${DIFF}s old, pid=$(cat "$LOCK_FILE.lk/pid" 2>/dev/null || echo unknown))."
			command rm -rf "$LOCK_FILE.lk"
			command mkdir "$LOCK_FILE.lk" 2>/dev/null || {
				elog error "unable to acquire lock after stale cleanup, aborting."
				exit "$EXIT_LOCK_ERROR"
			}
		else
			# lock is fresh — verify the holder is still alive
			local _lock_pid
			_lock_pid=$(cat "$LOCK_FILE.lk/pid" 2>/dev/null)
			if [ -n "$_lock_pid" ] && ! kill -0 "$_lock_pid" 2>/dev/null; then
				elog warn "cleared dead lock (pid=$_lock_pid exited, lock ${DIFF}s old)."
				command rm -rf "$LOCK_FILE.lk"
				command mkdir "$LOCK_FILE.lk" 2>/dev/null || {
					elog error "unable to acquire lock after dead-pid cleanup, aborting."
					exit "$EXIT_LOCK_ERROR"
				}
			else
				eout "locked subsystem, already running (pid=$_lock_pid, $DIFF seconds old), skipping." "l"
				exit "$EXIT_LOCK_ERROR"
			fi
		fi
	else
		elog error "lock directory exists but no timestamp file, aborting."
		exit "$EXIT_LOCK_ERROR"
	fi
fi
echo "$$" > "$LOCK_FILE.lk/pid"
echo "$UTIME" > "$LOCK_FILE"
command chmod 640 "$LOCK_FILE" 2>/dev/null || true  # non-fatal: content is an epoch timestamp
}

check() {
	local run_start active_count=0 rules_count=0 events_count=0 bans_count=0
	run_start=$(date +"%s")
	elog_event "scan_started" "info" "detection cycle started"

	# create alerts temp file for batched email delivery
	local alerts_file
	alerts_file=$(mktemp "$INSTALL_PATH/tmp/.alerts.XXXXXX")

	# --- per-cycle caches (cleaned up at end of check) ---
	# ignore cache: pre-loads all ignore lists into a single file for fast grep
	_IGNORE_CACHE_FILE=$(mktemp "$INSTALL_PATH/tmp/.ig_cache.XXXXXX")
	_build_ignore_cache "$IGNORE_HOST_FILES" "$_IGNORE_CACHE_FILE"

	# cycle-level caches: country weights and active bans (shared across all rules)
	declare -A _cw_map    # CC -> weight multiplier
	declare -A _active_bans  # IP -> 1
	local _cw_file="$INSTALL_PATH/pressure-country.conf"
	if [ -f "$_cw_file" ]; then
		local _cw_cc _cw_val
		while read -r _cw_cc _cw_val; do
			[[ "$_cw_cc" == \#* ]] && continue
			[ -z "$_cw_cc" ] && continue
			# dual-format: handle both CC=MULT (old) and CC MULT (new)
			if [[ "$_cw_cc" == *=* ]]; then
				_cw_val="${_cw_cc#*=}"
				_cw_cc="${_cw_cc%%=*}"
			fi
			[ -z "$_cw_val" ] && continue
			_cw_map[$_cw_cc]="$_cw_val"
		done < "$_cw_file"
	fi
	local _bans_file="$INSTALL_PATH/tmp/bans.active"
	if [ -f "$_bans_file" ] && [ -s "$_bans_file" ]; then
		local _ba_ip
		while read -r _ _ _ba_ip _; do
			[ -n "$_ba_ip" ] && _active_bans[$_ba_ip]=1
		done < "$_bans_file"
	fi

	# prune expired events once per run (10 half-lives = negligible contribution)
	# scan mode skips pruning — pressure.dat state must not be mutated during a scan
	if [ "${_SCAN_MODE:-}" != "1" ]; then
		local prune_window=$((PRESSURE_HALF_LIFE * 10))
		state_pressure_prune "$INSTALL_PATH" "$prune_window" "$UTIME"
	fi

	# prune attack pool periodically (once per 24h) — cron.daily skips during watch mode
	if [ "${_SCAN_MODE:-}" != "1" ]; then
		local _pool_prune_marker="$INSTALL_PATH/tmp/.pool_prune_ts"
		local _pool_last_prune=0
		[ -f "$_pool_prune_marker" ] && _pool_last_prune=$(cat "$_pool_prune_marker" 2>/dev/null)
		if [ $(( UTIME - _pool_last_prune )) -gt 86400 ]; then
			state_pool_prune "$INSTALL_PATH" "${APOOL_RETENTION_DAYS:-365}" "${APOOL_MAX_LINES:-500000}"
			echo "$UTIME" > "$_pool_prune_marker"
		fi
	fi

	for str in "$RULES_PATH"/*; do
		str=$(basename "$str")
		# scan mode: skip rules not matching the target
		if [ -n "${_SCAN_RULE:-}" ] && [ "$str" != "$_SCAN_RULE" ]; then
			continue
		fi
		vout "processing rule file $str"
		_clear_rule_vars
		safe_source "$RULES_PATH/$str" "rule:$str" || continue
		_compat_rule_vars
		_apply_pressure "$str"
		# resolve effective weight and trip for this rule
		local eff_weight="${PRESSURE_WEIGHT:-1}"
		local eff_trip="${PRESSURE_TRIP:-$GLOB_PRESSURE_TRIP}"
		MOD=$(sanitize_mod "$str") || { elog warn "invalid rule name '$str', skipping" le; continue; }
		validate_rule "$str" || continue
		active_count=$((active_count + 1))
		# scan mode: collect log file/tag pairs for cursor advancement
		if [ "${_SCAN_MODE:-}" = "1" ] && [ -n "${LOG_FILE:-}" ] && [ -n "${LOG_TAG:-}" ]; then
			_SCAN_LOG_PAIRS="${_SCAN_LOG_PAIRS:-}${LOG_FILE}|${LOG_TAG}
"
		fi
		if [ -z "${MATCHED_HOSTS:-}" ]; then
			continue  # active but no new events this cycle
		fi
		rules_count=$((rules_count + 1))
		# single awk pass: count events, build unique-IP and counted files
		local host_lines _unique_file _pressure_tmp _pool_tmp _counted_file
		_unique_file=$(mktemp "$INSTALL_PATH/tmp/.uniq_ips.XXXXXX")
		_pressure_tmp=$(mktemp "$INSTALL_PATH/tmp/.pressure_buf.XXXXXX")
		_pool_tmp=$(mktemp "$INSTALL_PATH/tmp/.pool_buf.XXXXXX")
		_counted_file=$(mktemp "$INSTALL_PATH/tmp/.counted.XXXXXX")
		host_lines=$(printf '%s\n' "$MATCHED_HOSTS" | awk -v uf="$_unique_file" -v cf="$_counted_file" '
			NF > 0 { for (i = 1; i <= NF; i++) { count[$i]++; total++ } }
			END {
				for (ip in count) {
					print ip > uf
					print count[ip], ip > cf
				}
				print total + 0
			}
		')
		vout "  $str: ${host_lines:-0} events, weight=$eff_weight, trip=$eff_trip"
		events_count=$((events_count + host_lines))

		# --- per-rule batch pre-computation ---
		# Build unique IP list and pre-compute filters, country, pressure in bulk

		# batch filter: identify ignored and local IPs via single grep passes
		declare -A _filter_map  # IP -> 1 (ignored) or 2 (local)
		local _ignored_ips _local_ips
		if [ -s "$_IGNORE_CACHE_FILE" ]; then
			_ignored_ips=$(grep -Fxf "$_IGNORE_CACHE_FILE" "$_unique_file" 2>/dev/null) || true  # exit 1 = no matches (normal)
			if [ -n "$_ignored_ips" ]; then
				local _fip
				while IFS= read -r _fip; do
					[ -n "$_fip" ] && _filter_map[$_fip]=1
				done <<< "$_ignored_ips"
			fi
		fi
		if [ -f "$LO_HOSTS" ] && [ -s "$LO_HOSTS" ]; then
			_local_ips=$(grep -Fxf "$LO_HOSTS" "$_unique_file" 2>/dev/null) || true  # exit 1 = no matches (normal)
			if [ -n "$_local_ips" ]; then
				local _lip
				while IFS= read -r _lip; do
					# only set local if not already ignored
					[ -n "$_lip" ] && [ -z "${_filter_map[$_lip]+_}" ] && _filter_map[$_lip]=2
				done <<< "$_local_ips"
			fi
		fi

		# batch country lookup: single awk pass over ipcountry.dat
		declare -A _cc_map  # IP -> CC (or "-")
		local _cc_ip _cc_val
		while read -r _cc_ip _cc_val; do
			[ -n "$_cc_ip" ] && _cc_map[$_cc_ip]="$_cc_val"
		done < <(_batch_ip_to_country "$INSTALL_PATH/ipcountry.dat" < "$_unique_file")

		# batch CDN lookup: single awk pass over cdn.dat for all unique IPs
		declare -A _cdn_map  # IP -> "PROVIDER TREATMENT MULT"
		if [ "${CDN_ENABLE:-0}" = "1" ] && [ -f "$INSTALL_PATH/cdn.dat" ]; then
			local _cdn_ip _cdn_provider _cdn_treatment _cdn_mult
			while read -r _cdn_ip _cdn_provider _cdn_treatment _cdn_mult; do
				[ -n "$_cdn_ip" ] && _cdn_map[$_cdn_ip]="$_cdn_provider $_cdn_treatment $_cdn_mult"
			done < <(_batch_cdn_lookup "$INSTALL_PATH/cdn.dat" < "$_unique_file")
		fi

		# batch pressure: single awk pass over pressure.dat for this MOD
		# Note: pressure values are pre-computed from events recorded BEFORE this
		# rule iteration. IP Y does not see IP X's events from the same rule in
		# this cycle. The delta is negligible (events at age~0 with decay~1.0).
		declare -A _pre_mod_p _pre_global_p  # IP -> scaled pressure (int)
		local _bp_ip _bp_mod _bp_glob
		while read -r _bp_ip _bp_mod _bp_glob; do
			[ -n "$_bp_ip" ] && _pre_mod_p[$_bp_ip]="$_bp_mod" && _pre_global_p[$_bp_ip]="$_bp_glob"
		done < <(_batch_pressure_compute "$INSTALL_PATH/tmp/pressure.dat" "$UTIME" "$PRESSURE_HALF_LIFE" "$MOD")

		# --- per-IP loop with O(1) lookups ---
		local _host_count
		while read -r _host_count ahost; do
			[ -z "$ahost" ] && continue
			ATTACK_HOST="$ahost"
			# defense-in-depth: reject non-IP strings (custom rules may bypass extract_hosts)
			validate_ip_any "$ahost" >/dev/null || continue
			# O(1) filter lookup
			local filter_rc="${_filter_map[$ATTACK_HOST]:-0}"
			if [ "$filter_rc" -eq 1 ]; then
				vout "  $ATTACK_HOST filtered (ignored)"
				continue
			fi
			# CDN treatment: ignore/exclude/derate
			local _cdn_exclude=0 _cdn_prov="" _cdn_treat="" _cdn_mult_val=""
			if [ -n "${_cdn_map[$ATTACK_HOST]:-}" ]; then
				read -r _cdn_prov _cdn_treat _cdn_mult_val <<< "${_cdn_map[$ATTACK_HOST]}"
				if [ "$_cdn_treat" = "ignore" ]; then
					vout "  $ATTACK_HOST filtered (cdn: $_cdn_prov, ignore)"
					continue
				elif [ "$_cdn_treat" = "exclude" ]; then
					_cdn_exclude=1
				fi
			fi
			# O(1) country + weight lookup
			local _cc="${_cc_map[$ATTACK_HOST]:-}"
			[ "$_cc" = "-" ] && _cc=""
			local scoring_weight="$eff_weight"
			if [ -n "$_cc" ] && [ -n "${_cw_map[$_cc]+_}" ]; then
				scoring_weight=$(( (eff_weight * ${_cw_map[$_cc]} + 5) / 10 ))
				[ "$scoring_weight" -lt 1 ] && scoring_weight=1
			fi
			# CDN derate: further reduce scoring weight
			if [ "$_cdn_treat" = "derate" ] && [ "${_cdn_mult_val:-10}" != "10" ]; then
				scoring_weight=$(( (scoring_weight * ${_cdn_mult_val:-10} + 5) / 10 ))
				[ "$scoring_weight" -lt 1 ] && scoring_weight=1
			fi
			# O(1) pressure: pre-computed base + new events at decay=1.0
			local pressure_scaled=$(( ${_pre_mod_p[$ATTACK_HOST]:-0} + _host_count * scoring_weight * 1000 ))
			# verbose: show per-IP pressure score
			if [ "${VERBOSE:-0}" = "1" ]; then
				local _p_fmt
				_p_fmt=$(pressure_format "$pressure_scaled")
				if [ "$scoring_weight" != "$eff_weight" ]; then
					vout "  $ATTACK_HOST: $MOD pressure=${_p_fmt}/${eff_trip} weight=${eff_weight}->${scoring_weight}"
				else
					vout "  $ATTACK_HOST: $MOD pressure=${_p_fmt}/${eff_trip} weight=${eff_weight}"
				fi
			fi
			local trip_scaled=$((eff_trip * 1000))
			local should_ban=0 _trip_type="service"
			if [ "$pressure_scaled" -ge "$trip_scaled" ]; then
				should_ban=1
			elif [ "${PRESSURE_TRIP_GLOBAL:-0}" -gt 0 ]; then
				# O(1) global pressure: pre-computed base + new events at decay=1.0
				local gp=$(( ${_pre_global_p[$ATTACK_HOST]:-0} + _host_count * scoring_weight * 1000 ))
				if [ "$gp" -ge $((PRESSURE_TRIP_GLOBAL * 1000)) ]; then
					should_ban=1
					_trip_type="global"
					if [ "${VERBOSE:-0}" = "1" ]; then
						local _gp_fmt
						_gp_fmt=$(pressure_format "$gp")
						vout "  $ATTACK_HOST: global pressure=${_gp_fmt}/${PRESSURE_TRIP_GLOBAL} -> ban"
					fi
				fi
			fi
			# CDN exclude: record observation but skip ban
			if [ "$_cdn_exclude" -eq 1 ] && [ "$should_ban" -eq 1 ]; then
				printf '%s\n' "$UTIME $ATTACK_HOST $MOD $_host_count ${_cc:---} cdn-exclude 0 ${PORTS:-all} $pressure_scaled -" >> "$_pool_tmp"
				vout "  $ATTACK_HOST: cdn-exclude ($_cdn_prov), skipping ban"
				elog_event "threat_detected" "info" "{$MOD} CDN exclude for $ATTACK_HOST" \
					"ip=$ATTACK_HOST" "mod=$MOD" "cdn_provider=$_cdn_prov" "cdn_treatment=exclude" "pressure=$pressure_scaled"
				# still accumulate pressure events for visibility
				local _pi
				for ((_pi = 0; _pi < _host_count; _pi++)); do
					printf '%s\n' "$UTIME $ATTACK_HOST $MOD $scoring_weight"
				done >> "$_pressure_tmp"
				continue
			fi
			if [ "$should_ban" -eq 1 ]; then
				# O(1) active ban check
				if [ -n "${_active_bans[$ATTACK_HOST]+_}" ]; then
					continue
				fi
				if [ "$filter_rc" -eq 2 ]; then
					# local address — record attack, skip ban
					printf '%s\n' "$UTIME $ATTACK_HOST $MOD $_host_count ${_cc:---} skip-local -1 ${PORTS:-all} $pressure_scaled $_trip_type" >> "$_pool_tmp"
					elog warn "{$MOD} $ATTACK_HOST is a local address, skipping ban."
				else
					local _pool_action="ban-failed" _pool_duration="-1"
					elog_event "threat_detected" "warn" "{$MOD} pressure trip for $ATTACK_HOST" \
						"ip=$ATTACK_HOST" "mod=$MOD" "pressure=$pressure_scaled" "trip=$trip_scaled" "trip_type=$_trip_type"
					if execute_ban "$ATTACK_HOST" "$MOD" "$DRY_RUN" "${PORTS:-all}"; then
						vout "  ban: $ATTACK_HOST via ${_FW_BACKEND} ($MOD, port ${PORTS:-all})"
						bans_count=$((bans_count + 1))
						local ban_result
						ban_result=$(record_ban "$INSTALL_PATH" "$UTIME" "$ATTACK_HOST" "$MOD" "${PORTS:-all}" "ban")
						local ban_expiry ban_action recent_bans
						IFS='|' read -r ban_expiry ban_action recent_bans <<< "$ban_result"
						_pool_action="$ban_action"
						if [ "$ban_expiry" = "0" ]; then
							_pool_duration="0"
						else
							_pool_duration=$((ban_expiry - UTIME))
						fi
						# collect alert data for batched delivery
						if [ "$EMAIL_ALERTS" = "1" ] && [ "$SKIP_ALERT" != "1" ] && [ "$DRY_RUN" != "1" ]; then
							local eff_recipient="${RULE_EMAIL:-$EMAIL_ADDRESS}"
							echo "${ATTACK_HOST}|${MOD}|${PORTS:-all}|${pressure_scaled}|${ban_expiry}|${ban_action}|${recent_bans}|${LOG_FILE}|${eff_recipient}|${eff_trip}|${PRESSURE_HALF_LIFE}|${scoring_weight}|${_host_count}" >> "$alerts_file"
						fi
						# update active bans cache for remainder of this cycle
						_active_bans[$ATTACK_HOST]=1
					fi
					printf '%s\n' "$UTIME $ATTACK_HOST $MOD $_host_count ${_cc:---} $_pool_action $_pool_duration ${PORTS:-all} $pressure_scaled $_trip_type" >> "$_pool_tmp"
				fi
			else
				# sub-trip: record observation to attack pool
				printf '%s\n' "$UTIME $ATTACK_HOST $MOD $_host_count ${_cc:---} observed 0 ${PORTS:-all} $pressure_scaled -" >> "$_pool_tmp"
			fi
			# accumulate pressure events for deferred write (one line per occurrence)
			local _pi
			for ((_pi = 0; _pi < _host_count; _pi++)); do
				printf '%s\n' "$UTIME $ATTACK_HOST $MOD $scoring_weight"
			done >> "$_pressure_tmp"
		done < "$_counted_file"

		# --- deferred bulk writes (one flock+append per file per rule) ---
		if [ -s "$_pressure_tmp" ]; then
			local _pdat="$INSTALL_PATH/tmp/pressure.dat"
			(
				flock -x 200
				command cat "$_pressure_tmp" >> "$_pdat"
			) 200>>"$_pdat"
		fi
		if [ -s "$_pool_tmp" ]; then
			local _pool_file="$INSTALL_PATH/stats/attack.pool"
			(
				flock -x 200
				command cat "$_pool_tmp" >> "$_pool_file"
			) 200>>"$_pool_file"
		fi

		# per-rule cleanup
		command rm -f "$_unique_file" "$_pressure_tmp" "$_pool_tmp" "$_counted_file"
		unset _filter_map _cc_map _pre_mod_p _pre_global_p _cdn_map
	done

	# distributed attack detection
	if [ "${SUBNET_TRIG:-0}" -gt 0 ]; then
		local subnet_bans
		subnet_bans=$(check_distributed "$INSTALL_PATH" "$((PRESSURE_HALF_LIFE * 10))" "$UTIME" "$alerts_file")
		bans_count=$((bans_count + subnet_bans))
	fi

	# send batched alert emails (or spool for digest)
	if [ "$EMAIL_ALERTS" = "1" ] && [ -s "$alerts_file" ]; then
		if [ "${EMAIL_DIGEST:-cycle}" = "timed" ]; then
			_bfd_spool_append "$alerts_file"
		else
			send_alerts "$alerts_file" "$EMAIL_SUBJECT" "${EMAIL_LOGLINES:-5}"
		fi
	fi
	# check digest spool for timed flush (handles pre-existing entries too)
	if [ "$EMAIL_ALERTS" = "1" ] && [ "${EMAIL_DIGEST:-cycle}" = "timed" ]; then
		_bfd_digest_check
	fi
	command rm -f "$alerts_file"

	# cleanup per-cycle caches
	command rm -f "$_IGNORE_CACHE_FILE"
	_IGNORE_CACHE_FILE=""
	unset _cw_map _active_bans

	local run_end run_elapsed
	run_end=$(date +"%s")
	run_elapsed=$((run_end - run_start))
	elog_event "scan_completed" "info" "detection cycle completed" \
		"active_rules=$active_count" "events=$events_count" "bans=$bans_count" "elapsed=$run_elapsed"
	local _run_label="run"
	[ "${_SCAN_MODE:-}" = "1" ] && _run_label="scan"
	local _log_flag="le"
	if [ "${LOG_IDLE_SUPPRESS:-0}" = "1" ] && [ "$events_count" = "0" ]; then
		_log_flag="l"
	fi
	eout "$_run_label complete: $active_count active rules, $rules_count with events, $events_count events parsed, $bans_count bans executed (${run_elapsed}s)" "$_log_flag"
}

bfd_run() {
	pre
	get_state
	process_unbans "$INSTALL_PATH" "$UTIME"
	check
}

# shellcheck disable=SC2317 # called via trap
cleanup_watch() {
	eout "watch mode shutting down (pid=$$)" le
	elog_event "service_state" "info" "watch mode shutting down"
	# flush any accumulated digest alerts before shutdown
	if [ "${EMAIL_ALERTS:-0}" = "1" ] && [ "${EMAIL_DIGEST:-cycle}" = "timed" ]; then
		_bfd_digest_flush
	fi
	_cleanup_common
}

# shellcheck disable=SC2317 # called via trap
reload_watch() {
	eout "watch mode reloading configuration (SIGHUP)" le
	if ! config_init 1; then
		elog error "reload aborted: configuration error, continuing with previous config"
		elog_event "config_error" "error" "watch mode reload failed"
		return 1
	fi
	# refresh local IPs (runtime state, not config)
	if [ -n "$IP_BIN" ]; then
		"$IP_BIN" addr list | grep -E 'inet6? ' | tr '/' ' ' | awk '{print$2}' > "$LO_HOSTS"
	else
		hostname -I | tr ' ' '\n' > "$LO_HOSTS"
	fi
	eout "watch mode reload complete (WATCH_INTERVAL=${WATCH_INTERVAL}s)" le
	elog_event "service_state" "info" "watch mode reload complete" \
		"interval=$WATCH_INTERVAL"
	elog_event "config_loaded" "info" "configuration reloaded"
}

watch() {
	trap cleanup_watch EXIT
	# shellcheck disable=SC2317 # reached via signal
	trap 'exit 143' TERM
	trap 'exit 130' INT
	trap reload_watch HUP
	# suppress stdout in daemon mode — elog writes directly to syslog/log files;
	# systemd SyslogIdentifier would re-log stdout causing duplicate entries
	# shellcheck disable=SC2034
	ELOG_STDOUT="never"
	pre
	get_state
	eout "watch mode started (interval=${WATCH_INTERVAL}s, pid=$$)" le
	elog_event "service_state" "info" "watch mode started" \
		"interval=$WATCH_INTERVAL"
	elog_event "config_loaded" "info" "configuration initialized"
	export TLOG_FLOCK=1
	while true; do
		UTIME=$(date +"%s")
		echo "$UTIME" > "$LOCK_FILE"
		process_unbans "$INSTALL_PATH" "$UTIME"
		check
		sleep "$WATCH_INTERVAL" &
		wait "$!"
	done
}
