#!/bin/bash
#
# Brute Force Detection 2.0.2 - Firewall Backend Abstraction
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
# Sourced by bfd.lib.sh. Provides firewall detection, backend dispatch (apf/csf/firewalld/ufw/nftables/iptables/route/custom), ban/unban operations, and retry logic.

# Source guard — prevent double-sourcing
[[ -n "${_BFD_FW_LOADED:-}" ]] && return 0 2>/dev/null
_BFD_FW_LOADED=1

# shellcheck disable=SC2034
BFD_FW_VERSION="1.0.0"

# --- Firewall backend system ---
# Auto-detects or uses configured firewall for ban/unban operations.
# Each backend implements: _fw_BACKEND_{ban,unban,setup,status}
# Dispatch layer: fw_resolve_backend, fw_setup, fw_ban, fw_unban, fw_status

# detect_firewall — auto-detect available firewall tool
# returns backend name on stdout: apf, csf, firewalld, ufw, nftables, iptables, route
detect_firewall() {
	if command -v apf >/dev/null 2>&1; then echo "apf"; return; fi
	if command -v csf >/dev/null 2>&1; then echo "csf"; return; fi
	if command -v firewall-cmd >/dev/null 2>&1 && \
	   firewall-cmd --state >/dev/null 2>&1; then echo "firewalld"; return; fi
	if command -v ufw >/dev/null 2>&1 && \
	   ufw status 2>/dev/null | grep -q "Status: active"; then echo "ufw"; return; fi
	if command -v nft >/dev/null 2>&1 && \
	   nft list tables >/dev/null 2>&1; then echo "nftables"; return; fi
	if command -v iptables >/dev/null 2>&1 && \
	   iptables -V >/dev/null 2>&1; then echo "iptables"; return; fi
	echo "route"
}

# --- APF backend ---
_fw_apf_setup() {
	_FW_APF_BIN=$(command -v apf 2>/dev/null) || _FW_APF_BIN=""
	if [ -z "$_FW_APF_BIN" ]; then
		elog error "{glob} apf binary not found"
		return 1
	fi
}

_fw_apf_ban() {
	local host="$1" mod="${2:-}"
	"$_FW_APF_BIN" -d "$host" "{bfd.$mod}" >/dev/null 2>&1
}

_fw_apf_unban() {
	local host="$1"
	"$_FW_APF_BIN" -u "$host" >/dev/null 2>&1
}

_fw_apf_status() {
	echo "apf (Advanced Policy Firewall)"
}

# --- CSF backend ---
_fw_csf_setup() {
	_FW_CSF_BIN=$(command -v csf 2>/dev/null) || _FW_CSF_BIN=""
	if [ -z "$_FW_CSF_BIN" ]; then
		elog error "{glob} csf binary not found"
		return 1
	fi
}

_fw_csf_ban() {
	local host="$1" mod="${2:-}"
	"$_FW_CSF_BIN" -d "$host" "bfd.$mod" >/dev/null 2>&1
}

_fw_csf_unban() {
	local host="$1"
	"$_FW_CSF_BIN" -dr "$host" >/dev/null 2>&1
}

_fw_csf_status() {
	echo "csf (ConfigServer Security & Firewall)"
}

# --- firewalld backend (runtime-only rich rules, no --permanent) ---
_fw_firewalld_ban() {
	local host="$1" family="ipv4"
	[[ "$host" == *:* ]] && family="ipv6"
	firewall-cmd --add-rich-rule="rule family=$family source address=$host drop" >/dev/null 2>&1
}

_fw_firewalld_unban() {
	local host="$1" family="ipv4"
	[[ "$host" == *:* ]] && family="ipv6"
	firewall-cmd --remove-rich-rule="rule family=$family source address=$host drop" >/dev/null 2>&1
}

_fw_firewalld_status() {
	local count=0
	count=$(firewall-cmd --list-rich-rules 2>/dev/null | grep -c "drop") || count=0
	echo "firewalld ($count rich rules, runtime-only)"
}

# --- UFW backend ---
_fw_ufw_ban() {
	local host="$1"
	# try with comment marker for identification; fall back for old UFW (<0.35)
	ufw insert 1 deny from "$host" comment "bfd" >/dev/null 2>&1 \
		|| ufw insert 1 deny from "$host" >/dev/null 2>&1
}

_fw_ufw_unban() {
	local host="$1"
	ufw delete deny from "$host" >/dev/null 2>&1
}

_fw_ufw_status() {
	local count=0
	# count BFD-commented rules; fall back to all deny rules if no comments found
	count=$(ufw status 2>/dev/null | grep -c "# bfd") || count=0
	if [ "$count" -eq 0 ]; then
		count=$(ufw status 2>/dev/null | grep -c "DENY") || count=0
	fi
	echo "ufw ($count deny rules)"
}

# --- nftables backend (dedicated inet bfd table with IP sets) ---
_fw_nftables_setup() {
	# idempotent: skip if table already exists
	nft list table inet bfd >/dev/null 2>&1 && return 0
	nft add table inet bfd || return 1
	nft add set inet bfd blocked4 '{ type ipv4_addr; flags interval; }' || return 1
	nft add set inet bfd blocked6 '{ type ipv6_addr; flags interval; }' || return 1
	nft add chain inet bfd input '{ type filter hook input priority -1; policy accept; }' || return 1
	nft add rule inet bfd input ip saddr @blocked4 drop || return 1
	nft add rule inet bfd input ip6 saddr @blocked6 drop || return 1
}

_fw_nftables_ban() {
	local host="$1"
	if [[ "$host" == *:* ]]; then
		nft add element inet bfd blocked6 "{ $host }" >/dev/null 2>&1
	else
		nft add element inet bfd blocked4 "{ $host }" >/dev/null 2>&1
	fi
}

_fw_nftables_unban() {
	local host="$1"
	if [[ "$host" == *:* ]]; then
		nft delete element inet bfd blocked6 "{ $host }" >/dev/null 2>&1
	else
		nft delete element inet bfd blocked4 "{ $host }" >/dev/null 2>&1
	fi
}

# _fw_nftables_count_elements set_name — count elements in an nft set
# Parses "elements = { ip1, ip2, ... }" from nft output; handles multiline.
_fw_nftables_count_elements() {
	local set_name="$1"
	nft list set inet bfd "$set_name" 2>/dev/null | awk '
		/elements/ { found = 1 }
		found {
			for (i = 1; i <= length($0); i++)
				if (substr($0, i, 1) == ",") commas++
			if (/\}/) exit
		}
		END { print found ? commas + 1 : 0 }
	' || echo "0"
}

_fw_nftables_status() {
	local v4_count=0 v6_count=0
	# count actual set elements (comma-delimited), not lines containing "elements"
	v4_count=$(_fw_nftables_count_elements "blocked4")
	v6_count=$(_fw_nftables_count_elements "blocked6")
	echo "nftables (inet bfd table, $v4_count v4 + $v6_count v6 blocked)"
}

# --- iptables backend (dedicated bfd chain) ---
_fw_iptables_setup() {
	_FW_IPT_BIN=$(command -v iptables 2>/dev/null) || _FW_IPT_BIN=""
	_FW_IP6T_BIN=$(command -v ip6tables 2>/dev/null) || _FW_IP6T_BIN=""
	if [ -z "$_FW_IPT_BIN" ]; then
		elog error "{glob} iptables binary not found"
		return 1
	fi
	"$_FW_IPT_BIN" -N bfd 2>/dev/null || true  # chain may already exist
	"$_FW_IPT_BIN" -C INPUT -j bfd 2>/dev/null || "$_FW_IPT_BIN" -I INPUT -j bfd
	if [ -n "$_FW_IP6T_BIN" ]; then
		"$_FW_IP6T_BIN" -N bfd 2>/dev/null || true  # chain may already exist
		"$_FW_IP6T_BIN" -C INPUT -j bfd 2>/dev/null || "$_FW_IP6T_BIN" -I INPUT -j bfd
	else
		elog warn "{glob} ip6tables not found — IPv6 bans will be skipped"
	fi
}

_fw_iptables_ban() {
	local host="$1"
	if [[ "$host" == *:* ]]; then
		if [ -z "$_FW_IP6T_BIN" ]; then
			elog warn "{iptables} IPv6 ban skipped — ip6tables not found"
			return 1
		fi
		"$_FW_IP6T_BIN" -A bfd -s "$host" -j DROP 2>/dev/null
	else
		"$_FW_IPT_BIN" -A bfd -s "$host" -j DROP
	fi
}

_fw_iptables_unban() {
	local host="$1"
	if [[ "$host" == *:* ]]; then
		if [ -z "$_FW_IP6T_BIN" ]; then
			elog warn "{iptables} IPv6 unban skipped — ip6tables not found"
			return 1
		fi
		"$_FW_IP6T_BIN" -D bfd -s "$host" -j DROP 2>/dev/null
	else
		"$_FW_IPT_BIN" -D bfd -s "$host" -j DROP 2>/dev/null
	fi
}

_fw_iptables_status() {
	local v4_count=0 v6_count=0
	v4_count=$("$_FW_IPT_BIN" -L bfd -n 2>/dev/null | grep -c "DROP") || v4_count=0
	if [ -n "$_FW_IP6T_BIN" ]; then
		v6_count=$("$_FW_IP6T_BIN" -L bfd -n 2>/dev/null | grep -c "DROP") || v6_count=0
	fi
	echo "iptables (bfd chain, $v4_count v4 + $v6_count v6 rules)"
}

# --- route backend (ip route null-route / blackhole) ---
_fw_route_setup() {
	_FW_ROUTE_IP_BIN=$(command -v ip 2>/dev/null) || _FW_ROUTE_IP_BIN=""
	if [ -z "$_FW_ROUTE_IP_BIN" ]; then
		elog error "{glob} ip binary not found"
		return 1
	fi
}

_fw_route_op() {
	local action="$1" host="$2"
	if [[ "$host" == */* ]]; then
		"$_FW_ROUTE_IP_BIN" route "$action" blackhole "$host" 2>/dev/null
	elif [[ "$host" == *:* ]]; then
		"$_FW_ROUTE_IP_BIN" route "$action" blackhole "$host/128" 2>/dev/null
	else
		"$_FW_ROUTE_IP_BIN" route "$action" blackhole "$host/32" 2>/dev/null
	fi
}

_fw_route_ban() { _fw_route_op add "$1"; }
_fw_route_unban() { _fw_route_op del "$1"; }

_fw_route_status() {
	local count=0
	count=$("$_FW_ROUTE_IP_BIN" route list type blackhole 2>/dev/null | wc -l) || count=0
	echo "route ($count blackhole routes)"
}

# --- custom backend (backward-compatible eval of BAN_COMMAND templates) ---
_fw_custom_exec() {
	local action="$1" host="$2" mod="$3" raw_ports="$4"
	local ports
	ports=$(sanitize_ports "$raw_ports") || { elog error "invalid PORTS value '$raw_ports'" "le"; return 1; }
	local cmd
	if [ "$action" = "ban" ]; then
		cmd="$BAN_COMMAND_TEMPLATE"
		[ -n "${BAN_COMMAND_V6_TEMPLATE:-}" ] && [[ "$host" == *:* ]] && cmd="$BAN_COMMAND_V6_TEMPLATE"
	else
		cmd="$UNBAN_COMMAND_TEMPLATE"
		[ -n "${UNBAN_COMMAND_V6_TEMPLATE:-}" ] && [[ "$host" == *:* ]] && cmd="$UNBAN_COMMAND_V6_TEMPLATE"
	fi
	# shellcheck disable=SC2034  # consumed by eval'd command template and alert templates
	ATTACK_HOST="$host"
	# shellcheck disable=SC2034
	MOD="$mod"
	# shellcheck disable=SC2034
	PORTS="$ports"
	# Security: $cmd is from BAN/UNBAN_COMMAND_TEMPLATE, extracted raw from conf.bfd
	# by extract_command_template(). $host is validated by validate_ip_any()
	# (check() loop + CLI callers), $mod by sanitize_mod(), $ports by
	# sanitize_ports(). conf.bfd is root-owned and verified by safe_source().
	# This eval is intentional for user-defined firewall commands.
	eval "$cmd" >/dev/null 2>&1
}

_fw_custom_ban() { _fw_custom_exec ban "$1" "$2" "$3"; }
_fw_custom_unban() { _fw_custom_exec unban "$1" "$2" "$3"; }

_fw_custom_status() {
	echo "custom (BAN_COMMAND template)"
}

# --- Dispatch layer ---

# fw_resolve_backend — set _FW_BACKEND from FIREWALL config or auto-detect
fw_resolve_backend() {
	local configured="${FIREWALL:-auto}"
	if [ "$configured" = "auto" ]; then
		_FW_BACKEND=$(detect_firewall)
	else
		_FW_BACKEND="$configured"
	fi
}

# fw_setup — initialize firewall backend (create chains/tables/sets as needed)
fw_setup() {
	case "$_FW_BACKEND" in
		apf)       _fw_apf_setup ;;
		csf)       _fw_csf_setup ;;
		nftables)  _fw_nftables_setup ;;
		iptables)  _fw_iptables_setup ;;
		route)     _fw_route_setup ;;
	esac
}

# fw_ban host [mod] [ports] — ban a host via the active backend
fw_ban() {
	local host="$1" mod="${2:-}" ports="${3:-all}"
	case "$_FW_BACKEND" in
		apf)       _fw_apf_ban "$host" "$mod" ;;
		csf)       _fw_csf_ban "$host" "$mod" ;;
		firewalld) _fw_firewalld_ban "$host" ;;
		ufw)       _fw_ufw_ban "$host" ;;
		nftables)  _fw_nftables_ban "$host" ;;
		iptables)  _fw_iptables_ban "$host" ;;
		route)     _fw_route_ban "$host" ;;
		custom)    _fw_custom_ban "$host" "$mod" "$ports" ;;
	esac
}

# fw_unban host [mod] [ports] — unban a host via the active backend
fw_unban() {
	local host="$1" mod="${2:-}" ports="${3:-all}"
	case "$_FW_BACKEND" in
		apf)       _fw_apf_unban "$host" ;;
		csf)       _fw_csf_unban "$host" ;;
		firewalld) _fw_firewalld_unban "$host" ;;
		ufw)       _fw_ufw_unban "$host" ;;
		nftables)  _fw_nftables_unban "$host" ;;
		iptables)  _fw_iptables_unban "$host" ;;
		route)     _fw_route_unban "$host" ;;
		custom)    _fw_custom_unban "$host" "$mod" "$ports" ;;
	esac
}

# fw_status — return human-readable status of the active backend
fw_status() {
	case "$_FW_BACKEND" in
		apf)       _fw_apf_status ;;
		csf)       _fw_csf_status ;;
		firewalld) _fw_firewalld_status ;;
		ufw)       _fw_ufw_status ;;
		nftables)  _fw_nftables_status ;;
		iptables)  _fw_iptables_status ;;
		route)     _fw_route_status ;;
		custom)    _fw_custom_status ;;
	esac
}

# _execute_fw_with_retry action host mod ports
# Shared retry loop for fw_ban/fw_unban with exponential backoff.
# action: "ban" or "unban" — dispatches to fw_ban() or fw_unban().
# Retries up to BAN_RETRY_COUNT (default 2) on failure.
# Returns 0 on success, fw command exit code on failure.
_execute_fw_with_retry() {
	local action="$1" host="$2" mod="$3" ports="$4"
	local max_retries="${BAN_RETRY_COUNT:-2}"
	local retry_delay=1 attempt=0 rc=1
	while [ "$attempt" -le "$max_retries" ] && [ "$rc" -ne 0 ]; do
		"fw_${action}" "$host" "$mod" "$ports"
		rc=$?
		if [ "$rc" -ne 0 ] && [ "$attempt" -lt "$max_retries" ]; then
			elog error "{$mod} $action for $host failed (attempt $((attempt + 1))), retrying in ${retry_delay}s."
			sleep "$retry_delay"
			retry_delay=$((retry_delay * 2))
		fi
		attempt=$((attempt + 1))
	done
	if [ "$rc" -ne 0 ]; then
		elog error "{$mod} $action for $host failed after $attempt attempt(s) via $_FW_BACKEND."
	fi
	return $rc
}
