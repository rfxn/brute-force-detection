#!/bin/bash
#
# Common BFD test setup for BATS
# Load in .bats files with: load 'helpers/bfd-common'
#
# Provides:
#   bfd_common_setup   — minimal tmpdir + logging (for unit tests)
#   bfd_standard_setup — full state + config defaults (for integration tests)
#   bfd_teardown       — cleanup tmpdir
#   bfd_load_function  — extract+eval a function from bfd or bfd.lib.sh
#   create_mock_bin    — mock binary creation (from bfd-mock.bash)
#   create_mock_rule   — mock rule creation (from bfd-mock.bash)
#   assert_banned, refute_banned, assert_ban_count, assert_event_count,
#   assert_history_count, assert_pool_count (from assert-bfd.bash)
#

PROJECT_ROOT="$(cd "${BATS_TEST_DIRNAME}/.." && pwd)"
export PROJECT_ROOT

# Source the BFD function library
# shellcheck disable=SC1091
source "${PROJECT_ROOT}/files/internals/bfd.lib.sh"

# Load additional helpers
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/assert-bfd.bash"
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/bfd-mock.bash"

# --- Compatibility ---

# bfd_require_bash42: skip test on bash <4.2 (centos6).
# BATS test helpers need declare -gA for global associative arrays from
# inside functions. Production code uses declare -A at script scope, so
# BFD itself runs fine on bash 4.1; this is purely a test infrastructure
# limitation. Call from setup() in files that use bfd_standard_setup or
# associative arrays directly.
bfd_require_bash42() {
	if [[ "${BASH_VERSINFO[0]}" -lt 4 ]] ||
	   [[ "${BASH_VERSINFO[0]}" -eq 4 && "${BASH_VERSINFO[1]}" -lt 2 ]]; then
		skip "requires bash 4.2+ (declare -gA)"
	fi
}

# --- Setup helpers ---

# bfd_common_setup: minimal test environment (tmpdir + logging)
# Use for: unit tests that need eout/logging but no state files
bfd_common_setup() {
	TEST_TMPDIR=$(mktemp -d)
	BFD_LOG_PATH="$TEST_TMPDIR/bfd.log"
	touch "$BFD_LOG_PATH"
	OUTPUT_SYSLOG="0"
	OUTPUT_SYSLOG_FILE="$TEST_TMPDIR/syslog"
	# elog_lib defaults for test environment
	ELOG_APP="bfd"
	ELOG_LOG_FILE="$BFD_LOG_PATH"
	ELOG_SYSLOG_FILE=""
	ELOG_STDOUT="always"
	ELOG_STDOUT_PREFIX="full"
	ELOG_TS_FORMAT="%b %e %H:%M:%S"
	ELOG_LEVEL="1"
	ELOG_VERBOSE="0"
	ELOG_FORMAT="classic"
	ELOG_LOG_DIR="$TEST_TMPDIR"
	ELOG_AUDIT_FILE="$TEST_TMPDIR/audit.log"
	touch "$ELOG_AUDIT_FILE"
	ELOG_LOG_MAX_LINES="0"
	# Enable syslog_file module unconditionally — eout() dynamically sets
	# ELOG_SYSLOG_FILE per call; handler checks var at write time (empty = skip)
	elog_output_enable "syslog_file" 2>/dev/null || true
}

# bfd_standard_setup: full test environment (common + state + config defaults)
# Use for: integration tests that need INSTALL_PATH, state files, firewall config
bfd_standard_setup() {
	bfd_common_setup
	INSTALL_PATH="$TEST_TMPDIR/bfd"
	mkdir -p "$INSTALL_PATH"
	state_init "$INSTALL_PATH"
	TLOG_BASERUN="$INSTALL_PATH/tmp"
	BAN_RETRY_COUNT="0"
	PRESSURE_TRIP="${PRESSURE_TRIP:-20}"
	PRESSURE_HALF_LIFE="${PRESSURE_HALF_LIFE:-300}"
	PRESSURE_TRIP_GLOBAL="${PRESSURE_TRIP_GLOBAL:-0}"
	GLOB_PRESSURE_TRIP="$PRESSURE_TRIP"
	# declare + clear pressure arrays; -gA requires bash 4.2+ (declare -g
	# is the only way to create global associative arrays from inside BATS
	# setup functions). On bash 4.1 (centos6), fall back to indexed arrays —
	# tests that need string-keyed access must call bfd_require_bash42.
	if [[ "${BASH_VERSINFO[0]}" -ge 5 ]] ||
	   [[ "${BASH_VERSINFO[0]}" -eq 4 && "${BASH_VERSINFO[1]}" -ge 2 ]]; then
		declare -gA _PRESS_WEIGHT _PRESS_TRIP _PRESS_SKIP_ALERT _PRESS_RULE_EMAIL
	else
		_PRESS_WEIGHT=()
		_PRESS_TRIP=()
		_PRESS_SKIP_ALERT=()
		_PRESS_RULE_EMAIL=()
	fi
	BAN_TTL="${BAN_TTL:-600}"
	BAN_ESCALATE_AFTER="${BAN_ESCALATE_AFTER:-5}"
	BAN_ESCALATE_WINDOW="${BAN_ESCALATE_WINDOW:-86400}"
	BAN_COMMAND_TEMPLATE="/bin/true"
	UNBAN_COMMAND_TEMPLATE="/bin/true"
	BAN_COMMAND_V6_TEMPLATE=""
	UNBAN_COMMAND_V6_TEMPLATE=""
	_FW_BACKEND="custom"
}

# bfd_load_function: extract and eval a single function from a source file.
# Usage: bfd_load_function "func_name" [source_file]
# Default source: $PROJECT_ROOT/files/bfd, with fallback to bfd_core.sh
bfd_load_function() {
	local func="$1" src="${2:-$PROJECT_ROOT/files/bfd}"
	local extracted
	extracted="$(awk "/^${func}\\(\\)/ { p=1 } p { print; if (/^\\}\$/) exit }" "$src")"
	# fallback: if not found in default source, try sub-libraries
	if [ -z "$extracted" ] && [ "$src" = "$PROJECT_ROOT/files/bfd" ]; then
		local _fallback
		for _fallback in bfd_core.sh bfd_cdn.sh; do
			extracted="$(awk "/^${func}\\(\\)/ { p=1 } p { print; if (/^\\}\$/) exit }" \
				"$PROJECT_ROOT/files/internals/$_fallback")"
			[ -n "$extracted" ] && break
		done
	fi
	eval "$extracted"
}

# bfd_teardown: cleanup test environment
bfd_teardown() {
	rm -rf "$TEST_TMPDIR"
}
