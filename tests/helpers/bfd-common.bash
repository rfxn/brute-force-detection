#!/bin/bash
#
# Common BFD test setup for BATS
# Load in .bats files with: load 'helpers/bfd-common'
#
# Provides:
#   bfd_common_setup   — minimal tmpdir + logging (for unit tests)
#   bfd_standard_setup — full state + config defaults (for integration tests)
#   bfd_teardown       — cleanup tmpdir
#   create_mock_bin    — mock binary creation (from bfd-mock.bash)
#   create_mock_rule   — mock rule creation (from bfd-mock.bash)
#   assert_banned, refute_banned, assert_ban_count, assert_event_count,
#   assert_history_count, assert_pool_count (from assert-bfd.bash)
#

PROJECT_ROOT="$(cd "${BATS_TEST_DIRNAME}/.." && pwd)"
export PROJECT_ROOT

# Source the BFD function library
# shellcheck disable=SC1091
source "${PROJECT_ROOT}/files/bfd.lib.sh"

# Load additional helpers
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/assert-bfd.bash"
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/bfd-mock.bash"

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
	# declare associative arrays for pressure.conf lookups (must be -gA to
	# survive outside setup scope; bash 4.2+ — safe on all test targets)
	declare -gA _PRESS_WEIGHT _PRESS_TRIP _PRESS_SKIP_ALERT _PRESS_RULE_EMAIL
	BAN_TTL="${BAN_TTL:-600}"
	BAN_ESCALATE_AFTER="${BAN_ESCALATE_AFTER:-5}"
	BAN_ESCALATE_WINDOW="${BAN_ESCALATE_WINDOW:-86400}"
	BAN_COMMAND_TEMPLATE="/bin/true"
	UNBAN_COMMAND_TEMPLATE="/bin/true"
	BAN_COMMAND_V6_TEMPLATE=""
	UNBAN_COMMAND_V6_TEMPLATE=""
	_FW_BACKEND="custom"
}

# bfd_teardown: cleanup test environment
bfd_teardown() {
	rm -rf "$TEST_TMPDIR"
}
