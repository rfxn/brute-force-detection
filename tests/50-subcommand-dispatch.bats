#!/usr/bin/env bats
#
# Test suite for Phase 5: Subcommand dispatch, help, and CLI routing
#   _ban_help, _ignore_help, _test_help, _cdn_help, _report_help, _status_help
#   _dispatch_ban, _dispatch_ignore, _dispatch_test, _dispatch_cdn,
#   _dispatch_report, _dispatch_status
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

setup() {
	bfd_require_bash42
	bfd_standard_setup
	# Load all help and dispatch functions from files/bfd
	bfd_load_function "_ban_help" "$PROJECT_ROOT/files/bfd"
	bfd_load_function "_ignore_help" "$PROJECT_ROOT/files/bfd"
	bfd_load_function "_test_help" "$PROJECT_ROOT/files/bfd"
	bfd_load_function "_cdn_help" "$PROJECT_ROOT/files/bfd"
	bfd_load_function "_report_help" "$PROJECT_ROOT/files/bfd"
	bfd_load_function "_status_help" "$PROJECT_ROOT/files/bfd"
	bfd_load_function "_dispatch_ban" "$PROJECT_ROOT/files/bfd"
	bfd_load_function "_dispatch_ignore" "$PROJECT_ROOT/files/bfd"
	bfd_load_function "_dispatch_test" "$PROJECT_ROOT/files/bfd"
	bfd_load_function "_dispatch_cdn" "$PROJECT_ROOT/files/bfd"
	bfd_load_function "_dispatch_report" "$PROJECT_ROOT/files/bfd"
	bfd_load_function "_dispatch_status" "$PROJECT_ROOT/files/bfd"

	# State needed by dispatch functions
	mkdir -p "$INSTALL_PATH/tmp" "$INSTALL_PATH/stats" "$INSTALL_PATH/rules"
	printf '%s\n' "127.0.0.1" "::1" > "$INSTALL_PATH/ignore.hosts"
	export OUTPUT_FORMAT="table"
	export _EVENTS_CUTOFF=0
	export _EVENTS_LIMIT=100
	export _EVENTS_SORT="count"
	export _EVENTS_WINDOW="24h"
	export LOCK_FILE="$TEST_TMPDIR/lock.utime"
	export LOCK_FILE_TIMEOUT=300
	export PRESSURE_HALF_LIFE=300
	export PRESSURE_TRIP=20

	# Mock functions that require full BFD init (vhead, pre, manual_ban, etc.)
	vhead() { echo "[vhead]"; }
	pre() { :; }
	manual_ban() { echo "banned $2 for $4"; }
	manual_unban() { echo "unbanned $2"; }
	flush_bans() { echo "flushed $2"; }
	test_rule() { echo "test_rule $2 ${3:-}"; }
	test_pattern() { echo "test_pattern $1 ${2:-}"; }
	test_alert() { echo "test_alert ${2:-}"; }
	cdn_update() { echo "cdn_update"; }
	cdn_check_ip() { echo "cdn_check $2"; }
	cdn_check_ip_json() { echo "cdn_check_json $2"; }
	cdn_list() { echo "cdn_list"; }
	cdn_list_json() { echo "cdn_list_json"; }
	cdn_detail() { echo "cdn_detail $2"; }
	cdn_detail_json() { echo "cdn_detail_json $2"; }
	report() { echo "report $1"; }
	show_status() { echo "show_status"; }
	show_service_status() { echo "show_service_status $2"; }
	_run_scan() { echo "run_scan ${*:-}"; }
	export -f vhead pre manual_ban manual_unban flush_bans test_rule test_pattern
	export -f test_alert cdn_update cdn_check_ip cdn_check_ip_json cdn_list
	export -f cdn_list_json cdn_detail cdn_detail_json report
	export -f show_status show_service_status _run_scan
}

teardown() {
	bfd_teardown
}

# ============================================================
# Help output tests (6)
# ============================================================

@test "ban help: shows add/remove/list/flush/history" {
	run _ban_help
	assert_success
	assert_output --partial "add IP"
	assert_output --partial "remove IP"
	assert_output --partial "list"
	assert_output --partial "flush"
	assert_output --partial "history"
}

@test "ignore help: shows add/remove/list/check" {
	run _ignore_help
	assert_success
	assert_output --partial "add IP"
	assert_output --partial "remove IP"
	assert_output --partial "list"
	assert_output --partial "check IP"
}

@test "test help: shows rule/pattern/alert/scan" {
	run _test_help
	assert_success
	assert_output --partial "rule RULE"
	assert_output --partial "pattern PAT"
	assert_output --partial "alert TYPE"
	assert_output --partial "scan"
}

@test "cdn help: shows list/update/check/provider" {
	run _cdn_help
	assert_success
	assert_output --partial "update"
	assert_output --partial "check IP"
	assert_output --partial "PROVIDER"
}

@test "report help: shows interval options" {
	run _report_help
	assert_success
	assert_output --partial "daily"
	assert_output --partial "weekly"
	assert_output --partial "monthly"
}

@test "status help: shows lock/cursors/pool/pressure" {
	run _status_help
	assert_success
	assert_output --partial "lock"
	assert_output --partial "cursors"
	assert_output --partial "pool"
	assert_output --partial "pressure"
}

# ============================================================
# Dispatch routing tests (8)
# ============================================================

@test "dispatch ban: empty args shows help" {
	run _dispatch_ban
	assert_success
	assert_output --partial "usage: bfd ban"
}

@test "dispatch ban: add calls manual_ban" {
	run _dispatch_ban add "192.0.2.1"
	assert_success
	assert_output --partial "banned 192.0.2.1"
}

@test "dispatch ban: remove calls manual_unban" {
	run _dispatch_ban remove "192.0.2.1"
	assert_success
	assert_output --partial "unbanned 192.0.2.1"
}

@test "dispatch ignore: add calls ignore_add" {
	run _dispatch_ignore add "192.0.2.1"
	assert_success
	assert_output --partial "added to ignore list"
}

@test "dispatch ignore: check calls ignore_check" {
	run _dispatch_ignore check "127.0.0.1"
	assert_success
	assert_output --partial "ignored"
}

@test "dispatch status: empty shows overview" {
	run _dispatch_status
	assert_success
	assert_output --partial "show_status"
}

@test "dispatch status: lock subcommand routes correctly" {
	run _dispatch_status lock
	assert_success
	assert_output --partial "Lock"
}

@test "dispatch cdn: empty lists providers" {
	run _dispatch_cdn
	assert_success
	assert_output --partial "cdn_list"
}

# ============================================================
# Error case tests (6)
# ============================================================

@test "dispatch ban: unknown verb shows error" {
	run _dispatch_ban frobnicate
	assert_failure
	assert_output --partial "error: unknown ban command"
}

@test "dispatch ignore: missing IP for add shows error" {
	run _dispatch_ignore add
	assert_failure
	assert_output --partial "error: ignore add requires"
}

@test "dispatch ignore: unknown verb shows error" {
	run _dispatch_ignore frobnicate
	assert_failure
	assert_output --partial "error: unknown ignore command"
}

@test "dispatch test: empty shows help" {
	run _dispatch_test
	assert_success
	assert_output --partial "usage: bfd test"
}

@test "dispatch test: unknown verb shows error" {
	run _dispatch_test frobnicate
	assert_failure
	assert_output --partial "error: unknown test command"
}

@test "dispatch ban: add without IP shows error" {
	run _dispatch_ban add
	assert_failure
	assert_output --partial "error: ban add requires"
}
