#!/usr/bin/env bats
#
# Test suite for eout()
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

setup() {
	bfd_common_setup
}

teardown() {
	bfd_teardown
}

@test "eout: basic output to stdout contains message" {
	run eout "test message"
	assert_success
	assert_output --partial "test message"
}

@test "eout: stdout includes timestamp format" {
	run eout "test message"
	local ts_pat='^[A-Z][a-z]{2} [ 0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}'
	[[ "$output" =~ $ts_pat ]]
}

@test "eout: stdout includes hostname and pid" {
	run eout "test message"
	local pid_pat='bfd\([0-9]+\):'
	[[ "$output" =~ $pid_pat ]]
}

@test "eout: no log write without le flag" {
	: > "$BFD_LOG_PATH"
	eout "no-log message" > /dev/null
	[ "$(wc -l < "$BFD_LOG_PATH")" -eq 0 ]
}

@test "eout: le flag writes to BFD_LOG_PATH" {
	: > "$BFD_LOG_PATH"
	eout "logged message" "le" > /dev/null
	[ "$(wc -l < "$BFD_LOG_PATH")" -eq 1 ]
}

@test "eout: log file contains the message" {
	: > "$BFD_LOG_PATH"
	eout "logged message" "le" > /dev/null
	grep -q "logged message" "$BFD_LOG_PATH"
}

@test "eout: syslog output disabled" {
	: > "$OUTPUT_SYSLOG_FILE"
	OUTPUT_SYSLOG="0"
	eout "no syslog" "le" > /dev/null
	[ "$(wc -l < "$OUTPUT_SYSLOG_FILE")" -eq 0 ]
}

@test "eout: syslog output enabled" {
	: > "$OUTPUT_SYSLOG_FILE"
	OUTPUT_SYSLOG="1"
	eout "syslog message" "le" > /dev/null
	[ "$(wc -l < "$OUTPUT_SYSLOG_FILE")" -eq 1 ]
}

@test "eout: syslog file contains the message" {
	: > "$OUTPUT_SYSLOG_FILE"
	OUTPUT_SYSLOG="1"
	eout "syslog message" "le" > /dev/null
	grep -q "syslog message" "$OUTPUT_SYSLOG_FILE"
}

@test "eout: empty arg produces no output" {
	run eout ""
	assert_success
	assert_output ""
}

@test "eout: empty arg does not write to log" {
	: > "$BFD_LOG_PATH"
	eout "" "le" > /dev/null
	[ "$(wc -l < "$BFD_LOG_PATH")" -eq 0 ]
}
