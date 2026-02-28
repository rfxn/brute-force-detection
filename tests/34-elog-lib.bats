#!/usr/bin/env bats
#
# Test suite for elog_lib.sh — structured logging library
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

# --- Source guard & version ---

@test "elog_lib: ELOG_LIB_VERSION is set" {
	[ -n "$ELOG_LIB_VERSION" ]
	[[ "$ELOG_LIB_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
}

@test "elog_lib: double-sourcing is idempotent" {
	local v1="$ELOG_LIB_VERSION"
	_ELOG_LIB_LOADED=""
	# shellcheck disable=SC1091
	. "$PROJECT_ROOT/files/elog_lib.sh"
	[ "$ELOG_LIB_VERSION" = "$v1" ]
}

# --- Classic format ---

@test "elog: info writes to ELOG_LOG_FILE" {
	: > "$ELOG_LOG_FILE"
	elog info "test log message" > /dev/null
	[ "$(wc -l < "$ELOG_LOG_FILE")" -eq 1 ]
	grep -q "test log message" "$ELOG_LOG_FILE"
}

@test "elog: classic format has correct structure" {
	run elog info "format check"
	assert_success
	# timestamp hostname app(pid): message
	local pat='^[A-Z][a-z]{2} [ 0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} [^ ]+ bfd\([0-9]+\): format check$'
	[[ "$output" =~ $pat ]]
}

@test "elog: info echoes to stdout (ELOG_STDOUT=always)" {
	ELOG_STDOUT="always"
	run elog info "stdout test"
	assert_success
	assert_output --partial "stdout test"
}

@test "elog: ELOG_STDOUT=never suppresses stdout" {
	ELOG_STDOUT="never"
	: > "$ELOG_LOG_FILE"
	run elog info "silent test"
	assert_success
	assert_output ""
	# but file still gets written
	grep -q "silent test" "$ELOG_LOG_FILE"
}

# --- JSON format ---

@test "elog: JSON format produces valid structure" {
	ELOG_FORMAT="json"
	: > "$ELOG_LOG_FILE"
	elog info "json test" > /dev/null
	local line
	line=$(cat "$ELOG_LOG_FILE")
	# verify JSON structure: starts with { ends with }
	[[ "$line" == \{* ]]
	[[ "$line" == *\} ]]
}

@test "elog: JSON includes required fields" {
	ELOG_FORMAT="json"
	run elog info "field test"
	assert_success
	assert_output --partial '"ts":'
	assert_output --partial '"host":'
	assert_output --partial '"app":"bfd"'
	assert_output --partial '"pid":'
	assert_output --partial '"level":"info"'
	assert_output --partial '"msg":"field test"'
}

@test "elog: JSON extracts {tag} prefix into tag field" {
	ELOG_FORMAT="json"
	run elog info "{sshd} login failed"
	assert_success
	assert_output --partial '"tag":"sshd"'
	assert_output --partial '"msg":"login failed"'
}

@test "elog: JSON omits tag field for messages without {tag}" {
	ELOG_FORMAT="json"
	run elog info "no tag here"
	assert_success
	refute_output --partial '"tag":'
	assert_output --partial '"msg":"no tag here"'
}

@test "elog: JSON escapes special characters" {
	ELOG_FORMAT="json"
	run elog info 'has "quotes" and \\backslash'
	assert_success
	assert_output --partial '\"quotes\"'
	assert_output --partial '\\\\'
}

@test "elog: JSON pid is unquoted integer" {
	ELOG_FORMAT="json"
	run elog info "pid test"
	assert_success
	local pid_pat='"pid":[0-9]+'
	[[ "$output" =~ $pid_pat ]]
}

# --- Severity filtering ---

@test "elog: ELOG_LEVEL=2 suppresses info messages" {
	ELOG_LEVEL="2"
	: > "$ELOG_LOG_FILE"
	run elog info "should be filtered"
	assert_success
	assert_output ""
	[ "$(wc -l < "$ELOG_LOG_FILE")" -eq 0 ]
}

@test "elog: ELOG_LEVEL=0 does not write debug to file" {
	ELOG_LEVEL="0"
	ELOG_VERBOSE="1"
	: > "$ELOG_LOG_FILE"
	elog debug "debug msg" > /dev/null
	[ "$(wc -l < "$ELOG_LOG_FILE")" -eq 0 ]
}

@test "elog: error appears at ELOG_LEVEL=3" {
	ELOG_LEVEL="3"
	run elog error "error message"
	assert_success
	assert_output --partial "error message"
}

@test "elog: critical appears at ELOG_LEVEL=4" {
	ELOG_LEVEL="4"
	run elog critical "critical message"
	assert_success
	assert_output --partial "critical message"
}

@test "elog: default ELOG_LEVEL=1 allows info" {
	ELOG_LEVEL="1"
	run elog info "allowed"
	assert_success
	assert_output --partial "allowed"
}

@test "elog: unknown level name defaults to info" {
	ELOG_LEVEL="1"
	run elog bogus "unknown level"
	assert_success
	assert_output --partial "unknown level"
}

# --- Debug/verbose ---

@test "elog: debug outputs when ELOG_VERBOSE=1" {
	ELOG_VERBOSE="1"
	run elog debug "verbose msg"
	assert_success
	assert_output "verbose msg"
}

@test "elog: debug silent when ELOG_VERBOSE=0" {
	ELOG_VERBOSE="0"
	run elog debug "silent debug"
	assert_success
	assert_output ""
}

@test "elog: debug never writes to ELOG_LOG_FILE" {
	ELOG_VERBOSE="1"
	: > "$ELOG_LOG_FILE"
	elog debug "no file write" > /dev/null
	[ "$(wc -l < "$ELOG_LOG_FILE")" -eq 0 ]
}

@test "elog: debug outputs bare text (no timestamp/hostname)" {
	ELOG_VERBOSE="1"
	run elog debug "bare text"
	assert_success
	assert_output "bare text"
}

# --- Syslog ---

@test "elog: ELOG_SYSLOG_FILE non-empty writes to syslog file" {
	local syslog_file="$TEST_TMPDIR/elog_syslog"
	: > "$syslog_file"
	ELOG_SYSLOG_FILE="$syslog_file"
	elog info "syslog test" > /dev/null
	[ "$(wc -l < "$syslog_file")" -eq 1 ]
	grep -q "syslog test" "$syslog_file"
}

@test "elog: ELOG_SYSLOG_FILE empty means no syslog write" {
	ELOG_SYSLOG_FILE=""
	: > "$TEST_TMPDIR/nosyslog"
	elog info "no syslog" > /dev/null
	[ ! -s "$TEST_TMPDIR/nosyslog" ]
}

@test "elog: debug never writes to syslog file" {
	local syslog_file="$TEST_TMPDIR/elog_syslog"
	: > "$syslog_file"
	ELOG_SYSLOG_FILE="$syslog_file"
	ELOG_VERBOSE="1"
	elog debug "debug no syslog" > /dev/null
	[ "$(wc -l < "$syslog_file")" -eq 0 ]
}

# --- Edge cases ---

@test "elog: empty message produces no output" {
	: > "$ELOG_LOG_FILE"
	run elog info ""
	assert_success
	assert_output ""
	[ "$(wc -l < "$ELOG_LOG_FILE")" -eq 0 ]
}

@test "elog: missing ELOG_LOG_FILE (empty) causes no error" {
	ELOG_LOG_FILE=""
	run elog info "no file target"
	assert_success
	assert_output --partial "no file target"
}

@test "_elog_json_escape: handles backslash, double-quote, newline, tab" {
	local result
	result=$(_elog_json_escape 'a\b"c
d	e')
	[[ "$result" == *'a\\b\"c\nd\te'* ]]
}

@test "_elog_extract_tag: returns empty for messages without {tag}" {
	local result
	result=$(_elog_extract_tag "no tag here")
	[ -z "$result" ]
}

@test "_elog_extract_tag: extracts tag from {tag} prefix" {
	local result
	result=$(_elog_extract_tag "{sshd} login failed")
	[ "$result" = "sshd" ]
}

# --- Convenience wrappers ---

@test "elog_info: convenience wrapper works" {
	run elog_info "wrapper test"
	assert_success
	assert_output --partial "wrapper test"
}

@test "elog_warn: convenience wrapper works" {
	run elog_warn "warning test"
	assert_success
	assert_output --partial "warning test"
}

# --- Stdout prefix modes ---

@test "elog: ELOG_STDOUT_PREFIX=short shows app(pid): msg" {
	ELOG_STDOUT_PREFIX="short"
	run elog info "prefix test"
	assert_success
	local pat='^bfd\([0-9]+\): prefix test$'
	[[ "$output" =~ $pat ]]
}

@test "elog: ELOG_STDOUT_PREFIX=none shows bare message" {
	ELOG_STDOUT_PREFIX="none"
	run elog info "bare prefix"
	assert_success
	assert_output "bare prefix"
}

@test "elog: ELOG_STDOUT=flag requires flag arg for stdout" {
	ELOG_STDOUT="flag"
	: > "$ELOG_LOG_FILE"
	# without flag — no stdout but file written
	run elog info "no flag"
	assert_success
	assert_output ""
	grep -q "no flag" "$ELOG_LOG_FILE"
	# with flag — stdout enabled
	run elog info "with flag" "1"
	assert_success
	assert_output --partial "with flag"
}
