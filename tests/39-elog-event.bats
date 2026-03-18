#!/usr/bin/env bats
#
# Test suite for elog_event() structured event integration
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

setup() {
	bfd_common_setup
	# Ensure audit_file module is enabled (elog_init not called in unit tests)
	elog_output_enable "audit_file" 2>/dev/null || true
}

teardown() {
	bfd_teardown
}

# --- Basic dispatch ---

@test "elog_event: block_added writes to ELOG_AUDIT_FILE" {
	: > "$ELOG_AUDIT_FILE"
	elog_event "block_added" "warn" "{sshd} banned 192.0.2.1 via iptables" \
		"ip=192.0.2.1" "mod=sshd" "backend=iptables" "ports=all"
	[ "$(wc -l < "$ELOG_AUDIT_FILE")" -eq 1 ]
	grep -q '"type":"block_added"' "$ELOG_AUDIT_FILE"
}

@test "elog_event: does NOT write to ELOG_LOG_FILE" {
	: > "$ELOG_LOG_FILE"
	: > "$ELOG_AUDIT_FILE"
	elog_event "block_added" "warn" "{sshd} banned 192.0.2.1" \
		"ip=192.0.2.1" "mod=sshd"
	# audit file has the event
	[ "$(wc -l < "$ELOG_AUDIT_FILE")" -eq 1 ]
	# app log file should be empty — event source filter prevents this
	[ "$(wc -l < "$ELOG_LOG_FILE")" -eq 0 ]
}

@test "eout: does NOT write to ELOG_AUDIT_FILE" {
	: > "$ELOG_AUDIT_FILE"
	: > "$ELOG_LOG_FILE"
	eout "test app log message" le > /dev/null
	# app log written
	[ "$(wc -l < "$ELOG_LOG_FILE")" -ge 1 ]
	# audit file should be empty — elog source filter prevents this
	[ "$(wc -l < "$ELOG_AUDIT_FILE")" -eq 0 ]
}

# --- JSON envelope ---

@test "elog_event: JSON envelope has required fields" {
	: > "$ELOG_AUDIT_FILE"
	elog_event "config_loaded" "info" "configuration initialized"
	local line
	line=$(cat "$ELOG_AUDIT_FILE")
	# mandatory fields
	[[ "$line" == *'"ts":'* ]]
	[[ "$line" == *'"host":'* ]]
	[[ "$line" == *'"app":"bfd"'* ]]
	[[ "$line" == *'"pid":'* ]]
	[[ "$line" == *'"type":"config_loaded"'* ]]
	[[ "$line" == *'"level":"info"'* ]]
	[[ "$line" == *'"msg":"configuration initialized"'* ]]
}

@test "elog_event: key=value pairs in JSON" {
	: > "$ELOG_AUDIT_FILE"
	elog_event "block_added" "warn" "{sshd} banned 192.0.2.1" \
		"ip=192.0.2.1" "mod=sshd" "backend=iptables"
	local line
	line=$(cat "$ELOG_AUDIT_FILE")
	[[ "$line" == *'"ip":"192.0.2.1"'* ]]
	[[ "$line" == *'"mod":"sshd"'* ]]
	[[ "$line" == *'"backend":"iptables"'* ]]
}

@test "elog_event: {tag} extraction in JSON" {
	: > "$ELOG_AUDIT_FILE"
	elog_event "block_added" "warn" "{sshd} banned 192.0.2.1"
	local line
	line=$(cat "$ELOG_AUDIT_FILE")
	[[ "$line" == *'"tag":"sshd"'* ]]
	[[ "$line" == *'"msg":"banned 192.0.2.1"'* ]]
}

# --- Severity filtering ---

@test "elog_event: below ELOG_LEVEL is suppressed" {
	ELOG_LEVEL="3"
	: > "$ELOG_AUDIT_FILE"
	elog_event "config_loaded" "info" "should be filtered"
	[ "$(wc -l < "$ELOG_AUDIT_FILE")" -eq 0 ]
}

# --- Input validation ---

@test "elog_event: empty type returns 1" {
	run elog_event "" "info" "no type"
	assert_failure
	assert_output --partial "requires event_type"
}

@test "elog_event: empty message returns 0 with no output" {
	: > "$ELOG_AUDIT_FILE"
	run elog_event "config_loaded" "info" ""
	assert_success
	[ "$(wc -l < "$ELOG_AUDIT_FILE")" -eq 0 ]
}

# --- elog_init ---

@test "elog_init: creates ELOG_LOG_DIR and ELOG_AUDIT_FILE" {
	local init_dir="$TEST_TMPDIR/init_test"
	ELOG_LOG_DIR="$init_dir"
	ELOG_AUDIT_FILE="$init_dir/audit.log"
	ELOG_LOG_FILE="$init_dir/bfd.log"
	# reset init state to allow re-init
	_ELOG_INIT_DONE=0
	run elog_init
	assert_success
	[ -d "$init_dir" ]
	[ -f "$init_dir/audit.log" ]
	[ -f "$init_dir/bfd.log" ]
}

# --- Convenience wrapper ---

@test "elog_critical: convenience wrapper works" {
	: > "$ELOG_LOG_FILE"
	run elog_critical "critical test"
	assert_success
	assert_output --partial "critical test"
}

# --- Cross-contamination guard ---

@test "audit file empty after elog() calls only" {
	: > "$ELOG_AUDIT_FILE"
	: > "$ELOG_LOG_FILE"
	elog info "app message 1" > /dev/null
	elog warn "app message 2" > /dev/null
	elog error "app message 3" > /dev/null
	# app log has 3 entries
	[ "$(wc -l < "$ELOG_LOG_FILE")" -eq 3 ]
	# audit log should have zero
	[ "$(wc -l < "$ELOG_AUDIT_FILE")" -eq 0 ]
}
