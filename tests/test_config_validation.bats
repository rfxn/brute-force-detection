#!/usr/bin/env bats
#
# Test suite for validate_config()
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

setup() {
	TEST_TMPDIR=$(mktemp -d)
}

teardown() {
	rm -rf "$TEST_TMPDIR"
}

# helper: set all config to valid defaults, then override one field
run_validate() {
	(
		TRIG="15"
		TRIG_WINDOW="300"
		TRIG_GLOBAL="0"
		BAN_DURATION="300"
		BAN_PERMANENT_AFTER="5"
		BAN_PERMANENT_WINDOW="86400"
		UNBAN_COMMAND_TEMPLATE=""
		EMAIL_ALERTS="0"
		LOCK_FILE_TIMEOUT="300"
		BAN_COMMAND_TEMPLATE="/etc/apf/apf -d test"
		FIREWALL="custom"
		INSTALL_PATH="$TEST_TMPDIR"
		eval "$1"
		validate_config
	) >/dev/null 2>&1
}

# helper: capture stdout+stderr for warning checks
run_validate_output() {
	(
		TRIG="15"
		TRIG_WINDOW="300"
		TRIG_GLOBAL="0"
		BAN_DURATION="300"
		BAN_PERMANENT_AFTER="5"
		BAN_PERMANENT_WINDOW="86400"
		UNBAN_COMMAND_TEMPLATE=""
		EMAIL_ALERTS="0"
		LOCK_FILE_TIMEOUT="300"
		BAN_COMMAND_TEMPLATE="/etc/apf/apf -d test"
		FIREWALL="custom"
		INSTALL_PATH="$TEST_TMPDIR"
		eval "$1"
		validate_config
	) 2>&1
}

@test "validate_config: valid config passes" {
	run run_validate ""
	assert_success
}

@test "validate_config: TRIG=abc rejects" {
	run run_validate 'TRIG="abc"'
	assert_failure
}

@test "validate_config: TRIG=0 rejects" {
	run run_validate 'TRIG="0"'
	assert_failure
}

@test "validate_config: TRIG= rejects" {
	run run_validate 'TRIG=""'
	assert_failure
}

@test "validate_config: TRIG=15 passes" {
	run run_validate 'TRIG="15"'
	assert_success
}

@test "validate_config: TRIG=1 passes" {
	run run_validate 'TRIG="1"'
	assert_success
}

@test "validate_config: EMAIL_ALERTS=2 rejects" {
	run run_validate 'EMAIL_ALERTS="2"'
	assert_failure
}

@test "validate_config: EMAIL_ALERTS=abc rejects" {
	run run_validate 'EMAIL_ALERTS="abc"'
	assert_failure
}

@test "validate_config: EMAIL_ALERTS=0 passes" {
	run run_validate 'EMAIL_ALERTS="0"'
	assert_success
}

@test "validate_config: EMAIL_ALERTS=1 passes" {
	run run_validate 'EMAIL_ALERTS="1"'
	assert_success
}

@test "validate_config: TIMEOUT=0 rejects" {
	run run_validate 'LOCK_FILE_TIMEOUT="0"'
	assert_failure
}

@test "validate_config: TIMEOUT=abc rejects" {
	run run_validate 'LOCK_FILE_TIMEOUT="abc"'
	assert_failure
}

@test "validate_config: TIMEOUT= rejects" {
	run run_validate 'LOCK_FILE_TIMEOUT=""'
	assert_failure
}

@test "validate_config: TIMEOUT=300 passes" {
	run run_validate 'LOCK_FILE_TIMEOUT="300"'
	assert_success
}

@test "validate_config: empty BAN_COMMAND rejects" {
	run run_validate 'BAN_COMMAND_TEMPLATE=""'
	assert_failure
}

@test "validate_config: bad INSTALL_PATH rejects" {
	run run_validate 'INSTALL_PATH="/nonexistent/path"'
	assert_failure
}

# --- TRIG_WINDOW ---

@test "validate_config: TRIG_WINDOW=300 passes" {
	run run_validate 'TRIG_WINDOW="300"'
	assert_success
}

@test "validate_config: TRIG_WINDOW=0 rejects" {
	run run_validate 'TRIG_WINDOW="0"'
	assert_failure
}

@test "validate_config: TRIG_WINDOW=abc rejects" {
	run run_validate 'TRIG_WINDOW="abc"'
	assert_failure
}

@test "validate_config: TRIG_WINDOW= rejects" {
	run run_validate 'TRIG_WINDOW=""'
	assert_failure
}

# --- TRIG_GLOBAL ---

@test "validate_config: TRIG_GLOBAL=0 passes (disabled)" {
	run run_validate 'TRIG_GLOBAL="0"'
	assert_success
}

@test "validate_config: TRIG_GLOBAL=10 passes" {
	run run_validate 'TRIG_GLOBAL="10"'
	assert_success
}

@test "validate_config: TRIG_GLOBAL=abc rejects" {
	run run_validate 'TRIG_GLOBAL="abc"'
	assert_failure
}

@test "validate_config: TRIG_GLOBAL= rejects" {
	run run_validate 'TRIG_GLOBAL=""'
	assert_failure
}

# --- BAN_DURATION ---

@test "validate_config: BAN_DURATION=300 passes" {
	run run_validate 'BAN_DURATION="300"; UNBAN_COMMAND_TEMPLATE="echo test"'
	assert_success
}

@test "validate_config: BAN_DURATION=0 passes (permanent)" {
	run run_validate 'BAN_DURATION="0"'
	assert_success
}

@test "validate_config: BAN_DURATION=abc rejects" {
	run run_validate 'BAN_DURATION="abc"'
	assert_failure
}

# --- BAN_PERMANENT_AFTER ---

@test "validate_config: BAN_PERMANENT_AFTER=5 passes" {
	run run_validate 'BAN_PERMANENT_AFTER="5"; UNBAN_COMMAND_TEMPLATE="echo test"'
	assert_success
}

@test "validate_config: BAN_PERMANENT_AFTER=0 passes (disabled)" {
	run run_validate 'BAN_PERMANENT_AFTER="0"; UNBAN_COMMAND_TEMPLATE="echo test"'
	assert_success
}

@test "validate_config: BAN_PERMANENT_AFTER=abc rejects" {
	run run_validate 'BAN_PERMANENT_AFTER="abc"'
	assert_failure
}

# --- BAN_PERMANENT_WINDOW ---

@test "validate_config: BAN_PERMANENT_WINDOW=86400 passes" {
	run run_validate 'BAN_PERMANENT_WINDOW="86400"; UNBAN_COMMAND_TEMPLATE="echo test"'
	assert_success
}

@test "validate_config: BAN_PERMANENT_WINDOW=0 rejects" {
	run run_validate 'BAN_PERMANENT_WINDOW="0"'
	assert_failure
}

@test "validate_config: BAN_PERMANENT_WINDOW=abc rejects" {
	run run_validate 'BAN_PERMANENT_WINDOW="abc"'
	assert_failure
}

# --- UNBAN_COMMAND warning ---

@test "validate_config: warns when BAN_DURATION>0 and UNBAN_COMMAND empty" {
	run run_validate_output 'BAN_DURATION="300"; UNBAN_COMMAND_TEMPLATE=""'
	assert_success
	assert_output --partial "warning"
	assert_output --partial "UNBAN_COMMAND"
}

# --- WATCH_INTERVAL ---

@test "validate_config: WATCH_INTERVAL=10 passes" {
	run run_validate 'WATCH_INTERVAL="10"'
	assert_success
}

@test "validate_config: WATCH_INTERVAL=1 passes" {
	run run_validate 'WATCH_INTERVAL="1"'
	assert_success
}

@test "validate_config: WATCH_INTERVAL=0 rejects" {
	run run_validate 'WATCH_INTERVAL="0"'
	assert_failure
}

@test "validate_config: WATCH_INTERVAL=abc rejects" {
	run run_validate 'WATCH_INTERVAL="abc"'
	assert_failure
}

@test "validate_config: WATCH_INTERVAL= rejects" {
	run run_validate 'WATCH_INTERVAL=""'
	assert_failure
}

@test "validate_config: WATCH_INTERVAL unset uses default (passes)" {
	run run_validate 'unset WATCH_INTERVAL'
	assert_success
}

# --- BAN_ESCALATION ---

@test "validate_config: BAN_ESCALATION=none passes" {
	run run_validate 'BAN_ESCALATION="none"'
	assert_success
}

@test "validate_config: BAN_ESCALATION=linear passes" {
	run run_validate 'BAN_ESCALATION="linear"'
	assert_success
}

@test "validate_config: BAN_ESCALATION=exponential passes" {
	run run_validate 'BAN_ESCALATION="exponential"'
	assert_success
}

@test "validate_config: BAN_ESCALATION=bogus rejects" {
	run run_validate 'BAN_ESCALATION="bogus"'
	assert_failure
}

@test "validate_config: BAN_ESCALATION unset uses default (passes)" {
	run run_validate 'unset BAN_ESCALATION'
	assert_success
}

@test "validate_config: BAN_ESCALATION_CAP=86400 passes" {
	run run_validate 'BAN_ESCALATION_CAP="86400"'
	assert_success
}

@test "validate_config: BAN_ESCALATION_CAP=0 passes" {
	run run_validate 'BAN_ESCALATION_CAP="0"'
	assert_success
}

@test "validate_config: BAN_ESCALATION_CAP=abc rejects" {
	run run_validate 'BAN_ESCALATION_CAP="abc"'
	assert_failure
}

# ============================================================
# SUBNET_TRIG / SUBNET_MASK / SUBNET_MASK_V6 validation
# ============================================================

@test "validate_config: SUBNET_TRIG=0 passes" {
	run run_validate 'SUBNET_TRIG="0"'
	assert_success
}

@test "validate_config: SUBNET_TRIG=5 passes" {
	run run_validate 'SUBNET_TRIG="5"'
	assert_success
}

@test "validate_config: SUBNET_TRIG=abc rejects" {
	run run_validate 'SUBNET_TRIG="abc"'
	assert_failure
}

@test "validate_config: SUBNET_MASK=24 passes" {
	run run_validate 'SUBNET_MASK="24"'
	assert_success
}

@test "validate_config: SUBNET_MASK=7 rejects (below minimum)" {
	run run_validate 'SUBNET_MASK="7"'
	assert_failure
}

@test "validate_config: SUBNET_MASK=33 rejects (above maximum)" {
	run run_validate 'SUBNET_MASK="33"'
	assert_failure
}

@test "validate_config: SUBNET_MASK_V6=48 passes" {
	run run_validate 'SUBNET_MASK_V6="48"'
	assert_success
}

@test "validate_config: SUBNET_MASK_V6=50 rejects (not multiple of 16)" {
	run run_validate 'SUBNET_MASK_V6="50"'
	assert_failure
}

@test "validate_config: SUBNET_MASK_V6 unset uses default (passes)" {
	run run_validate 'unset SUBNET_MASK_V6'
	assert_success
}

# --- show_config injection tests (Phase 26) ---

@test "show_config: rejects \$(cmd) injection attempt" {
	TRIG="15"
	run show_config '$(touch /tmp/pwned)'
	assert_failure
	assert_output --partial "unknown config variable"
	[ ! -f "/tmp/pwned" ]
}

@test "show_config: rejects backtick injection attempt" {
	TRIG="15"
	run show_config '`touch /tmp/pwned2`'
	assert_failure
	assert_output --partial "unknown config variable"
	[ ! -f "/tmp/pwned2" ]
}

@test "show_config: rejects unknown variable name" {
	TRIG="15"
	run show_config "NONEXISTENT_VAR"
	assert_failure
	assert_output --partial "unknown config variable"
}

@test "show_config: accepts valid config var TRIG" {
	TRIG="42"
	run show_config "TRIG"
	assert_success
	assert_output "42"
}

# --- eout tests (Phase 27) ---

@test "eout: writes to stdout" {
	BFD_LOG_PATH="$TEST_TMPDIR/bfd.log"
	touch "$BFD_LOG_PATH"
	OUTPUT_SYSLOG="0"
	OUTPUT_SYSLOG_FILE="/dev/null"
	run eout "test message"
	assert_success
	assert_output --partial "test message"
}

@test "eout: writes to BFD_LOG_PATH with le flag" {
	BFD_LOG_PATH="$TEST_TMPDIR/bfd.log"
	touch "$BFD_LOG_PATH"
	OUTPUT_SYSLOG="0"
	OUTPUT_SYSLOG_FILE="/dev/null"
	eout "logged message" "le"
	run cat "$BFD_LOG_PATH"
	assert_output --partial "logged message"
}

# --- _hc_config case statement tests (Phase 27) ---

@test "_hc_config: validates log paths with case statement" {
	AUTH_LOG_PATH="/var/log/auth.log"
	KERNEL_LOG_PATH=""
	MAIL_LOG_PATH="/var/log/mail.log"
	_hc_pass=0
	_hc_warn=0
	_hc_fail=0
	BAN_COMMAND_TEMPLATE="/bin/true"
	UNBAN_COMMAND_TEMPLATE="/bin/true"
	BAN_COMMAND_V6_TEMPLATE=""
	UNBAN_COMMAND_V6_TEMPLATE=""
	_FW_BACKEND="custom"
	# just test config section's log path logic
	run _hc_config
	assert_output --partial "KERNEL_LOG_PATH: not configured"
}
