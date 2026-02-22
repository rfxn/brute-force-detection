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
