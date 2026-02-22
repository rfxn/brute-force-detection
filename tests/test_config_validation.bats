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
		EMAIL_ALERTS="0"
		LOCK_FILE_TIMEOUT="300"
		BAN_COMMAND_TEMPLATE="/etc/apf/apf -d test"
		INSTALL_PATH="$TEST_TMPDIR"
		eval "$1"
		validate_config
	) >/dev/null 2>&1
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
