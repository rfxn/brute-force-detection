#!/usr/bin/env bats
#
# Test suite for validate_rule()
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

setup() {
	TEST_TMPDIR=$(mktemp -d)
	# eout dependencies
	BFD_LOG_PATH="$TEST_TMPDIR/bfd.log"
	touch "$BFD_LOG_PATH"
	OUTPUT_SYSLOG="0"
	OUTPUT_SYSLOG_FILE="/dev/null"
	# create a real log file for LP
	echo "log line" > "$TEST_TMPDIR/test.log"
}

teardown() {
	rm -rf "$TEST_TMPDIR"
}

@test "validate_rule: all required variables set returns 0" {
	LP="$TEST_TMPDIR/test.log"
	TLOG_TF="sshd"
	ARG_VAL="10.0.0.1:user"
	run validate_rule "sshd"
	assert_success
}

@test "validate_rule: LP unset returns 1" {
	unset LP
	TLOG_TF="sshd"
	ARG_VAL="10.0.0.1:user"
	run validate_rule "sshd"
	assert_failure
	assert_output --partial "LP not set"
}

@test "validate_rule: LP empty returns 1" {
	LP=""
	TLOG_TF="sshd"
	ARG_VAL="10.0.0.1:user"
	run validate_rule "sshd"
	assert_failure
	assert_output --partial "LP not set"
}

@test "validate_rule: LP file does not exist returns 1" {
	LP="$TEST_TMPDIR/nonexistent.log"
	TLOG_TF="sshd"
	ARG_VAL="10.0.0.1:user"
	LOG_SOURCE="file"
	run validate_rule "sshd"
	assert_failure
	assert_output --partial "does not exist"
}

@test "validate_rule: TLOG_TF unset returns 1" {
	LP="$TEST_TMPDIR/test.log"
	unset TLOG_TF
	ARG_VAL="10.0.0.1:user"
	run validate_rule "sshd"
	assert_failure
	assert_output --partial "TLOG_TF not set"
}

@test "validate_rule: TLOG_TF empty returns 1" {
	LP="$TEST_TMPDIR/test.log"
	TLOG_TF=""
	ARG_VAL="10.0.0.1:user"
	run validate_rule "sshd"
	assert_failure
	assert_output --partial "TLOG_TF not set"
}

@test "validate_rule: ARG_VAL empty returns 1 silently" {
	LP="$TEST_TMPDIR/test.log"
	TLOG_TF="sshd"
	ARG_VAL=""
	run validate_rule "sshd"
	assert_failure
	assert_output ""
}

@test "validate_rule: ARG_VAL unset returns 1 silently" {
	LP="$TEST_TMPDIR/test.log"
	TLOG_TF="sshd"
	unset ARG_VAL
	run validate_rule "sshd"
	assert_failure
	assert_output ""
}

@test "validate_rule: rule name appears in log messages" {
	LP=""
	TLOG_TF="sshd"
	ARG_VAL="10.0.0.1:user"
	run validate_rule "dovecot"
	assert_output --partial "dovecot"
}
