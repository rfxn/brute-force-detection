#!/usr/bin/env bats
#
# Test suite for validate_rule()
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

setup() {
	bfd_common_setup
	# create a real log file for LOG_FILE
	echo "log line" > "$TEST_TMPDIR/test.log"
}

teardown() {
	bfd_teardown
}

@test "validate_rule: all required variables set returns 0" {
	LOG_FILE="$TEST_TMPDIR/test.log"
	LOG_TAG="sshd"
	MATCHED_HOSTS="192.0.2.1:user"
	run validate_rule "sshd"
	assert_success
}

@test "validate_rule: LOG_FILE unset returns 1" {
	unset LOG_FILE
	LOG_TAG="sshd"
	MATCHED_HOSTS="192.0.2.1:user"
	run validate_rule "sshd"
	assert_failure
	assert_output --partial "LOG_FILE not set"
}

@test "validate_rule: LOG_FILE empty returns 1" {
	LOG_FILE=""
	LOG_TAG="sshd"
	MATCHED_HOSTS="192.0.2.1:user"
	run validate_rule "sshd"
	assert_failure
	assert_output --partial "LOG_FILE not set"
}

@test "validate_rule: LOG_FILE file does not exist returns 1" {
	LOG_FILE="$TEST_TMPDIR/nonexistent.log"
	LOG_TAG="sshd"
	MATCHED_HOSTS="192.0.2.1:user"
	LOG_SOURCE="file"
	run validate_rule "sshd"
	assert_failure
	assert_output --partial "does not exist"
}

@test "validate_rule: LOG_TAG unset returns 1" {
	LOG_FILE="$TEST_TMPDIR/test.log"
	unset LOG_TAG
	MATCHED_HOSTS="192.0.2.1:user"
	run validate_rule "sshd"
	assert_failure
	assert_output --partial "LOG_TAG not set"
}

@test "validate_rule: LOG_TAG empty returns 1" {
	LOG_FILE="$TEST_TMPDIR/test.log"
	LOG_TAG=""
	MATCHED_HOSTS="192.0.2.1:user"
	run validate_rule "sshd"
	assert_failure
	assert_output --partial "LOG_TAG not set"
}

@test "validate_rule: MATCHED_HOSTS empty returns 1 silently" {
	LOG_FILE="$TEST_TMPDIR/test.log"
	LOG_TAG="sshd"
	MATCHED_HOSTS=""
	run validate_rule "sshd"
	assert_failure
	assert_output ""
}

@test "validate_rule: MATCHED_HOSTS unset returns 1 silently" {
	LOG_FILE="$TEST_TMPDIR/test.log"
	LOG_TAG="sshd"
	unset MATCHED_HOSTS
	run validate_rule "sshd"
	assert_failure
	assert_output ""
}

@test "validate_rule: rule name appears in log messages" {
	LOG_FILE=""
	LOG_TAG="sshd"
	MATCHED_HOSTS="192.0.2.1:user"
	run validate_rule "dovecot"
	assert_output --partial "dovecot"
}
