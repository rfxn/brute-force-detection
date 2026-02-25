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

@test "validate_rule: active rule with all variables set returns 0" {
	PREREQ="$TEST_TMPDIR/test.log"
	LOG_FILE="$TEST_TMPDIR/test.log"
	LOG_TAG="sshd"
	run validate_rule "sshd"
	assert_success
}

@test "validate_rule: PREREQ missing binary — silent skip" {
	PREREQ="/nonexistent/binary"
	LOG_FILE="$TEST_TMPDIR/test.log"
	LOG_TAG="sshd"
	run validate_rule "sshd"
	assert_failure
	assert_output ""
}

@test "validate_rule: PREREQ empty + LOG_FILE empty — silent skip (file-detection no match)" {
	PREREQ=""
	LOG_FILE=""
	LOG_TAG=""
	run validate_rule "http_401"
	assert_failure
	assert_output ""
}

@test "validate_rule: PREREQ exists but LOG_FILE empty — misconfiguration message" {
	PREREQ="/bin/sh"
	LOG_FILE=""
	LOG_TAG="sshd"
	run validate_rule "sshd"
	assert_failure
	assert_output --partial "LOG_FILE not set"
}

@test "validate_rule: LOG_FILE file does not exist returns 1" {
	PREREQ="/bin/sh"
	LOG_FILE="$TEST_TMPDIR/nonexistent.log"
	LOG_TAG="sshd"
	LOG_SOURCE="file"
	run validate_rule "sshd"
	assert_failure
	assert_output --partial "does not exist"
}

@test "validate_rule: LOG_TAG unset returns 1" {
	PREREQ="/bin/sh"
	LOG_FILE="$TEST_TMPDIR/test.log"
	unset LOG_TAG
	run validate_rule "sshd"
	assert_failure
	assert_output --partial "LOG_TAG not set"
}

@test "validate_rule: LOG_TAG empty returns 1" {
	PREREQ="/bin/sh"
	LOG_FILE="$TEST_TMPDIR/test.log"
	LOG_TAG=""
	run validate_rule "sshd"
	assert_failure
	assert_output --partial "LOG_TAG not set"
}

@test "validate_rule: MATCHED_HOSTS empty still returns 0 (caller checks)" {
	PREREQ="/bin/sh"
	LOG_FILE="$TEST_TMPDIR/test.log"
	LOG_TAG="sshd"
	MATCHED_HOSTS=""
	run validate_rule "sshd"
	assert_success
}

@test "validate_rule: MATCHED_HOSTS unset still returns 0 (caller checks)" {
	PREREQ="/bin/sh"
	LOG_FILE="$TEST_TMPDIR/test.log"
	LOG_TAG="sshd"
	unset MATCHED_HOSTS
	run validate_rule "sshd"
	assert_success
}

@test "validate_rule: rule name appears in log messages" {
	PREREQ="/bin/sh"
	LOG_FILE=""
	LOG_TAG="sshd"
	run validate_rule "dovecot"
	assert_output --partial "dovecot"
}

@test "validate_rule: file-detection rule with PREREQ from LOG_FILE" {
	# Simulates file-detection pattern: PREREQ="${LOG_FILE:-}"
	LOG_FILE="$TEST_TMPDIR/test.log"
	PREREQ="$LOG_FILE"
	LOG_TAG="http.401"
	run validate_rule "http_401"
	assert_success
}
