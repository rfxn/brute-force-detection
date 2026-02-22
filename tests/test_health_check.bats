#!/usr/bin/env bats
#
# Tests for health_check() — Phase 13C
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

setup() {
	TEST_TMPDIR=$(mktemp -d)
	INSTALL_PATH="$TEST_TMPDIR/bfd"
	mkdir -p "$INSTALL_PATH/tmp" "$INSTALL_PATH/stats" "$INSTALL_PATH/rules"
	state_init "$INSTALL_PATH"

	# eout dependencies
	BFD_LOG_PATH="$TEST_TMPDIR/bfd.log"
	touch "$BFD_LOG_PATH"
	OUTPUT_SYSLOG="0"
	OUTPUT_SYSLOG_FILE="/dev/null"

	# config variables needed by validate_config and health_check
	TRIG="15"
	TRIG_WINDOW="300"
	TRIG_GLOBAL="0"
	BAN_DURATION="0"
	BAN_PERMANENT_AFTER="0"
	BAN_PERMANENT_WINDOW="86400"
	EMAIL_ALERTS="0"
	LOCK_FILE_TIMEOUT="300"
	BAN_COMMAND_TEMPLATE="/bin/true -d \$ATTACK_HOST"
	UNBAN_COMMAND_TEMPLATE=""
	BAN_COMMAND_V6_TEMPLATE=""
	GLOB_TRIG="$TRIG"
	RULES_PATH="$INSTALL_PATH/rules"
	TLOG_PATH="$INSTALL_PATH/tlog"
	LOCK_FILE="$INSTALL_PATH/lock.utime"

	# log paths
	AUTH_LOG_PATH="$TEST_TMPDIR/auth.log"
	KERNEL_LOG_PATH="$TEST_TMPDIR/messages"
	MAIL_LOG_PATH="$TEST_TMPDIR/maillog"
	touch "$AUTH_LOG_PATH" "$KERNEL_LOG_PATH"

	# create tlog stub
	echo '#!/bin/bash' > "$TLOG_PATH"
	chmod +x "$TLOG_PATH"
}

teardown() {
	rm -rf "$TEST_TMPDIR"
}

@test "health_check: PASS for valid config" {
	run health_check "$INSTALL_PATH"
	assert_success
	assert_output --partial "[PASS] Configuration validated"
}

@test "health_check: FAIL for missing BAN_COMMAND" {
	BAN_COMMAND_TEMPLATE=""
	# validate_config will exit, so capture via subshell
	run bash -c "
		source '${PROJECT_ROOT}/files/bfd.lib.sh'
		INSTALL_PATH='$INSTALL_PATH'
		BFD_LOG_PATH='$BFD_LOG_PATH'
		OUTPUT_SYSLOG='0'
		OUTPUT_SYSLOG_FILE='/dev/null'
		TRIG='15'; TRIG_WINDOW='300'; TRIG_GLOBAL='0'
		BAN_DURATION='0'; BAN_PERMANENT_AFTER='0'; BAN_PERMANENT_WINDOW='86400'
		EMAIL_ALERTS='0'; LOCK_FILE_TIMEOUT='300'
		BAN_COMMAND_TEMPLATE=''
		UNBAN_COMMAND_TEMPLATE=''
		BAN_COMMAND_V6_TEMPLATE=''
		GLOB_TRIG='15'
		RULES_PATH='$INSTALL_PATH/rules'
		TLOG_PATH='$INSTALL_PATH/tlog'
		LOCK_FILE='$INSTALL_PATH/lock.utime'
		AUTH_LOG_PATH='$AUTH_LOG_PATH'
		KERNEL_LOG_PATH='$KERNEL_LOG_PATH'
		MAIL_LOG_PATH='$MAIL_LOG_PATH'
		health_check '$INSTALL_PATH'
	"
	assert_output --partial "[FAIL] Configuration"
}

@test "health_check: WARN for missing log file" {
	MAIL_LOG_PATH="/nonexistent/mail.log"
	run health_check "$INSTALL_PATH"
	assert_success
	assert_output --partial "[WARN] MAIL_LOG_PATH: /nonexistent/mail.log (not found)"
}

@test "health_check: PASS for existing readable log" {
	run health_check "$INSTALL_PATH"
	assert_success
	assert_output --partial "[PASS] AUTH_LOG_PATH: $AUTH_LOG_PATH (exists, readable)"
}

@test "health_check: WARN for empty UNBAN_COMMAND with BAN_DURATION>0" {
	BAN_DURATION="300"
	UNBAN_COMMAND_TEMPLATE=""
	run health_check "$INSTALL_PATH"
	assert_success
	assert_output --partial "[WARN] UNBAN_COMMAND is empty; temp bans won't auto-unban firewall rules"
}

@test "health_check: active rule reported correctly" {
	# create a rule that has REQ pointing to an existing binary
	cat > "$INSTALL_PATH/rules/testrule" <<EOF
TRIG="10"
REQ="/bin/sh"
PORTS="22"
LP="$AUTH_LOG_PATH"
TLOG_TF="testrule"
ARG_VAL=""
EOF
	run health_check "$INSTALL_PATH"
	assert_success
	assert_output --partial "[PASS] testrule: active (TRIG=10, PORTS=22"
}

@test "health_check: inactive rule (missing REQ) reported correctly" {
	cat > "$INSTALL_PATH/rules/missingreq" <<EOF
TRIG="5"
REQ="/nonexistent/binary"
LP="$AUTH_LOG_PATH"
TLOG_TF="missingreq"
ARG_VAL=""
EOF
	run health_check "$INSTALL_PATH"
	assert_success
	assert_output --partial "[SKIP] missingreq: inactive"
}

@test "health_check: rule count matches" {
	cat > "$INSTALL_PATH/rules/active1" <<EOF
REQ="/bin/sh"
LP="$AUTH_LOG_PATH"
TLOG_TF="active1"
ARG_VAL=""
EOF
	cat > "$INSTALL_PATH/rules/inactive1" <<EOF
REQ="/no/such/bin"
LP="$AUTH_LOG_PATH"
TLOG_TF="inactive1"
ARG_VAL=""
EOF
	cat > "$INSTALL_PATH/rules/inactive2" <<EOF
REQ="/no/such/bin2"
LP="$AUTH_LOG_PATH"
TLOG_TF="inactive2"
ARG_VAL=""
EOF
	run health_check "$INSTALL_PATH"
	assert_success
	assert_output --partial "Rules: 1 active, 2 inactive (3 total)"
}

@test "health_check: state dirs checked" {
	run health_check "$INSTALL_PATH"
	assert_success
	assert_output --partial "[PASS] State: tmp/ and stats/ exist"
}

@test "health_check: lock file detection" {
	echo "1234567890" > "$LOCK_FILE"
	run health_check "$INSTALL_PATH"
	assert_success
	assert_output --partial "[WARN] Lock: active lock file exists"
	rm -f "$LOCK_FILE"
}

@test "health_check: active bans counted" {
	state_bans_active_append "$INSTALL_PATH" "1000" "0" "10.0.0.1" "sshd" "22"
	state_bans_active_append "$INSTALL_PATH" "1000" "0" "10.0.0.2" "dovecot" "110"
	state_bans_active_append "$INSTALL_PATH" "1000" "0" "10.0.0.3" "sshd" "22"
	run health_check "$INSTALL_PATH"
	assert_success
	assert_output --partial "Active bans: 3"
}

@test "health_check: BAN_COMMAND_V6 binary check" {
	BAN_COMMAND_V6_TEMPLATE="/nonexistent/v6bin -d \$ATTACK_HOST"
	run health_check "$INSTALL_PATH"
	assert_success
	assert_output --partial "[WARN] BAN_COMMAND_V6 binary: /nonexistent/v6bin (not found)"
}

@test "health_check: output shows summary line" {
	run health_check "$INSTALL_PATH"
	assert_success
	assert_output --partial "Summary:"
	assert_output --partial "passed"
}

@test "health_check: tlog not executable warns" {
	chmod -x "$TLOG_PATH"
	run health_check "$INSTALL_PATH"
	assert_success
	assert_output --partial "[WARN] tlog:"
	assert_output --partial "not executable"
}

@test "health_check: no lock file shows PASS" {
	run health_check "$INSTALL_PATH"
	assert_success
	assert_output --partial "[PASS] Lock: no active lock"
}
