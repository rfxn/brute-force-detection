#!/usr/bin/env bats
#
# Tests for Phase 20: rule testing tool (test_rule, test_pattern)
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

setup() {
	bfd_standard_setup
	GLOB_PRESSURE_TRIP="15"
	PRESSURE_TRIP=""
	RULES_PATH="$INSTALL_PATH/rules"
	mkdir -p "$RULES_PATH"
	LOG_SOURCE="file"
	# create sample log file with known sshd patterns
	SAMPLE_LOG="$TEST_TMPDIR/sample.log"
	cat > "$SAMPLE_LOG" <<'LOGEOF'
Feb 20 10:01:01 server sshd[1234]: Failed password for root from 203.0.113.100 port 22 ssh2
Feb 20 10:01:02 server sshd[1235]: Failed password for admin from 203.0.113.100 port 22 ssh2
Feb 20 10:01:03 server sshd[1236]: Invalid user test from 203.0.113.200 port 22 ssh2
Feb 20 10:01:04 server sshd[1237]: Failed password for root from 203.0.113.200 port 22 ssh2
Feb 20 10:01:05 server sshd[1238]: Failed password for nobody from 203.0.113.100 port 22 ssh2
LOGEOF
	# create test rule file
	cat > "$INSTALL_PATH/rules/test-sshd" <<RULEEOF
TRIG="5"
REQ="/bin/sh"
PORTS="22"
LP="$SAMPLE_LOG"
TLOG_TF="sshd"
ARG_VAL=\$(_rule_tlog "\$LP" "\$TLOG_TF" | extract_hosts \\
	"sshd.*Failed password for .* from <HOST>" \\
	"sshd.*Invalid user .* from <HOST>")
RULEEOF
	chown root "$INSTALL_PATH/rules/test-sshd"
	chmod 644 "$INSTALL_PATH/rules/test-sshd"
}

teardown() {
	bfd_teardown
}

@test "test_rule: reports rule name" {
	run test_rule "$INSTALL_PATH" "test-sshd" "$SAMPLE_LOG"
	assert_success
	assert_output --partial "Rule:         test-sshd"
}

@test "test_rule: correct match count" {
	run test_rule "$INSTALL_PATH" "test-sshd" "$SAMPLE_LOG"
	assert_success
	# 4 Failed password (lines 1,2,4,5) + 1 Invalid user (line 3) = 5 matches, 2 unique IPs
	assert_output --partial "5 matches, 2 unique IPs"
}

@test "test_rule: correct unique IP count" {
	run test_rule "$INSTALL_PATH" "test-sshd" "$SAMPLE_LOG"
	assert_success
	assert_output --partial "2 unique IPs"
}

@test "test_rule: shows top IPs" {
	run test_rule "$INSTALL_PATH" "test-sshd" "$SAMPLE_LOG"
	assert_success
	assert_output --partial "203.0.113.100"
}

@test "test_rule: error for nonexistent rule" {
	run test_rule "$INSTALL_PATH" "nonexistent" "$SAMPLE_LOG"
	assert_failure
	assert_output --partial "not found"
}

@test "test_rule: custom log file overrides LP" {
	local alt_log="$TEST_TMPDIR/alt.log"
	echo "Feb 20 10:01:01 server sshd[1234]: Failed password for root from 192.0.2.1 port 22 ssh2" > "$alt_log"
	run test_rule "$INSTALL_PATH" "test-sshd" "$alt_log"
	assert_success
	assert_output --partial "Log file:     $alt_log"
	assert_output --partial "192.0.2.1"
}

@test "test_rule: zero matches on empty log" {
	local empty_log="$TEST_TMPDIR/empty.log"
	echo "nothing relevant here" > "$empty_log"
	run test_rule "$INSTALL_PATH" "test-sshd" "$empty_log"
	assert_success
	assert_output --partial "0 matches"
}

@test "test_rule: shows trip, weight and ports" {
	run test_rule "$INSTALL_PATH" "test-sshd" "$SAMPLE_LOG"
	assert_success
	assert_output --partial "Trip:"
	assert_output --partial "Weight:"
	assert_output --partial "Ports:        22"
}

@test "test_pattern: matches from file" {
	run test_pattern "sshd.*Failed password for .* from <HOST>" "$SAMPLE_LOG"
	assert_success
	# 3 "Failed password" lines match (lines 1, 2, 5 have .100; line 4 has .200)
	assert_output --partial "Matches:  4"
}

@test "test_pattern: empty input yields zero matches" {
	local empty_log="$TEST_TMPDIR/nolog.log"
	echo "nothing here" > "$empty_log"
	run test_pattern "sshd.*Failed password for .* from <HOST>" "$empty_log"
	assert_success
	assert_output --partial "Matches:  0"
}

@test "test_pattern: error for missing file" {
	run test_pattern "sshd.*Failed password for .* from <HOST>" "/nonexistent/file"
	assert_failure
	assert_output --partial "not found"
}

@test "test_pattern: IPv6 match" {
	local v6_log="$TEST_TMPDIR/v6.log"
	echo "Feb 20 10:01:01 server sshd[1234]: Failed password for root from 2001:db8::1 port 22 ssh2" > "$v6_log"
	echo "Feb 20 10:01:02 server sshd[1235]: Failed password for admin from 2001:db8::1 port 22 ssh2" >> "$v6_log"
	run test_pattern "sshd.*Failed password for .* from <HOST>" "$v6_log"
	assert_success
	assert_output --partial "Matches:  2"
	assert_output --partial "2001:db8::1"
}
