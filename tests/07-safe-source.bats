#!/usr/bin/env bats
#
# Test suite for safe_source()
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

@test "safe_source: valid root-owned file returns 0" {
	echo 'SAFE_SOURCE_TEST_VAR="loaded"' > "$TEST_TMPDIR/good.conf"
	chmod 640 "$TEST_TMPDIR/good.conf"
	run safe_source "$TEST_TMPDIR/good.conf" "test:good"
	assert_success
}

@test "safe_source: valid file sets variable" {
	echo 'SAFE_SOURCE_TEST_VAR="loaded"' > "$TEST_TMPDIR/good.conf"
	chmod 640 "$TEST_TMPDIR/good.conf"
	SAFE_SOURCE_TEST_VAR=""
	safe_source "$TEST_TMPDIR/good.conf" "test:good" >/dev/null 2>&1
	[ "$SAFE_SOURCE_TEST_VAR" = "loaded" ]
}

@test "safe_source: missing file returns 1" {
	run safe_source "$TEST_TMPDIR/no_such_file" "test:missing"
	assert_failure
}

@test "safe_source: world-writable file returns 1" {
	echo 'SAFE_SOURCE_TEST_VAR="bad"' > "$TEST_TMPDIR/world_writable.conf"
	chmod 666 "$TEST_TMPDIR/world_writable.conf"
	run safe_source "$TEST_TMPDIR/world_writable.conf" "test:writable"
	assert_failure
}

@test "safe_source: world-writable file does not set variable" {
	echo 'SAFE_SOURCE_TEST_VAR="bad"' > "$TEST_TMPDIR/world_writable.conf"
	chmod 666 "$TEST_TMPDIR/world_writable.conf"
	SAFE_SOURCE_TEST_VAR=""
	safe_source "$TEST_TMPDIR/world_writable.conf" "test:writable" >/dev/null 2>&1 || true
	[ "$SAFE_SOURCE_TEST_VAR" = "" ]
}

@test "safe_source: 644 perms succeeds" {
	echo 'SAFE_SOURCE_TEST_VAR="ok644"' > "$TEST_TMPDIR/readable.conf"
	chmod 644 "$TEST_TMPDIR/readable.conf"
	run safe_source "$TEST_TMPDIR/readable.conf" "test:644"
	assert_success
}

@test "safe_source: 644 file sets variable" {
	echo 'SAFE_SOURCE_TEST_VAR="ok644"' > "$TEST_TMPDIR/readable.conf"
	chmod 644 "$TEST_TMPDIR/readable.conf"
	SAFE_SOURCE_TEST_VAR=""
	safe_source "$TEST_TMPDIR/readable.conf" "test:644" >/dev/null 2>&1
	[ "$SAFE_SOURCE_TEST_VAR" = "ok644" ]
}

@test "safe_source: 777 perms fails" {
	echo 'SAFE_SOURCE_TEST_VAR="bad777"' > "$TEST_TMPDIR/all_perms.conf"
	chmod 777 "$TEST_TMPDIR/all_perms.conf"
	run safe_source "$TEST_TMPDIR/all_perms.conf" "test:777"
	assert_failure
}

@test "safe_source: 777 does not set variable" {
	echo 'SAFE_SOURCE_TEST_VAR="bad777"' > "$TEST_TMPDIR/all_perms.conf"
	chmod 777 "$TEST_TMPDIR/all_perms.conf"
	SAFE_SOURCE_TEST_VAR=""
	safe_source "$TEST_TMPDIR/all_perms.conf" "test:777" >/dev/null 2>&1 || true
	[ "$SAFE_SOURCE_TEST_VAR" = "" ]
}

@test "safe_source: 643 perms (world-writable+exec) fails" {
	echo 'SAFE_SOURCE_TEST_VAR="bad643"' > "$TEST_TMPDIR/writable643.conf"
	chmod 643 "$TEST_TMPDIR/writable643.conf"
	run safe_source "$TEST_TMPDIR/writable643.conf" "test:643"
	assert_failure
}

@test "safe_source: 641 perms (world-exec not writable) succeeds" {
	echo 'SAFE_SOURCE_TEST_VAR="ok641"' > "$TEST_TMPDIR/exec641.conf"
	chmod 641 "$TEST_TMPDIR/exec641.conf"
	run safe_source "$TEST_TMPDIR/exec641.conf" "test:641"
	assert_success
}

# --- _check_file_safety tests ---

@test "_check_file_safety: root-owned 640 returns success" {
	echo 'test' > "$TEST_TMPDIR/safe640.conf"
	chmod 640 "$TEST_TMPDIR/safe640.conf"
	run _check_file_safety "$TEST_TMPDIR/safe640.conf"
	assert_success
}

@test "_check_file_safety: world-writable returns failure" {
	echo 'test' > "$TEST_TMPDIR/writable.conf"
	chmod 666 "$TEST_TMPDIR/writable.conf"
	run _check_file_safety "$TEST_TMPDIR/writable.conf"
	assert_failure
}

@test "_check_file_safety: sets _CSAF_UID and _CSAF_PERMS (zero-padded 4 digits)" {
	echo 'test' > "$TEST_TMPDIR/check_vars.conf"
	chmod 640 "$TEST_TMPDIR/check_vars.conf"
	_check_file_safety "$TEST_TMPDIR/check_vars.conf"
	[ "$_CSAF_UID" = "0" ]
	[ "$_CSAF_PERMS" = "0640" ]
}

@test "_check_file_safety: group-writable 660 returns failure" {
	echo 'test' > "$TEST_TMPDIR/gw660.conf"
	chmod 660 "$TEST_TMPDIR/gw660.conf"
	run _check_file_safety "$TEST_TMPDIR/gw660.conf"
	assert_failure
}

@test "_check_file_safety: group-writable 670 returns failure" {
	echo 'test' > "$TEST_TMPDIR/gw670.conf"
	chmod 670 "$TEST_TMPDIR/gw670.conf"
	run _check_file_safety "$TEST_TMPDIR/gw670.conf"
	assert_failure
}

@test "_check_file_safety: setuid 4750 accepted (group=5, world=0 not writable)" {
	echo 'test' > "$TEST_TMPDIR/suid4750.conf"
	chmod 4750 "$TEST_TMPDIR/suid4750.conf"
	run _check_file_safety "$TEST_TMPDIR/suid4750.conf"
	assert_success
}

@test "_check_file_safety: setgid 2770 rejected (group=7, world=0 writable)" {
	echo 'test' > "$TEST_TMPDIR/sgid2770.conf"
	chmod 2770 "$TEST_TMPDIR/sgid2770.conf"
	run _check_file_safety "$TEST_TMPDIR/sgid2770.conf"
	assert_failure
}

@test "_check_file_safety: sticky+world-writable 1777 rejected" {
	echo 'test' > "$TEST_TMPDIR/sticky1777.conf"
	chmod 1777 "$TEST_TMPDIR/sticky1777.conf"
	run _check_file_safety "$TEST_TMPDIR/sticky1777.conf"
	assert_failure
}

@test "safe_source: group-writable file returns 1" {
	echo 'SAFE_SOURCE_TEST_VAR="bad"' > "$TEST_TMPDIR/group_writable.conf"
	chmod 660 "$TEST_TMPDIR/group_writable.conf"
	run safe_source "$TEST_TMPDIR/group_writable.conf" "test:gw"
	assert_failure
}

@test "safe_source: group-writable file does not set variable" {
	echo 'SAFE_SOURCE_TEST_VAR="bad"' > "$TEST_TMPDIR/group_writable.conf"
	chmod 660 "$TEST_TMPDIR/group_writable.conf"
	SAFE_SOURCE_TEST_VAR=""
	safe_source "$TEST_TMPDIR/group_writable.conf" "test:gw" >/dev/null 2>&1 || true
	[ "$SAFE_SOURCE_TEST_VAR" = "" ]
}

@test "safe_source: group-writable error message mentions group" {
	echo 'SAFE_SOURCE_TEST_VAR="bad"' > "$TEST_TMPDIR/group_writable.conf"
	chmod 660 "$TEST_TMPDIR/group_writable.conf"
	run safe_source "$TEST_TMPDIR/group_writable.conf" "test:gw"
	assert_failure
	assert_output --partial "group- or world-writable"
}

# --- Alert template directory validation tests (Phase 26) ---

@test "send_alerts: template dir without header tpl skips alerts" {
	local alerts_file="$TEST_TMPDIR/alerts.tmp"
	echo "192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|root|5|300|3|5" > "$alerts_file"
	local tpl_dir="$TEST_TMPDIR/alert_empty"
	mkdir -p "$tpl_dir"
	ALERT_TEMPLATE_DIR="$tpl_dir"
	run send_alerts "$alerts_file" "BFD Alert" "50"
	assert_failure
}

@test "send_alerts: valid template dir passes validation" {
	local alerts_file="$TEST_TMPDIR/alerts.tmp"
	echo "192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|root|5|300|3|5" > "$alerts_file"
	ALERT_TEMPLATE_DIR="$PROJECT_ROOT/files/alert"
	EMAIL_FORMAT="text"
	# mock mail so delivery doesn't fail on missing binary
	mkdir -p "$TEST_TMPDIR/bin"
	echo '#!/bin/bash' > "$TEST_TMPDIR/bin/mail"
	echo 'cat > /dev/null' >> "$TEST_TMPDIR/bin/mail"
	chmod +x "$TEST_TMPDIR/bin/mail"
	export PATH="$TEST_TMPDIR/bin:$PATH"
	run send_alerts "$alerts_file" "BFD Alert" "50"
	# should not fail with template validation error
	if [ "$status" -ne 0 ]; then
		refute_output --partial "invalid"
		refute_output --partial "not found"
	fi
}
