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

# --- Alert template safety tests (Phase 26) ---

@test "send_alerts: world-writable template skips alerts" {
	local alerts_file="$TEST_TMPDIR/alerts.tmp"
	echo "192.0.2.1|sshd|22|5|0|ban|recent|/var/log/auth.log|root@localhost|5|300" > "$alerts_file"
	local template="$TEST_TMPDIR/alert.bfd"
	echo 'echo "alert"' > "$template"
	chmod 666 "$template"
	run send_alerts "$alerts_file" "BFD Alert" "$template" "50"
	assert_failure
	# alerts_file should be cleaned up
	[ ! -f "$alerts_file" ]
}

@test "send_alerts: missing template skips alerts" {
	local alerts_file="$TEST_TMPDIR/alerts.tmp"
	echo "192.0.2.1|sshd|22|5|0|ban|recent|/var/log/auth.log|root@localhost|5|300" > "$alerts_file"
	run send_alerts "$alerts_file" "BFD Alert" "$TEST_TMPDIR/nonexistent_template" "50"
	assert_failure
	# alerts_file should be cleaned up
	[ ! -f "$alerts_file" ]
}

@test "send_alerts: root-owned 644 template passes safety check" {
	local alerts_file="$TEST_TMPDIR/alerts.tmp"
	echo "192.0.2.1|sshd|22|5|0|ban|recent|/var/log/auth.log|root@localhost|5|300" > "$alerts_file"
	local template="$TEST_TMPDIR/alert.bfd"
	echo 'echo "alert body"' > "$template"
	chmod 644 "$template"
	# mail command likely not available in test, but we're testing safety check passes
	# send_alerts will get past the safety check (return 0 path or fail on mail)
	run send_alerts "$alerts_file" "BFD Alert" "$template" "50"
	# If it gets past the safety check, it won't return 1 with "unsafe" message
	if [ "$status" -ne 0 ]; then
		refute_output --partial "unsafe ownership"
		refute_output --partial "not found"
	fi
}
