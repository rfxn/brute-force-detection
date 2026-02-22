#!/usr/bin/env bats
#
# Test suite for state file I/O functions
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

setup() {
	TEST_TMPDIR=$(mktemp -d)
	INSTALL_PATH="$TEST_TMPDIR/bfd"
	mkdir -p "$INSTALL_PATH"
}

teardown() {
	rm -rf "$TEST_TMPDIR"
}

# --- state_init ---

@test "state_init: creates tmp and stats directories" {
	state_init "$INSTALL_PATH"
	[ -d "$INSTALL_PATH/tmp" ]
	[ -d "$INSTALL_PATH/stats" ]
}

@test "state_init: creates track.attack, ban.list, attack.pool" {
	state_init "$INSTALL_PATH"
	[ -f "$INSTALL_PATH/tmp/track.attack" ]
	[ -f "$INSTALL_PATH/tmp/ban.list" ]
	[ -f "$INSTALL_PATH/stats/attack.pool" ]
}

@test "state_init: sets 600 permissions on state files" {
	state_init "$INSTALL_PATH"
	local perms
	perms=$(stat -c '%a' "$INSTALL_PATH/tmp/track.attack")
	[ "$perms" = "600" ]
	perms=$(stat -c '%a' "$INSTALL_PATH/tmp/ban.list")
	[ "$perms" = "600" ]
	perms=$(stat -c '%a' "$INSTALL_PATH/stats/attack.pool")
	[ "$perms" = "600" ]
}

@test "state_init: idempotent on existing dirs and files" {
	state_init "$INSTALL_PATH"
	echo "1.2.3.4 5 sshd" >> "$INSTALL_PATH/tmp/track.attack"
	state_init "$INSTALL_PATH"
	# file should not be truncated
	run cat "$INSTALL_PATH/tmp/track.attack"
	assert_output "1.2.3.4 5 sshd"
}

# --- state_track_append ---

@test "state_track_append: appends entry to track.attack" {
	state_init "$INSTALL_PATH"
	state_track_append "$INSTALL_PATH" "10.0.0.1" "3" "sshd"
	run cat "$INSTALL_PATH/tmp/track.attack"
	assert_output "10.0.0.1 3 sshd"
}

@test "state_track_append: multiple appends accumulate" {
	state_init "$INSTALL_PATH"
	state_track_append "$INSTALL_PATH" "10.0.0.1" "3" "sshd"
	state_track_append "$INSTALL_PATH" "10.0.0.2" "5" "dovecot"
	local line_count
	line_count=$(wc -l < "$INSTALL_PATH/tmp/track.attack")
	[ "$line_count" -eq 2 ]
}

# --- state_track_count ---

@test "state_track_count: returns 0 for unknown host" {
	state_init "$INSTALL_PATH"
	run state_track_count "$INSTALL_PATH" "192.168.1.1"
	assert_output "0"
}

@test "state_track_count: sums counts for single entry" {
	state_init "$INSTALL_PATH"
	state_track_append "$INSTALL_PATH" "10.0.0.1" "7" "sshd"
	run state_track_count "$INSTALL_PATH" "10.0.0.1"
	assert_output "7"
}

@test "state_track_count: sums counts across multiple entries" {
	state_init "$INSTALL_PATH"
	state_track_append "$INSTALL_PATH" "10.0.0.1" "3" "sshd"
	state_track_append "$INSTALL_PATH" "10.0.0.2" "5" "dovecot"
	state_track_append "$INSTALL_PATH" "10.0.0.1" "4" "postfix"
	run state_track_count "$INSTALL_PATH" "10.0.0.1"
	assert_output "7"
}

@test "state_track_count: does not match partial IPs" {
	state_init "$INSTALL_PATH"
	state_track_append "$INSTALL_PATH" "10.0.0.1" "5" "sshd"
	state_track_append "$INSTALL_PATH" "10.0.0.10" "3" "sshd"
	run state_track_count "$INSTALL_PATH" "10.0.0.1"
	assert_output "5"
}

# --- state_track_trim ---

@test "state_track_trim: no-op when under max_lines" {
	state_init "$INSTALL_PATH"
	state_track_append "$INSTALL_PATH" "10.0.0.1" "1" "sshd"
	state_track_append "$INSTALL_PATH" "10.0.0.2" "2" "sshd"
	state_track_trim "$INSTALL_PATH" "5"
	local line_count
	line_count=$(wc -l < "$INSTALL_PATH/tmp/track.attack")
	[ "$line_count" -eq 2 ]
}

@test "state_track_trim: trims to max_lines keeping newest" {
	state_init "$INSTALL_PATH"
	local i
	for i in $(seq 1 10); do
		state_track_append "$INSTALL_PATH" "10.0.0.$i" "$i" "sshd"
	done
	state_track_trim "$INSTALL_PATH" "3"
	local line_count
	line_count=$(wc -l < "$INSTALL_PATH/tmp/track.attack")
	[ "$line_count" -eq 3 ]
	# newest entries (8, 9, 10) should remain
	run head -1 "$INSTALL_PATH/tmp/track.attack"
	assert_output "10.0.0.8 8 sshd"
}

# --- state_ban_check ---

@test "state_ban_check: returns 1 for unbanned host" {
	state_init "$INSTALL_PATH"
	run state_ban_check "$INSTALL_PATH" "10.0.0.1"
	assert_failure
}

@test "state_ban_check: returns 0 for banned host" {
	state_init "$INSTALL_PATH"
	echo "10.0.0.1" >> "$INSTALL_PATH/tmp/ban.list"
	run state_ban_check "$INSTALL_PATH" "10.0.0.1"
	assert_success
}

@test "state_ban_check: does not match partial IPs" {
	state_init "$INSTALL_PATH"
	echo "10.0.0.1" >> "$INSTALL_PATH/tmp/ban.list"
	run state_ban_check "$INSTALL_PATH" "10.0.0.10"
	assert_failure
}

# --- state_ban_append ---

@test "state_ban_append: adds host to ban.list" {
	state_init "$INSTALL_PATH"
	state_ban_append "$INSTALL_PATH" "10.0.0.1" "100"
	run grep -Fw "10.0.0.1" "$INSTALL_PATH/tmp/ban.list"
	assert_success
}

@test "state_ban_append: does not duplicate existing host" {
	state_init "$INSTALL_PATH"
	state_ban_append "$INSTALL_PATH" "10.0.0.1" "100"
	state_ban_append "$INSTALL_PATH" "10.0.0.1" "100"
	local count
	count=$(grep -cFw "10.0.0.1" "$INSTALL_PATH/tmp/ban.list")
	[ "$count" -eq 1 ]
}

@test "state_ban_append: trims ban.list to max_lines" {
	state_init "$INSTALL_PATH"
	local i
	for i in $(seq 1 10); do
		echo "10.0.0.$i" >> "$INSTALL_PATH/tmp/ban.list"
	done
	state_ban_append "$INSTALL_PATH" "10.0.0.99" "5"
	local line_count
	line_count=$(wc -l < "$INSTALL_PATH/tmp/ban.list")
	# trimmed to 5 then appended 1 = 6
	[ "$line_count" -eq 6 ]
}

# --- state_pool_append ---

@test "state_pool_append: appends entry to attack.pool" {
	state_init "$INSTALL_PATH"
	state_pool_append "$INSTALL_PATH" "1700000000" "10.0.0.1" "sshd"
	run cat "$INSTALL_PATH/stats/attack.pool"
	assert_output "1700000000 10.0.0.1 sshd"
}

@test "state_pool_append: multiple appends accumulate" {
	state_init "$INSTALL_PATH"
	state_pool_append "$INSTALL_PATH" "1700000000" "10.0.0.1" "sshd"
	state_pool_append "$INSTALL_PATH" "1700000001" "10.0.0.2" "dovecot"
	local line_count
	line_count=$(wc -l < "$INSTALL_PATH/stats/attack.pool")
	[ "$line_count" -eq 2 ]
}
