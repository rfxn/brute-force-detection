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

@test "state_init: creates events.dat, bans.active, bans.history, attack.pool" {
	state_init "$INSTALL_PATH"
	[ -f "$INSTALL_PATH/tmp/events.dat" ]
	[ -f "$INSTALL_PATH/tmp/bans.active" ]
	[ -f "$INSTALL_PATH/tmp/bans.history" ]
	[ -f "$INSTALL_PATH/stats/attack.pool" ]
}

@test "state_init: sets 600 permissions on state files" {
	state_init "$INSTALL_PATH"
	local perms
	perms=$(stat -c '%a' "$INSTALL_PATH/tmp/events.dat")
	[ "$perms" = "600" ]
	perms=$(stat -c '%a' "$INSTALL_PATH/tmp/bans.active")
	[ "$perms" = "600" ]
	perms=$(stat -c '%a' "$INSTALL_PATH/stats/attack.pool")
	[ "$perms" = "600" ]
}

@test "state_init: idempotent on existing dirs and files" {
	state_init "$INSTALL_PATH"
	echo "1000 10.0.0.1 sshd" >> "$INSTALL_PATH/tmp/events.dat"
	state_init "$INSTALL_PATH"
	# file should not be truncated
	run cat "$INSTALL_PATH/tmp/events.dat"
	assert_output "1000 10.0.0.1 sshd"
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

# --- extract_command_template ---

@test "extract_command_template: extracts unquoted value" {
	local tmpconf="$TEST_TMPDIR/test.conf"
	echo 'BAN_COMMAND=/sbin/iptables -I INPUT -s $ATTACK_HOST -j DROP' > "$tmpconf"
	run extract_command_template "$tmpconf" "BAN_COMMAND"
	assert_output '/sbin/iptables -I INPUT -s $ATTACK_HOST -j DROP'
}

@test "extract_command_template: extracts quoted value" {
	local tmpconf="$TEST_TMPDIR/test.conf"
	echo 'BAN_COMMAND="/etc/apf/apf -d $ATTACK_HOST {bfd.$MOD}"' > "$tmpconf"
	run extract_command_template "$tmpconf" "BAN_COMMAND"
	assert_output '/etc/apf/apf -d $ATTACK_HOST {bfd.$MOD}'
}

@test "extract_command_template: takes last occurrence" {
	local tmpconf="$TEST_TMPDIR/test.conf"
	printf 'BAN_COMMAND="first"\nBAN_COMMAND="second"\n' > "$tmpconf"
	run extract_command_template "$tmpconf" "BAN_COMMAND"
	assert_output "second"
}

@test "extract_command_template: returns empty for missing var" {
	local tmpconf="$TEST_TMPDIR/test.conf"
	echo 'OTHER_VAR="value"' > "$tmpconf"
	run extract_command_template "$tmpconf" "BAN_COMMAND"
	assert_output ""
}

# --- flock-protected appends ---

@test "state_pool_append: concurrent writes produce correct line count" {
	state_init "$INSTALL_PATH"
	# run 10 appends in parallel
	local i
	for i in $(seq 1 10); do
		state_pool_append "$INSTALL_PATH" "1700000$i" "10.0.0.$i" "sshd" &
	done
	wait
	local line_count
	line_count=$(wc -l < "$INSTALL_PATH/stats/attack.pool")
	[ "$line_count" -eq 10 ]
}

@test "state_events_append: concurrent writes produce correct line count" {
	state_init "$INSTALL_PATH"
	local i
	for i in $(seq 1 10); do
		state_events_append "$INSTALL_PATH" "100$i" "10.0.0.$i" "sshd" &
	done
	wait
	local line_count
	line_count=$(wc -l < "$INSTALL_PATH/tmp/events.dat")
	[ "$line_count" -eq 10 ]
}

@test "state_bans_history_append: concurrent writes produce correct line count" {
	state_init "$INSTALL_PATH"
	local i
	for i in $(seq 1 10); do
		state_bans_history_append "$INSTALL_PATH" "100$i" "200$i" "10.0.0.$i" "sshd" "ban" &
	done
	wait
	local line_count
	line_count=$(wc -l < "$INSTALL_PATH/tmp/bans.history")
	[ "$line_count" -eq 10 ]
}
