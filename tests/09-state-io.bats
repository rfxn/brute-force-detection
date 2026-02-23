#!/usr/bin/env bats
#
# Test suite for state file I/O functions
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

setup() {
	bfd_common_setup
	INSTALL_PATH="$TEST_TMPDIR/bfd"
	mkdir -p "$INSTALL_PATH"
}

teardown() {
	bfd_teardown
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

# --- flock-protected mutation tests (Phase 26) ---

@test "state_bans_active_remove: preserves other entries after remove" {
	state_init "$INSTALL_PATH"
	state_bans_active_append "$INSTALL_PATH" "1000" "0" "10.0.0.1" "sshd" "22"
	state_bans_active_append "$INSTALL_PATH" "1001" "0" "10.0.0.2" "dovecot" "143"
	state_bans_active_append "$INSTALL_PATH" "1002" "0" "10.0.0.3" "postfix" "25"
	state_bans_active_remove "$INSTALL_PATH" "10.0.0.2"
	# 10.0.0.1 and 10.0.0.3 must still be present
	run state_bans_active_check "$INSTALL_PATH" "10.0.0.1"
	assert_success
	run state_bans_active_check "$INSTALL_PATH" "10.0.0.3"
	assert_success
	# 10.0.0.2 must be gone
	run state_bans_active_check "$INSTALL_PATH" "10.0.0.2"
	assert_failure
}

@test "state_events_prune: respects cutoff window" {
	state_init "$INSTALL_PATH"
	# seed events: old (t=100) and new (t=900)
	state_events_append "$INSTALL_PATH" "100" "10.0.0.1" "sshd" "3"
	state_events_append "$INSTALL_PATH" "900" "10.0.0.2" "sshd" "2"
	# now=1000, window=300, cutoff=700 => old events at t=100 pruned
	state_events_prune "$INSTALL_PATH" "300" "1000"
	local count
	count=$(wc -l < "$INSTALL_PATH/tmp/events.dat")
	[ "$count" -eq 2 ]
	# only 10.0.0.2 events should remain
	run cat "$INSTALL_PATH/tmp/events.dat"
	assert_output --partial "10.0.0.2"
	refute_output --partial "10.0.0.1"
}

@test "state_bans_active_remove: empty file is no-op" {
	state_init "$INSTALL_PATH"
	# file exists but is empty
	run state_bans_active_remove "$INSTALL_PATH" "10.0.0.1"
	assert_success
}

@test "state_events_prune: empty file is no-op" {
	state_init "$INSTALL_PATH"
	# file exists but is empty
	run state_events_prune "$INSTALL_PATH" "300" "1000"
	assert_success
}
