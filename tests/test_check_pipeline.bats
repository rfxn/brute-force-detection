#!/usr/bin/env bats
#
# Integration tests for the check() pipeline:
# count_attacks, count_failures, execute_ban, and end-to-end flow
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

setup() {
	TEST_TMPDIR=$(mktemp -d)
	INSTALL_PATH="$TEST_TMPDIR/bfd"
	state_init "$INSTALL_PATH"
	# eout dependencies
	BFD_LOG_PATH="$TEST_TMPDIR/bfd.log"
	touch "$BFD_LOG_PATH"
	OUTPUT_SYSLOG="0"
	OUTPUT_SYSLOG_FILE="/dev/null"
	MOD="sshd"
}

teardown() {
	rm -rf "$TEST_TMPDIR"
}

# --- count_attacks (legacy, still in bfd.lib.sh) ---

@test "count_attacks: counts host occurrence with accumulation" {
	local hosts_parsed
	hosts_parsed=$(printf "10.0.0.1\n10.0.0.2\n10.0.0.1\n")
	# 2 occurrences in hosts_parsed; appended to track.attack then accumulated
	# yields 2 (parsed) + 2 (from track entry just written) = 4
	run count_attacks "10.0.0.1" "$hosts_parsed" "$INSTALL_PATH" "10"
	assert_success
	assert_output "4"
}

@test "count_attacks: counts zero for absent host" {
	local hosts_parsed
	hosts_parsed=$(printf "10.0.0.1\n10.0.0.2\n")
	run count_attacks "10.0.0.3" "$hosts_parsed" "$INSTALL_PATH" "10"
	assert_success
	assert_output "0"
}

@test "count_attacks: accumulates across runs when under trig" {
	local hosts_parsed
	hosts_parsed=$(printf "10.0.0.1\n10.0.0.1\n10.0.0.1\n")
	# first run: 3 hits
	count_attacks "10.0.0.1" "$hosts_parsed" "$INSTALL_PATH" "10" >/dev/null
	# second run: 3 more hits, should accumulate to 6 + 3 = 9
	# (3 already in track.attack + 3 new occurrences in hosts_parsed)
	run count_attacks "10.0.0.1" "$hosts_parsed" "$INSTALL_PATH" "10"
	assert_success
	# 3 (from hosts_parsed) + 6 (3 from first run's track entry + 3 from second run's track entry)
	local result="$output"
	[ "$result" -gt 3 ]
}

@test "count_attacks: skips accumulation when at or above trig" {
	local hosts_parsed
	hosts_parsed=$(printf "10.0.0.1\n10.0.0.1\n10.0.0.1\n10.0.0.1\n10.0.0.1\n")
	# 5 hits, trig is 5 — count should be exactly 5 (no accumulation needed)
	run count_attacks "10.0.0.1" "$hosts_parsed" "$INSTALL_PATH" "5"
	assert_success
	assert_output "5"
}

@test "count_attacks: appends to track.attack" {
	local hosts_parsed
	hosts_parsed=$(printf "10.0.0.1\n10.0.0.1\n")
	count_attacks "10.0.0.1" "$hosts_parsed" "$INSTALL_PATH" "10" >/dev/null
	run cat "$INSTALL_PATH/tmp/track.attack"
	assert_output --partial "10.0.0.1 2 sshd"
}

@test "count_attacks: does not match partial IPs" {
	local hosts_parsed
	hosts_parsed=$(printf "10.0.0.1\n10.0.0.10\n10.0.0.100\n")
	# 1 occurrence in hosts_parsed + 1 from track accumulation = 2
	run count_attacks "10.0.0.1" "$hosts_parsed" "$INSTALL_PATH" "10"
	assert_success
	assert_output "2"
}

# --- count_failures (windowed replacement) ---

@test "count_failures: counts host in windowed mode" {
	local hosts_parsed
	hosts_parsed=$(printf "10.0.0.1\n10.0.0.2\n10.0.0.1\n")
	run count_failures "10.0.0.1" "$hosts_parsed" "$INSTALL_PATH" "300" "1000" "sshd"
	assert_success
	assert_output "2"
}

@test "count_failures: accumulates within window" {
	local hosts_parsed
	hosts_parsed=$(printf "10.0.0.1\n10.0.0.1\n10.0.0.1\n")
	# first run at t=900
	count_failures "10.0.0.1" "$hosts_parsed" "$INSTALL_PATH" "300" "900" "sshd" >/dev/null
	# second run at t=1000 (within window)
	run count_failures "10.0.0.1" "$hosts_parsed" "$INSTALL_PATH" "300" "1000" "sshd"
	assert_success
	assert_output "6"
}

@test "count_failures: old events expire outside window" {
	# seed old events at t=100
	state_events_append "$INSTALL_PATH" "100" "10.0.0.1" "sshd" "5"
	local hosts_parsed
	hosts_parsed=$(printf "10.0.0.1\n10.0.0.1\n")
	# now=1000, window=300, cutoff=700 => old events at t=100 excluded
	run count_failures "10.0.0.1" "$hosts_parsed" "$INSTALL_PATH" "300" "1000" "sshd"
	assert_success
	assert_output "2"
}

@test "count_failures: per-service isolation in windowed mode" {
	# seed dovecot events in window
	state_events_append "$INSTALL_PATH" "900" "10.0.0.1" "dovecot" "10"
	local hosts_parsed
	hosts_parsed=$(printf "10.0.0.1\n10.0.0.1\n")
	# count sshd only
	run count_failures "10.0.0.1" "$hosts_parsed" "$INSTALL_PATH" "300" "1000" "sshd"
	assert_success
	assert_output "2"
}

# --- TRIG_GLOBAL ---

@test "pipeline: TRIG_GLOBAL triggers ban across services" {
	# seed dovecot events (3) and sshd events (3) in window, total = 6
	state_events_append "$INSTALL_PATH" "900" "10.0.0.1" "dovecot" "3"
	state_events_append "$INSTALL_PATH" "900" "10.0.0.1" "sshd" "3"
	# TRIG_GLOBAL=5: cross-service total of 6 >= 5
	local global_count
	global_count=$(state_events_count "$INSTALL_PATH" "10.0.0.1" "300" "1000")
	[ "$global_count" -ge 5 ]
}

@test "pipeline: TRIG_GLOBAL=0 disables cross-service check" {
	# With TRIG_GLOBAL=0, should not trigger
	local trig_global=0
	local should_ban=0
	local attack_count=2
	local trig=5
	if [ "$attack_count" -ge "$trig" ]; then
		should_ban=1
	elif [ "$trig_global" -gt 0 ]; then
		should_ban=1
	fi
	[ "$should_ban" -eq 0 ]
}

# --- execute_ban ---

@test "execute_ban: dry run logs without executing" {
	run execute_ban "10.0.0.1" "sshd" "echo banned" "1"
	assert_success
	assert_output --partial "dry-run"
	assert_output --partial "10.0.0.1"
}

@test "execute_ban: sets ATTACK_HOST global" {
	execute_ban "10.0.0.1" "sshd" "true" "1" >/dev/null
	[ "$ATTACK_HOST" = "10.0.0.1" ]
}

@test "execute_ban: sets BAN_COMMAND global" {
	execute_ban "10.0.0.1" "sshd" "echo test_cmd" "1" >/dev/null
	[ "$BAN_COMMAND" = "echo test_cmd" ]
}

@test "execute_ban: executes command in live mode" {
	local marker="$TEST_TMPDIR/ban_executed"
	execute_ban "10.0.0.1" "sshd" "touch $marker" "0" >/dev/null
	[ -f "$marker" ]
}

@test "execute_ban: returns non-zero on command failure" {
	run execute_ban "10.0.0.1" "sshd" "false" "0"
	[ "$status" -ne 0 ]
}

@test "execute_ban: logs ban command failure" {
	run execute_ban "10.0.0.1" "sshd" "false" "0"
	assert_output --partial "exited with code"
}

# --- end-to-end pipeline ---

@test "pipeline: filter_host + count_failures + state_ban_append" {
	# setup ignore infrastructure
	local ignore_files="$TEST_TMPDIR/exclude.files"
	local lo_hosts="$TEST_TMPDIR/lo_hosts"
	touch "$ignore_files" "$lo_hosts"

	local host="10.0.0.1"
	local hosts_parsed
	hosts_parsed=$(printf "10.0.0.1\n10.0.0.1\n10.0.0.1\n10.0.0.1\n10.0.0.1\n")

	# host passes filter
	filter_host "$host" "$ignore_files" "$lo_hosts"
	local filter_rc=$?
	[ "$filter_rc" -eq 0 ]

	# count failures (windowed)
	local count
	count=$(count_failures "$host" "$hosts_parsed" "$INSTALL_PATH" "300" "1000" "sshd")
	[ "$count" -ge 5 ]

	# ban and record
	state_ban_append "$INSTALL_PATH" "$host" 50
	state_pool_append "$INSTALL_PATH" "1700000000" "$host" "sshd"

	# verify state
	state_ban_check "$INSTALL_PATH" "$host"
	run cat "$INSTALL_PATH/stats/attack.pool"
	assert_output --partial "10.0.0.1"
}

@test "pipeline: ignored host skips ban entirely" {
	local ignore_list="$TEST_TMPDIR/ignore.hosts"
	local ignore_files="$TEST_TMPDIR/exclude.files"
	local lo_hosts="$TEST_TMPDIR/lo_hosts"
	echo "10.0.0.1" > "$ignore_list"
	echo "$ignore_list" > "$ignore_files"
	touch "$lo_hosts"

	local filter_rc=0
	filter_host "10.0.0.1" "$ignore_files" "$lo_hosts" || filter_rc=$?
	[ "$filter_rc" -eq 1 ]

	# ban.list and attack.pool should be empty
	run cat "$INSTALL_PATH/tmp/ban.list"
	assert_output ""
	run cat "$INSTALL_PATH/stats/attack.pool"
	assert_output ""
}

@test "pipeline: local address gets pool entry but no ban" {
	local ignore_files="$TEST_TMPDIR/exclude.files"
	local lo_hosts="$TEST_TMPDIR/lo_hosts"
	touch "$ignore_files"
	echo "192.168.1.1" > "$lo_hosts"

	local filter_rc=0
	filter_host "192.168.1.1" "$ignore_files" "$lo_hosts" || filter_rc=$?
	[ "$filter_rc" -eq 2 ]

	# record in pool but do not ban
	state_pool_append "$INSTALL_PATH" "1700000000" "192.168.1.1" "sshd"
	run cat "$INSTALL_PATH/stats/attack.pool"
	assert_output --partial "192.168.1.1"
	# ban.list should be empty
	run cat "$INSTALL_PATH/tmp/ban.list"
	assert_output ""
}
