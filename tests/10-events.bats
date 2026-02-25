#!/usr/bin/env bats
#
# Test suite for timestamped event tracking and record_and_score()
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

setup() {
	bfd_standard_setup
	MOD="sshd"
}

teardown() {
	bfd_teardown
}

# --- state_events_append ---

@test "state_events_append: single event appended" {
	state_events_append "$INSTALL_PATH" "1708560000" "192.0.2.1" "sshd"
	run cat "$INSTALL_PATH/tmp/events.dat"
	assert_output "1708560000 192.0.2.1 sshd 1"
}

@test "state_events_append: bulk append with count" {
	state_events_append "$INSTALL_PATH" "1708560000" "192.0.2.1" "sshd" "3"
	local line_count
	line_count=$(wc -l < "$INSTALL_PATH/tmp/events.dat")
	[ "$line_count" -eq 3 ]
}

@test "state_events_append: format is TIMESTAMP IP MOD WEIGHT" {
	state_events_append "$INSTALL_PATH" "1708560000" "203.0.113.100" "dovecot"
	run cat "$INSTALL_PATH/tmp/events.dat"
	assert_output "1708560000 203.0.113.100 dovecot 1"
}

@test "state_events_append: explicit weight produces 4-field output" {
	state_events_append "$INSTALL_PATH" "1708560000" "192.0.2.1" "sshd" "1" "3"
	run cat "$INSTALL_PATH/tmp/events.dat"
	assert_output "1708560000 192.0.2.1 sshd 3"
}

@test "state_events_append: multiple appends accumulate" {
	state_events_append "$INSTALL_PATH" "1708560000" "192.0.2.1" "sshd" "2"
	state_events_append "$INSTALL_PATH" "1708560001" "192.0.2.2" "dovecot" "1"
	local line_count
	line_count=$(wc -l < "$INSTALL_PATH/tmp/events.dat")
	[ "$line_count" -eq 3 ]
}

@test "state_events_append: count=0 appends nothing" {
	state_events_append "$INSTALL_PATH" "1708560000" "192.0.2.1" "sshd" "0"
	local line_count
	line_count=$(wc -l < "$INSTALL_PATH/tmp/events.dat")
	[ "$line_count" -eq 0 ]
}

# --- state_events_count ---

@test "state_events_count: returns 0 for empty file" {
	run state_events_count "$INSTALL_PATH" "192.0.2.1" "300" "1708560300"
	assert_output "0"
}

@test "state_events_count: counts events within window" {
	state_events_append "$INSTALL_PATH" "1708560100" "192.0.2.1" "sshd" "3"
	run state_events_count "$INSTALL_PATH" "192.0.2.1" "300" "1708560300" "sshd"
	assert_output "3"
}

@test "state_events_count: excludes events outside window" {
	# event at t=100, window=300, now=500 => cutoff=200 => event at 100 excluded
	state_events_append "$INSTALL_PATH" "100" "192.0.2.1" "sshd" "2"
	# event at t=300, within window
	state_events_append "$INSTALL_PATH" "300" "192.0.2.1" "sshd" "1"
	run state_events_count "$INSTALL_PATH" "192.0.2.1" "300" "500" "sshd"
	assert_output "1"
}

@test "state_events_count: per-service filter" {
	state_events_append "$INSTALL_PATH" "1000" "192.0.2.1" "sshd" "3"
	state_events_append "$INSTALL_PATH" "1000" "192.0.2.1" "dovecot" "2"
	run state_events_count "$INSTALL_PATH" "192.0.2.1" "300" "1200" "sshd"
	assert_output "3"
}

@test "state_events_count: cross-service (no mod filter)" {
	state_events_append "$INSTALL_PATH" "1000" "192.0.2.1" "sshd" "3"
	state_events_append "$INSTALL_PATH" "1000" "192.0.2.1" "dovecot" "2"
	run state_events_count "$INSTALL_PATH" "192.0.2.1" "300" "1200"
	assert_output "5"
}

@test "state_events_count: does not match partial IPs" {
	state_events_append "$INSTALL_PATH" "1000" "192.0.2.1" "sshd" "5"
	state_events_append "$INSTALL_PATH" "1000" "192.0.2.10" "sshd" "3"
	run state_events_count "$INSTALL_PATH" "192.0.2.1" "300" "1200" "sshd"
	assert_output "5"
}

@test "state_events_count: returns 0 for unknown host" {
	state_events_append "$INSTALL_PATH" "1000" "192.0.2.1" "sshd" "5"
	run state_events_count "$INSTALL_PATH" "192.0.2.99" "300" "1200" "sshd"
	assert_output "0"
}

# --- state_events_prune ---

@test "state_events_prune: removes old events" {
	# old event
	state_events_append "$INSTALL_PATH" "100" "192.0.2.1" "sshd" "2"
	# recent event
	state_events_append "$INSTALL_PATH" "900" "192.0.2.2" "sshd" "1"
	state_events_prune "$INSTALL_PATH" "300" "1000"
	local line_count
	line_count=$(wc -l < "$INSTALL_PATH/tmp/events.dat")
	[ "$line_count" -eq 1 ]
	run cat "$INSTALL_PATH/tmp/events.dat"
	assert_output --partial "192.0.2.2"
}

@test "state_events_prune: preserves recent events" {
	state_events_append "$INSTALL_PATH" "900" "192.0.2.1" "sshd" "3"
	state_events_prune "$INSTALL_PATH" "300" "1000"
	local line_count
	line_count=$(wc -l < "$INSTALL_PATH/tmp/events.dat")
	[ "$line_count" -eq 3 ]
}

@test "state_events_prune: safety cap enforced" {
	# write 10 recent events
	local i
	for i in $(seq 1 10); do
		state_events_append "$INSTALL_PATH" "900" "192.0.2.$i" "sshd"
	done
	# prune with max_lines=5
	state_events_prune "$INSTALL_PATH" "300" "1000" "5"
	local line_count
	line_count=$(wc -l < "$INSTALL_PATH/tmp/events.dat")
	[ "$line_count" -eq 5 ]
}

@test "state_events_prune: no-op on empty file" {
	state_events_prune "$INSTALL_PATH" "300" "1000"
	local line_count
	line_count=$(wc -l < "$INSTALL_PATH/tmp/events.dat")
	[ "$line_count" -eq 0 ]
}

# --- count_failures ---

@test "count_failures: basic counting" {
	local hosts_parsed
	hosts_parsed=$(printf "192.0.2.1\n192.0.2.2\n192.0.2.1\n")
	run count_failures "192.0.2.1" "$hosts_parsed" "$INSTALL_PATH" "300" "1000" "sshd"
	assert_output "2"
}

@test "count_failures: zero for absent host" {
	local hosts_parsed
	hosts_parsed=$(printf "192.0.2.1\n192.0.2.2\n")
	run count_failures "192.0.2.3" "$hosts_parsed" "$INSTALL_PATH" "300" "1000" "sshd"
	assert_output "0"
}

@test "count_failures: windowed expiry" {
	# pre-seed old events (will be outside window)
	state_events_append "$INSTALL_PATH" "500" "192.0.2.1" "sshd" "5"
	# new events from hosts_parsed at now=1000, window=300 => cutoff=700
	local hosts_parsed
	hosts_parsed=$(printf "192.0.2.1\n192.0.2.1\n")
	run count_failures "192.0.2.1" "$hosts_parsed" "$INSTALL_PATH" "300" "1000" "sshd"
	# should only count the 2 new events, not the 5 old ones
	assert_output "2"
}

@test "count_failures: accumulation across runs" {
	local hosts_parsed
	hosts_parsed=$(printf "192.0.2.1\n192.0.2.1\n192.0.2.1\n")
	# first run at t=900
	count_failures "192.0.2.1" "$hosts_parsed" "$INSTALL_PATH" "300" "900" "sshd" >/dev/null
	# second run at t=1000 (within window of first run)
	run count_failures "192.0.2.1" "$hosts_parsed" "$INSTALL_PATH" "300" "1000" "sshd"
	# 3 from first run + 3 from second = 6
	assert_output "6"
}

@test "count_failures: does not match partial IPs" {
	local hosts_parsed
	hosts_parsed=$(printf "192.0.2.1\n192.0.2.10\n192.0.2.100\n")
	run count_failures "192.0.2.1" "$hosts_parsed" "$INSTALL_PATH" "300" "1000" "sshd"
	assert_output "1"
}

@test "count_failures: per-service isolation" {
	# pre-seed dovecot events in window
	state_events_append "$INSTALL_PATH" "900" "192.0.2.1" "dovecot" "5"
	local hosts_parsed
	hosts_parsed=$(printf "192.0.2.1\n192.0.2.1\n")
	# count failures for sshd only
	run count_failures "192.0.2.1" "$hosts_parsed" "$INSTALL_PATH" "300" "1000" "sshd"
	# should only see the 2 sshd events, not the 5 dovecot
	assert_output "2"
}

# --- state_init events.dat ---

@test "state_init: creates events.dat" {
	local new_path="$TEST_TMPDIR/newbfd"
	mkdir -p "$new_path"
	state_init "$new_path"
	[ -f "$new_path/tmp/events.dat" ]
}

@test "state_init: events.dat has 600 permissions" {
	local new_path="$TEST_TMPDIR/newbfd"
	mkdir -p "$new_path"
	state_init "$new_path"
	local perms
	perms=$(stat -c '%a' "$new_path/tmp/events.dat")
	[ "$perms" = "600" ]
}
