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

