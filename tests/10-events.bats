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

# --- state_pressure_append ---

@test "state_pressure_append: single event appended" {
	state_pressure_append "$INSTALL_PATH" "1708560000" "192.0.2.1" "sshd"
	run cat "$INSTALL_PATH/tmp/pressure.dat"
	assert_output "1708560000 192.0.2.1 sshd 1"
}

@test "state_pressure_append: bulk append with count" {
	state_pressure_append "$INSTALL_PATH" "1708560000" "192.0.2.1" "sshd" "3"
	local line_count
	line_count=$(wc -l < "$INSTALL_PATH/tmp/pressure.dat")
	[ "$line_count" -eq 3 ]
}

@test "state_pressure_append: format is TIMESTAMP IP MOD WEIGHT" {
	state_pressure_append "$INSTALL_PATH" "1708560000" "203.0.113.100" "dovecot"
	run cat "$INSTALL_PATH/tmp/pressure.dat"
	assert_output "1708560000 203.0.113.100 dovecot 1"
}

@test "state_pressure_append: explicit weight produces 4-field output" {
	state_pressure_append "$INSTALL_PATH" "1708560000" "192.0.2.1" "sshd" "1" "3"
	run cat "$INSTALL_PATH/tmp/pressure.dat"
	assert_output "1708560000 192.0.2.1 sshd 3"
}

@test "state_pressure_append: multiple appends accumulate" {
	state_pressure_append "$INSTALL_PATH" "1708560000" "192.0.2.1" "sshd" "2"
	state_pressure_append "$INSTALL_PATH" "1708560001" "192.0.2.2" "dovecot" "1"
	local line_count
	line_count=$(wc -l < "$INSTALL_PATH/tmp/pressure.dat")
	[ "$line_count" -eq 3 ]
}

@test "state_pressure_append: count=0 appends nothing" {
	state_pressure_append "$INSTALL_PATH" "1708560000" "192.0.2.1" "sshd" "0"
	local line_count
	line_count=$(wc -l < "$INSTALL_PATH/tmp/pressure.dat")
	[ "$line_count" -eq 0 ]
}

# --- state_pressure_prune ---

@test "state_pressure_prune: removes old events" {
	# old event
	state_pressure_append "$INSTALL_PATH" "100" "192.0.2.1" "sshd" "2"
	# recent event
	state_pressure_append "$INSTALL_PATH" "900" "192.0.2.2" "sshd" "1"
	state_pressure_prune "$INSTALL_PATH" "300" "1000"
	local line_count
	line_count=$(wc -l < "$INSTALL_PATH/tmp/pressure.dat")
	[ "$line_count" -eq 1 ]
	run cat "$INSTALL_PATH/tmp/pressure.dat"
	assert_output --partial "192.0.2.2"
}

@test "state_pressure_prune: preserves recent events" {
	state_pressure_append "$INSTALL_PATH" "900" "192.0.2.1" "sshd" "3"
	state_pressure_prune "$INSTALL_PATH" "300" "1000"
	local line_count
	line_count=$(wc -l < "$INSTALL_PATH/tmp/pressure.dat")
	[ "$line_count" -eq 3 ]
}

@test "state_pressure_prune: safety cap enforced" {
	# write 10 recent events
	local i
	for i in $(seq 1 10); do
		state_pressure_append "$INSTALL_PATH" "900" "192.0.2.$i" "sshd"
	done
	# prune with max_lines=5
	state_pressure_prune "$INSTALL_PATH" "300" "1000" "5"
	local line_count
	line_count=$(wc -l < "$INSTALL_PATH/tmp/pressure.dat")
	[ "$line_count" -eq 5 ]
}

@test "state_pressure_prune: no-op on empty file" {
	state_pressure_prune "$INSTALL_PATH" "300" "1000"
	local line_count
	line_count=$(wc -l < "$INSTALL_PATH/tmp/pressure.dat")
	[ "$line_count" -eq 0 ]
}

