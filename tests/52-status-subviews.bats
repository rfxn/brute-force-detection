#!/usr/bin/env bats
#
# Test suite for status sub-view functions:
#   status_lock, status_cursors, status_pool, status_pressure
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

setup() {
	bfd_require_bash42
	bfd_standard_setup
	mkdir -p "$INSTALL_PATH/stats" "$INSTALL_PATH/tmp"
	export LOCK_FILE="$TEST_TMPDIR/lock.utime"
	export LOCK_FILE_TIMEOUT=300
	export PRESSURE_HALF_LIFE=300
	export PRESSURE_TRIP=20
}

teardown() {
	bfd_teardown
}

# ============================================================
# status_lock
# ============================================================

@test "status_lock: idle - no lock file or directory" {
	run status_lock "$INSTALL_PATH"
	assert_success
	assert_output --partial "idle (no activity recorded)"
}

@test "status_lock: held - active PID" {
	# Create lock dir with our own PID (guaranteed alive)
	local lock_dir="${LOCK_FILE}.lk"
	mkdir -p "$lock_dir"
	echo "$$" > "$lock_dir/pid"
	echo "$(date +%s)" > "$LOCK_FILE"

	run status_lock "$INSTALL_PATH"
	assert_success
	assert_output --partial "held by PID $$"
}

@test "status_lock: stale - dead PID" {
	# Use a PID that almost certainly does not exist
	local lock_dir="${LOCK_FILE}.lk"
	mkdir -p "$lock_dir"
	echo "999999" > "$lock_dir/pid"
	echo "$(date +%s)" > "$LOCK_FILE"

	run status_lock "$INSTALL_PATH"
	assert_success
	assert_output --partial "stale"
}

# ============================================================
# status_cursors
# ============================================================

@test "status_cursors: lists cursor files" {
	echo "12345" > "$INSTALL_PATH/tmp/sshd.cursor"
	echo "67890" > "$INSTALL_PATH/tmp/dovecot.jts"
	touch "$INSTALL_PATH/tmp/sshd.cursor"
	touch "$INSTALL_PATH/tmp/dovecot.jts"

	run status_cursors "$INSTALL_PATH"
	assert_success
	assert_output --partial "sshd.cursor"
	assert_output --partial "dovecot.jts"
	assert_output --partial "2 cursor file(s)"
}

@test "status_cursors: empty - no cursors" {
	run status_cursors "$INSTALL_PATH"
	assert_success
	assert_output --partial "no cursors"
}

# ============================================================
# status_pool
# ============================================================

@test "status_pool: statistics with events" {
	local now
	now=$(date +%s)
	local pool="$INSTALL_PATH/stats/attack.pool"
	# 3 events, 2 unique IPs
	printf '%s\n' \
		"$((now - 3600)) 10.0.0.1 sshd 5 15.0 US ban 600 22 15000" \
		"$((now - 1800)) 10.0.0.2 dovecot 3 10.0 DE ban 600 143 10000" \
		"$((now - 900)) 10.0.0.1 sshd 7 21.0 US ban 600 22 21000" \
		> "$pool"

	run status_pool "$INSTALL_PATH"
	assert_success
	assert_output --partial "Total events: 3"
	assert_output --partial "Unique IPs:   2"
}

@test "status_pool: empty pool" {
	run status_pool "$INSTALL_PATH"
	assert_success
	assert_output --partial "attack pool: empty"
}

# ============================================================
# status_pressure
# ============================================================

@test "status_pressure: single IP with events" {
	local now
	now=$(date +%s)
	# Populate pressure.dat: TIMESTAMP HOST SERVICE WEIGHT
	printf '%s\n' \
		"$now 10.0.0.1 sshd 3" \
		"$now 10.0.0.1 dovecot 2" \
		> "$INSTALL_PATH/tmp/pressure.dat"

	run status_pressure "$INSTALL_PATH" "10.0.0.1"
	assert_success
	assert_output --partial "Pressure Status: 10.0.0.1"
}

@test "status_pressure: unknown IP returns zero" {
	run status_pressure "$INSTALL_PATH" "192.0.2.99"
	assert_success
	assert_output --partial "no pressure events recorded"
}

@test "status_pressure: all IPs view with data" {
	local now
	now=$(date +%s)
	printf '%s\n' \
		"$now 10.0.0.1 sshd 3" \
		"$now 10.0.0.2 dovecot 2" \
		> "$INSTALL_PATH/tmp/pressure.dat"

	run status_pressure "$INSTALL_PATH"
	assert_success
	assert_output --partial "Active Pressure Scores:"
}

@test "status_pressure: empty pressure data" {
	run status_pressure "$INSTALL_PATH"
	assert_success
	assert_output --partial "no pressure data"
}
