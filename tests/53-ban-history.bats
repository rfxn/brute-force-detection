#!/usr/bin/env bats
#
# Test suite for ban history query functions:
#   ban_history, ban_history_json, ban_history_csv
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

setup() {
	bfd_standard_setup
	_EVENTS_CUTOFF=0
	_EVENTS_LIMIT=0
}

teardown() {
	bfd_teardown
}

# --- Test data helper ---

_populate_history() {
	local now
	now=$(date +%s)
	local hour_ago=$(( now - 3600 ))
	local day_ago=$(( now - 86400 ))
	local expiry=$(( now + 3600 ))
	printf '%s 0 192.0.2.1 sshd ban\n' "$now" > "$INSTALL_PATH/tmp/bans.history"
	printf '%s %s 192.0.2.2 postfix ban\n' "$hour_ago" "$expiry" >> "$INSTALL_PATH/tmp/bans.history"
	printf '%s 0 192.0.2.3 sshd unban\n' "$day_ago" >> "$INSTALL_PATH/tmp/bans.history"
}

# --- ban_history tests ---

@test "ban_history: all events across archives" {
	_populate_history
	# Put an older event in a rotated archive
	local two_days_ago
	two_days_ago=$(( $(date +%s) - 172800 ))
	printf '%s 0 192.0.2.4 dovecot ban\n' "$two_days_ago" > "$INSTALL_PATH/tmp/bans.history.1"

	run ban_history "$INSTALL_PATH"
	assert_success
	assert_output --partial "192.0.2.1"
	assert_output --partial "192.0.2.2"
	assert_output --partial "192.0.2.3"
	assert_output --partial "192.0.2.4"
}

@test "ban_history: filter by IP" {
	_populate_history

	run ban_history "$INSTALL_PATH" "192.0.2.1"
	assert_success
	assert_output --partial "192.0.2.1"
	refute_output --partial "192.0.2.2"
	refute_output --partial "192.0.2.3"
}

@test "ban_history: respects time window" {
	_populate_history
	# Set cutoff to 2 hours ago — should exclude the day-old event
	_EVENTS_CUTOFF=$(( $(date +%s) - 7200 ))

	run ban_history "$INSTALL_PATH"
	assert_success
	assert_output --partial "192.0.2.1"
	assert_output --partial "192.0.2.2"
	refute_output --partial "192.0.2.3"
}

@test "ban_history: respects limit" {
	_populate_history
	_EVENTS_LIMIT=1

	run ban_history "$INSTALL_PATH"
	assert_success
	assert_output --partial "events"
	assert_output --partial "showing"
}

@test "ban_history: empty history" {
	run ban_history "$INSTALL_PATH"
	assert_success
	assert_output --partial "no ban history"
}

@test "ban_history_json: outputs valid JSON structure" {
	_populate_history

	run ban_history_json "$INSTALL_PATH"
	assert_success
	assert_output --partial '"events":['
	assert_output --partial '"total":3'
}

@test "ban_history_csv: outputs header and rows" {
	_populate_history

	run ban_history_csv "$INSTALL_PATH"
	assert_success
	# First line is the header
	local header
	header=$(echo "$output" | head -1)
	[ "$header" = "timestamp,expiry,ip,service,action" ]
	# Should have 4 lines total (1 header + 3 data)
	local line_count
	line_count=$(echo "$output" | wc -l)
	[ "$line_count" -eq 4 ]
}

@test "ban_history_json: empty returns zero total" {
	run ban_history_json "$INSTALL_PATH"
	assert_success
	assert_output --partial '{"events":[],"total":0}'
}
