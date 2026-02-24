#!/usr/bin/env bats
#
# Tests for ban lifecycle state functions:
# state_bans_active_*, state_bans_history_*, state_bans_count_recent
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

setup() {
	bfd_standard_setup
}

teardown() {
	bfd_teardown
}

# --- state_bans_active_append ---

@test "state_bans_active_append: single entry appended" {
	state_bans_active_append "$INSTALL_PATH" "1000" "1300" "192.0.2.1" "sshd" "22"
	run cat "$INSTALL_PATH/tmp/bans.active"
	assert_output "1000 1300 192.0.2.1 sshd 22"
}

@test "state_bans_active_append: duplicate host skipped" {
	state_bans_active_append "$INSTALL_PATH" "1000" "1300" "192.0.2.1" "sshd" "22"
	state_bans_active_append "$INSTALL_PATH" "2000" "2300" "192.0.2.1" "dovecot" "110"
	local count
	count=$(wc -l < "$INSTALL_PATH/tmp/bans.active")
	[ "$count" -eq 1 ]
}

@test "state_bans_active_append: different hosts both added" {
	state_bans_active_append "$INSTALL_PATH" "1000" "1300" "192.0.2.1" "sshd" "22"
	state_bans_active_append "$INSTALL_PATH" "1000" "1300" "192.0.2.2" "sshd" "22"
	local count
	count=$(wc -l < "$INSTALL_PATH/tmp/bans.active")
	[ "$count" -eq 2 ]
}

@test "state_bans_active_append: format is TIMESTAMP EXPIRY IP MOD PORTS" {
	state_bans_active_append "$INSTALL_PATH" "1708560000" "1708560300" "203.0.113.100" "sshd" "22"
	run cat "$INSTALL_PATH/tmp/bans.active"
	assert_output "1708560000 1708560300 203.0.113.100 sshd 22"
}

# --- state_bans_active_remove ---

@test "state_bans_active_remove: removes entry" {
	state_bans_active_append "$INSTALL_PATH" "1000" "1300" "192.0.2.1" "sshd" "22"
	state_bans_active_append "$INSTALL_PATH" "1000" "1300" "192.0.2.2" "sshd" "22"
	state_bans_active_remove "$INSTALL_PATH" "192.0.2.1"
	run cat "$INSTALL_PATH/tmp/bans.active"
	assert_output "1000 1300 192.0.2.2 sshd 22"
}

@test "state_bans_active_remove: preserves other entries" {
	state_bans_active_append "$INSTALL_PATH" "1000" "1300" "192.0.2.1" "sshd" "22"
	state_bans_active_append "$INSTALL_PATH" "1000" "1300" "192.0.2.2" "dovecot" "110"
	state_bans_active_append "$INSTALL_PATH" "1000" "1300" "192.0.2.3" "postfix" "25"
	state_bans_active_remove "$INSTALL_PATH" "192.0.2.2"
	local count
	count=$(wc -l < "$INSTALL_PATH/tmp/bans.active")
	[ "$count" -eq 2 ]
	run grep -c "192.0.2.2" "$INSTALL_PATH/tmp/bans.active"
	assert_output "0"
}

@test "state_bans_active_remove: handles missing host gracefully" {
	state_bans_active_append "$INSTALL_PATH" "1000" "1300" "192.0.2.1" "sshd" "22"
	run state_bans_active_remove "$INSTALL_PATH" "192.0.2.99"
	assert_success
}

@test "state_bans_active_remove: handles empty file" {
	run state_bans_active_remove "$INSTALL_PATH" "192.0.2.1"
	assert_success
}

# --- state_bans_active_check ---

@test "state_bans_active_check: returns 0 when found" {
	state_bans_active_append "$INSTALL_PATH" "1000" "1300" "192.0.2.1" "sshd" "22"
	run state_bans_active_check "$INSTALL_PATH" "192.0.2.1"
	assert_success
}

@test "state_bans_active_check: returns 1 when not found" {
	state_bans_active_append "$INSTALL_PATH" "1000" "1300" "192.0.2.1" "sshd" "22"
	run state_bans_active_check "$INSTALL_PATH" "192.0.2.2"
	assert_failure
}

# --- state_bans_active_list ---

@test "state_bans_active_list: formats output with pipe delimiters" {
	state_bans_active_append "$INSTALL_PATH" "1708560000" "1708560300" "203.0.113.100" "sshd" "22"
	run state_bans_active_list "$INSTALL_PATH"
	assert_success
	assert_output --partial "203.0.113.100"
	assert_output --partial "sshd"
	assert_output --partial "22"
}

@test "state_bans_active_list: permanent ban shows permanent" {
	state_bans_active_append "$INSTALL_PATH" "1708560000" "0" "192.0.2.5" "dovecot" "110,995"
	run state_bans_active_list "$INSTALL_PATH"
	assert_success
	assert_output --partial "permanent"
}

@test "state_bans_active_list: empty file produces no output" {
	run state_bans_active_list "$INSTALL_PATH"
	assert_success
	assert_output ""
}

# --- state_bans_active_expired ---

@test "state_bans_active_expired: returns expired entries" {
	state_bans_active_append "$INSTALL_PATH" "1000" "1300" "192.0.2.1" "sshd" "22"
	run state_bans_active_expired "$INSTALL_PATH" "1400"
	assert_success
	assert_output --partial "192.0.2.1"
}

@test "state_bans_active_expired: preserves non-expired entries" {
	state_bans_active_append "$INSTALL_PATH" "1000" "1300" "192.0.2.1" "sshd" "22"
	run state_bans_active_expired "$INSTALL_PATH" "1200"
	assert_success
	assert_output ""
}

@test "state_bans_active_expired: permanent (expiry=0) never expires" {
	state_bans_active_append "$INSTALL_PATH" "1000" "0" "192.0.2.1" "sshd" "22"
	run state_bans_active_expired "$INSTALL_PATH" "9999999999"
	assert_success
	assert_output ""
}

@test "state_bans_active_expired: mixed entries returns only expired" {
	echo "1000 1300 192.0.2.1 sshd 22" >> "$INSTALL_PATH/tmp/bans.active"
	echo "1000 0 192.0.2.2 dovecot 110" >> "$INSTALL_PATH/tmp/bans.active"
	echo "1000 2000 192.0.2.3 postfix 25" >> "$INSTALL_PATH/tmp/bans.active"
	# at now=1500: 192.0.2.1 (expiry=1300) is expired, 192.0.2.2 (permanent) is not, 192.0.2.3 (expiry=2000) is not
	run state_bans_active_expired "$INSTALL_PATH" "1500"
	assert_output --partial "192.0.2.1"
	refute_output --partial "192.0.2.2"
	refute_output --partial "192.0.2.3"
}

# --- state_bans_history_append ---

@test "state_bans_history_append: appends correctly" {
	state_bans_history_append "$INSTALL_PATH" "1000" "1300" "192.0.2.1" "sshd" "ban"
	run cat "$INSTALL_PATH/tmp/bans.history"
	assert_output "1000 1300 192.0.2.1 sshd ban"
}

@test "state_bans_history_append: format is TIMESTAMP EXPIRY IP MOD ACTION" {
	state_bans_history_append "$INSTALL_PATH" "1708560000" "1708560300" "203.0.113.100" "sshd" "ban"
	state_bans_history_append "$INSTALL_PATH" "1708560300" "1708560300" "203.0.113.100" "sshd" "unban"
	local count
	count=$(wc -l < "$INSTALL_PATH/tmp/bans.history")
	[ "$count" -eq 2 ]
}

# --- state_bans_count_recent ---

@test "state_bans_count_recent: counts bans within window" {
	state_bans_history_append "$INSTALL_PATH" "900" "1200" "192.0.2.1" "sshd" "ban"
	state_bans_history_append "$INSTALL_PATH" "950" "1250" "192.0.2.1" "sshd" "ban"
	# now=1000, window=200, cutoff=800
	run state_bans_count_recent "$INSTALL_PATH" "192.0.2.1" "200" "1000"
	assert_output "2"
}

@test "state_bans_count_recent: excludes bans outside window" {
	state_bans_history_append "$INSTALL_PATH" "100" "400" "192.0.2.1" "sshd" "ban"
	state_bans_history_append "$INSTALL_PATH" "900" "1200" "192.0.2.1" "sshd" "ban"
	# now=1000, window=200, cutoff=800 — only second ban counts
	run state_bans_count_recent "$INSTALL_PATH" "192.0.2.1" "200" "1000"
	assert_output "1"
}

@test "state_bans_count_recent: counts only ban and escalate actions" {
	state_bans_history_append "$INSTALL_PATH" "900" "1200" "192.0.2.1" "sshd" "ban"
	state_bans_history_append "$INSTALL_PATH" "950" "0" "192.0.2.1" "sshd" "escalate"
	state_bans_history_append "$INSTALL_PATH" "960" "1200" "192.0.2.1" "sshd" "unban"
	# now=1000, window=200 — ban + escalate = 2, unban excluded
	run state_bans_count_recent "$INSTALL_PATH" "192.0.2.1" "200" "1000"
	assert_output "2"
}

@test "state_bans_count_recent: returns 0 for empty history" {
	run state_bans_count_recent "$INSTALL_PATH" "192.0.2.1" "200" "1000"
	assert_output "0"
}

@test "state_bans_count_recent: returns 0 for unknown host" {
	state_bans_history_append "$INSTALL_PATH" "900" "1200" "192.0.2.1" "sshd" "ban"
	run state_bans_count_recent "$INSTALL_PATH" "192.0.2.99" "200" "1000"
	assert_output "0"
}

# --- state_init ---

@test "state_init: creates bans.active" {
	local new_path="$TEST_TMPDIR/new_bfd"
	state_init "$new_path"
	[ -f "$new_path/tmp/bans.active" ]
}

@test "state_init: creates bans.history" {
	local new_path="$TEST_TMPDIR/new_bfd"
	state_init "$new_path"
	[ -f "$new_path/tmp/bans.history" ]
}

# --- compute_ban_duration ---

@test "compute_ban_duration: none mode returns base duration" {
	run compute_ban_duration 300 3 "none" 0
	assert_output "300"
}

@test "compute_ban_duration: linear first offense (count=0)" {
	run compute_ban_duration 300 0 "linear" 0
	assert_output "300"
}

@test "compute_ban_duration: linear second offense (count=1)" {
	run compute_ban_duration 300 1 "linear" 0
	assert_output "600"
}

@test "compute_ban_duration: linear third offense (count=2)" {
	run compute_ban_duration 300 2 "linear" 0
	assert_output "900"
}

@test "compute_ban_duration: exponential first offense (count=0)" {
	run compute_ban_duration 300 0 "exponential" 0
	assert_output "300"
}

@test "compute_ban_duration: exponential second offense (count=1)" {
	run compute_ban_duration 300 1 "exponential" 0
	assert_output "600"
}

@test "compute_ban_duration: exponential third offense (count=2)" {
	run compute_ban_duration 300 2 "exponential" 0
	assert_output "1200"
}

@test "compute_ban_duration: linear cap enforcement" {
	run compute_ban_duration 300 9 "linear" 1800
	assert_output "1800"
}

@test "compute_ban_duration: exponential cap enforcement" {
	run compute_ban_duration 300 5 "exponential" 3600
	assert_output "3600"
}

@test "compute_ban_duration: cap=0 means no cap" {
	run compute_ban_duration 300 5 "exponential" 0
	assert_output "9600"
}

@test "compute_ban_duration: unknown mode defaults to base" {
	run compute_ban_duration 300 3 "bogus" 0
	assert_output "300"
}
