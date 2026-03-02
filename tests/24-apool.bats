#!/usr/bin/env bats
#
# Tests for enhanced attack summary — Phase 13D
# Tests _apool_report() ban status, _apool_service_summary(),
# and _apool_ban_status()
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

# Source apool functions from bfd (defined there, not in bfd.lib.sh)
bfd_load_function _apool_awk
bfd_load_function _apool_report
bfd_load_function _apool_ban_status
bfd_load_function _apool_service_summary
bfd_load_function apool_list

setup() {
	bfd_standard_setup
	UTIME=$(date +"%s")
}

teardown() {
	bfd_teardown
}

# --- per-service breakdown ---

@test "service summary: counts correct" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	echo "1000 192.0.2.1 sshd" >> "$pool"
	echo "1001 192.0.2.1 sshd" >> "$pool"
	echo "1002 192.0.2.2 sshd" >> "$pool"
	echo "1003 192.0.2.1 dovecot" >> "$pool"
	run _apool_service_summary "$pool"
	assert_success
	assert_output --partial "sshd"
	assert_output --partial "dovecot"
}

@test "service summary: unique IP count correct" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	echo "1000 192.0.2.1 sshd" >> "$pool"
	echo "1001 192.0.2.1 sshd" >> "$pool"
	echo "1002 192.0.2.2 sshd" >> "$pool"
	echo "1003 192.0.2.3 dovecot" >> "$pool"
	run _apool_service_summary "$pool"
	assert_success
	# sshd: 3 events, 2 unique IPs; dovecot: 1 event, 1 unique IP
	# output is table-formatted; check the data content
	assert_output --partial "Per-service breakdown"
	assert_output --partial "UNIQUE_IPS"
}

@test "service summary: multiple services sorted by count" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	echo "1000 192.0.2.1 dovecot" >> "$pool"
	echo "1001 192.0.2.1 sshd" >> "$pool"
	echo "1002 192.0.2.2 sshd" >> "$pool"
	echo "1003 192.0.2.3 sshd" >> "$pool"
	run _apool_service_summary "$pool"
	assert_success
	# sshd has 3 events (sorted first), dovecot has 1
	assert_output --partial "sshd"
	assert_output --partial "dovecot"
}

@test "service summary: empty pool produces no output" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	# pool exists but is empty
	run _apool_service_summary "$pool"
	assert_success
	refute_output --partial "Per-service"
}

# --- ban status ---

@test "ban status: BANNED(perm) shown for permanent ban" {
	state_bans_active_append "$INSTALL_PATH" "1000" "0" "192.0.2.1" "sshd" "22"
	run _apool_ban_status "192.0.2.1"
	assert_success
	assert_output "BANNED(perm)"
}

@test "ban status: BANNED(Xm) shown for temp ban" {
	local now future
	now=$(date +"%s")
	future=$((now + 600))  # 10 minutes from now
	state_bans_active_append "$INSTALL_PATH" "$now" "$future" "192.0.2.2" "sshd" "22"
	run _apool_ban_status "192.0.2.2"
	assert_success
	# should show BANNED(Xm) where X is roughly 10 (or 9 due to rounding)
	assert_output --partial "BANNED("
	assert_output --partial "m)"
}

@test "ban status: prev:N shown for historical bans" {
	# not in bans.active, but in bans.history
	state_bans_history_append "$INSTALL_PATH" "900" "1200" "192.0.2.3" "sshd" "ban"
	state_bans_history_append "$INSTALL_PATH" "1300" "1600" "192.0.2.3" "sshd" "ban"
	state_bans_history_append "$INSTALL_PATH" "1700" "2000" "192.0.2.3" "sshd" "ban"
	run _apool_ban_status "192.0.2.3"
	assert_success
	assert_output "prev:3"
}

@test "ban status: no status for unknown IP" {
	run _apool_ban_status "192.0.2.99"
	assert_success
	assert_output ""
}

# --- _apool_report with PRESSURE column ---

@test "apool report: header includes PRESSURE column" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	echo "1000 192.0.2.1 sshd" >> "$pool"
	run _apool_report "$pool" "Test report"
	assert_success
	assert_output --partial "PRESSURE"
}

@test "apool report: pressure value shown for IP with events" {
	local now
	now=$(date +"%s")
	local pool="$INSTALL_PATH/stats/attack.pool"
	echo "$now 192.0.2.1 sshd" >> "$pool"
	# create matching events so pressure_compute returns non-zero
	state_events_append "$INSTALL_PATH" "$((now - 1))" "192.0.2.1" "sshd" "5" "3"
	run _apool_report "$pool" "Test report"
	assert_success
	# pressure column should show format like X.Y/20
	assert_output --partial "/20"
}

# --- _apool_report with ban status column ---

@test "apool report: header includes STATUS column" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	echo "1000 192.0.2.1 sshd" >> "$pool"
	run _apool_report "$pool" "Test report"
	assert_success
	assert_output --partial "STATUS"
}

@test "apool report: banned IP shows status in output" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	echo "1000 192.0.2.1 sshd" >> "$pool"
	state_bans_active_append "$INSTALL_PATH" "1000" "0" "192.0.2.1" "sshd" "22"
	run _apool_report "$pool" "Test report"
	assert_success
	assert_output --partial "BANNED(perm)"
}

# --- IPv6 exact-match tests for attack pool ---

@test "ban status: IPv6 BANNED(perm) exact match" {
	state_bans_active_append "$INSTALL_PATH" "1000" "0" "2001:db8::1" "sshd" "22"
	run _apool_ban_status "2001:db8::1"
	assert_success
	assert_output "BANNED(perm)"
}

@test "ban status: IPv6 does not false-match prefix" {
	state_bans_active_append "$INSTALL_PATH" "1000" "0" "2001:db8::1" "sshd" "22"
	# 2001:db8::10 must NOT match
	run _apool_ban_status "2001:db8::10"
	assert_success
	assert_output ""
}

@test "ban status: IPv6 prev:N from history" {
	state_bans_history_append "$INSTALL_PATH" "900" "1200" "2001:db8::1" "sshd" "ban"
	state_bans_history_append "$INSTALL_PATH" "1300" "1600" "2001:db8::1" "sshd" "ban"
	run _apool_ban_status "2001:db8::1"
	assert_success
	assert_output "prev:2"
}

@test "apool report: search uses literal matching not regex" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	echo "1000 192.0.2.1 sshd" >> "$pool"
	echo "1001 10x0x0x1 sshd" >> "$pool"
	# search for literal "192.0.2.1" — dots should NOT match "x"
	run _apool_report "$pool" "Test" "192.0.2.1"
	assert_success
	assert_output --partial "192.0.2.1"
	refute_output --partial "10x0x0x1"
}

# --- apool_list() orchestrator ---

@test "apool_list: empty pool produces no crash" {
	APOOL_LIST="$INSTALL_PATH/stats/attack.pool"
	> "$APOOL_LIST"
	run apool_list
	assert_success
}

@test "apool_list: pool with entries shows today report and service summary" {
	APOOL_LIST="$INSTALL_PATH/stats/attack.pool"
	echo "1000 192.0.2.1 sshd" >> "$APOOL_LIST"
	echo "1001 192.0.2.2 dovecot" >> "$APOOL_LIST"
	run apool_list
	assert_success
	assert_output --partial "Top 25 brute force attackers today"
	assert_output --partial "Per-service breakdown"
	assert_output --partial "Top 25 brute force attackers this week"
}

@test "apool_list: search filter shows filtered results" {
	APOOL_LIST="$INSTALL_PATH/stats/attack.pool"
	echo "1000 192.0.2.1 sshd" >> "$APOOL_LIST"
	echo "1001 192.0.2.2 dovecot" >> "$APOOL_LIST"
	run apool_list "sshd"
	assert_success
	assert_output --partial "Events for search string"
	assert_output --partial "sshd"
}

@test "apool_list: cleans up temp file after execution" {
	APOOL_LIST="$INSTALL_PATH/stats/attack.pool"
	echo "1000 192.0.2.1 sshd" >> "$APOOL_LIST"
	apool_list >/dev/null 2>&1
	# verify no leftover weekly temp files
	local leftover
	leftover=$(find "$INSTALL_PATH/tmp" -name '.weekly.apool.*' 2>/dev/null | wc -l)
	[ "$leftover" -eq 0 ]
}
