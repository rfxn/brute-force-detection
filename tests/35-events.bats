#!/usr/bin/env bats
#
# Tests for --events CLI command: validate_cidr(), events_dashboard(),
# events_ip(), events_cidr()
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

# Source _apool_ban_status from bfd (needed by events functions)
bfd_load_function _apool_ban_status

setup() {
	bfd_standard_setup
	PRESSURE_TRIP="20"
	PRESSURE_HALF_LIFE="300"
	PRESSURE_TRIP_GLOBAL="0"
	GLOB_PRESSURE_TRIP="$PRESSURE_TRIP"
}

teardown() {
	bfd_teardown
}

# --- validate_cidr ---

@test "validate_cidr: valid /24 returns normalized" {
	run validate_cidr "192.0.2.0/24"
	assert_success
	assert_output "192.0.2.0/24"
}

@test "validate_cidr: valid /32 returns success" {
	run validate_cidr "192.0.2.1/32"
	assert_success
	assert_output "192.0.2.1/32"
}

@test "validate_cidr: valid /8 returns success" {
	run validate_cidr "10.0.0.0/8"
	assert_success
	assert_output "10.0.0.0/8"
}

@test "validate_cidr: rejects mask > 32" {
	run validate_cidr "192.0.2.0/33"
	assert_failure
}

@test "validate_cidr: rejects mask < 8" {
	run validate_cidr "192.0.2.0/7"
	assert_failure
}

@test "validate_cidr: rejects non-numeric mask" {
	run validate_cidr "192.0.2.0/abc"
	assert_failure
}

@test "validate_cidr: rejects invalid IP in address" {
	run validate_cidr "999.0.2.0/24"
	assert_failure
}

@test "validate_cidr: rejects missing slash" {
	run validate_cidr "192.0.2.0"
	assert_failure
}

@test "validate_cidr: rejects empty string" {
	run validate_cidr ""
	assert_failure
}

@test "validate_cidr: rejects IPv6 CIDR" {
	run validate_cidr "2001:db8::/32"
	assert_failure
}

# --- events_dashboard ---

@test "events_dashboard: shows IPs sorted by pressure" {
	local now
	now=$(date +"%s")
	# IP with more events (higher pressure)
	local i
	for i in $(seq 1 10); do
		state_events_append "$INSTALL_PATH" "$((now - i))" "192.0.2.10" "sshd" "1" "3"
	done
	# IP with fewer events (lower pressure)
	state_events_append "$INSTALL_PATH" "$((now - 1))" "192.0.2.20" "sshd" "1" "1"
	run events_dashboard "$INSTALL_PATH"
	assert_success
	assert_output --partial "192.0.2.10"
	assert_output --partial "192.0.2.20"
	# higher pressure IP should appear first (before lower pressure IP in output)
	local line_10 line_20
	line_10=$(echo "$output" | grep -n "192.0.2.10" | head -1 | cut -d: -f1)
	line_20=$(echo "$output" | grep -n "192.0.2.20" | head -1 | cut -d: -f1)
	[ "$line_10" -lt "$line_20" ]
}

@test "events_dashboard: header row present" {
	local now
	now=$(date +"%s")
	state_events_append "$INSTALL_PATH" "$((now - 1))" "192.0.2.10" "sshd" "1" "1"
	run events_dashboard "$INSTALL_PATH"
	assert_success
	assert_output --partial "PRESSURE"
}

@test "events_dashboard: empty events shows message" {
	run events_dashboard "$INSTALL_PATH"
	assert_success
	assert_output --partial "No active events"
}

@test "events_dashboard: banned IP shows BANNED status" {
	local now
	now=$(date +"%s")
	state_events_append "$INSTALL_PATH" "$((now - 1))" "192.0.2.30" "sshd" "1" "1"
	state_bans_active_append "$INSTALL_PATH" "$now" "0" "192.0.2.30" "sshd" "22"
	run events_dashboard "$INSTALL_PATH"
	assert_success
	assert_output --partial "BANNED"
}

@test "events_dashboard: multiple services shown comma-separated" {
	local now
	now=$(date +"%s")
	state_events_append "$INSTALL_PATH" "$((now - 1))" "192.0.2.40" "sshd" "1" "1"
	state_events_append "$INSTALL_PATH" "$((now - 2))" "192.0.2.40" "dovecot" "1" "1"
	run events_dashboard "$INSTALL_PATH"
	assert_success
	assert_output --partial "sshd"
	assert_output --partial "dovecot"
}

@test "events_dashboard: correct event count per IP" {
	local now
	now=$(date +"%s")
	state_events_append "$INSTALL_PATH" "$((now - 1))" "192.0.2.50" "sshd" "3" "1"
	state_events_append "$INSTALL_PATH" "$((now - 2))" "192.0.2.50" "sshd" "2" "1"
	run events_dashboard "$INSTALL_PATH"
	assert_success
	# 5 total events
	assert_output --partial "5"
}

# --- events_ip ---

@test "events_ip: shows overall pressure score" {
	local now
	now=$(date +"%s")
	state_events_append "$INSTALL_PATH" "$((now - 1))" "192.0.2.10" "sshd" "5" "3"
	run events_ip "$INSTALL_PATH" "192.0.2.10"
	assert_success
	assert_output --partial "Pressure:"
	assert_output --partial "/${GLOB_PRESSURE_TRIP}"
}

@test "events_ip: shows per-service breakdown" {
	local now
	now=$(date +"%s")
	state_events_append "$INSTALL_PATH" "$((now - 1))" "192.0.2.10" "sshd" "3" "3"
	state_events_append "$INSTALL_PATH" "$((now - 2))" "192.0.2.10" "dovecot" "2" "2"
	run events_ip "$INSTALL_PATH" "192.0.2.10"
	assert_success
	assert_output --partial "sshd"
	assert_output --partial "dovecot"
	assert_output --partial "SERVICE"
}

@test "events_ip: shows first/last seen timestamps" {
	local now
	now=$(date +"%s")
	state_events_append "$INSTALL_PATH" "$((now - 100))" "192.0.2.10" "sshd" "1" "1"
	state_events_append "$INSTALL_PATH" "$((now - 1))" "192.0.2.10" "sshd" "1" "1"
	run events_ip "$INSTALL_PATH" "192.0.2.10"
	assert_success
	assert_output --partial "First seen:"
	assert_output --partial "Last seen:"
}

@test "events_ip: shows ban status" {
	local now
	now=$(date +"%s")
	state_events_append "$INSTALL_PATH" "$((now - 1))" "192.0.2.10" "sshd" "1" "1"
	state_bans_active_append "$INSTALL_PATH" "$now" "0" "192.0.2.10" "sshd" "22"
	run events_ip "$INSTALL_PATH" "192.0.2.10"
	assert_success
	assert_output --partial "BANNED"
}

@test "events_ip: no events shows message" {
	run events_ip "$INSTALL_PATH" "192.0.2.99"
	assert_success
	assert_output --partial "No active events"
}

@test "events_ip: multiple services listed separately" {
	local now
	now=$(date +"%s")
	state_events_append "$INSTALL_PATH" "$((now - 1))" "192.0.2.10" "sshd" "2" "3"
	state_events_append "$INSTALL_PATH" "$((now - 2))" "192.0.2.10" "dovecot" "1" "2"
	state_events_append "$INSTALL_PATH" "$((now - 3))" "192.0.2.10" "postfix" "1" "1"
	run events_ip "$INSTALL_PATH" "192.0.2.10"
	assert_success
	assert_output --partial "sshd"
	assert_output --partial "dovecot"
	assert_output --partial "postfix"
}

# --- events_cidr ---

@test "events_cidr: finds IPs in /24 range" {
	local now
	now=$(date +"%s")
	state_events_append "$INSTALL_PATH" "$((now - 1))" "192.0.2.10" "sshd" "1" "1"
	state_events_append "$INSTALL_PATH" "$((now - 2))" "192.0.2.20" "sshd" "1" "1"
	run events_cidr "$INSTALL_PATH" "192.0.2.0/24"
	assert_success
	assert_output --partial "192.0.2.10"
	assert_output --partial "192.0.2.20"
}

@test "events_cidr: excludes IPs outside range" {
	local now
	now=$(date +"%s")
	state_events_append "$INSTALL_PATH" "$((now - 1))" "192.0.2.10" "sshd" "1" "1"
	state_events_append "$INSTALL_PATH" "$((now - 2))" "198.51.100.5" "sshd" "1" "1"
	run events_cidr "$INSTALL_PATH" "192.0.2.0/24"
	assert_success
	assert_output --partial "192.0.2.10"
	refute_output --partial "198.51.100.5"
}

@test "events_cidr: shows pressure column" {
	local now
	now=$(date +"%s")
	state_events_append "$INSTALL_PATH" "$((now - 1))" "192.0.2.10" "sshd" "5" "3"
	run events_cidr "$INSTALL_PATH" "192.0.2.0/24"
	assert_success
	assert_output --partial "PRESSURE"
}

@test "events_cidr: shows BANNED status for banned IPs" {
	local now
	now=$(date +"%s")
	state_events_append "$INSTALL_PATH" "$((now - 1))" "192.0.2.10" "sshd" "1" "1"
	state_bans_active_append "$INSTALL_PATH" "$now" "0" "192.0.2.10" "sshd" "22"
	run events_cidr "$INSTALL_PATH" "192.0.2.0/24"
	assert_success
	assert_output --partial "BANNED"
}

@test "events_cidr: empty events shows message" {
	run events_cidr "$INSTALL_PATH" "192.0.2.0/24"
	assert_success
	assert_output --partial "No events found"
}

@test "events_cidr: no matching IPs shows message" {
	local now
	now=$(date +"%s")
	state_events_append "$INSTALL_PATH" "$((now - 1))" "198.51.100.5" "sshd" "1" "1"
	run events_cidr "$INSTALL_PATH" "192.0.2.0/24"
	assert_success
	assert_output --partial "No events found for 192.0.2.0/24"
}

@test "events_cidr: summary line with totals" {
	local now
	now=$(date +"%s")
	state_events_append "$INSTALL_PATH" "$((now - 1))" "192.0.2.10" "sshd" "3" "1"
	state_events_append "$INSTALL_PATH" "$((now - 2))" "192.0.2.20" "sshd" "2" "1"
	run events_cidr "$INSTALL_PATH" "192.0.2.0/24"
	assert_success
	assert_output --partial "2 IPs"
	assert_output --partial "5 events"
}

@test "events_cidr: invalid CIDR shows error" {
	run events_cidr "$INSTALL_PATH" "not-a-cidr"
	assert_failure
	assert_output --partial "error:"
}
