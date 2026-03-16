#!/usr/bin/env bats
#
# Tests for JSON/CSV structured output: events_list_json/csv,
# events_list_ip_json/csv, events_list_cidr_json/csv
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

# Source apool functions from bfd (needed by events_list functions)
bfd_load_function _apool_ban_status
bfd_load_function _apool_awk
bfd_load_function _batch_ban_status_init
bfd_load_function _batch_ban_status_lookup
bfd_load_function _batch_ban_status_cleanup

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

# Helper: seed attack.pool
_seed_pool() {
	local pool="$INSTALL_PATH/stats/attack.pool"
	local now
	now=$(date +"%s")
	echo "$((now - 100)) 192.0.2.10 sshd 10 RU ban 600 22 30000 service" >> "$pool"
	echo "$((now - 200)) 192.0.2.20 dovecot 5 US observed 0 143 8000 -" >> "$pool"
}

# --- events_list_json ---

@test "events_list_json: empty pool returns empty array" {
	run events_list_json "$INSTALL_PATH"
	assert_success
	assert_output "[]"
}

@test "events_list_json: has correct fields" {
	_seed_pool
	run events_list_json "$INSTALL_PATH"
	assert_success
	assert_output --partial '"ip":'
	assert_output --partial '"count":'
	assert_output --partial '"services":'
	assert_output --partial '"country":'
	assert_output --partial '"first_seen":'
	assert_output --partial '"last_seen":'
	assert_output --partial '"status":'
}

@test "events_list_json: services is JSON array" {
	_seed_pool
	run events_list_json "$INSTALL_PATH"
	assert_success
	assert_output --partial '["sshd"]'
}

@test "events_list_json: banned IP shows BANNED status" {
	local now pool
	now=$(date +"%s")
	pool="$INSTALL_PATH/stats/attack.pool"
	echo "$now 192.0.2.10 sshd 5 RU ban 600 22 15000 service" >> "$pool"
	state_bans_active_append "$INSTALL_PATH" "$now" "0" "192.0.2.10" "sshd" "22"
	run events_list_json "$INSTALL_PATH"
	assert_success
	assert_output --partial "BANNED"
}

@test "events_list_json: count is numeric" {
	_seed_pool
	run events_list_json "$INSTALL_PATH"
	assert_success
	echo "$output" | grep -qE '"count": [0-9]'
}

# --- events_list_csv ---

@test "events_list_csv: header present" {
	run events_list_csv "$INSTALL_PATH"
	assert_success
	assert_output --partial "ip,count,services,country,first_seen,last_seen,status"
}

@test "events_list_csv: empty pool returns header only" {
	run events_list_csv "$INSTALL_PATH"
	assert_success
	[ "$(echo "$output" | wc -l)" -eq 1 ]
}

@test "events_list_csv: data rows present" {
	_seed_pool
	run events_list_csv "$INSTALL_PATH"
	assert_success
	assert_output --partial "192.0.2.10"
	# header + 2 data rows
	[ "$(echo "$output" | wc -l)" -eq 3 ]
}

# --- events_list_ip_json ---

@test "events_list_ip_json: zero-state for unknown IP" {
	run events_list_ip_json "$INSTALL_PATH" "192.0.2.99"
	assert_success
	assert_output --partial '"total_failures": 0'
	assert_output --partial '"services": []'
	assert_output --partial '"pressure": 0.0'
	assert_output --partial '"log_sample": []'
}

@test "events_list_ip_json: invalid IP returns error" {
	run events_list_ip_json "$INSTALL_PATH" "not-an-ip"
	assert_failure
	assert_output --partial "error:"
}

@test "events_list_ip_json: has all expected fields" {
	_seed_pool
	run events_list_ip_json "$INSTALL_PATH" "192.0.2.10"
	assert_success
	assert_output --partial '"ip": "192.0.2.10"'
	assert_output --partial '"country": "RU"'
	assert_output --partial '"total_failures": 10'
	assert_output --partial '"ban_triggers": 1'
	assert_output --partial '"services":'
	assert_output --partial '"pressure":'
	assert_output --partial '"pressure_trip":'
	assert_output --partial '"half_life":'
	assert_output --partial '"log_sample":'
}

@test "events_list_ip_json: services array has per-service detail" {
	_seed_pool
	run events_list_ip_json "$INSTALL_PATH" "192.0.2.10"
	assert_success
	assert_output --partial '"service": "sshd"'
	assert_output --partial '"count": 10'
	assert_output --partial '"first_seen":'
	assert_output --partial '"last_seen":'
}

@test "events_list_ip_json: banned IP shows status" {
	local now pool
	now=$(date +"%s")
	pool="$INSTALL_PATH/stats/attack.pool"
	echo "$now 192.0.2.10 sshd 5 RU ban 600 22 15000 service" >> "$pool"
	state_bans_active_append "$INSTALL_PATH" "$now" "0" "192.0.2.10" "sshd" "22"
	run events_list_ip_json "$INSTALL_PATH" "192.0.2.10"
	assert_success
	assert_output --partial "BANNED"
}

# --- events_list_ip_csv ---

@test "events_list_ip_csv: header present" {
	run events_list_ip_csv "$INSTALL_PATH" "192.0.2.10"
	assert_success
	assert_output --partial "ip,total_failures,ban_triggers,country,service,count,first_seen,last_seen,status"
}

@test "events_list_ip_csv: empty returns header only" {
	run events_list_ip_csv "$INSTALL_PATH" "192.0.2.99"
	assert_success
	[ "$(echo "$output" | wc -l)" -eq 1 ]
}

@test "events_list_ip_csv: one row per service" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	local now
	now=$(date +"%s")
	echo "$now 192.0.2.10 sshd 5 RU ban 600 22 15000 service" >> "$pool"
	echo "$((now - 100)) 192.0.2.10 dovecot 3 RU observed 0 143 5000 -" >> "$pool"
	run events_list_ip_csv "$INSTALL_PATH" "192.0.2.10"
	assert_success
	# header + 2 service rows
	[ "$(echo "$output" | wc -l)" -eq 3 ]
}

@test "events_list_ip_csv: invalid IP returns error" {
	run events_list_ip_csv "$INSTALL_PATH" "not-an-ip"
	assert_failure
	assert_output --partial "error:"
}

# --- events_list_cidr_json ---

@test "events_list_cidr_json: structure has cidr, summary, ips" {
	_seed_pool
	run events_list_cidr_json "$INSTALL_PATH" "192.0.2.0/24"
	assert_success
	assert_output --partial '"cidr": "192.0.2.0/24"'
	assert_output --partial '"summary":'
	assert_output --partial '"ips":'
}

@test "events_list_cidr_json: empty pool returns empty ips" {
	run events_list_cidr_json "$INSTALL_PATH" "192.0.2.0/24"
	assert_success
	assert_output --partial '"match_count": 0'
	assert_output --partial '"ips": []'
}

@test "events_list_cidr_json: summary fields correct" {
	_seed_pool
	run events_list_cidr_json "$INSTALL_PATH" "192.0.2.0/24"
	assert_success
	assert_output --partial '"match_count": 2'
	assert_output --partial '"total_count": 15'
}

@test "events_list_cidr_json: invalid CIDR returns error" {
	run events_list_cidr_json "$INSTALL_PATH" "not-a-cidr"
	assert_failure
	assert_output --partial "error:"
}

# --- events_list_cidr_csv ---

@test "events_list_cidr_csv: header present" {
	run events_list_cidr_csv "$INSTALL_PATH" "192.0.2.0/24"
	assert_success
	assert_output --partial "ip,count,services,country,first_seen,last_seen,status"
}

@test "events_list_cidr_csv: data rows present" {
	_seed_pool
	run events_list_cidr_csv "$INSTALL_PATH" "192.0.2.0/24"
	assert_success
	assert_output --partial "192.0.2.10"
	[ "$(echo "$output" | wc -l)" -eq 3 ]
}

@test "events_list_cidr_csv: excludes non-matching IPs" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	local now
	now=$(date +"%s")
	echo "$now 192.0.2.10 sshd 5 US ban 600 22 15000 service" >> "$pool"
	echo "$now 198.51.100.5 sshd 3 RU observed 0 22 5000 -" >> "$pool"
	run events_list_cidr_csv "$INSTALL_PATH" "192.0.2.0/24"
	assert_success
	assert_output --partial "192.0.2.10"
	refute_output --partial "198.51.100.5"
}

# --- JSON/CSV limit tests ---

@test "events_list_json: respects limit parameter" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	local now
	now=$(date +"%s")
	local i
	for i in $(seq 1 20); do
		echo "$now 192.0.2.$i sshd 1 -- observed 0 22 1000 -" >> "$pool"
	done
	run events_list_json "$INSTALL_PATH" "count" "5"
	assert_success
	# Count JSON objects (lines with "ip":)
	local ip_count
	ip_count=$(echo "$output" | grep -c '"ip":')
	[ "$ip_count" -eq 5 ]
}

@test "events_list_json: limit=0 returns all entries" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	local now
	now=$(date +"%s")
	local i
	for i in $(seq 1 30); do
		echo "$now 192.0.2.$i sshd 1 -- observed 0 22 1000 -" >> "$pool"
	done
	run events_list_json "$INSTALL_PATH" "count" "0"
	assert_success
	local ip_count
	ip_count=$(echo "$output" | grep -c '"ip":')
	[ "$ip_count" -eq 30 ]
}

@test "events_list_csv: respects limit parameter" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	local now
	now=$(date +"%s")
	local i
	for i in $(seq 1 20); do
		echo "$now 192.0.2.$i sshd 1 -- observed 0 22 1000 -" >> "$pool"
	done
	run events_list_csv "$INSTALL_PATH" "count" "5"
	assert_success
	# Header + 5 data rows = 6 lines
	[ "$(echo "$output" | wc -l)" -eq 6 ]
}

@test "events_list_csv: limit=0 returns all entries" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	local now
	now=$(date +"%s")
	local i
	for i in $(seq 1 30); do
		echo "$now 192.0.2.$i sshd 1 -- observed 0 22 1000 -" >> "$pool"
	done
	run events_list_csv "$INSTALL_PATH" "count" "0"
	assert_success
	# Header + 30 data rows = 31 lines
	[ "$(echo "$output" | wc -l)" -eq 31 ]
}

@test "events_list_cidr_json: respects limit parameter" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	local now
	now=$(date +"%s")
	local i
	for i in $(seq 1 20); do
		echo "$now 192.0.2.$i sshd 1 -- observed 0 22 1000 -" >> "$pool"
	done
	run events_list_cidr_json "$INSTALL_PATH" "192.0.2.0/24" "count" "5"
	assert_success
	local ip_count
	ip_count=$(echo "$output" | grep -c '"ip":')
	[ "$ip_count" -eq 5 ]
	assert_output --partial '"truncated": true'
}

@test "events_list_cidr_json: truncated false when within limit" {
	_seed_pool
	run events_list_cidr_json "$INSTALL_PATH" "192.0.2.0/24" "count" "100"
	assert_success
	assert_output --partial '"truncated": false'
}

@test "events_list_cidr_csv: respects limit parameter" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	local now
	now=$(date +"%s")
	local i
	for i in $(seq 1 20); do
		echo "$now 192.0.2.$i sshd 1 -- observed 0 22 1000 -" >> "$pool"
	done
	run events_list_cidr_csv "$INSTALL_PATH" "192.0.2.0/24" "count" "5"
	assert_success
	# Header + 5 data rows = 6 lines
	[ "$(echo "$output" | wc -l)" -eq 6 ]
}
