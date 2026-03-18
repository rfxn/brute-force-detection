#!/usr/bin/env bats
#
# Tests for shared event helpers: validate_cidr(), _pressure_aggregate_all(),
# _events_rule_log_file(), _resolve_trip(), _resolve_min_trip(), search_ip()
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

# Source _apool_ban_status from bfd (needed by search_ip)
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

# --- _pressure_aggregate_all ---

@test "_pressure_aggregate_all: returns scaled pressure for all IPs" {
	local now
	now=$(date +"%s")
	local events_file="$INSTALL_PATH/tmp/pressure.dat"
	# 3 events for one IP, 1 event for another
	state_pressure_append "$INSTALL_PATH" "$((now - 1))" "192.0.2.10" "sshd" "3" "2"
	state_pressure_append "$INSTALL_PATH" "$((now - 2))" "198.51.100.5" "dovecot" "1" "1"
	run _pressure_aggregate_all "$events_file" "$now" "300"
	assert_success
	# first line should be the higher-pressure IP (192.0.2.10 with weight=2, count=3)
	assert_line --index 0 --regexp '^[0-9]+ 192\.0\.2\.10$'
	# second line should be the lower-pressure IP
	assert_line --index 1 --regexp '^[0-9]+ 198\.51\.100\.5$'
}

# --- _events_rule_log_file ---

@test "_events_rule_log_file: extracts LOG_FILE from rule" {
	RULES_PATH="$INSTALL_PATH/rules"
	mkdir -p "$RULES_PATH"
	cat > "$RULES_PATH/testrule" <<'RULE'
PREREQ=""
LOG_FILE="/var/log/test.log"
LOG_TAG="test"
RULE
	chown root "$RULES_PATH/testrule"
	chmod 644 "$RULES_PATH/testrule"
	run _events_rule_log_file "testrule"
	assert_success
	assert_output "/var/log/test.log"
}

@test "_events_rule_log_file: returns failure for missing rule" {
	RULES_PATH="$INSTALL_PATH/rules"
	mkdir -p "$RULES_PATH"
	run _events_rule_log_file "nonexistent"
	assert_failure
}

# --- Per-rule pressure trip threshold display ---

@test "_resolve_trip: returns per-rule trip when set" {
	bfd_require_bash42
	_PRESS_TRIP=([sshd]="10" [dovecot]="30")
	run _resolve_trip "sshd"
	assert_success
	assert_output "10"
}

@test "_resolve_trip: falls back to GLOB_PRESSURE_TRIP when unset" {
	bfd_require_bash42
	_PRESS_TRIP=([dovecot]="30")
	GLOB_PRESSURE_TRIP="50"
	run _resolve_trip "sshd"
	assert_success
	assert_output "50"
}

@test "_resolve_min_trip: returns minimum across multiple services" {
	bfd_require_bash42
	_PRESS_TRIP=([sshd]="15" [dovecot]="8" [postfix]="25")
	GLOB_PRESSURE_TRIP="20"
	run _resolve_min_trip "sshd,dovecot,postfix"
	assert_success
	assert_output "8"
}

@test "_resolve_min_trip: uses global fallback for unknown services" {
	bfd_require_bash42
	_PRESS_TRIP=([sshd]="30")
	GLOB_PRESSURE_TRIP="10"
	run _resolve_min_trip "sshd,unknown_svc"
	assert_success
	assert_output "10"
}

@test "_resolve_min_trip: all unknown returns global" {
	_PRESS_TRIP=()
	GLOB_PRESSURE_TRIP="42"
	run _resolve_min_trip "foo,bar"
	assert_success
	assert_output "42"
}

@test "search_ip: per-service pressure shows per-rule trip" {
	bfd_require_bash42
	_PRESS_TRIP=([sshd]="8")
	GLOB_PRESSURE_TRIP="20"
	local now
	now=$(date +"%s")
	state_pressure_append "$INSTALL_PATH" "$((now - 1))" "192.0.2.10" "sshd" "1" "5"
	run search_ip "$INSTALL_PATH" "192.0.2.10"
	assert_success
	# overall pressure line uses min-trip from services
	assert_output --partial "/8"
	# per-service pressure line uses per-rule trip
	assert_output --regexp "sshd:.*\/8"
}

# --- _events_ip_awk (F-A03: mawk-compatible) ---

@test "_events_ip_awk: returns per-service and summary output for populated events (F-A03)" {
	local now
	now=$(date +"%s")
	local events_file="$INSTALL_PATH/tmp/pressure.dat"
	state_pressure_append "$INSTALL_PATH" "$((now - 10))" "192.0.2.50" "sshd" "3" "2"
	state_pressure_append "$INSTALL_PATH" "$((now - 5))" "192.0.2.50" "dovecot" "1" "1"
	run _events_ip_awk "$events_file" "192.0.2.50" "$now" "300"
	assert_success
	# should have S| lines for both services and an H| summary
	assert_output --partial "S|"
	assert_output --partial "H|"
}

@test "_events_ip_awk: returns empty output for unknown IP (F-A03)" {
	local now
	now=$(date +"%s")
	local events_file="$INSTALL_PATH/tmp/pressure.dat"
	state_pressure_append "$INSTALL_PATH" "$((now - 10))" "192.0.2.50" "sshd" "1" "1"
	run _events_ip_awk "$events_file" "198.51.100.99" "$now" "300"
	assert_success
	assert_output ""
}
