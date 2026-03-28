#!/usr/bin/env bats
#
# Tests for JSON/CSV structured output: search_ip and apool_list
# structured variants.
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

# Source apool functions from bfd (needed by structured output tests)
bfd_load_function _apool_ban_status
bfd_load_function _apool_awk
bfd_load_function _apool_report_json
bfd_load_function _apool_report_csv
bfd_load_function _apool_summary_awk
bfd_load_function _apool_summary_json
bfd_load_function _apool_summary_csv
bfd_load_function _apool_service_dual_awk
bfd_load_function _apool_service_dual_json
bfd_load_function _apool_service_dual_csv
bfd_load_function apool_list_json
bfd_load_function apool_list_csv

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

# --- _json_array_from_csv ---

@test "_json_array_from_csv: single item" {
	run _json_array_from_csv "sshd"
	assert_success
	assert_output '["sshd"]'
}

@test "_json_array_from_csv: multiple items" {
	run _json_array_from_csv "sshd,dovecot,postfix"
	assert_success
	assert_output '["sshd","dovecot","postfix"]'
}

@test "_json_array_from_csv: empty string" {
	run _json_array_from_csv ""
	assert_success
	assert_output "[]"
}

# --- search_ip_json ---

@test "search_ip_json: all fields present" {
	local now
	now=$(date +"%s")
	state_pressure_append "$INSTALL_PATH" "$now" "192.0.2.10" "sshd" "1" "3"
	run search_ip_json "$INSTALL_PATH" "192.0.2.10"
	assert_success
	assert_output --partial '"ip": "192.0.2.10"'
	assert_output --partial '"status":'
	assert_output --partial '"pressure":'
	assert_output --partial '"pressure_trip":'
	assert_output --partial '"ban_history_24h":'
	assert_output --partial '"ban_history_total":'
	assert_output --partial '"count_24h":'
	assert_output --partial '"services":'
	assert_output --partial '"attack_pool_triggers":'
	assert_output --partial '"attack_pool_failures":'
}

@test "search_ip_json: invalid IP returns error" {
	run search_ip_json "$INSTALL_PATH" "not-an-ip"
	assert_failure
	assert_output --partial "error:"
}

@test "search_ip_json: banned IP shows BANNED status" {
	local now
	now=$(date +"%s")
	state_bans_active_append "$INSTALL_PATH" "$now" "0" "192.0.2.10" "sshd" "22"
	run search_ip_json "$INSTALL_PATH" "192.0.2.10"
	assert_success
	assert_output --partial "BANNED"
}

# --- search_ip_csv ---

@test "search_ip_csv: header and single row" {
	run search_ip_csv "$INSTALL_PATH" "192.0.2.10"
	assert_success
	assert_output --partial "ip,status,pressure,pressure_trip,ban_history_24h,ban_history_total,count_24h,first_seen,last_seen,attack_pool_triggers,attack_pool_failures"
	[ "$(echo "$output" | wc -l)" -eq 2 ]
}

# --- _apool_report_json ---

@test "_apool_report_json: formats entries as JSON array with pressure and country" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	echo "1000 192.0.2.1 sshd" >> "$pool"
	echo "1001 192.0.2.1 sshd" >> "$pool"
	run _apool_report_json "$pool"
	assert_success
	assert_output --partial '"count": 2'
	assert_output --partial '"ip": "192.0.2.1"'
	assert_output --partial '"rules": ["sshd"]'
	assert_output --partial '"pressure":'
	assert_output --partial '"pressure_trip":'
	assert_output --partial '"country":'
}

@test "_apool_report_json: empty pool returns empty array" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	run _apool_report_json "$pool"
	assert_success
	# should contain [ and ] with nothing in between (just whitespace)
	local trimmed
	trimmed=$(echo "$output" | tr -d '[:space:]')
	[ "$trimmed" = "[]" ]
}

# --- _apool_report_csv ---

@test "_apool_report_csv: header includes pressure columns" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	echo "1000 192.0.2.1 sshd" >> "$pool"
	run _apool_report_csv "$pool"
	assert_success
	assert_output --partial "count,ip,pressure,pressure_trip,country,first_seen,last_seen,rules,status"
	assert_output --partial "192.0.2.1"
}

# --- apool_list_json ---

@test "apool_list_json: empty pool returns empty JSON object" {
	APOOL_LIST="$INSTALL_PATH/stats/attack.pool"
	> "$APOOL_LIST"
	run apool_list_json
	assert_success
	# empty pool file (zero-byte): apool_list_json falls through to else branch returning {}
	assert_output "{}"
}

@test "apool_list_json: has summary, last_24h, last_7d, services sections" {
	APOOL_LIST="$INSTALL_PATH/stats/attack.pool"
	local now
	now=$(date +"%s")
	echo "$now 192.0.2.1 sshd" >> "$APOOL_LIST"
	run apool_list_json
	assert_success
	assert_output --partial '"summary":'
	assert_output --partial '"last_24h":'
	assert_output --partial '"last_7d":'
	assert_output --partial '"services":'
}

@test "apool_list_json: search mode has search and results" {
	APOOL_LIST="$INSTALL_PATH/stats/attack.pool"
	echo "1000 192.0.2.1 sshd" >> "$APOOL_LIST"
	run apool_list_json "sshd"
	assert_success
	assert_output --partial '"search": "sshd"'
	assert_output --partial '"results":'
}

# --- apool_list_csv ---

@test "apool_list_csv: empty pool returns empty output" {
	APOOL_LIST="$INSTALL_PATH/stats/attack.pool"
	> "$APOOL_LIST"
	run apool_list_csv
	assert_success
	assert_output ""
}

@test "apool_list_csv: sections labeled with summary" {
	APOOL_LIST="$INSTALL_PATH/stats/attack.pool"
	local now
	now=$(date +"%s")
	echo "$now 192.0.2.1 sshd" >> "$APOOL_LIST"
	run apool_list_csv
	assert_success
	assert_output --partial "# summary"
	assert_output --partial "# last_24h"
	assert_output --partial "# last_7d"
	assert_output --partial "# services"
}

# --- dual-interval service JSON/CSV ---

@test "_apool_service_dual_json: expanded fields" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	local now
	now=$(date +"%s")
	echo "$now 192.0.2.1 sshd 5 RU ban 600 22 15000 service" >> "$pool"
	local cutoff_24h=$((now - 86400))
	local cutoff_7d=$((now - 604800))
	run _apool_service_dual_json "$pool" "$cutoff_24h" "$cutoff_7d"
	assert_success
	assert_output --partial '"service":'
	assert_output --partial '"count_24h":'
	assert_output --partial '"count_7d":'
	assert_output --partial '"unique_ips_24h":'
	assert_output --partial '"unique_ips_7d":'
	assert_output --partial '"top_country":'
}

@test "_apool_service_dual_csv: header and data" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	local now
	now=$(date +"%s")
	echo "$now 192.0.2.1 sshd 5 US ban 600 22 15000 service" >> "$pool"
	local cutoff_24h=$((now - 86400))
	local cutoff_7d=$((now - 604800))
	run _apool_service_dual_csv "$pool" "$cutoff_24h" "$cutoff_7d"
	assert_success
	assert_output --partial "service,count_24h,count_7d,unique_ips_24h,unique_ips_7d,top_country"
	assert_output --partial "sshd,"
}

@test "apool_list_json: summary has unique_ips and active_bans" {
	APOOL_LIST="$INSTALL_PATH/stats/attack.pool"
	local now
	now=$(date +"%s")
	echo "$now 192.0.2.1 sshd 5 US ban 600 22 15000 service" >> "$APOOL_LIST"
	run apool_list_json
	assert_success
	assert_output --partial '"unique_ips_24h":'
	assert_output --partial '"active_bans":'
}

@test "apool_list_csv: summary section has correct header" {
	APOOL_LIST="$INSTALL_PATH/stats/attack.pool"
	local now
	now=$(date +"%s")
	echo "$now 192.0.2.1 sshd" >> "$APOOL_LIST"
	run apool_list_csv
	assert_success
	assert_output --partial "unique_ips_24h,unique_ips_7d,total_count_24h,total_count_7d,active_bans"
}
