#!/usr/bin/env bats
#
# Tests for JSON/CSV structured output: events_dashboard, events_ip,
# events_cidr, search_ip, and apool_list structured variants.
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

# Source apool functions from bfd (needed by structured output tests)
bfd_load_function _apool_ban_status
bfd_load_function _apool_awk
bfd_load_function _apool_report_json
bfd_load_function _apool_report_csv
bfd_load_function _apool_service_summary_awk
bfd_load_function _apool_service_summary_json
bfd_load_function _apool_service_summary_csv
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

# --- events_dashboard_json ---

@test "events_dashboard_json: empty events returns empty array" {
	run events_dashboard_json "$INSTALL_PATH"
	assert_success
	assert_output "[]"
}

@test "events_dashboard_json: single IP has correct fields" {
	local now
	now=$(date +"%s")
	state_events_append "$INSTALL_PATH" "$((now - 1))" "192.0.2.10" "sshd" "5" "3"
	run events_dashboard_json "$INSTALL_PATH"
	assert_success
	assert_output --partial '"ip": "192.0.2.10"'
	assert_output --partial '"pressure":'
	assert_output --partial '"pressure_trip": 20'
	assert_output --partial '"count": 5'
	assert_output --partial '"services": ["sshd"]'
	assert_output --partial '"first_seen":'
	assert_output --partial '"last_seen":'
	assert_output --partial '"status":'
}

@test "events_dashboard_json: pressure is numeric (not quoted)" {
	local now
	now=$(date +"%s")
	state_events_append "$INSTALL_PATH" "$((now - 1))" "192.0.2.10" "sshd" "1" "3"
	run events_dashboard_json "$INSTALL_PATH"
	assert_success
	# pressure value should NOT be in quotes — look for "pressure": followed by digit
	echo "$output" | grep -qE '"pressure": [0-9]'
}

@test "events_dashboard_json: multiple services as array" {
	local now
	now=$(date +"%s")
	state_events_append "$INSTALL_PATH" "$((now - 1))" "192.0.2.10" "sshd" "1" "3"
	state_events_append "$INSTALL_PATH" "$((now - 2))" "192.0.2.10" "dovecot" "1" "2"
	run events_dashboard_json "$INSTALL_PATH"
	assert_success
	assert_output --partial '"sshd"'
	assert_output --partial '"dovecot"'
}

@test "events_dashboard_json: banned IP shows BANNED status" {
	local now
	now=$(date +"%s")
	state_events_append "$INSTALL_PATH" "$((now - 1))" "192.0.2.10" "sshd" "1" "3"
	state_bans_active_append "$INSTALL_PATH" "$now" "0" "192.0.2.10" "sshd" "22"
	run events_dashboard_json "$INSTALL_PATH"
	assert_success
	assert_output --partial "BANNED"
}

# --- events_dashboard_csv ---

@test "events_dashboard_csv: header present" {
	run events_dashboard_csv "$INSTALL_PATH"
	assert_success
	assert_output --partial "ip,pressure,pressure_trip,count,services,first_seen,last_seen,status"
}

@test "events_dashboard_csv: empty returns header only" {
	run events_dashboard_csv "$INSTALL_PATH"
	assert_success
	[ "$(echo "$output" | wc -l)" -eq 1 ]
}

@test "events_dashboard_csv: data rows present" {
	local now
	now=$(date +"%s")
	state_events_append "$INSTALL_PATH" "$((now - 1))" "192.0.2.10" "sshd" "1" "3"
	run events_dashboard_csv "$INSTALL_PATH"
	assert_success
	assert_output --partial "192.0.2.10"
	# header + 1 data row
	[ "$(echo "$output" | wc -l)" -eq 2 ]
}

# --- events_ip_json ---

@test "events_ip_json: single object with service breakdown" {
	local now
	now=$(date +"%s")
	state_events_append "$INSTALL_PATH" "$((now - 1))" "192.0.2.10" "sshd" "3" "3"
	state_events_append "$INSTALL_PATH" "$((now - 2))" "192.0.2.10" "dovecot" "2" "2"
	run events_ip_json "$INSTALL_PATH" "192.0.2.10"
	assert_success
	assert_output --partial '"ip": "192.0.2.10"'
	assert_output --partial '"half_life": 300'
	assert_output --partial '"pressure_trip": 20'
	assert_output --partial '"service": "sshd"'
	assert_output --partial '"service": "dovecot"'
}

@test "events_ip_json: no events returns zero pressure" {
	run events_ip_json "$INSTALL_PATH" "192.0.2.99"
	assert_success
	assert_output --partial '"pressure": 0.0'
	assert_output --partial '"services": []'
}

@test "events_ip_json: invalid IP returns error" {
	run events_ip_json "$INSTALL_PATH" "not-an-ip"
	assert_failure
	assert_output --partial "error:"
}

@test "events_ip_json: has pressure_trip and half_life fields" {
	local now
	now=$(date +"%s")
	state_events_append "$INSTALL_PATH" "$((now - 1))" "192.0.2.10" "sshd" "1" "3"
	run events_ip_json "$INSTALL_PATH" "192.0.2.10"
	assert_success
	assert_output --partial '"pressure_trip":'
	assert_output --partial '"half_life":'
}

# --- events_ip_csv ---

@test "events_ip_csv: header present" {
	run events_ip_csv "$INSTALL_PATH" "192.0.2.10"
	assert_success
	assert_output --partial "ip,pressure,pressure_trip,half_life,service,weight,count,service_pressure,first_seen,last_seen,status"
}

@test "events_ip_csv: one row per service" {
	local now
	now=$(date +"%s")
	state_events_append "$INSTALL_PATH" "$((now - 1))" "192.0.2.10" "sshd" "3" "3"
	state_events_append "$INSTALL_PATH" "$((now - 2))" "192.0.2.10" "dovecot" "2" "2"
	run events_ip_csv "$INSTALL_PATH" "192.0.2.10"
	assert_success
	# header + 2 service rows
	[ "$(echo "$output" | wc -l)" -eq 3 ]
}

@test "events_ip_csv: empty returns header only" {
	run events_ip_csv "$INSTALL_PATH" "192.0.2.99"
	assert_success
	[ "$(echo "$output" | wc -l)" -eq 1 ]
}

# --- events_cidr_json ---

@test "events_cidr_json: structure has cidr, summary, ips" {
	local now
	now=$(date +"%s")
	state_events_append "$INSTALL_PATH" "$((now - 1))" "192.0.2.10" "sshd" "1" "1"
	run events_cidr_json "$INSTALL_PATH" "192.0.2.0/24"
	assert_success
	assert_output --partial '"cidr": "192.0.2.0/24"'
	assert_output --partial '"summary":'
	assert_output --partial '"ips":'
}

@test "events_cidr_json: empty events returns empty ips" {
	run events_cidr_json "$INSTALL_PATH" "192.0.2.0/24"
	assert_success
	assert_output --partial '"match_count": 0'
	assert_output --partial '"ips": []'
}

@test "events_cidr_json: summary fields correct" {
	local now
	now=$(date +"%s")
	state_events_append "$INSTALL_PATH" "$((now - 1))" "192.0.2.10" "sshd" "3" "1"
	state_events_append "$INSTALL_PATH" "$((now - 2))" "192.0.2.20" "sshd" "2" "1"
	run events_cidr_json "$INSTALL_PATH" "192.0.2.0/24"
	assert_success
	assert_output --partial '"match_count": 2'
	assert_output --partial '"total_count": 5'
}

@test "events_cidr_json: invalid CIDR returns error" {
	run events_cidr_json "$INSTALL_PATH" "not-a-cidr"
	assert_failure
	assert_output --partial "error:"
}

# --- events_cidr_csv ---

@test "events_cidr_csv: header present" {
	run events_cidr_csv "$INSTALL_PATH" "192.0.2.0/24"
	assert_success
	assert_output --partial "ip,pressure,pressure_trip,count,services,first_seen,last_seen,status"
}

@test "events_cidr_csv: data rows present" {
	local now
	now=$(date +"%s")
	state_events_append "$INSTALL_PATH" "$((now - 1))" "192.0.2.10" "sshd" "1" "1"
	run events_cidr_csv "$INSTALL_PATH" "192.0.2.0/24"
	assert_success
	assert_output --partial "192.0.2.10"
	[ "$(echo "$output" | wc -l)" -eq 2 ]
}

# --- search_ip_json ---

@test "search_ip_json: all fields present" {
	local now
	now=$(date +"%s")
	state_events_append "$INSTALL_PATH" "$now" "192.0.2.10" "sshd" "1" "3"
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

# --- _apool_service_summary_json ---

@test "_apool_service_summary_json: formats service breakdown" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	echo "1000 192.0.2.1 sshd" >> "$pool"
	echo "1001 192.0.2.2 sshd" >> "$pool"
	echo "1002 192.0.2.1 dovecot" >> "$pool"
	run _apool_service_summary_json "$pool"
	assert_success
	assert_output --partial '"service": "sshd"'
	assert_output --partial '"count": 2'
	assert_output --partial '"unique_ips": 2'
}

# --- _apool_service_summary_csv ---

@test "_apool_service_summary_csv: header and data" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	echo "1000 192.0.2.1 sshd" >> "$pool"
	run _apool_service_summary_csv "$pool"
	assert_success
	assert_output --partial "service,count,unique_ips"
	assert_output --partial "sshd,1,1"
}

# --- apool_list_json ---

@test "apool_list_json: empty pool returns valid structure" {
	APOOL_LIST="$INSTALL_PATH/stats/attack.pool"
	> "$APOOL_LIST"
	run apool_list_json
	assert_success
	# pool file exists but empty: still outputs full JSON structure
	assert_output --partial '"last_24h":'
	assert_output --partial '"services":'
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

# --- events_cidr_json: temp file cleanup ---

@test "events_cidr_json: no PID temp files left after call" {
	local now
	now=$(date +"%s")
	state_events_append "$INSTALL_PATH" "$((now - 1))" "192.0.2.10" "sshd" "1" "1"
	events_cidr_json "$INSTALL_PATH" "192.0.2.0/24" >/dev/null 2>&1
	# verify no .cidr_json_summary.$$ or .cidr_json_ips.$$ files remain
	local leftover
	leftover=$(find "$INSTALL_PATH/tmp" -name '.cidr_json_summary.*' -o -name '.cidr_json_ips.*' 2>/dev/null | wc -l)
	[ "$leftover" -eq 0 ]
}
