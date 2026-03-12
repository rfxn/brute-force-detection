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
bfd_load_function _apool_service_summary_awk
bfd_load_function _apool_service_summary
bfd_load_function _apool_summary_awk
bfd_load_function _apool_summary
bfd_load_function _apool_service_dual_awk
bfd_load_function _apool_service_dual
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
	assert_output --partial "Per-service threat breakdown"
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

@test "apool report: header includes PRESSURE and COUNTRY columns" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	echo "1000 192.0.2.1 sshd" >> "$pool"
	run _apool_report "$pool" "Test report"
	assert_success
	assert_output --partial "PRESSURE"
	assert_output --partial "COUNTRY"
}

@test "apool report: pressure value shown for IP with events" {
	local now
	now=$(date +"%s")
	local pool="$INSTALL_PATH/stats/attack.pool"
	echo "$now 192.0.2.1 sshd" >> "$pool"
	# create matching events so pressure_compute returns non-zero
	state_pressure_append "$INSTALL_PATH" "$((now - 1))" "192.0.2.1" "sshd" "5" "3"
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

@test "apool_list: absent pool file prints no-data message" {
	APOOL_LIST="$INSTALL_PATH/stats/attack.pool.nonexistent"
	run apool_list
	assert_success
	assert_output "No attack pool data."
}

@test "apool_list: empty pool file prints no-data message" {
	APOOL_LIST="$INSTALL_PATH/stats/attack.pool"
	> "$APOOL_LIST"
	run apool_list
	assert_success
	assert_output "No attack pool data."
}

@test "apool_list: pool with entries shows summary, 24h, 7d, then services" {
	APOOL_LIST="$INSTALL_PATH/stats/attack.pool"
	local now
	now=$(date +"%s")
	echo "$now 192.0.2.1 sshd" >> "$APOOL_LIST"
	echo "$((now - 1)) 192.0.2.2 dovecot" >> "$APOOL_LIST"
	run apool_list
	assert_success
	assert_output --partial "Threat Activity Summary"
	assert_output --partial "Top 25 threat IPs (24h)"
	assert_output --partial "Top 25 threat IPs (7d)"
	assert_output --partial "Per-service threat breakdown"
	# verify ordering: summary < 24h < 7d < services
	local ln_sum ln_24h ln_7d ln_svc
	ln_sum=$(echo "$output" | grep -n "Threat Activity Summary" | head -1 | cut -d: -f1)
	ln_24h=$(echo "$output" | grep -n "Top 25 threat IPs (24h)" | head -1 | cut -d: -f1)
	ln_7d=$(echo "$output" | grep -n "Top 25 threat IPs (7d)" | head -1 | cut -d: -f1)
	ln_svc=$(echo "$output" | grep -n "Per-service threat breakdown" | head -1 | cut -d: -f1)
	[ "$ln_sum" -lt "$ln_24h" ]
	[ "$ln_24h" -lt "$ln_7d" ]
	[ "$ln_7d" -lt "$ln_svc" ]
}

@test "apool_list: search filter shows filtered results" {
	APOOL_LIST="$INSTALL_PATH/stats/attack.pool"
	local now
	now=$(date +"%s")
	echo "$now 192.0.2.1 sshd" >> "$APOOL_LIST"
	echo "$((now - 1)) 192.0.2.2 dovecot" >> "$APOOL_LIST"
	run apool_list "sshd"
	assert_success
	assert_output --partial "Matching entries for"
	assert_output --partial "sshd"
}

# --- _apool_awk substring dedup ---

@test "_apool_awk: substring rules not falsely deduped (vsftpd vs vsftpd2)" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	echo "1000 192.0.2.1 vsftpd" >> "$pool"
	echo "1001 192.0.2.1 vsftpd2" >> "$pool"
	run _apool_awk "$pool"
	assert_success
	assert_output --partial "vsftpd,vsftpd2"
}

@test "_apool_awk: substring rules not falsely deduped (openvpn vs openvpnas)" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	echo "1000 192.0.2.1 openvpn" >> "$pool"
	echo "1001 192.0.2.1 openvpnas" >> "$pool"
	run _apool_awk "$pool"
	assert_success
	assert_output --partial "openvpn,openvpnas"
}

@test "_apool_awk: exact duplicate rules still deduped" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	echo "1000 192.0.2.1 sshd" >> "$pool"
	echo "1001 192.0.2.1 sshd" >> "$pool"
	echo "1002 192.0.2.1 dovecot" >> "$pool"
	run _apool_awk "$pool"
	assert_success
	# sshd should appear only once in the rules list
	local rules_field
	rules_field=$(echo "$output" | awk -F'|' '{print $5}')
	[ "$(echo "$rules_field" | grep -o 'sshd' | wc -l)" -eq 1 ]
}

@test "apool_list: no temp files created for timestamp-based views" {
	APOOL_LIST="$INSTALL_PATH/stats/attack.pool"
	local now
	now=$(date +"%s")
	echo "$now 192.0.2.1 sshd" >> "$APOOL_LIST"
	apool_list >/dev/null 2>&1
	# verify no leftover temp files from old weekly aggregation
	local leftover
	leftover=$(find "$INSTALL_PATH/tmp" -name '.weekly.apool.*' 2>/dev/null | wc -l)
	[ "$leftover" -eq 0 ]
}

# --- enriched format tests ---

@test "_apool_awk: sums count field from enriched entries" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	local now
	now=$(date +"%s")
	echo "$now 192.0.2.1 sshd 5 CN ban 600 22 15000 service" >> "$pool"
	echo "$((now + 1)) 192.0.2.1 sshd 3 CN ban 600 22 12000 service" >> "$pool"
	run _apool_awk "$pool"
	assert_success
	# total count should be 8 (5+3)
	assert_output --partial "8|192.0.2.1"
}

@test "_apool_awk: backward compat with 3-field entries" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	echo "1000 192.0.2.1 sshd" >> "$pool"
	echo "1001 192.0.2.1 sshd" >> "$pool"
	run _apool_awk "$pool"
	assert_success
	# 3-field entries default COUNT=1, so 2 lines = count 2
	assert_output --partial "2|192.0.2.1"
}

@test "_apool_awk: extracts country code from enriched entries" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	local now
	now=$(date +"%s")
	echo "$now 192.0.2.1 sshd 5 RU ban 600 22 15000 service" >> "$pool"
	run _apool_awk "$pool"
	assert_success
	# 6th pipe-delimited field should be country code
	local cc_field
	cc_field=$(echo "$output" | awk -F'|' '{print $6}')
	[ "$cc_field" = "RU" ]
}

@test "_apool_report: COUNTRY column present in output" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	local now
	now=$(date +"%s")
	echo "$now 192.0.2.1 sshd 5 DE ban 600 22 15000 service" >> "$pool"
	run _apool_report "$pool" "Test report"
	assert_success
	assert_output --partial "DE"
}

@test "_apool_awk: cutoff filters old entries" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	local now
	now=$(date +"%s")
	echo "$((now - 200)) 192.0.2.1 sshd" >> "$pool"
	echo "$now 192.0.2.2 sshd" >> "$pool"
	# cutoff at now - 100: should exclude 192.0.2.1
	run _apool_awk "$pool" "" "$((now - 100))"
	assert_success
	assert_output --partial "192.0.2.2"
	refute_output --partial "192.0.2.1"
}

@test "state_pool_prune: removes old entries" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	local now
	now=$(date +"%s")
	# write entries: one old (400 days), one recent
	echo "$((now - 34560000)) 192.0.2.1 sshd" >> "$pool"
	echo "$now 192.0.2.2 sshd" >> "$pool"
	state_pool_prune "$INSTALL_PATH" "365" "500000"
	local content
	content=$(cat "$pool")
	echo "$content" | grep -qF "192.0.2.2"
	! echo "$content" | grep -qF "192.0.2.1"
}

@test "state_pool_prune: respects max_lines cap" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	local now
	now=$(date +"%s")
	local i
	for i in $(seq 1 10); do
		echo "$((now - i)) 192.0.2.$i sshd" >> "$pool"
	done
	# cap at 3 lines
	state_pool_prune "$INSTALL_PATH" "0" "3"
	local line_count
	line_count=$(wc -l < "$pool")
	[ "$line_count" -eq 3 ]
}

# --- summary header ---

@test "summary_awk: counts unique IPs and totals for 24h and 7d" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	local now
	now=$(date +"%s")
	# 3 entries in 24h window, 1 additional in 7d-only window
	echo "$now 192.0.2.1 sshd 5 CN ban 600 22 15000 service" >> "$pool"
	echo "$((now - 100)) 192.0.2.2 sshd 3 US ban 600 22 12000 service" >> "$pool"
	echo "$((now - 200)) 192.0.2.1 dovecot 2 CN ban 600 143 8000 service" >> "$pool"
	echo "$((now - 172800)) 192.0.2.3 sshd 10 RU ban 600 22 20000 service" >> "$pool"
	local cutoff_24h=$((now - 86400))
	local cutoff_7d=$((now - 604800))
	run _apool_summary_awk "$pool" "$cutoff_24h" "$cutoff_7d"
	assert_success
	# 24h: 2 unique IPs (192.0.2.1, 192.0.2.2), total 10 (5+3+2)
	# 7d: 3 unique IPs, total 20 (5+3+2+10)
	IFS='|' read -r u24 t24 u7d t7d <<< "$output"
	[ "$u24" -eq 2 ]
	[ "$t24" -eq 10 ]
	[ "$u7d" -eq 3 ]
	[ "$t7d" -eq 20 ]
}

@test "summary: text output contains header and stats" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	local now
	now=$(date +"%s")
	echo "$now 192.0.2.1 sshd 5 CN ban 600 22 15000 service" >> "$pool"
	local cutoff_24h=$((now - 86400))
	local cutoff_7d=$((now - 604800))
	run _apool_summary "$pool" "$cutoff_24h" "$cutoff_7d"
	assert_success
	assert_output --partial "Threat Activity Summary"
	assert_output --partial "Unique IPs:"
	assert_output --partial "Total Count:"
	assert_output --partial "Active Bans:"
}

@test "summary: active bans count reflects bans.active" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	local now
	now=$(date +"%s")
	echo "$now 192.0.2.1 sshd" >> "$pool"
	state_bans_active_append "$INSTALL_PATH" "$now" "0" "192.0.2.1" "sshd" "22"
	state_bans_active_append "$INSTALL_PATH" "$now" "0" "192.0.2.2" "sshd" "22"
	local cutoff_24h=$((now - 86400))
	local cutoff_7d=$((now - 604800))
	run _apool_summary "$pool" "$cutoff_24h" "$cutoff_7d"
	assert_success
	assert_output --partial "Active Bans:  2"
}

@test "summary: empty pool shows zeroes" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	local now
	now=$(date +"%s")
	local cutoff_24h=$((now - 86400))
	local cutoff_7d=$((now - 604800))
	run _apool_summary "$pool" "$cutoff_24h" "$cutoff_7d"
	assert_success
	assert_output --partial "Unique IPs:   0 (24h) / 0 (7d)"
	assert_output --partial "Total Count:  0 (24h) / 0 (7d)"
	assert_output --partial "Active Bans:  0"
}

@test "apool_list: shows summary header before IP tables" {
	APOOL_LIST="$INSTALL_PATH/stats/attack.pool"
	local now
	now=$(date +"%s")
	echo "$now 192.0.2.1 sshd" >> "$APOOL_LIST"
	run apool_list
	assert_success
	assert_output --partial "Threat Activity Summary"
	# summary should appear before the first IP table
	local summary_line ip_table_line
	summary_line=$(echo "$output" | grep -n "Threat Activity Summary" | head -1 | cut -d: -f1)
	ip_table_line=$(echo "$output" | grep -n "Top 25 threat IPs" | head -1 | cut -d: -f1)
	[ "$summary_line" -lt "$ip_table_line" ]
}

# --- dual-interval per-service breakdown ---

@test "service_dual_awk: dual-interval counts for single service" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	local now
	now=$(date +"%s")
	# 2 entries in 24h, 1 additional in 7d-only window
	echo "$now 192.0.2.1 sshd 5 RU ban 600 22 15000 service" >> "$pool"
	echo "$((now - 100)) 192.0.2.2 sshd 3 US ban 600 22 12000 service" >> "$pool"
	echo "$((now - 172800)) 192.0.2.3 sshd 10 RU ban 600 22 20000 service" >> "$pool"
	local cutoff_24h=$((now - 86400))
	local cutoff_7d=$((now - 604800))
	run _apool_service_dual_awk "$pool" "$cutoff_24h" "$cutoff_7d"
	assert_success
	# sshd: 24h count=8(5+3), 7d count=18(5+3+10), 24h IPs=2, 7d IPs=3, top_cc=RU
	IFS='|' read -r svc c24 c7d u24 u7d top_cc <<< "$output"
	[ "$svc" = "sshd" ]
	[ "$c24" -eq 8 ]
	[ "$c7d" -eq 18 ]
	[ "$u24" -eq 2 ]
	[ "$u7d" -eq 3 ]
	[ "$top_cc" = "RU" ]
}

@test "service_dual_awk: multiple services with top country" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	local now
	now=$(date +"%s")
	echo "$now 192.0.2.1 sshd 5 RU ban 600 22 15000 service" >> "$pool"
	echo "$now 192.0.2.2 dovecot 3 CN ban 600 143 12000 service" >> "$pool"
	echo "$now 192.0.2.3 dovecot 2 CN ban 600 143 8000 service" >> "$pool"
	local cutoff_24h=$((now - 86400))
	local cutoff_7d=$((now - 604800))
	run _apool_service_dual_awk "$pool" "$cutoff_24h" "$cutoff_7d"
	assert_success
	# dovecot should have top_cc=CN (both entries are CN)
	local dovecot_line
	dovecot_line=$(echo "$output" | grep "^dovecot|")
	local dovecot_cc
	dovecot_cc=$(echo "$dovecot_line" | awk -F'|' '{print $6}')
	[ "$dovecot_cc" = "CN" ]
}

@test "service_dual: text output shows header and columns" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	local now
	now=$(date +"%s")
	echo "$now 192.0.2.1 sshd 5 RU ban 600 22 15000 service" >> "$pool"
	local cutoff_24h=$((now - 86400))
	local cutoff_7d=$((now - 604800))
	run _apool_service_dual "$pool" "$cutoff_24h" "$cutoff_7d"
	assert_success
	assert_output --partial "Per-service threat breakdown (24h / 7d)"
	assert_output --partial "24H_COUNT"
	assert_output --partial "7D_COUNT"
	assert_output --partial "24H_IPS"
	assert_output --partial "7D_IPS"
	assert_output --partial "TOP_COUNTRY"
}

@test "service_dual: empty pool produces no output" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	local now
	now=$(date +"%s")
	local cutoff_24h=$((now - 86400))
	local cutoff_7d=$((now - 604800))
	run _apool_service_dual "$pool" "$cutoff_24h" "$cutoff_7d"
	assert_success
	refute_output --partial "Per-service"
}

@test "apool_list: dual-interval service view with TOP_COUNTRY" {
	APOOL_LIST="$INSTALL_PATH/stats/attack.pool"
	local now
	now=$(date +"%s")
	echo "$now 192.0.2.1 sshd 5 DE ban 600 22 15000 service" >> "$APOOL_LIST"
	run apool_list
	assert_success
	assert_output --partial "Per-service threat breakdown (24h / 7d)"
	assert_output --partial "TOP_COUNTRY"
	assert_output --partial "DE"
}
