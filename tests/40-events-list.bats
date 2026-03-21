#!/usr/bin/env bats
#
# Tests for events_list, events_list_ip, events_list_cidr (attack.pool-backed)
# and _apool_awk sort/limit/CIDR extensions.
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

# Helper: seed attack.pool with entries
_seed_pool() {
	local pool="$INSTALL_PATH/stats/attack.pool"
	local now
	now=$(date +"%s")
	# IP with 10 failures (sshd)
	echo "$((now - 100)) 192.0.2.10 sshd 10 RU ban 600 22 30000 service" >> "$pool"
	# IP with 5 failures (dovecot)
	echo "$((now - 200)) 192.0.2.20 dovecot 5 US observed 0 143 8000 -" >> "$pool"
	# IP with 3 failures (sshd) — same service as .10
	echo "$((now - 50)) 192.0.2.30 sshd 3 DE observed 0 22 5000 -" >> "$pool"
	# IP .10 with additional dovecot entry
	echo "$((now - 80)) 192.0.2.10 dovecot 2 RU observed 0 143 3000 -" >> "$pool"
}

# --- _apool_awk sort modes (Merge K) ---

@test "_apool_awk: sort modes (count, time, ip)" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	local now
	now=$(date +"%s")

	# --- sort_mode=count (default, backward compat) ---
	echo "$now 192.0.2.1 sshd 5 US ban 600 22 15000 service" >> "$pool"
	echo "$now 192.0.2.2 sshd 10 RU ban 600 22 30000 service" >> "$pool"
	run _apool_awk "$pool"
	assert_success
	# .2 has higher count, should be first
	assert_line --index 0 --partial "192.0.2.2"
	assert_line --index 1 --partial "192.0.2.1"

	# --- sort_mode=time ---
	: > "$pool"
	echo "$((now - 500)) 192.0.2.1 sshd 10 US ban 600 22 30000 service" >> "$pool"
	echo "$((now - 10)) 192.0.2.2 sshd 1 RU observed 0 22 1000 -" >> "$pool"
	run _apool_awk "$pool" "" "0" "time"
	assert_success
	# .2 has more recent last_ts, should be first despite lower count
	assert_line --index 0 --partial "192.0.2.2"

	# --- sort_mode=ip ---
	: > "$pool"
	echo "$now 192.0.2.20 sshd 5 US ban 600 22 15000 service" >> "$pool"
	echo "$now 192.0.2.2 sshd 10 RU ban 600 22 30000 service" >> "$pool"
	run _apool_awk "$pool" "" "0" "ip"
	assert_success
	# .2 before .20 in version sort
	assert_line --index 0 --partial "192.0.2.2|"
	assert_line --index 1 --partial "192.0.2.20"
}

# --- _apool_awk limits (Merge L) ---

@test "_apool_awk: limit=0 returns all, default limit=25 truncates" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	local now
	now=$(date +"%s")
	local i
	for i in $(seq 1 30); do
		echo "$now 192.0.2.$i sshd 1 -- observed 0 22 1000 -" >> "$pool"
	done

	# limit=0 returns all entries
	run _apool_awk "$pool" "" "0" "count" "0"
	assert_success
	[ "$(echo "$output" | wc -l)" -eq 30 ]

	# default limit=25 truncates to 25 entries
	run _apool_awk "$pool"
	assert_success
	[ "$(echo "$output" | wc -l)" -eq 25 ]
}

@test "_apool_awk: CIDR filter selects matching subnet" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	local now
	now=$(date +"%s")
	echo "$now 192.0.2.10 sshd 5 US ban 600 22 15000 service" >> "$pool"
	echo "$now 198.51.100.5 sshd 3 RU observed 0 22 5000 -" >> "$pool"
	run _apool_awk "$pool" "" "0" "count" "0" "192.0.2.0" "24"
	assert_success
	assert_output --partial "192.0.2.10"
	refute_output --partial "198.51.100.5"
}

@test "_apool_awk: CIDR filter with cutoff combines both filters" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	local now
	now=$(date +"%s")
	echo "$((now - 100)) 192.0.2.10 sshd 5 US ban 600 22 15000 service" >> "$pool"
	echo "$((now - 200000)) 192.0.2.20 sshd 3 RU observed 0 22 5000 -" >> "$pool"
	local cutoff=$((now - 1000))
	run _apool_awk "$pool" "" "$cutoff" "count" "0" "192.0.2.0" "24"
	assert_success
	assert_output --partial "192.0.2.10"
	refute_output --partial "192.0.2.20"
}

# --- events_list (Merge M: populated tests merged) ---

@test "events_list: populated pool shows sorted IPs, header, country, multi-service" {
	_seed_pool
	run events_list "$INSTALL_PATH"
	assert_success
	# all IPs present
	assert_output --partial "192.0.2.10"
	assert_output --partial "192.0.2.20"
	assert_output --partial "192.0.2.30"
	# .10 has highest count (12), should appear first
	local line_10 line_20
	line_10=$(echo "$output" | grep -n "192.0.2.10" | head -1 | cut -d: -f1)
	line_20=$(echo "$output" | grep -n "192.0.2.20" | head -1 | cut -d: -f1)
	[ "$line_10" -lt "$line_20" ]
	# header row present
	assert_output --partial "COUNT"
	assert_output --partial "SERVICES"
	assert_output --partial "COUNTRY"
	# country codes
	assert_output --partial "RU"
	assert_output --partial "US"
	# multiple services shown (.10 has sshd + dovecot)
	assert_output --partial "sshd"
	assert_output --partial "dovecot"
}

@test "events_list: empty pool shows message" {
	run events_list "$INSTALL_PATH"
	assert_success
	assert_output --partial "No events recorded"
}

@test "events_list: shows ban status for banned IPs" {
	local now
	now=$(date +"%s")
	local pool="$INSTALL_PATH/stats/attack.pool"
	echo "$now 192.0.2.10 sshd 5 RU ban 600 22 15000 service" >> "$pool"
	state_bans_active_append "$INSTALL_PATH" "$now" "0" "192.0.2.10" "sshd" "22"
	run events_list "$INSTALL_PATH"
	assert_success
	assert_output --partial "BANNED"
}

@test "events_list: cutoff filters old entries" {
	local now pool
	now=$(date +"%s")
	pool="$INSTALL_PATH/stats/attack.pool"
	echo "$((now - 100)) 192.0.2.10 sshd 5 RU ban 600 22 15000 service" >> "$pool"
	echo "$((now - 200000)) 192.0.2.20 sshd 3 US observed 0 22 5000 -" >> "$pool"
	_EVENTS_CUTOFF=$((now - 1000))
	run events_list "$INSTALL_PATH"
	assert_success
	assert_output --partial "192.0.2.10"
	refute_output --partial "192.0.2.20"
}

@test "events_list: sort_mode=time sorts by last_seen" {
	local now pool
	now=$(date +"%s")
	pool="$INSTALL_PATH/stats/attack.pool"
	echo "$((now - 500)) 192.0.2.10 sshd 50 RU ban 600 22 50000 service" >> "$pool"
	echo "$((now - 10)) 192.0.2.20 sshd 1 US observed 0 22 1000 -" >> "$pool"
	run events_list "$INSTALL_PATH" "time"
	assert_success
	# .20 has more recent activity, should be first despite lower count
	local line_10 line_20
	line_10=$(echo "$output" | grep -n "192.0.2.10" | head -1 | cut -d: -f1)
	line_20=$(echo "$output" | grep -n "192.0.2.20" | head -1 | cut -d: -f1)
	[ "$line_20" -lt "$line_10" ]
}

# --- events_list_ip (Merge N: seed_pool tests merged) ---

@test "events_list_ip: populated pool shows failures, services, triggers, country, timestamps, pressure" {
	_seed_pool
	local now
	now=$(date +"%s")
	# add pressure data for live pressure assertion
	state_pressure_append "$INSTALL_PATH" "$((now - 1))" "192.0.2.10" "sshd" "5" "3"

	run events_list_ip "$INSTALL_PATH" "192.0.2.10"
	assert_success
	# total failures
	assert_output --partial "Total failures:"
	assert_output --partial "12"
	# per-service breakdown
	assert_output --partial "SERVICE"
	assert_output --partial "sshd"
	assert_output --partial "dovecot"
	# ban triggers
	assert_output --partial "Ban triggers:"
	# country
	assert_output --partial "Country:"
	assert_output --partial "RU"
	# first/last seen
	assert_output --partial "First seen:"
	assert_output --partial "Last seen:"
	# live pressure
	assert_output --partial "Live pressure:"
	assert_output --partial "half-life="
}

@test "events_list_ip: shows ban status" {
	local now pool
	now=$(date +"%s")
	pool="$INSTALL_PATH/stats/attack.pool"
	echo "$now 192.0.2.10 sshd 5 RU ban 600 22 15000 service" >> "$pool"
	state_bans_active_append "$INSTALL_PATH" "$now" "0" "192.0.2.10" "sshd" "22"
	run events_list_ip "$INSTALL_PATH" "192.0.2.10"
	assert_success
	assert_output --partial "BANNED"
}

@test "events_list_ip: edge cases (no events, invalid IP)" {
	# no events shows message
	run events_list_ip "$INSTALL_PATH" "192.0.2.99"
	assert_success
	assert_output --partial "No events for"

	# invalid IP returns error
	run events_list_ip "$INSTALL_PATH" "not-an-ip"
	assert_failure
	assert_output --partial "error:"
}

@test "events_list_ip: shows log sample section" {
	RULES_PATH="$INSTALL_PATH/rules"
	mkdir -p "$RULES_PATH"
	local logfile="$TEST_TMPDIR/auth.log"
	cat > "$logfile" <<EOF
Mar  4 10:00:01 server sshd[1234]: Failed password for root from 192.0.2.10 port 22 ssh2
EOF
	cat > "$RULES_PATH/sshd" <<RULE
PREREQ=""
LOG_FILE="$logfile"
LOG_TAG="sshd"
RULE
	chown root "$RULES_PATH/sshd"
	chmod 644 "$RULES_PATH/sshd"
	local now pool
	now=$(date +"%s")
	pool="$INSTALL_PATH/stats/attack.pool"
	echo "$now 192.0.2.10 sshd 5 RU ban 600 22 15000 service" >> "$pool"
	run events_list_ip "$INSTALL_PATH" "192.0.2.10"
	assert_success
	assert_output --partial "Recent log activity:"
	assert_output --partial "Failed password"
}

@test "events_list_ip: works with only pressure data (no pool entries)" {
	local now
	now=$(date +"%s")
	state_pressure_append "$INSTALL_PATH" "$((now - 1))" "192.0.2.10" "sshd" "5" "3"
	run events_list_ip "$INSTALL_PATH" "192.0.2.10"
	assert_success
	assert_output --partial "192.0.2.10"
	assert_output --partial "Live pressure:"
}

# --- events_list_cidr (Merge O: shared _seed_pool tests merged) ---

@test "events_list_cidr: finds IPs in range and shows summary" {
	_seed_pool
	run events_list_cidr "$INSTALL_PATH" "192.0.2.0/24"
	assert_success
	assert_output --partial "192.0.2.10"
	assert_output --partial "192.0.2.20"
	assert_output --partial "192.0.2.30"
	# summary line with totals
	assert_output --partial "3 IPs"
	assert_output --partial "failures"
}

@test "events_list_cidr: excludes IPs outside range" {
	local now pool
	now=$(date +"%s")
	pool="$INSTALL_PATH/stats/attack.pool"
	echo "$now 192.0.2.10 sshd 5 US ban 600 22 15000 service" >> "$pool"
	echo "$now 198.51.100.5 sshd 3 RU observed 0 22 5000 -" >> "$pool"
	run events_list_cidr "$INSTALL_PATH" "192.0.2.0/24"
	assert_success
	assert_output --partial "192.0.2.10"
	refute_output --partial "198.51.100.5"
}

@test "events_list_cidr: shows BANNED status for banned IPs" {
	local now pool
	now=$(date +"%s")
	pool="$INSTALL_PATH/stats/attack.pool"
	echo "$now 192.0.2.10 sshd 5 US ban 600 22 15000 service" >> "$pool"
	state_bans_active_append "$INSTALL_PATH" "$now" "0" "192.0.2.10" "sshd" "22"
	run events_list_cidr "$INSTALL_PATH" "192.0.2.0/24"
	assert_success
	assert_output --partial "BANNED"
}

@test "events_list_cidr: empty pool shows message" {
	run events_list_cidr "$INSTALL_PATH" "192.0.2.0/24"
	assert_success
	assert_output --partial "No events found"
}

@test "events_list_cidr: no matching IPs shows message" {
	local now pool
	now=$(date +"%s")
	pool="$INSTALL_PATH/stats/attack.pool"
	echo "$now 198.51.100.5 sshd 3 RU observed 0 22 5000 -" >> "$pool"
	run events_list_cidr "$INSTALL_PATH" "192.0.2.0/24"
	assert_success
	assert_output --partial "No events found for 192.0.2.0/24"
}

@test "events_list_cidr: invalid CIDR shows error" {
	run events_list_cidr "$INSTALL_PATH" "not-a-cidr"
	assert_failure
	assert_output --partial "error:"
}

# --- _events_list_ip_pool_awk ---

@test "_events_list_ip_pool_awk: returns header and service lines" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	local now
	now=$(date +"%s")
	echo "$now 192.0.2.10 sshd 5 RU ban 600 22 15000 service" >> "$pool"
	echo "$((now - 100)) 192.0.2.10 dovecot 3 RU observed 0 143 5000 -" >> "$pool"
	run _events_list_ip_pool_awk "$pool" "192.0.2.10"
	assert_success
	assert_line --index 0 --regexp '^H\|8\|'
	assert_output --partial "S|sshd|5|"
	assert_output --partial "S|dovecot|3|"
}

@test "_events_list_ip_pool_awk: counts ban triggers" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	local now
	now=$(date +"%s")
	echo "$now 192.0.2.10 sshd 5 RU ban 600 22 15000 service" >> "$pool"
	echo "$((now - 100)) 192.0.2.10 sshd 3 RU escalate 1200 22 20000 service" >> "$pool"
	echo "$((now - 200)) 192.0.2.10 sshd 2 RU observed 0 22 3000 -" >> "$pool"
	run _events_list_ip_pool_awk "$pool" "192.0.2.10"
	assert_success
	# H|total|first_ts|last_ts|bans|cc — bans should be 2 (ban + escalate)
	assert_line --index 0 --regexp '^H\|10\|.*\|2\|RU$'
}

@test "_events_list_ip_pool_awk: returns failure for unknown IP" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	echo "1000 192.0.2.1 sshd 5 US ban 600 22 15000 service" >> "$pool"
	run _events_list_ip_pool_awk "$pool" "192.0.2.99"
	assert_failure
}

# --- events_list --limit= (Merge P) ---

@test "events_list: limit parameter caps output and shows truncation footer" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	local now
	now=$(date +"%s")
	local i
	for i in $(seq 1 120); do
		printf '%s 198.51.100.%s sshd %s US observed 0 22 1000 -\n' \
			"$((now - i))" "$((i % 256))" "$i" >> "$pool"
	done

	# default limit=100 truncates large result sets
	run events_list "$INSTALL_PATH" "count" "100"
	assert_success
	assert_output --partial "showing 100 IPs"
	assert_output --partial "--limit=0"

	# explicit limit=10 caps output
	run events_list "$INSTALL_PATH" "count" "10"
	assert_success
	assert_output --partial "showing 10 IPs"

	# limit=0 returns all entries
	run events_list "$INSTALL_PATH" "count" "0"
	assert_success
	refute_output --partial "showing"
	refute_output --partial "--limit="
	# verify all 120 data rows are present (no truncation)
	local data_lines
	data_lines=$(echo "$output" | grep -c '^[0-9]')
	[ "$data_lines" -eq 120 ]
}

@test "events_list: no truncation footer when result fits within limit" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	local now
	now=$(date +"%s")
	local i
	for i in $(seq 1 5); do
		echo "$now 192.0.2.$i sshd 1 -- observed 0 22 1000 -" >> "$pool"
	done
	run events_list "$INSTALL_PATH" "count" "100"
	assert_success
	refute_output --partial "showing"
	refute_output --partial "--limit="
}

@test "events_list_cidr: respects limit parameter" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	local now
	now=$(date +"%s")
	local i
	for i in $(seq 1 20); do
		echo "$now 192.0.2.$i sshd 1 -- observed 0 22 1000 -" >> "$pool"
	done
	run events_list_cidr "$INSTALL_PATH" "192.0.2.0/24" "count" "5"
	assert_success
	assert_output --partial "showing 5"
	assert_output --partial "--limit=0"
}

# --- rotated bans.history coverage (F-02) ---

@test "_batch_ban_status_init: includes rotated bans.history archives" {
	local now
	now=$(date +"%s")
	# Put ban in rotated archive, not current file
	echo "$((now - 90000)) $((now - 89400)) 192.0.2.50 sshd ban" > "$INSTALL_PATH/tmp/bans.history.032026"
	echo "$((now - 80000)) $((now - 79400)) 192.0.2.50 sshd ban" >> "$INSTALL_PATH/tmp/bans.history.032026"
	# Current bans.history has a different IP
	echo "$((now - 100)) $((now - 0)) 192.0.2.99 dovecot ban" > "$INSTALL_PATH/tmp/bans.history"

	_batch_ban_status_init "$INSTALL_PATH"
	# IP in rotated archive should show prev:2
	run _batch_ban_status_lookup "192.0.2.50"
	assert_output "prev:2"
	# IP in current file should also work
	run _batch_ban_status_lookup "192.0.2.99"
	assert_output "prev:1"
	_batch_ban_status_cleanup
	rm -f "$INSTALL_PATH/tmp/bans.history.032026"
}

@test "_batch_ban_status_init: combines counts across current and rotated files" {
	local now
	now=$(date +"%s")
	# 1 ban in rotated archive
	echo "$((now - 90000)) $((now - 89400)) 192.0.2.60 sshd ban" > "$INSTALL_PATH/tmp/bans.history.031926"
	# 2 bans in current file
	echo "$((now - 500)) $((now - 0)) 192.0.2.60 sshd ban" > "$INSTALL_PATH/tmp/bans.history"
	echo "$((now - 200)) $((now - 0)) 192.0.2.60 sshd escalate" >> "$INSTALL_PATH/tmp/bans.history"

	_batch_ban_status_init "$INSTALL_PATH"
	run _batch_ban_status_lookup "192.0.2.60"
	assert_output "prev:3"
	_batch_ban_status_cleanup
	rm -f "$INSTALL_PATH/tmp/bans.history.031926"
}
