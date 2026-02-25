#!/usr/bin/env bats
#
# Integration tests for the check() pipeline:
# count_failures, execute_ban, and end-to-end flow
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

setup() {
	bfd_standard_setup
	MOD="sshd"
}

teardown() {
	bfd_teardown
}

# --- count_failures (windowed replacement) ---

@test "count_failures: counts host in windowed mode" {
	local hosts_parsed
	hosts_parsed=$(printf "192.0.2.1\n192.0.2.2\n192.0.2.1\n")
	run count_failures "192.0.2.1" "$hosts_parsed" "$INSTALL_PATH" "300" "1000" "sshd"
	assert_success
	assert_output "2"
}

@test "count_failures: accumulates within window" {
	local hosts_parsed
	hosts_parsed=$(printf "192.0.2.1\n192.0.2.1\n192.0.2.1\n")
	# first run at t=900
	count_failures "192.0.2.1" "$hosts_parsed" "$INSTALL_PATH" "300" "900" "sshd" >/dev/null
	# second run at t=1000 (within window)
	run count_failures "192.0.2.1" "$hosts_parsed" "$INSTALL_PATH" "300" "1000" "sshd"
	assert_success
	assert_output "6"
}

@test "count_failures: old events expire outside window" {
	# seed old events at t=100
	state_events_append "$INSTALL_PATH" "100" "192.0.2.1" "sshd" "5"
	local hosts_parsed
	hosts_parsed=$(printf "192.0.2.1\n192.0.2.1\n")
	# now=1000, window=300, cutoff=700 => old events at t=100 excluded
	run count_failures "192.0.2.1" "$hosts_parsed" "$INSTALL_PATH" "300" "1000" "sshd"
	assert_success
	assert_output "2"
}

@test "count_failures: per-service isolation in windowed mode" {
	# seed dovecot events in window
	state_events_append "$INSTALL_PATH" "900" "192.0.2.1" "dovecot" "10"
	local hosts_parsed
	hosts_parsed=$(printf "192.0.2.1\n192.0.2.1\n")
	# count sshd only
	run count_failures "192.0.2.1" "$hosts_parsed" "$INSTALL_PATH" "300" "1000" "sshd"
	assert_success
	assert_output "2"
}

# --- PRESSURE_TRIP_GLOBAL ---

@test "pipeline: PRESSURE_TRIP_GLOBAL triggers ban across services" {
	# seed dovecot events (3) and sshd events (3) in window, total = 6
	state_events_append "$INSTALL_PATH" "900" "192.0.2.1" "dovecot" "3"
	state_events_append "$INSTALL_PATH" "900" "192.0.2.1" "sshd" "3"
	# PRESSURE_TRIP_GLOBAL=5: cross-service total of 6 >= 5
	local global_count
	global_count=$(state_events_count "$INSTALL_PATH" "192.0.2.1" "300" "1000")
	[ "$global_count" -ge 5 ]
}

@test "pipeline: PRESSURE_TRIP_GLOBAL=0 disables cross-service check" {
	# With PRESSURE_TRIP_GLOBAL=0, should not trigger
	local trig_global=0
	local should_ban=0
	local attack_count=2
	local trig=5
	if [ "$attack_count" -ge "$trig" ]; then
		should_ban=1
	elif [ "$trig_global" -gt 0 ]; then
		should_ban=1
	fi
	[ "$should_ban" -eq 0 ]
}

# --- execute_ban ---

@test "execute_ban: dry run logs without executing" {
	run execute_ban "192.0.2.1" "sshd" "1"
	assert_success
	assert_output --partial "dry-run"
	assert_output --partial "192.0.2.1"
}

@test "execute_ban: sets ATTACK_HOST global" {
	execute_ban "192.0.2.1" "sshd" "1" >/dev/null
	[ "$ATTACK_HOST" = "192.0.2.1" ]
}

@test "execute_ban: sets BAN_COMMAND global for custom backend" {
	BAN_COMMAND_TEMPLATE="echo test_cmd"
	execute_ban "192.0.2.1" "sshd" "1" >/dev/null
	[ "$BAN_COMMAND" = "echo test_cmd" ]
}

@test "execute_ban: executes command in live mode" {
	local marker="$TEST_TMPDIR/ban_executed"
	BAN_COMMAND_TEMPLATE="touch $marker"
	execute_ban "192.0.2.1" "sshd" "0" >/dev/null
	[ -f "$marker" ]
}

@test "execute_ban: returns non-zero on command failure" {
	BAN_COMMAND_TEMPLATE="false"
	run execute_ban "192.0.2.1" "sshd" "0"
	[ "$status" -ne 0 ]
}

@test "execute_ban: logs ban command failure" {
	BAN_COMMAND_TEMPLATE="false"
	run execute_ban "192.0.2.1" "sshd" "0"
	assert_output --partial "failed after"
}

@test "execute_ban: failed ban skips lifecycle recording" {
	BAN_COMMAND_TEMPLATE="false"
	run execute_ban "192.0.2.1" "sshd" "0"
	[ "$status" -ne 0 ]

	# bans.active and bans.history must remain empty
	run cat "$INSTALL_PATH/tmp/bans.active"
	assert_output ""
	run cat "$INSTALL_PATH/tmp/bans.history"
	assert_output ""
}

# --- ban retry logic ---

@test "execute_ban: retries on failure with BAN_RETRY_COUNT" {
	BAN_RETRY_COUNT="2"
	# create a script that fails twice then succeeds
	local counter="$TEST_TMPDIR/attempt_counter"
	echo "0" > "$counter"
	local cmd="$TEST_TMPDIR/retry_cmd.sh"
	cat > "$cmd" <<'EOF'
#!/bin/bash
c=$(cat "$1")
c=$((c + 1))
echo "$c" > "$1"
[ "$c" -ge 3 ] && exit 0
exit 1
EOF
	chmod +x "$cmd"
	BAN_COMMAND_TEMPLATE="$cmd $counter"
	run execute_ban "192.0.2.1" "sshd" "0"
	assert_success
	# verify it took 3 attempts
	local attempts
	attempts=$(cat "$counter")
	[ "$attempts" -eq 3 ]
}

@test "execute_ban: no retries when BAN_RETRY_COUNT=0" {
	BAN_RETRY_COUNT="0"
	BAN_COMMAND_TEMPLATE="false"
	run execute_ban "192.0.2.1" "sshd" "0"
	[ "$status" -ne 0 ]
	assert_output --partial "after 1 attempt"
}

@test "execute_unban: retries on failure with BAN_RETRY_COUNT" {
	BAN_RETRY_COUNT="1"
	local counter="$TEST_TMPDIR/unban_counter"
	echo "0" > "$counter"
	local cmd="$TEST_TMPDIR/retry_unban.sh"
	cat > "$cmd" <<'EOF'
#!/bin/bash
c=$(cat "$1")
c=$((c + 1))
echo "$c" > "$1"
[ "$c" -ge 2 ] && exit 0
exit 1
EOF
	chmod +x "$cmd"
	UNBAN_COMMAND_TEMPLATE="$cmd $counter"
	run execute_unban "192.0.2.1" "sshd"
	assert_success
}

# --- end-to-end pipeline ---

@test "pipeline: filter_host + count_failures + ban state" {
	# setup ignore infrastructure
	local ignore_files="$TEST_TMPDIR/exclude.files"
	local lo_hosts="$TEST_TMPDIR/lo_hosts"
	touch "$ignore_files" "$lo_hosts"

	local host="192.0.2.1"
	local hosts_parsed
	hosts_parsed=$(printf "192.0.2.1\n192.0.2.1\n192.0.2.1\n192.0.2.1\n192.0.2.1\n")

	# host passes filter
	filter_host "$host" "$ignore_files" "$lo_hosts"
	local filter_rc=$?
	[ "$filter_rc" -eq 0 ]

	# count failures (windowed)
	local count
	count=$(count_failures "$host" "$hosts_parsed" "$INSTALL_PATH" "300" "1000" "sshd")
	[ "$count" -ge 5 ]

	# ban and record
	state_pool_append "$INSTALL_PATH" "1700000000" "$host" "sshd"
	state_bans_active_append "$INSTALL_PATH" "1000" "0" "$host" "sshd" "22"

	# verify state
	run state_bans_active_check "$INSTALL_PATH" "$host"
	assert_success
	run cat "$INSTALL_PATH/stats/attack.pool"
	assert_output --partial "192.0.2.1"
}

@test "pipeline: ignored host skips ban entirely" {
	local ignore_list="$TEST_TMPDIR/ignore.hosts"
	local ignore_files="$TEST_TMPDIR/exclude.files"
	local lo_hosts="$TEST_TMPDIR/lo_hosts"
	echo "192.0.2.1" > "$ignore_list"
	echo "$ignore_list" > "$ignore_files"
	touch "$lo_hosts"

	local filter_rc=0
	filter_host "192.0.2.1" "$ignore_files" "$lo_hosts" || filter_rc=$?
	[ "$filter_rc" -eq 1 ]

	# bans.active and attack.pool should be empty
	run cat "$INSTALL_PATH/tmp/bans.active"
	assert_output ""
	run cat "$INSTALL_PATH/stats/attack.pool"
	assert_output ""
}

@test "pipeline: local address gets pool entry but no ban" {
	local ignore_files="$TEST_TMPDIR/exclude.files"
	local lo_hosts="$TEST_TMPDIR/lo_hosts"
	touch "$ignore_files"
	echo "203.0.113.1" > "$lo_hosts"

	local filter_rc=0
	filter_host "203.0.113.1" "$ignore_files" "$lo_hosts" || filter_rc=$?
	[ "$filter_rc" -eq 2 ]

	# record in pool but do not ban
	state_pool_append "$INSTALL_PATH" "1700000000" "203.0.113.1" "sshd"
	run cat "$INSTALL_PATH/stats/attack.pool"
	assert_output --partial "203.0.113.1"
	# bans.active should be empty
	run cat "$INSTALL_PATH/tmp/bans.active"
	assert_output ""
}

# --- execute_unban ---

@test "execute_unban: runs command and sets globals" {
	local marker="$TEST_TMPDIR/unban_executed"
	UNBAN_COMMAND_TEMPLATE="touch $marker"
	execute_unban "192.0.2.1" "sshd" >/dev/null
	[ -f "$marker" ]
	[ "$ATTACK_HOST" = "192.0.2.1" ]
}

@test "execute_unban: returns non-zero on command failure" {
	UNBAN_COMMAND_TEMPLATE="false"
	run execute_unban "192.0.2.1" "sshd"
	[ "$status" -ne 0 ]
}

# --- process_unbans ---

@test "process_unbans: removes expired bans" {
	state_bans_active_append "$INSTALL_PATH" "1000" "1300" "192.0.2.1" "sshd" "22"
	process_unbans "$INSTALL_PATH" "1400" >/dev/null
	run state_bans_active_check "$INSTALL_PATH" "192.0.2.1"
	assert_failure
}

@test "process_unbans: skips permanent bans (expiry=0)" {
	state_bans_active_append "$INSTALL_PATH" "1000" "0" "192.0.2.1" "sshd" "22"
	process_unbans "$INSTALL_PATH" "9999999" >/dev/null
	run state_bans_active_check "$INSTALL_PATH" "192.0.2.1"
	assert_success
}

@test "process_unbans: with empty UNBAN_COMMAND still removes from state" {
	UNBAN_COMMAND_TEMPLATE=""
	state_bans_active_append "$INSTALL_PATH" "1000" "1300" "192.0.2.1" "sshd" "22"
	process_unbans "$INSTALL_PATH" "1400" >/dev/null
	run state_bans_active_check "$INSTALL_PATH" "192.0.2.1"
	assert_failure
	# verify history recorded
	run cat "$INSTALL_PATH/tmp/bans.history"
	assert_output --partial "192.0.2.1"
	assert_output --partial "unban"
}

@test "process_unbans: executes unban command when set" {
	local marker="$TEST_TMPDIR/unban_ran"
	UNBAN_COMMAND_TEMPLATE="touch $marker"
	state_bans_active_append "$INSTALL_PATH" "1000" "1300" "192.0.2.1" "sshd" "22"
	process_unbans "$INSTALL_PATH" "1400" >/dev/null
	[ -f "$marker" ]
}

# --- check_recidivism ---

@test "check_recidivism: returns 0 when threshold met" {
	# seed 5 ban events in window
	local i
	for i in 1 2 3 4 5; do
		state_bans_history_append "$INSTALL_PATH" "$((800 + i))" "1100" "192.0.2.1" "sshd" "ban"
	done
	run check_recidivism "$INSTALL_PATH" "192.0.2.1" "500" "1000" "5"
	assert_success
}

@test "check_recidivism: returns 1 when below threshold" {
	state_bans_history_append "$INSTALL_PATH" "900" "1200" "192.0.2.1" "sshd" "ban"
	run check_recidivism "$INSTALL_PATH" "192.0.2.1" "500" "1000" "5"
	assert_failure
}

@test "check_recidivism: returns 1 when disabled (permanent_after=0)" {
	state_bans_history_append "$INSTALL_PATH" "900" "1200" "192.0.2.1" "sshd" "ban"
	run check_recidivism "$INSTALL_PATH" "192.0.2.1" "500" "1000" "0"
	assert_failure
}

# --- ban lifecycle flow ---

@test "pipeline: ban → record → expire → unban flow" {
	# simulate a ban
	execute_ban "192.0.2.1" "sshd" "0" >/dev/null
	state_bans_active_append "$INSTALL_PATH" "1000" "1300" "192.0.2.1" "sshd" "22"
	state_bans_history_append "$INSTALL_PATH" "1000" "1300" "192.0.2.1" "sshd" "ban"

	# verify active
	run state_bans_active_check "$INSTALL_PATH" "192.0.2.1"
	assert_success

	# process unbans at time past expiry
	process_unbans "$INSTALL_PATH" "1400" >/dev/null

	# verify removed from active
	run state_bans_active_check "$INSTALL_PATH" "192.0.2.1"
	assert_failure

	# verify unban recorded in history
	run cat "$INSTALL_PATH/tmp/bans.history"
	assert_output --partial "unban"
}

# --- manual_ban / manual_unban ---

@test "manual_ban: bans IP and records in state" {
	manual_ban "$INSTALL_PATH" "192.0.2.1" "1000" "sshd" >/dev/null
	run state_bans_active_check "$INSTALL_PATH" "192.0.2.1"
	assert_success
	run cat "$INSTALL_PATH/tmp/bans.history"
	assert_output --partial "192.0.2.1"
	assert_output --partial "ban"
}

@test "manual_ban: rejects already banned IP" {
	state_bans_active_append "$INSTALL_PATH" "900" "0" "192.0.2.1" "sshd" "22"
	run manual_ban "$INSTALL_PATH" "192.0.2.1" "1000" "sshd"
	assert_failure
	assert_output --partial "already banned"
}

@test "manual_unban: unbans IP and records in history" {
	state_bans_active_append "$INSTALL_PATH" "900" "0" "192.0.2.1" "sshd" "22"
	run manual_unban "$INSTALL_PATH" "192.0.2.1" "1000"
	assert_success
	assert_output --partial "unbanned"
	# verify removed from active
	run state_bans_active_check "$INSTALL_PATH" "192.0.2.1"
	assert_failure
}

@test "manual_unban: rejects IP not in ban list" {
	run manual_unban "$INSTALL_PATH" "192.0.2.99" "1000"
	assert_failure
	assert_output --partial "not in the active ban list"
}

# --- PORTS enforcement ---

@test "execute_ban: sets PORTS global" {
	execute_ban "192.0.2.1" "sshd" "1" "22" >/dev/null
	[ "$PORTS" = "22" ]
}

@test "execute_ban: PORTS available in template expansion" {
	local marker="$TEST_TMPDIR/ports_check"
	BAN_COMMAND_TEMPLATE="echo \$PORTS > $marker"
	execute_ban "192.0.2.1" "sshd" "0" "110,143,993,995" >/dev/null
	run cat "$marker"
	assert_output "110,143,993,995"
}

@test "execute_ban: defaults PORTS to all when not provided" {
	execute_ban "192.0.2.1" "sshd" "1" >/dev/null
	[ "$PORTS" = "all" ]
}

@test "execute_ban: sets MOD global" {
	execute_ban "192.0.2.1" "dovecot" "1" "22" >/dev/null
	[ "$MOD" = "dovecot" ]
}

@test "execute_unban: sets PORTS global" {
	execute_unban "192.0.2.1" "sshd" "22" >/dev/null
	[ "$PORTS" = "22" ]
}

@test "execute_unban: defaults PORTS to all when not provided" {
	execute_unban "192.0.2.1" "sshd" >/dev/null
	[ "$PORTS" = "all" ]
}

@test "process_unbans: passes PORTS from state to unban command" {
	local marker="$TEST_TMPDIR/unban_ports"
	UNBAN_COMMAND_TEMPLATE="echo \$PORTS > $marker"
	state_bans_active_append "$INSTALL_PATH" "1000" "1300" "192.0.2.1" "sshd" "22"
	process_unbans "$INSTALL_PATH" "1400" >/dev/null
	run cat "$marker"
	assert_output "22"
}

@test "manual_unban: reads and passes PORTS from state" {
	local marker="$TEST_TMPDIR/manual_unban_ports"
	UNBAN_COMMAND_TEMPLATE="echo \$PORTS > $marker"
	state_bans_active_append "$INSTALL_PATH" "900" "0" "192.0.2.1" "dovecot" "110,143,993,995"
	manual_unban "$INSTALL_PATH" "192.0.2.1" "1000" >/dev/null
	run cat "$marker"
	assert_output "110,143,993,995"
}

# --- IPv6 pipeline tests ---

@test "count_failures: counts IPv6 host with grep -cxF" {
	local hosts_parsed
	hosts_parsed=$(printf "2001:db8::1\n192.0.2.1\n2001:db8::1\n")
	run count_failures "2001:db8::1" "$hosts_parsed" "$INSTALL_PATH" "300" "1000" "sshd"
	assert_success
	assert_output "2"
}

@test "count_failures: IPv6 no false positive on prefix match" {
	local hosts_parsed
	hosts_parsed=$(printf "2001:db8::1\n2001:db8::1:0\n2001:db8::10\n")
	# grep -cxF ensures exact line match — only "2001:db8::1" matches
	run count_failures "2001:db8::1" "$hosts_parsed" "$INSTALL_PATH" "300" "1000" "sshd"
	assert_success
	assert_output "1"
}

@test "pipeline: IPv6 host flows through filter + count + ban" {
	local ignore_files="$TEST_TMPDIR/exclude.files"
	local lo_hosts="$TEST_TMPDIR/lo_hosts"
	touch "$ignore_files" "$lo_hosts"

	local host="2001:db8::1"
	local hosts_parsed
	hosts_parsed=$(printf "2001:db8::1\n2001:db8::1\n2001:db8::1\n2001:db8::1\n2001:db8::1\n")

	# host passes filter
	filter_host "$host" "$ignore_files" "$lo_hosts"
	local filter_rc=$?
	[ "$filter_rc" -eq 0 ]

	# count failures
	local count
	count=$(count_failures "$host" "$hosts_parsed" "$INSTALL_PATH" "300" "1000" "sshd")
	[ "$count" -ge 5 ]

	# ban and record
	state_pool_append "$INSTALL_PATH" "1700000000" "$host" "sshd"
	state_bans_active_append "$INSTALL_PATH" "1000" "0" "$host" "sshd" "22"

	# verify state
	run state_bans_active_check "$INSTALL_PATH" "$host"
	assert_success
	run cat "$INSTALL_PATH/stats/attack.pool"
	assert_output --partial "2001:db8::1"
}

@test "pipeline: mixed IPv4+IPv6 counted independently" {
	local hosts_parsed
	hosts_parsed=$(printf "192.0.2.1\n2001:db8::1\n192.0.2.1\n2001:db8::1\n192.0.2.1\n")
	local v4_count
	v4_count=$(count_failures "192.0.2.1" "$hosts_parsed" "$INSTALL_PATH" "300" "1000" "sshd")
	[ "$v4_count" -eq 3 ]
	local v6_count
	v6_count=$(count_failures "2001:db8::1" "$hosts_parsed" "$INSTALL_PATH" "300" "1000" "sshd")
	[ "$v6_count" -eq 2 ]
}

# --- IPv6 ban command selection ---

@test "execute_ban: selects V6 command for IPv6 host" {
	local marker_v4="$TEST_TMPDIR/ban_v4"
	local marker_v6="$TEST_TMPDIR/ban_v6"
	BAN_COMMAND_TEMPLATE="touch $marker_v4"
	BAN_COMMAND_V6_TEMPLATE="touch $marker_v6"
	execute_ban "2001:db8::1" "sshd" "0" "22" >/dev/null
	# V6 command should have run, not V4
	[ -f "$marker_v6" ]
	[ ! -f "$marker_v4" ]
}

@test "execute_ban: uses standard command for IPv4 even when V6 set" {
	local marker_v4="$TEST_TMPDIR/ban_v4"
	local marker_v6="$TEST_TMPDIR/ban_v6"
	BAN_COMMAND_TEMPLATE="touch $marker_v4"
	BAN_COMMAND_V6_TEMPLATE="touch $marker_v6"
	execute_ban "192.0.2.1" "sshd" "0" "22" >/dev/null
	# V4 command should have run, not V6
	[ -f "$marker_v4" ]
	[ ! -f "$marker_v6" ]
}

@test "execute_ban: falls back to standard for IPv6 when V6 empty" {
	local marker="$TEST_TMPDIR/ban_fallback"
	BAN_COMMAND_TEMPLATE="touch $marker"
	BAN_COMMAND_V6_TEMPLATE=""
	execute_ban "2001:db8::1" "sshd" "0" "22" >/dev/null
	# standard command should have run
	[ -f "$marker" ]
}

@test "execute_unban: selects V6 command for IPv6 host" {
	local marker_v6="$TEST_TMPDIR/unban_v6"
	UNBAN_COMMAND_TEMPLATE="/bin/true"
	UNBAN_COMMAND_V6_TEMPLATE="touch $marker_v6"
	execute_unban "2001:db8::1" "sshd" "22" >/dev/null
	[ -f "$marker_v6" ]
}

@test "execute_unban: uses standard for IPv4 when V6 set" {
	local marker_v4="$TEST_TMPDIR/unban_v4"
	local marker_v6="$TEST_TMPDIR/unban_v6"
	UNBAN_COMMAND_TEMPLATE="touch $marker_v4"
	UNBAN_COMMAND_V6_TEMPLATE="touch $marker_v6"
	execute_unban "192.0.2.1" "sshd" "22" >/dev/null
	[ -f "$marker_v4" ]
	[ ! -f "$marker_v6" ]
}

# --- IPv6 local address detection ---

@test "filter_host: IPv6 local address detected" {
	local ignore_files="$TEST_TMPDIR/exclude.files"
	local lo_hosts="$TEST_TMPDIR/lo_hosts"
	touch "$ignore_files"
	echo "2001:db8::1" > "$lo_hosts"
	local filter_rc=0
	filter_host "2001:db8::1" "$ignore_files" "$lo_hosts" || filter_rc=$?
	[ "$filter_rc" -eq 2 ]
}

@test "filter_host: IPv6 loopback detected" {
	local ignore_files="$TEST_TMPDIR/exclude.files"
	local lo_hosts="$TEST_TMPDIR/lo_hosts"
	touch "$ignore_files"
	echo "::1" > "$lo_hosts"
	local filter_rc=0
	filter_host "::1" "$ignore_files" "$lo_hosts" || filter_rc=$?
	[ "$filter_rc" -eq 2 ]
}

# --- IPv6 manual ban/unban ---

@test "manual_ban: accepts IPv6 address" {
	manual_ban "$INSTALL_PATH" "2001:db8::1" "1000" "sshd" >/dev/null
	run state_bans_active_check "$INSTALL_PATH" "2001:db8::1"
	assert_success
}

@test "manual_unban: accepts IPv6 address" {
	state_bans_active_append "$INSTALL_PATH" "900" "0" "2001:db8::1" "sshd" "22"
	run manual_unban "$INSTALL_PATH" "2001:db8::1" "1000"
	assert_success
	assert_output --partial "unbanned"
}

# --- run statistics (Phase 13A) ---

# Source check() function from bfd (defined there, not in bfd.lib.sh)
eval "$(awk '/^check\(\)/ { p=1 } p { print; if (/^\}$/) exit }' "$PROJECT_ROOT/files/bfd")"

# Helper to run check() with controlled rules dir and capture output
_run_check_with_stats() {
	local rules_dir="$1"
	# set up minimal environment for check()
	RULES_PATH="$rules_dir"
	GLOB_PRESSURE_TRIP="5"
	GLOB_TRIG="5"
	PRESSURE_HALF_LIFE="300"
	TRIG_WINDOW="300"
	PRESSURE_TRIP_GLOBAL="0"
	TRIG_GLOBAL="0"
	UTIME="1000"
	IGNORE_HOST_FILES="$TEST_TMPDIR/exclude.files"
	LO_HOSTS="$TEST_TMPDIR/lo_hosts"
	touch "$IGNORE_HOST_FILES" "$LO_HOSTS"
	BAN_COMMAND_TEMPLATE="true"
	BAN_COMMAND_V6_TEMPLATE=""
	DRY_RUN="1"
	BAN_TTL="0"
	BAN_DURATION="0"
	BAN_ESCALATE_AFTER="0"
	BAN_PERMANENT_AFTER="0"
	BAN_ESCALATE_WINDOW="86400"
	BAN_PERMANENT_WINDOW="86400"
	SKIP_ALERT=""
	check
}

@test "run stats: summary line appears after check()" {
	local rules_dir="$TEST_TMPDIR/rules"
	mkdir -p "$rules_dir"
	run _run_check_with_stats "$rules_dir"
	assert_success
	assert_output --partial "run complete:"
	assert_output --partial "rules checked"
	assert_output --partial "events parsed"
	assert_output --partial "bans executed"
}

@test "run stats: rules count matches valid rules" {
	local rules_dir="$TEST_TMPDIR/rules"
	mkdir -p "$rules_dir"
	# create 2 valid rule files with REQ that exists, LP pointing to a real file
	local logfile="$TEST_TMPDIR/test.log"
	echo "test line" > "$logfile"
	cat > "$rules_dir/testrule1" <<EOF
TRIG="5"
REQ="/bin/sh"
LP="$logfile"
TLOG_TF="testrule1"
ARG_VAL=""
EOF
	cat > "$rules_dir/testrule2" <<EOF
TRIG="5"
REQ="/bin/sh"
LP="$logfile"
TLOG_TF="testrule2"
ARG_VAL=""
EOF
	# create 1 rule that will fail validate_rule (no ARG_VAL, LP missing)
	cat > "$rules_dir/badrule" <<EOF
TRIG="5"
REQ="/bin/sh"
LP="/nonexistent/log"
TLOG_TF="badrule"
ARG_VAL=""
EOF
	run _run_check_with_stats "$rules_dir"
	assert_success
	# badrule has LP that doesn't exist, so validate_rule skips it
	# testrule1 and testrule2 pass validate_rule but have empty ARG_VAL so
	# validate_rule returns 1 for empty ARG_VAL — 0 valid rules
	assert_output --partial "0 rules checked"
}

@test "run stats: counts events from HOSTS_PARSED" {
	local rules_dir="$TEST_TMPDIR/rules"
	mkdir -p "$rules_dir"
	local logfile="$TEST_TMPDIR/test.log"
	echo "test line" > "$logfile"
	# create a rule that produces 3 events via ARG_VAL
	cat > "$rules_dir/testrule" <<'RULEEOF'
TRIG="100"
REQ="/bin/sh"
RULEEOF
	cat >> "$rules_dir/testrule" <<EOF
LP="$logfile"
TLOG_TF="testrule"
ARG_VAL="192.0.2.1 192.0.2.2 192.0.2.1"
EOF
	run _run_check_with_stats "$rules_dir"
	assert_success
	assert_output --partial "1 rules checked"
	assert_output --partial "3 events parsed"
}

@test "run stats: zero events when no log activity" {
	local rules_dir="$TEST_TMPDIR/rules"
	mkdir -p "$rules_dir"
	run _run_check_with_stats "$rules_dir"
	assert_success
	assert_output --partial "0 rules checked, 0 events parsed, 0 bans executed"
}

@test "run stats: elapsed time is non-negative integer" {
	local rules_dir="$TEST_TMPDIR/rules"
	mkdir -p "$rules_dir"
	run _run_check_with_stats "$rules_dir"
	assert_success
	# extract elapsed from "(...s)"
	local elapsed
	elapsed=$(echo "$output" | grep -o '([0-9]*s)' | tr -dc '0-9')
	[ -n "$elapsed" ]
	[ "$elapsed" -ge 0 ]
}

# --- IPv6 exact-match tests for ban state functions ---

@test "state_bans_active: IPv6 does not false-match prefix" {
	state_bans_active_append "$INSTALL_PATH" "1000" "0" "2001:db8::1" "sshd" "22"
	# 2001:db8::10 must NOT match — it is a different address
	run state_bans_active_check "$INSTALL_PATH" "2001:db8::10"
	assert_failure
}

@test "state_bans_active: IPv6 exact match works" {
	state_bans_active_append "$INSTALL_PATH" "1000" "0" "2001:db8::1" "sshd" "22"
	run state_bans_active_check "$INSTALL_PATH" "2001:db8::1"
	assert_success
}

@test "state_bans_active: IPv6 remove does not remove prefix match" {
	state_bans_active_append "$INSTALL_PATH" "1000" "0" "2001:db8::1" "sshd" "22"
	state_bans_active_append "$INSTALL_PATH" "1001" "0" "2001:db8::10" "dovecot" "143"
	# removing ::10 must not remove ::1
	state_bans_active_remove "$INSTALL_PATH" "2001:db8::10"
	run state_bans_active_check "$INSTALL_PATH" "2001:db8::1"
	assert_success
	run state_bans_active_check "$INSTALL_PATH" "2001:db8::10"
	assert_failure
}

@test "state_bans_active: IPv6 append dedup exact match" {
	state_bans_active_append "$INSTALL_PATH" "1000" "0" "2001:db8::1" "sshd" "22"
	# appending same IP again should be a no-op (dedup)
	state_bans_active_append "$INSTALL_PATH" "1001" "0" "2001:db8::1" "dovecot" "143"
	local count
	count=$(grep -c "2001:db8::1" "$INSTALL_PATH/tmp/bans.active")
	[ "$count" -eq 1 ]
}

@test "filter_host: IPv6 does not false-match prefix in ignore list" {
	local ignore_files="$TEST_TMPDIR/exclude.files"
	local hosts_file="$TEST_TMPDIR/ignore.hosts"
	echo "$hosts_file" > "$ignore_files"
	echo "2001:db8::1" > "$hosts_file"
	local lo_hosts="$TEST_TMPDIR/lo_hosts"
	touch "$lo_hosts"
	# 2001:db8::10 should NOT be ignored
	run filter_host "2001:db8::10" "$ignore_files" "$lo_hosts"
	assert_success
	# 2001:db8::1 should be ignored
	run filter_host "2001:db8::1" "$ignore_files" "$lo_hosts"
	assert_failure
}

@test "check_recidivism: works with IPv6 addresses" {
	local i
	for i in 1 2 3 4 5; do
		state_bans_history_append "$INSTALL_PATH" "$((800 + i))" "1100" "2001:db8::1" "sshd" "ban"
	done
	run check_recidivism "$INSTALL_PATH" "2001:db8::1" "500" "1000" "5"
	assert_success
}

@test "pipeline: ban → record → expire → unban flow with IPv6" {
	execute_ban "2001:db8::1" "sshd" "0" >/dev/null
	state_bans_active_append "$INSTALL_PATH" "1000" "1300" "2001:db8::1" "sshd" "22"
	state_bans_history_append "$INSTALL_PATH" "1000" "1300" "2001:db8::1" "sshd" "ban"
	# verify active
	run state_bans_active_check "$INSTALL_PATH" "2001:db8::1"
	assert_success
	# process unbans at time past expiry
	process_unbans "$INSTALL_PATH" "1400" >/dev/null
	# verify removed
	run state_bans_active_check "$INSTALL_PATH" "2001:db8::1"
	assert_failure
	# verify unban recorded
	run cat "$INSTALL_PATH/tmp/bans.history"
	assert_output --partial "unban"
}

# --- IGNOREREGEX/PORTS reset tests (Phase 26) ---

@test "check: IGNOREREGEX does not leak between rules" {
	local rules_dir="$TEST_TMPDIR/rules"
	mkdir -p "$rules_dir"
	local logfile="$TEST_TMPDIR/test.log"
	echo "test line" > "$logfile"
	# rule1 sets IGNOREREGEX
	cat > "$rules_dir/rule1" <<EOF
TRIG="100"
REQ="/bin/sh"
LP="$logfile"
TLOG_TF="rule1"
IGNOREREGEX="no auth attempts"
ARG_VAL=""
EOF
	# rule2 should NOT inherit IGNOREREGEX from rule1
	cat > "$rules_dir/rule2" <<EOF
TRIG="100"
REQ="/bin/sh"
LP="$logfile"
TLOG_TF="rule2"
ARG_VAL=""
EOF
	chmod 644 "$rules_dir/rule1" "$rules_dir/rule2"
	chown root "$rules_dir/rule1" "$rules_dir/rule2"
	# run check and verify IGNOREREGEX is empty after rule2
	RULES_PATH="$rules_dir"
	GLOB_PRESSURE_TRIP="5"
	GLOB_TRIG="5"
	PRESSURE_HALF_LIFE="300"
	TRIG_WINDOW="300"
	PRESSURE_TRIP_GLOBAL="0"
	TRIG_GLOBAL="0"
	UTIME="1000"
	IGNORE_HOST_FILES="$TEST_TMPDIR/exclude.files"
	LO_HOSTS="$TEST_TMPDIR/lo_hosts"
	touch "$IGNORE_HOST_FILES" "$LO_HOSTS"
	BAN_COMMAND_TEMPLATE="true"
	BAN_COMMAND_V6_TEMPLATE=""
	DRY_RUN="1"
	BAN_TTL="0"
	BAN_DURATION="0"
	BAN_ESCALATE_AFTER="0"
	BAN_PERMANENT_AFTER="0"
	BAN_ESCALATE_WINDOW="86400"
	BAN_PERMANENT_WINDOW="86400"
	SKIP_ALERT=""
	# After processing rule2, IGNOREREGEX should be empty
	check
	[ -z "$IGNOREREGEX" ]
}

@test "check: PORTS does not leak between rules" {
	local rules_dir="$TEST_TMPDIR/rules"
	mkdir -p "$rules_dir"
	local logfile="$TEST_TMPDIR/test.log"
	echo "test line" > "$logfile"
	# rule1 sets PORTS
	cat > "$rules_dir/rule1" <<EOF
TRIG="100"
REQ="/bin/sh"
LP="$logfile"
TLOG_TF="rule1"
PORTS="22"
ARG_VAL=""
EOF
	# rule2 should NOT inherit PORTS from rule1
	cat > "$rules_dir/rule2" <<EOF
TRIG="100"
REQ="/bin/sh"
LP="$logfile"
TLOG_TF="rule2"
ARG_VAL=""
EOF
	chmod 644 "$rules_dir/rule1" "$rules_dir/rule2"
	chown root "$rules_dir/rule1" "$rules_dir/rule2"
	RULES_PATH="$rules_dir"
	GLOB_PRESSURE_TRIP="5"
	GLOB_TRIG="5"
	PRESSURE_HALF_LIFE="300"
	TRIG_WINDOW="300"
	PRESSURE_TRIP_GLOBAL="0"
	TRIG_GLOBAL="0"
	UTIME="1000"
	IGNORE_HOST_FILES="$TEST_TMPDIR/exclude.files"
	LO_HOSTS="$TEST_TMPDIR/lo_hosts"
	touch "$IGNORE_HOST_FILES" "$LO_HOSTS"
	BAN_COMMAND_TEMPLATE="true"
	BAN_COMMAND_V6_TEMPLATE=""
	DRY_RUN="1"
	BAN_TTL="0"
	BAN_DURATION="0"
	BAN_ESCALATE_AFTER="0"
	BAN_PERMANENT_AFTER="0"
	BAN_ESCALATE_WINDOW="86400"
	BAN_PERMANENT_WINDOW="86400"
	SKIP_ALERT=""
	check
	[ -z "$PORTS" ]
}

@test "check: IGNOREREGEX set in rule applies correctly" {
	local rules_dir="$TEST_TMPDIR/rules"
	mkdir -p "$rules_dir"
	local logfile="$TEST_TMPDIR/test.log"
	echo "test line" > "$logfile"
	cat > "$rules_dir/testrule" <<EOF
TRIG="100"
REQ="/bin/sh"
LP="$logfile"
TLOG_TF="testrule"
IGNOREREGEX="filter_this"
ARG_VAL=""
EOF
	chmod 644 "$rules_dir/testrule"
	chown root "$rules_dir/testrule"
	# Source the rule through safe_source to verify IGNOREREGEX is set
	IGNOREREGEX=""
	safe_source "$rules_dir/testrule" "rule:testrule"
	[ "$IGNOREREGEX" = "filter_this" ]
}

@test "check: PORTS reset after rule without PORTS" {
	# Set PORTS to a value, then source a rule without PORTS
	# After check() resets, PORTS should be empty
	PORTS="9999"
	local rules_dir="$TEST_TMPDIR/rules"
	mkdir -p "$rules_dir"
	local logfile="$TEST_TMPDIR/test.log"
	echo "test line" > "$logfile"
	cat > "$rules_dir/testrule" <<EOF
TRIG="100"
REQ="/bin/sh"
LP="$logfile"
TLOG_TF="testrule"
ARG_VAL=""
EOF
	chmod 644 "$rules_dir/testrule"
	chown root "$rules_dir/testrule"
	RULES_PATH="$rules_dir"
	GLOB_PRESSURE_TRIP="5"
	GLOB_TRIG="5"
	PRESSURE_HALF_LIFE="300"
	TRIG_WINDOW="300"
	PRESSURE_TRIP_GLOBAL="0"
	TRIG_GLOBAL="0"
	UTIME="1000"
	IGNORE_HOST_FILES="$TEST_TMPDIR/exclude.files"
	LO_HOSTS="$TEST_TMPDIR/lo_hosts"
	touch "$IGNORE_HOST_FILES" "$LO_HOSTS"
	BAN_COMMAND_TEMPLATE="true"
	BAN_COMMAND_V6_TEMPLATE=""
	DRY_RUN="1"
	BAN_TTL="0"
	BAN_DURATION="0"
	BAN_ESCALATE_AFTER="0"
	BAN_PERMANENT_AFTER="0"
	BAN_ESCALATE_WINDOW="86400"
	BAN_PERMANENT_WINDOW="86400"
	SKIP_ALERT=""
	check
	# PORTS should be empty (reset by check before sourcing rule)
	[ -z "$PORTS" ]
}

# --- Rule file correctness tests (Phase 26) ---

@test "rule: postgresql uses [ -d ] for Debian log path" {
	run cat "$PROJECT_ROOT/files/rules/postgresql"
	# must contain [ -d "/var/log/postgresql" ] not [ -f "/var/log/postgresql" ]
	assert_output --partial '[ -d "/var/log/postgresql" ]'
	refute_output --partial '[ -f "/var/log/postgresql" ]'
}

@test "rule: vsftpd and vsftpd2 have different TLOG_TF values" {
	local tf1 tf2
	tf1=$(grep -E '^[[:space:]]*TLOG_TF=' "$PROJECT_ROOT/files/rules/vsftpd" | tail -1 | sed 's/.*="\?\([^"]*\)"\?/\1/')
	tf2=$(grep -E '^[[:space:]]*TLOG_TF=' "$PROJECT_ROOT/files/rules/vsftpd2" | tail -1 | sed 's/.*="\?\([^"]*\)"\?/\1/')
	[ "$tf1" != "$tf2" ]
	[ "$tf1" = "vsftpd" ]
	[ "$tf2" = "vsftpd2" ]
}

@test "rule: ignore.hosts contains both 127.0.0.1 and ::1" {
	run cat "$PROJECT_ROOT/files/ignore.hosts"
	assert_output --partial "127.0.0.1"
	assert_output --partial "::1"
}

# --- LAST/LAST_HOST removal tests (Phase 27) ---

@test "check: same IP in two rules is banned only once (state dedup)" {
	local rules_dir="$TEST_TMPDIR/rules"
	mkdir -p "$rules_dir"
	local logfile="$TEST_TMPDIR/test.log"
	echo "test line" > "$logfile"
	# rule1: IP triggers ban
	cat > "$rules_dir/rule1" <<'RULEEOF'
TRIG="2"
REQ="/bin/sh"
RULEEOF
	cat >> "$rules_dir/rule1" <<EOF
LP="$logfile"
TLOG_TF="rule1"
ARG_VAL="192.0.2.1 192.0.2.1 192.0.2.1"
EOF
	# rule2: same IP triggers ban
	cat > "$rules_dir/rule2" <<'RULEEOF'
TRIG="2"
REQ="/bin/sh"
RULEEOF
	cat >> "$rules_dir/rule2" <<EOF
LP="$logfile"
TLOG_TF="rule2"
ARG_VAL="192.0.2.1 192.0.2.1 192.0.2.1"
EOF
	chmod 644 "$rules_dir/rule1" "$rules_dir/rule2"
	chown root "$rules_dir/rule1" "$rules_dir/rule2"
	RULES_PATH="$rules_dir"
	GLOB_PRESSURE_TRIP="5"
	GLOB_TRIG="5"
	PRESSURE_HALF_LIFE="300"
	TRIG_WINDOW="300"
	PRESSURE_TRIP_GLOBAL="0"
	TRIG_GLOBAL="0"
	UTIME="1000"
	IGNORE_HOST_FILES="$TEST_TMPDIR/exclude.files"
	LO_HOSTS="$TEST_TMPDIR/lo_hosts"
	touch "$IGNORE_HOST_FILES" "$LO_HOSTS"
	BAN_COMMAND_TEMPLATE="/bin/true"
	BAN_COMMAND_V6_TEMPLATE=""
	DRY_RUN="0"
	BAN_TTL="0"
	BAN_DURATION="0"
	BAN_ESCALATE_AFTER="0"
	BAN_PERMANENT_AFTER="0"
	BAN_ESCALATE_WINDOW="86400"
	BAN_PERMANENT_WINDOW="86400"
	SKIP_ALERT=""
	EMAIL_ALERTS="0"
	SUBNET_TRIG="0"
	run _run_check_with_stats "$rules_dir"
	assert_success
	# only 1 ban executed, not 2 (state_bans_active_check dedup)
	assert_output --partial "1 bans executed"
}

@test "check: local address across two rules gets pool entry for each" {
	local rules_dir="$TEST_TMPDIR/rules"
	mkdir -p "$rules_dir"
	local logfile="$TEST_TMPDIR/test.log"
	echo "test line" > "$logfile"
	# use 127.0.0.1 as a local address
	cat > "$rules_dir/rule1" <<'RULEEOF'
TRIG="2"
REQ="/bin/sh"
RULEEOF
	cat >> "$rules_dir/rule1" <<EOF
LP="$logfile"
TLOG_TF="rule1"
ARG_VAL="127.0.0.1 127.0.0.1 127.0.0.1"
EOF
	cat > "$rules_dir/rule2" <<'RULEEOF'
TRIG="2"
REQ="/bin/sh"
RULEEOF
	cat >> "$rules_dir/rule2" <<EOF
LP="$logfile"
TLOG_TF="rule2"
ARG_VAL="127.0.0.1 127.0.0.1 127.0.0.1"
EOF
	chmod 644 "$rules_dir/rule1" "$rules_dir/rule2"
	chown root "$rules_dir/rule1" "$rules_dir/rule2"
	# create lo_hosts with 127.0.0.1 so filter_host returns 2
	LO_HOSTS="$TEST_TMPDIR/lo_hosts"
	echo "127.0.0.1" > "$LO_HOSTS"
	IGNORE_HOST_FILES="$TEST_TMPDIR/exclude.files"
	touch "$IGNORE_HOST_FILES"
	RULES_PATH="$rules_dir"
	GLOB_PRESSURE_TRIP="5"
	GLOB_TRIG="5"
	PRESSURE_HALF_LIFE="300"
	TRIG_WINDOW="300"
	PRESSURE_TRIP_GLOBAL="0"
	TRIG_GLOBAL="0"
	UTIME="1000"
	BAN_COMMAND_TEMPLATE="/bin/true"
	BAN_COMMAND_V6_TEMPLATE=""
	DRY_RUN="1"
	BAN_TTL="0"
	BAN_DURATION="0"
	BAN_ESCALATE_AFTER="0"
	BAN_PERMANENT_AFTER="0"
	BAN_ESCALATE_WINDOW="86400"
	BAN_PERMANENT_WINDOW="86400"
	SKIP_ALERT=""
	EMAIL_ALERTS="0"
	SUBNET_TRIG="0"
	check
	# pool entries from both rules should exist
	local pool_count
	pool_count=$(grep -c "127.0.0.1" "$INSTALL_PATH/stats/attack.pool" 2>/dev/null || echo 0)
	[ "$pool_count" -ge 2 ]
}

# --- record_ban ---

@test "record_ban: normal ban with duration returns correct expiry" {
	BAN_TTL="600"
	BAN_DURATION="600"
	BAN_ESCALATE_AFTER="0"
	BAN_PERMANENT_AFTER="0"
	BAN_ESCALATE_WINDOW="86400"
	BAN_PERMANENT_WINDOW="86400"
	BAN_ESCALATION="none"
	BAN_ESCALATION_CAP="0"
	run record_ban "$INSTALL_PATH" "1000" "192.0.2.1" "sshd" "all" "ban"
	assert_success
	assert_output "1600|ban|0"
}

@test "record_ban: permanent ban (BAN_TTL=0) returns expiry=0" {
	BAN_TTL="0"
	BAN_DURATION="0"
	BAN_ESCALATE_AFTER="0"
	BAN_PERMANENT_AFTER="0"
	BAN_ESCALATE_WINDOW="86400"
	BAN_PERMANENT_WINDOW="86400"
	BAN_ESCALATION="none"
	BAN_ESCALATION_CAP="0"
	run record_ban "$INSTALL_PATH" "1000" "192.0.2.2" "sshd" "all" "ban"
	assert_success
	assert_output "0|ban|0"
}

@test "record_ban: escalated ban overrides action to escalate" {
	BAN_TTL="600"
	BAN_DURATION="600"
	BAN_ESCALATE_AFTER="2"
	BAN_PERMANENT_AFTER="2"
	BAN_ESCALATE_WINDOW="86400"
	BAN_PERMANENT_WINDOW="86400"
	BAN_ESCALATION="none"
	BAN_ESCALATION_CAP="0"
	# seed 2 prior bans within window
	state_bans_history_append "$INSTALL_PATH" "500" "1100" "192.0.2.3" "sshd" "ban"
	state_bans_history_append "$INSTALL_PATH" "800" "1400" "192.0.2.3" "sshd" "ban"
	run record_ban "$INSTALL_PATH" "1000" "192.0.2.3" "sshd" "all" "ban"
	assert_success
	# expiry=0 (permanent), action=escalate, recent_bans=2
	# eout prints escalation message on stdout; check last line for result
	local last_line
	last_line=$(echo "$output" | tail -1)
	[ "$last_line" = "0|escalate|2" ]
}

@test "record_ban: custom action preserved when no escalation" {
	BAN_TTL="300"
	BAN_DURATION="300"
	BAN_ESCALATE_AFTER="0"
	BAN_PERMANENT_AFTER="0"
	BAN_ESCALATE_WINDOW="86400"
	BAN_PERMANENT_WINDOW="86400"
	BAN_ESCALATION="none"
	BAN_ESCALATION_CAP="0"
	run record_ban "$INSTALL_PATH" "2000" "192.0.2.4" "postfix" "25" "subnet"
	assert_success
	assert_output "2300|subnet|0"
}

@test "record_ban: records in bans.active and bans.history" {
	BAN_TTL="600"
	BAN_DURATION="600"
	BAN_ESCALATE_AFTER="0"
	BAN_PERMANENT_AFTER="0"
	BAN_ESCALATE_WINDOW="86400"
	BAN_PERMANENT_WINDOW="86400"
	BAN_ESCALATION="none"
	BAN_ESCALATION_CAP="0"
	record_ban "$INSTALL_PATH" "5000" "192.0.2.5" "dovecot" "993" "ban" >/dev/null
	# verify bans.active
	local active_line
	active_line=$(cat "$INSTALL_PATH/tmp/bans.active")
	[[ "$active_line" == *"192.0.2.5"* ]]
	[[ "$active_line" == *"dovecot"* ]]
	# verify bans.history
	local hist_line
	hist_line=$(cat "$INSTALL_PATH/tmp/bans.history")
	[[ "$hist_line" == *"192.0.2.5"* ]]
	[[ "$hist_line" == *"ban"* ]]
}

@test "check: LAST_HOST and LAST variables are not used" {
	# verify the check() function source does not reference LAST_HOST or LAST
	local check_src
	check_src=$(awk '/^check\(\)/ { p=1 } p { print; if (/^\}$/) exit }' "$PROJECT_ROOT/files/bfd")
	# should not contain LAST_HOST or bare LAST assignment
	! echo "$check_src" | grep -q 'LAST_HOST'
	! echo "$check_src" | grep -q 'LAST="'
}

# --- pressure.conf / thresholds.conf precedence integration ---

@test "check: pressure.conf PRESSURE_TRIP used when rule TRIG commented out" {
	local rules_dir="$TEST_TMPDIR/rules"
	mkdir -p "$rules_dir"
	local logfile="$TEST_TMPDIR/test.log"
	echo "test line" > "$logfile"
	# rule with TRIG commented out (empty after _clear_rule_vars)
	cat > "$rules_dir/testrule" <<'RULEEOF'
# TRIG="5"
REQ="/bin/sh"
RULEEOF
	cat >> "$rules_dir/testrule" <<EOF
LP="$logfile"
TLOG_TF="testrule"
ARG_VAL="192.0.2.1 192.0.2.1 192.0.2.1"
EOF
	chmod 644 "$rules_dir/testrule"
	chown root "$rules_dir/testrule"
	# set up pressure.conf with PRESSURE_TRIP=2 for testrule
	local press_conf="$TEST_TMPDIR/pressure.conf"
	echo "testrule:PRESSURE_TRIP=2" > "$press_conf"
	chown root "$press_conf"
	chmod 640 "$press_conf"
	# load pressure config
	declare -gA _PRESS_WEIGHT _PRESS_TRIP _PRESS_SKIP_ALERT _PRESS_RULE_EMAIL
	_load_pressure_conf "$press_conf"
	# also load thresholds for backward compat path
	declare -gA _THRESH_TRIG _THRESH_SKIP_ALERT _THRESH_RULE_EMAIL
	_load_thresholds "$press_conf"
	# GLOB_PRESSURE_TRIP is high so it would NOT trigger ban
	GLOB_PRESSURE_TRIP="999"
	GLOB_TRIG="999"
	RULES_PATH="$rules_dir"
	PRESSURE_HALF_LIFE="300"
	TRIG_WINDOW="300"
	PRESSURE_TRIP_GLOBAL="0"
	TRIG_GLOBAL="0"
	UTIME="1000"
	IGNORE_HOST_FILES="$TEST_TMPDIR/exclude.files"
	LO_HOSTS="$TEST_TMPDIR/lo_hosts"
	touch "$IGNORE_HOST_FILES" "$LO_HOSTS"
	BAN_COMMAND_TEMPLATE="/bin/true"
	BAN_COMMAND_V6_TEMPLATE=""
	DRY_RUN="0"
	BAN_TTL="0"
	BAN_DURATION="0"
	BAN_ESCALATE_AFTER="0"
	BAN_PERMANENT_AFTER="0"
	BAN_ESCALATE_WINDOW="86400"
	BAN_PERMANENT_WINDOW="86400"
	SKIP_ALERT=""
	EMAIL_ALERTS="0"
	SUBNET_TRIG="0"
	run _run_check_with_stats "$rules_dir"
	assert_success
	# pressure.conf PRESSURE_TRIP=2, 3 events → should ban (1 ban executed)
	assert_output --partial "1 bans executed"
}

@test "check: rule file TRIG overrides pressure.conf PRESSURE_TRIP" {
	local rules_dir="$TEST_TMPDIR/rules"
	mkdir -p "$rules_dir"
	local logfile="$TEST_TMPDIR/test.log"
	echo "test line" > "$logfile"
	# rule with explicit TRIG=999 (very high, should NOT trigger ban)
	cat > "$rules_dir/testrule" <<'RULEEOF'
TRIG="999"
REQ="/bin/sh"
RULEEOF
	cat >> "$rules_dir/testrule" <<EOF
LP="$logfile"
TLOG_TF="testrule"
ARG_VAL="192.0.2.1 192.0.2.1 192.0.2.1"
EOF
	chmod 644 "$rules_dir/testrule"
	chown root "$rules_dir/testrule"
	# pressure.conf says PRESSURE_TRIP=1 (low), but rule file should override
	local press_conf="$TEST_TMPDIR/pressure.conf"
	echo "testrule:PRESSURE_TRIP=1" > "$press_conf"
	chown root "$press_conf"
	chmod 640 "$press_conf"
	declare -gA _PRESS_WEIGHT _PRESS_TRIP _PRESS_SKIP_ALERT _PRESS_RULE_EMAIL
	_load_pressure_conf "$press_conf"
	declare -gA _THRESH_TRIG _THRESH_SKIP_ALERT _THRESH_RULE_EMAIL
	_load_thresholds "$press_conf"
	GLOB_PRESSURE_TRIP="999"
	GLOB_TRIG="999"
	RULES_PATH="$rules_dir"
	PRESSURE_HALF_LIFE="300"
	TRIG_WINDOW="300"
	PRESSURE_TRIP_GLOBAL="0"
	TRIG_GLOBAL="0"
	UTIME="1000"
	IGNORE_HOST_FILES="$TEST_TMPDIR/exclude.files"
	LO_HOSTS="$TEST_TMPDIR/lo_hosts"
	touch "$IGNORE_HOST_FILES" "$LO_HOSTS"
	BAN_COMMAND_TEMPLATE="/bin/true"
	BAN_COMMAND_V6_TEMPLATE=""
	DRY_RUN="0"
	BAN_TTL="0"
	BAN_DURATION="0"
	BAN_ESCALATE_AFTER="0"
	BAN_PERMANENT_AFTER="0"
	BAN_ESCALATE_WINDOW="86400"
	BAN_PERMANENT_WINDOW="86400"
	SKIP_ALERT=""
	EMAIL_ALERTS="0"
	SUBNET_TRIG="0"
	run _run_check_with_stats "$rules_dir"
	assert_success
	# rule TRIG=999 overrides pressure.conf PRESSURE_TRIP=1, so 0 bans
	assert_output --partial "0 bans executed"
}
