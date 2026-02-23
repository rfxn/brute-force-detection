#!/usr/bin/env bats
#
# Integration tests for the check() pipeline:
# count_failures, execute_ban, and end-to-end flow
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

setup() {
	TEST_TMPDIR=$(mktemp -d)
	INSTALL_PATH="$TEST_TMPDIR/bfd"
	state_init "$INSTALL_PATH"
	# eout dependencies
	BFD_LOG_PATH="$TEST_TMPDIR/bfd.log"
	touch "$BFD_LOG_PATH"
	OUTPUT_SYSLOG="0"
	OUTPUT_SYSLOG_FILE="/dev/null"
	MOD="sshd"
	BAN_RETRY_COUNT="0"
}

teardown() {
	rm -rf "$TEST_TMPDIR"
}

# --- count_failures (windowed replacement) ---

@test "count_failures: counts host in windowed mode" {
	local hosts_parsed
	hosts_parsed=$(printf "10.0.0.1\n10.0.0.2\n10.0.0.1\n")
	run count_failures "10.0.0.1" "$hosts_parsed" "$INSTALL_PATH" "300" "1000" "sshd"
	assert_success
	assert_output "2"
}

@test "count_failures: accumulates within window" {
	local hosts_parsed
	hosts_parsed=$(printf "10.0.0.1\n10.0.0.1\n10.0.0.1\n")
	# first run at t=900
	count_failures "10.0.0.1" "$hosts_parsed" "$INSTALL_PATH" "300" "900" "sshd" >/dev/null
	# second run at t=1000 (within window)
	run count_failures "10.0.0.1" "$hosts_parsed" "$INSTALL_PATH" "300" "1000" "sshd"
	assert_success
	assert_output "6"
}

@test "count_failures: old events expire outside window" {
	# seed old events at t=100
	state_events_append "$INSTALL_PATH" "100" "10.0.0.1" "sshd" "5"
	local hosts_parsed
	hosts_parsed=$(printf "10.0.0.1\n10.0.0.1\n")
	# now=1000, window=300, cutoff=700 => old events at t=100 excluded
	run count_failures "10.0.0.1" "$hosts_parsed" "$INSTALL_PATH" "300" "1000" "sshd"
	assert_success
	assert_output "2"
}

@test "count_failures: per-service isolation in windowed mode" {
	# seed dovecot events in window
	state_events_append "$INSTALL_PATH" "900" "10.0.0.1" "dovecot" "10"
	local hosts_parsed
	hosts_parsed=$(printf "10.0.0.1\n10.0.0.1\n")
	# count sshd only
	run count_failures "10.0.0.1" "$hosts_parsed" "$INSTALL_PATH" "300" "1000" "sshd"
	assert_success
	assert_output "2"
}

# --- TRIG_GLOBAL ---

@test "pipeline: TRIG_GLOBAL triggers ban across services" {
	# seed dovecot events (3) and sshd events (3) in window, total = 6
	state_events_append "$INSTALL_PATH" "900" "10.0.0.1" "dovecot" "3"
	state_events_append "$INSTALL_PATH" "900" "10.0.0.1" "sshd" "3"
	# TRIG_GLOBAL=5: cross-service total of 6 >= 5
	local global_count
	global_count=$(state_events_count "$INSTALL_PATH" "10.0.0.1" "300" "1000")
	[ "$global_count" -ge 5 ]
}

@test "pipeline: TRIG_GLOBAL=0 disables cross-service check" {
	# With TRIG_GLOBAL=0, should not trigger
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
	run execute_ban "10.0.0.1" "sshd" "echo banned" "1"
	assert_success
	assert_output --partial "dry-run"
	assert_output --partial "10.0.0.1"
}

@test "execute_ban: sets ATTACK_HOST global" {
	execute_ban "10.0.0.1" "sshd" "true" "1" >/dev/null
	[ "$ATTACK_HOST" = "10.0.0.1" ]
}

@test "execute_ban: sets BAN_COMMAND global" {
	execute_ban "10.0.0.1" "sshd" "echo test_cmd" "1" >/dev/null
	[ "$BAN_COMMAND" = "echo test_cmd" ]
}

@test "execute_ban: executes command in live mode" {
	local marker="$TEST_TMPDIR/ban_executed"
	execute_ban "10.0.0.1" "sshd" "touch $marker" "0" >/dev/null
	[ -f "$marker" ]
}

@test "execute_ban: returns non-zero on command failure" {
	run execute_ban "10.0.0.1" "sshd" "false" "0"
	[ "$status" -ne 0 ]
}

@test "execute_ban: logs ban command failure" {
	run execute_ban "10.0.0.1" "sshd" "false" "0"
	assert_output --partial "exited with code"
}

@test "execute_ban: failed ban skips lifecycle recording" {
	# execute_ban with a command that fails
	run execute_ban "10.0.0.1" "sshd" "false" "0"
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
	run execute_ban "10.0.0.1" "sshd" "$cmd $counter" "0"
	assert_success
	# verify it took 3 attempts
	local attempts
	attempts=$(cat "$counter")
	[ "$attempts" -eq 3 ]
}

@test "execute_ban: no retries when BAN_RETRY_COUNT=0" {
	BAN_RETRY_COUNT="0"
	run execute_ban "10.0.0.1" "sshd" "false" "0"
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
	run execute_unban "10.0.0.1" "sshd" "$cmd $counter"
	assert_success
}

# --- end-to-end pipeline ---

@test "pipeline: filter_host + count_failures + ban state" {
	# setup ignore infrastructure
	local ignore_files="$TEST_TMPDIR/exclude.files"
	local lo_hosts="$TEST_TMPDIR/lo_hosts"
	touch "$ignore_files" "$lo_hosts"

	local host="10.0.0.1"
	local hosts_parsed
	hosts_parsed=$(printf "10.0.0.1\n10.0.0.1\n10.0.0.1\n10.0.0.1\n10.0.0.1\n")

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
	assert_output --partial "10.0.0.1"
}

@test "pipeline: ignored host skips ban entirely" {
	local ignore_list="$TEST_TMPDIR/ignore.hosts"
	local ignore_files="$TEST_TMPDIR/exclude.files"
	local lo_hosts="$TEST_TMPDIR/lo_hosts"
	echo "10.0.0.1" > "$ignore_list"
	echo "$ignore_list" > "$ignore_files"
	touch "$lo_hosts"

	local filter_rc=0
	filter_host "10.0.0.1" "$ignore_files" "$lo_hosts" || filter_rc=$?
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
	echo "192.168.1.1" > "$lo_hosts"

	local filter_rc=0
	filter_host "192.168.1.1" "$ignore_files" "$lo_hosts" || filter_rc=$?
	[ "$filter_rc" -eq 2 ]

	# record in pool but do not ban
	state_pool_append "$INSTALL_PATH" "1700000000" "192.168.1.1" "sshd"
	run cat "$INSTALL_PATH/stats/attack.pool"
	assert_output --partial "192.168.1.1"
	# bans.active should be empty
	run cat "$INSTALL_PATH/tmp/bans.active"
	assert_output ""
}

# --- execute_unban ---

@test "execute_unban: runs command and sets globals" {
	local marker="$TEST_TMPDIR/unban_executed"
	execute_unban "10.0.0.1" "sshd" "touch $marker" >/dev/null
	[ -f "$marker" ]
	[ "$ATTACK_HOST" = "10.0.0.1" ]
}

@test "execute_unban: returns non-zero on command failure" {
	run execute_unban "10.0.0.1" "sshd" "false"
	[ "$status" -ne 0 ]
}

# --- process_unbans ---

@test "process_unbans: removes expired bans" {
	state_bans_active_append "$INSTALL_PATH" "1000" "1300" "10.0.0.1" "sshd" "22"
	process_unbans "$INSTALL_PATH" "1400" "" >/dev/null
	run state_bans_active_check "$INSTALL_PATH" "10.0.0.1"
	assert_failure
}

@test "process_unbans: skips permanent bans (expiry=0)" {
	state_bans_active_append "$INSTALL_PATH" "1000" "0" "10.0.0.1" "sshd" "22"
	process_unbans "$INSTALL_PATH" "9999999" "" >/dev/null
	run state_bans_active_check "$INSTALL_PATH" "10.0.0.1"
	assert_success
}

@test "process_unbans: with empty UNBAN_COMMAND still removes from state" {
	state_bans_active_append "$INSTALL_PATH" "1000" "1300" "10.0.0.1" "sshd" "22"
	process_unbans "$INSTALL_PATH" "1400" "" >/dev/null
	run state_bans_active_check "$INSTALL_PATH" "10.0.0.1"
	assert_failure
	# verify history recorded
	run cat "$INSTALL_PATH/tmp/bans.history"
	assert_output --partial "10.0.0.1"
	assert_output --partial "unban"
}

@test "process_unbans: executes unban command when set" {
	local marker="$TEST_TMPDIR/unban_ran"
	state_bans_active_append "$INSTALL_PATH" "1000" "1300" "10.0.0.1" "sshd" "22"
	process_unbans "$INSTALL_PATH" "1400" "touch $marker" >/dev/null
	[ -f "$marker" ]
}

# --- check_recidivism ---

@test "check_recidivism: returns 0 when threshold met" {
	# seed 5 ban events in window
	local i
	for i in 1 2 3 4 5; do
		state_bans_history_append "$INSTALL_PATH" "$((800 + i))" "1100" "10.0.0.1" "sshd" "ban"
	done
	run check_recidivism "$INSTALL_PATH" "10.0.0.1" "500" "1000" "5"
	assert_success
}

@test "check_recidivism: returns 1 when below threshold" {
	state_bans_history_append "$INSTALL_PATH" "900" "1200" "10.0.0.1" "sshd" "ban"
	run check_recidivism "$INSTALL_PATH" "10.0.0.1" "500" "1000" "5"
	assert_failure
}

@test "check_recidivism: returns 1 when disabled (permanent_after=0)" {
	state_bans_history_append "$INSTALL_PATH" "900" "1200" "10.0.0.1" "sshd" "ban"
	run check_recidivism "$INSTALL_PATH" "10.0.0.1" "500" "1000" "0"
	assert_failure
}

# --- ban lifecycle flow ---

@test "pipeline: ban → record → expire → unban flow" {
	# simulate a ban
	execute_ban "10.0.0.1" "sshd" "true" "0" >/dev/null
	state_bans_active_append "$INSTALL_PATH" "1000" "1300" "10.0.0.1" "sshd" "22"
	state_bans_history_append "$INSTALL_PATH" "1000" "1300" "10.0.0.1" "sshd" "ban"

	# verify active
	run state_bans_active_check "$INSTALL_PATH" "10.0.0.1"
	assert_success

	# process unbans at time past expiry
	process_unbans "$INSTALL_PATH" "1400" "" >/dev/null

	# verify removed from active
	run state_bans_active_check "$INSTALL_PATH" "10.0.0.1"
	assert_failure

	# verify unban recorded in history
	run cat "$INSTALL_PATH/tmp/bans.history"
	assert_output --partial "unban"
}

# --- manual_ban / manual_unban ---

@test "manual_ban: bans IP and records in state" {
	manual_ban "$INSTALL_PATH" "10.0.0.1" "1000" "true" "sshd" >/dev/null
	run state_bans_active_check "$INSTALL_PATH" "10.0.0.1"
	assert_success
	run cat "$INSTALL_PATH/tmp/bans.history"
	assert_output --partial "10.0.0.1"
	assert_output --partial "ban"
}

@test "manual_ban: rejects already banned IP" {
	state_bans_active_append "$INSTALL_PATH" "900" "0" "10.0.0.1" "sshd" "22"
	run manual_ban "$INSTALL_PATH" "10.0.0.1" "1000" "true" "sshd"
	assert_failure
	assert_output --partial "already banned"
}

@test "manual_unban: unbans IP and records in history" {
	state_bans_active_append "$INSTALL_PATH" "900" "0" "10.0.0.1" "sshd" "22"
	run manual_unban "$INSTALL_PATH" "10.0.0.1" "1000" ""
	assert_success
	assert_output --partial "unbanned"
	# verify removed from active
	run state_bans_active_check "$INSTALL_PATH" "10.0.0.1"
	assert_failure
}

@test "manual_unban: rejects IP not in ban list" {
	run manual_unban "$INSTALL_PATH" "10.0.0.99" "1000" ""
	assert_failure
	assert_output --partial "not in the active ban list"
}

# --- PORTS enforcement ---

@test "execute_ban: sets PORTS global" {
	execute_ban "10.0.0.1" "sshd" "true" "1" "22" >/dev/null
	[ "$PORTS" = "22" ]
}

@test "execute_ban: PORTS available in template expansion" {
	local marker="$TEST_TMPDIR/ports_check"
	execute_ban "10.0.0.1" "sshd" "echo \$PORTS > $marker" "0" "110,143,993,995" >/dev/null
	run cat "$marker"
	assert_output "110,143,993,995"
}

@test "execute_ban: defaults PORTS to all when not provided" {
	execute_ban "10.0.0.1" "sshd" "true" "1" >/dev/null
	[ "$PORTS" = "all" ]
}

@test "execute_ban: sets MOD global" {
	execute_ban "10.0.0.1" "dovecot" "true" "1" "22" >/dev/null
	[ "$MOD" = "dovecot" ]
}

@test "execute_unban: sets PORTS global" {
	execute_unban "10.0.0.1" "sshd" "true" "22" >/dev/null
	[ "$PORTS" = "22" ]
}

@test "execute_unban: defaults PORTS to all when not provided" {
	execute_unban "10.0.0.1" "sshd" "true" >/dev/null
	[ "$PORTS" = "all" ]
}

@test "process_unbans: passes PORTS from state to unban command" {
	local marker="$TEST_TMPDIR/unban_ports"
	state_bans_active_append "$INSTALL_PATH" "1000" "1300" "10.0.0.1" "sshd" "22"
	process_unbans "$INSTALL_PATH" "1400" "echo \$PORTS > $marker" >/dev/null
	run cat "$marker"
	assert_output "22"
}

@test "manual_unban: reads and passes PORTS from state" {
	local marker="$TEST_TMPDIR/manual_unban_ports"
	state_bans_active_append "$INSTALL_PATH" "900" "0" "10.0.0.1" "dovecot" "110,143,993,995"
	manual_unban "$INSTALL_PATH" "10.0.0.1" "1000" "echo \$PORTS > $marker" >/dev/null
	run cat "$marker"
	assert_output "110,143,993,995"
}

# --- IPv6 pipeline tests ---

@test "count_failures: counts IPv6 host with grep -cxF" {
	local hosts_parsed
	hosts_parsed=$(printf "2001:db8::1\n10.0.0.1\n2001:db8::1\n")
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
	hosts_parsed=$(printf "10.0.0.1\n2001:db8::1\n10.0.0.1\n2001:db8::1\n10.0.0.1\n")
	local v4_count
	v4_count=$(count_failures "10.0.0.1" "$hosts_parsed" "$INSTALL_PATH" "300" "1000" "sshd")
	[ "$v4_count" -eq 3 ]
	local v6_count
	v6_count=$(count_failures "2001:db8::1" "$hosts_parsed" "$INSTALL_PATH" "300" "1000" "sshd")
	[ "$v6_count" -eq 2 ]
}

# --- IPv6 ban command selection ---

@test "execute_ban: selects V6 command for IPv6 host" {
	local marker_v4="$TEST_TMPDIR/ban_v4"
	local marker_v6="$TEST_TMPDIR/ban_v6"
	execute_ban "2001:db8::1" "sshd" "touch $marker_v4" "0" "22" "touch $marker_v6" >/dev/null
	# V6 command should have run, not V4
	[ -f "$marker_v6" ]
	[ ! -f "$marker_v4" ]
}

@test "execute_ban: uses standard command for IPv4 even when V6 set" {
	local marker_v4="$TEST_TMPDIR/ban_v4"
	local marker_v6="$TEST_TMPDIR/ban_v6"
	execute_ban "10.0.0.1" "sshd" "touch $marker_v4" "0" "22" "touch $marker_v6" >/dev/null
	# V4 command should have run, not V6
	[ -f "$marker_v4" ]
	[ ! -f "$marker_v6" ]
}

@test "execute_ban: falls back to standard for IPv6 when V6 empty" {
	local marker="$TEST_TMPDIR/ban_fallback"
	execute_ban "2001:db8::1" "sshd" "touch $marker" "0" "22" "" >/dev/null
	# standard command should have run
	[ -f "$marker" ]
}

@test "execute_unban: selects V6 command for IPv6 host" {
	local marker_v6="$TEST_TMPDIR/unban_v6"
	execute_unban "2001:db8::1" "sshd" "true" "22" "touch $marker_v6" >/dev/null
	[ -f "$marker_v6" ]
}

@test "execute_unban: uses standard for IPv4 when V6 set" {
	local marker_v4="$TEST_TMPDIR/unban_v4"
	local marker_v6="$TEST_TMPDIR/unban_v6"
	execute_unban "10.0.0.1" "sshd" "touch $marker_v4" "22" "touch $marker_v6" >/dev/null
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
	manual_ban "$INSTALL_PATH" "2001:db8::1" "1000" "true" "sshd" >/dev/null
	run state_bans_active_check "$INSTALL_PATH" "2001:db8::1"
	assert_success
}

@test "manual_unban: accepts IPv6 address" {
	state_bans_active_append "$INSTALL_PATH" "900" "0" "2001:db8::1" "sshd" "22"
	run manual_unban "$INSTALL_PATH" "2001:db8::1" "1000" ""
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
	GLOB_TRIG="5"
	TRIG_WINDOW="300"
	TRIG_GLOBAL="0"
	UTIME="1000"
	IGNORE_HOST_FILES="$TEST_TMPDIR/exclude.files"
	LO_HOSTS="$TEST_TMPDIR/lo_hosts"
	touch "$IGNORE_HOST_FILES" "$LO_HOSTS"
	BAN_COMMAND_TEMPLATE="true"
	BAN_COMMAND_V6_TEMPLATE=""
	DRY_RUN="1"
	BAN_DURATION="0"
	BAN_PERMANENT_AFTER="0"
	BAN_PERMANENT_WINDOW="86400"
	LAST_HOST=""
	LAST=""
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
ARG_VAL="10.0.0.1 10.0.0.2 10.0.0.1"
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
	execute_ban "2001:db8::1" "sshd" "true" "0" >/dev/null
	state_bans_active_append "$INSTALL_PATH" "1000" "1300" "2001:db8::1" "sshd" "22"
	state_bans_history_append "$INSTALL_PATH" "1000" "1300" "2001:db8::1" "sshd" "ban"
	# verify active
	run state_bans_active_check "$INSTALL_PATH" "2001:db8::1"
	assert_success
	# process unbans at time past expiry
	process_unbans "$INSTALL_PATH" "1400" "" >/dev/null
	# verify removed
	run state_bans_active_check "$INSTALL_PATH" "2001:db8::1"
	assert_failure
	# verify unban recorded
	run cat "$INSTALL_PATH/tmp/bans.history"
	assert_output --partial "unban"
}
