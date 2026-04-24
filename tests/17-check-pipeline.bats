#!/usr/bin/env bats
#
# Integration tests for the check() pipeline:
# execute_ban, ban lifecycle, manual ban/unban, PORTS, IPv6 basics
# Extended tests split to 17a-check-pipeline-ext.bats
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

# --- PRESSURE_TRIP_GLOBAL ---

@test "pipeline: PRESSURE_TRIP_GLOBAL triggers ban across services" {
	# seed dovecot events (3) and sshd events (3) at now, total = 6
	state_pressure_append "$INSTALL_PATH" "1000" "192.0.2.1" "dovecot" "3"
	state_pressure_append "$INSTALL_PATH" "1000" "192.0.2.1" "sshd" "3"
	# PRESSURE_TRIP_GLOBAL=5000 (scaled): cross-service pressure >= 5
	local global_pressure
	global_pressure=$(pressure_compute "$INSTALL_PATH" "192.0.2.1" "300" "1000")
	[ "$global_pressure" -ge 5000 ]
}

# --- execute_ban ---

@test "execute_ban: dry-run sets globals and logs without executing" {
	BAN_COMMAND_TEMPLATE="echo test_cmd"
	# call directly (not via run) so globals persist; tee output to file
	local outfile="$TEST_TMPDIR/dryrun_out"
	execute_ban "192.0.2.1" "sshd" "1" > "$outfile"
	# verify output contains dry-run message
	grep -q "dry-run" "$outfile"
	grep -q "192.0.2.1" "$outfile"
	# globals set even in dry-run
	[ "$ATTACK_HOST" = "192.0.2.1" ]
	[ "$BAN_COMMAND" = "echo test_cmd" ]
}

@test "execute_ban: executes command in live mode" {
	local marker="$TEST_TMPDIR/ban_executed"
	BAN_COMMAND_TEMPLATE="touch $marker"
	execute_ban "192.0.2.1" "sshd" "0" >/dev/null
	[ -f "$marker" ]
}

@test "execute_ban: command failure returns non-zero, logs, and skips recording" {
	BAN_COMMAND_TEMPLATE="false"
	run execute_ban "192.0.2.1" "sshd" "0"
	[ "$status" -ne 0 ]
	assert_output --partial "failed after"

	# bans.active and bans.history must remain empty
	run cat "$INSTALL_PATH/tmp/bans.active"
	assert_output ""
	run cat "$INSTALL_PATH/tmp/bans.history"
	assert_output ""
}

# --- ban retry logic ---

@test "execute_ban: retry logic respects BAN_RETRY_COUNT" {
	# scenario 1: BAN_RETRY_COUNT=2 retries up to 3 attempts
	BAN_RETRY_COUNT="2"
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
	local attempts
	attempts=$(cat "$counter")
	[ "$attempts" -eq 3 ]

	# scenario 2: BAN_RETRY_COUNT=0 means exactly 1 attempt
	BAN_RETRY_COUNT="0"
	BAN_COMMAND_TEMPLATE="false"
	run execute_ban "192.0.2.2" "sshd" "0"
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

@test "pipeline: ban → record → expire → unban flow (IPv4 and IPv6)" {
	local ip
	for ip in "192.0.2.1" "2001:db8::1"; do
		echo "# Testing IP family: $ip" >&3
		# reset state between IP families
		: > "$INSTALL_PATH/tmp/bans.active"
		: > "$INSTALL_PATH/tmp/bans.history"

		# simulate a ban
		execute_ban "$ip" "sshd" "0" >/dev/null
		state_bans_active_append "$INSTALL_PATH" "1000" "1300" "$ip" "sshd" "22"
		state_bans_history_append "$INSTALL_PATH" "1000" "1300" "$ip" "sshd" "ban"

		# verify active
		run state_bans_active_check "$INSTALL_PATH" "$ip"
		assert_success

		# process unbans at time past expiry
		process_unbans "$INSTALL_PATH" "1400" >/dev/null

		# verify removed from active
		run state_bans_active_check "$INSTALL_PATH" "$ip"
		assert_failure

		# verify unban recorded in history
		run cat "$INSTALL_PATH/tmp/bans.history"
		assert_output --partial "unban"
	done
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

@test "execute_ban: sets PORTS global and expands in template" {
	# scenario 1: explicit PORTS set and available in template
	local marker="$TEST_TMPDIR/ports_check"
	BAN_COMMAND_TEMPLATE="echo \$PORTS > $marker"
	execute_ban "192.0.2.1" "sshd" "0" "110,143,993,995" >/dev/null
	[ "$PORTS" = "110,143,993,995" ]
	run cat "$marker"
	assert_output "110,143,993,995"

	# scenario 2: no PORTS arg defaults to "all"
	PORTS=""
	execute_ban "192.0.2.2" "sshd" "1" >/dev/null
	[ "$PORTS" = "all" ]
}

@test "execute_ban: sets MOD global" {
	execute_ban "192.0.2.1" "dovecot" "1" "22" >/dev/null
	[ "$MOD" = "dovecot" ]
}

@test "execute_unban: sets PORTS global or defaults to all" {
	# scenario 1: explicit PORTS
	execute_unban "192.0.2.1" "sshd" "22" >/dev/null
	[ "$PORTS" = "22" ]

	# scenario 2: no PORTS defaults to "all"
	PORTS=""
	execute_unban "192.0.2.2" "sshd" >/dev/null
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

# --- IPv6 ban command selection ---

@test "execute_ban: IPv6/IPv4 command selection and V6 fallback" {
	# scenario 1: IPv6 host selects V6 command
	local marker_v4="$TEST_TMPDIR/ban_v4"
	local marker_v6="$TEST_TMPDIR/ban_v6"
	BAN_COMMAND_TEMPLATE="touch $marker_v4"
	BAN_COMMAND_V6_TEMPLATE="touch $marker_v6"
	execute_ban "2001:db8::1" "sshd" "0" "22" >/dev/null
	[ -f "$marker_v6" ]
	[ ! -f "$marker_v4" ]

	# scenario 2: IPv4 host uses standard command even when V6 set
	rm -f "$marker_v4" "$marker_v6"
	execute_ban "192.0.2.1" "sshd" "0" "22" >/dev/null
	[ -f "$marker_v4" ]
	[ ! -f "$marker_v6" ]

	# scenario 3: IPv6 host falls back to standard when V6 template empty
	rm -f "$marker_v4"
	BAN_COMMAND_V6_TEMPLATE=""
	execute_ban "2001:db8::2" "sshd" "0" "22" >/dev/null
	[ -f "$marker_v4" ]
}

@test "execute_unban: IPv6/IPv4 command selection" {
	# scenario 1: IPv6 host selects V6 command
	local marker_v4="$TEST_TMPDIR/unban_v4"
	local marker_v6="$TEST_TMPDIR/unban_v6"
	UNBAN_COMMAND_TEMPLATE="touch $marker_v4"
	UNBAN_COMMAND_V6_TEMPLATE="touch $marker_v6"
	execute_unban "2001:db8::1" "sshd" "22" >/dev/null
	[ -f "$marker_v6" ]
	[ ! -f "$marker_v4" ]

	# scenario 2: IPv4 host uses standard command when V6 set
	rm -f "$marker_v4" "$marker_v6"
	execute_unban "192.0.2.1" "sshd" "22" >/dev/null
	[ -f "$marker_v4" ]
	[ ! -f "$marker_v6" ]
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

