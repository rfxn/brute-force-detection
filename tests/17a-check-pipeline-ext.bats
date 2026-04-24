#!/usr/bin/env bats
#
# Extended check() pipeline tests: run statistics, IPv6 exact-match,
# IGNOREREGEX/PORTS reset, rule correctness, record_ban, pressure integration
# Split from 17-check-pipeline.bats for parallel execution efficiency
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

# --- run statistics (Phase 13A) ---

# Source check() function from bfd (defined there, not in bfd.lib.sh)
bfd_load_function check

# _setup_check_env: set up minimal environment for check()
_setup_check_env() {
	local rules_dir="$1"
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
	EMAIL_ALERTS="0"
	SUBNET_TRIG="0"
}

# Helper to run check() with controlled rules dir and capture output
_run_check_with_stats() {
	_setup_check_env "$1"
	check
}

@test "run stats: empty rules dir shows summary with zeros and valid elapsed" {
	local rules_dir="$TEST_TMPDIR/rules"
	mkdir -p "$rules_dir"
	run _run_check_with_stats "$rules_dir"
	assert_success
	# summary line structure
	assert_output --partial "run complete:"
	assert_output --partial "active rules"
	assert_output --partial "events parsed"
	assert_output --partial "bans executed"
	# zero events
	assert_output --partial "0 active rules, 0 with events, 0 events parsed, 0 bans executed"
	# elapsed time is non-negative integer
	local elapsed
	elapsed=$(echo "$output" | grep -o '([0-9]*s)' | tr -dc '0-9')
	[ -n "$elapsed" ]
	[ "$elapsed" -ge 0 ]
}

@test "run stats: rules count matches valid rules" {
	local rules_dir="$TEST_TMPDIR/rules"
	mkdir -p "$rules_dir"
	# create 2 valid rule files with PREREQ that exists, LOG_FILE pointing to a real file
	local logfile="$TEST_TMPDIR/test.log"
	echo "test line" > "$logfile"
	cat > "$rules_dir/testrule1" <<EOF
TRIG="5"
PREREQ="/bin/sh"
LOG_FILE="$logfile"
LOG_TAG="testrule1"
MATCHED_HOSTS=""
EOF
	cat > "$rules_dir/testrule2" <<EOF
TRIG="5"
PREREQ="/bin/sh"
LOG_FILE="$logfile"
LOG_TAG="testrule2"
MATCHED_HOSTS=""
EOF
	# create 1 rule that will fail validate_rule (no MATCHED_HOSTS, LOG_FILE missing)
	cat > "$rules_dir/badrule" <<EOF
TRIG="5"
PREREQ="/bin/sh"
LOG_FILE="/nonexistent/log"
LOG_TAG="badrule"
MATCHED_HOSTS=""
EOF
	run _run_check_with_stats "$rules_dir"
	assert_success
	# badrule has LOG_FILE that doesn't exist, so validate_rule skips it
	# testrule1 and testrule2 pass validate_rule (2 active) but have empty
	# MATCHED_HOSTS so 0 rules have events
	assert_output --partial "2 active rules, 0 with events"
}

@test "run stats: counts events from HOSTS_PARSED" {
	local rules_dir="$TEST_TMPDIR/rules"
	mkdir -p "$rules_dir"
	local logfile="$TEST_TMPDIR/test.log"
	echo "test line" > "$logfile"
	# create a rule that produces 3 events via MATCHED_HOSTS
	cat > "$rules_dir/testrule" <<'RULEEOF'
TRIG="100"
PREREQ="/bin/sh"
RULEEOF
	cat >> "$rules_dir/testrule" <<EOF
LOG_FILE="$logfile"
LOG_TAG="testrule"
MATCHED_HOSTS="192.0.2.1 192.0.2.2 192.0.2.1"
EOF
	run _run_check_with_stats "$rules_dir"
	assert_success
	assert_output --partial "1 with events"
	assert_output --partial "3 events parsed"
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

@test "check_recidivism: works with IPv6 addresses" {
	local i
	for i in 1 2 3 4 5; do
		state_bans_history_append "$INSTALL_PATH" "$((800 + i))" "1100" "2001:db8::1" "sshd" "ban"
	done
	run check_recidivism "$INSTALL_PATH" "2001:db8::1" "500" "1000" "5"
	assert_success
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
PREREQ="/bin/sh"
LOG_FILE="$logfile"
LOG_TAG="rule1"
IGNOREREGEX="no auth attempts"
MATCHED_HOSTS=""
EOF
	# rule2 should NOT inherit IGNOREREGEX from rule1
	cat > "$rules_dir/rule2" <<EOF
TRIG="100"
PREREQ="/bin/sh"
LOG_FILE="$logfile"
LOG_TAG="rule2"
MATCHED_HOSTS=""
EOF
	chmod 644 "$rules_dir/rule1" "$rules_dir/rule2"
	chown root "$rules_dir/rule1" "$rules_dir/rule2"
	_setup_check_env "$rules_dir"
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
PREREQ="/bin/sh"
LOG_FILE="$logfile"
LOG_TAG="rule1"
PORTS="22"
MATCHED_HOSTS=""
EOF
	# rule2 should NOT inherit PORTS from rule1
	cat > "$rules_dir/rule2" <<EOF
TRIG="100"
PREREQ="/bin/sh"
LOG_FILE="$logfile"
LOG_TAG="rule2"
MATCHED_HOSTS=""
EOF
	chmod 644 "$rules_dir/rule1" "$rules_dir/rule2"
	chown root "$rules_dir/rule1" "$rules_dir/rule2"
	_setup_check_env "$rules_dir"
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
PREREQ="/bin/sh"
LOG_FILE="$logfile"
LOG_TAG="testrule"
IGNOREREGEX="filter_this"
MATCHED_HOSTS=""
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
PREREQ="/bin/sh"
LOG_FILE="$logfile"
LOG_TAG="testrule"
MATCHED_HOSTS=""
EOF
	chmod 644 "$rules_dir/testrule"
	chown root "$rules_dir/testrule"
	_setup_check_env "$rules_dir"
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

@test "rule: vsftpd and vsftpd2 have different LOG_TAG values" {
	local tf1 tf2
	tf1=$(grep -E '^[[:space:]]*LOG_TAG=' "$PROJECT_ROOT/files/rules/vsftpd" | tail -1 | sed 's/.*="\?\([^"]*\)"\?/\1/')
	tf2=$(grep -E '^[[:space:]]*LOG_TAG=' "$PROJECT_ROOT/files/rules/vsftpd2" | tail -1 | sed 's/.*="\?\([^"]*\)"\?/\1/')
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
PREREQ="/bin/sh"
RULEEOF
	cat >> "$rules_dir/rule1" <<EOF
LOG_FILE="$logfile"
LOG_TAG="rule1"
MATCHED_HOSTS="192.0.2.1 192.0.2.1 192.0.2.1"
EOF
	# rule2: same IP triggers ban
	cat > "$rules_dir/rule2" <<'RULEEOF'
TRIG="2"
PREREQ="/bin/sh"
RULEEOF
	cat >> "$rules_dir/rule2" <<EOF
LOG_FILE="$logfile"
LOG_TAG="rule2"
MATCHED_HOSTS="192.0.2.1 192.0.2.1 192.0.2.1"
EOF
	chmod 644 "$rules_dir/rule1" "$rules_dir/rule2"
	chown root "$rules_dir/rule1" "$rules_dir/rule2"
	_setup_check_env "$rules_dir"
	BAN_COMMAND_TEMPLATE="/bin/true"
	DRY_RUN="0"
	run check
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
PREREQ="/bin/sh"
RULEEOF
	cat >> "$rules_dir/rule1" <<EOF
LOG_FILE="$logfile"
LOG_TAG="rule1"
MATCHED_HOSTS="127.0.0.1 127.0.0.1 127.0.0.1"
EOF
	cat > "$rules_dir/rule2" <<'RULEEOF'
TRIG="2"
PREREQ="/bin/sh"
RULEEOF
	cat >> "$rules_dir/rule2" <<EOF
LOG_FILE="$logfile"
LOG_TAG="rule2"
MATCHED_HOSTS="127.0.0.1 127.0.0.1 127.0.0.1"
EOF
	chmod 644 "$rules_dir/rule1" "$rules_dir/rule2"
	chown root "$rules_dir/rule1" "$rules_dir/rule2"
	_setup_check_env "$rules_dir"
	# override lo_hosts with 127.0.0.1 so filter_host returns 2
	echo "127.0.0.1" > "$LO_HOSTS"
	check
	# pool entries from both rules should exist
	local pool_count
	pool_count=$(grep -c "127.0.0.1" "$INSTALL_PATH/stats/attack.pool" 2>/dev/null || echo 0)
	[ "$pool_count" -ge 2 ]
}

# --- record_ban ---

@test "record_ban: normal and permanent ban expiry" {
	# scenario 1: BAN_TTL=600 → expiry = 1000 + 600 = 1600
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

	# reset state for scenario 2
	: > "$INSTALL_PATH/tmp/bans.active"
	: > "$INSTALL_PATH/tmp/bans.history"

	# scenario 2: BAN_TTL=0 → permanent (expiry=0)
	BAN_TTL="0"
	BAN_DURATION="0"
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

# --- pressure.conf precedence integration ---

@test "check: pressure.conf PRESSURE_TRIP used when rule TRIG commented out" {
	bfd_require_bash42
	local rules_dir="$TEST_TMPDIR/rules"
	mkdir -p "$rules_dir"
	local logfile="$TEST_TMPDIR/test.log"
	echo "test line" > "$logfile"
	# rule with TRIG commented out (empty after _clear_rule_vars)
	cat > "$rules_dir/testrule" <<'RULEEOF'
# TRIG="5"
PREREQ="/bin/sh"
RULEEOF
	cat >> "$rules_dir/testrule" <<EOF
LOG_FILE="$logfile"
LOG_TAG="testrule"
MATCHED_HOSTS="192.0.2.1 192.0.2.1 192.0.2.1"
EOF
	chmod 644 "$rules_dir/testrule"
	chown root "$rules_dir/testrule"
	# set up pressure.conf with trip=2 for testrule
	local press_conf="$TEST_TMPDIR/pressure.conf"
	echo "testrule  trip=2" > "$press_conf"
	chown root "$press_conf"
	chmod 640 "$press_conf"
	# load pressure config
	declare -gA _PRESS_WEIGHT _PRESS_TRIP _PRESS_SKIP_ALERT _PRESS_RULE_EMAIL
	_load_pressure_conf "$press_conf"
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
	bfd_require_bash42
	local rules_dir="$TEST_TMPDIR/rules"
	mkdir -p "$rules_dir"
	local logfile="$TEST_TMPDIR/test.log"
	echo "test line" > "$logfile"
	# rule with explicit TRIG=999 (very high, should NOT trigger ban)
	cat > "$rules_dir/testrule" <<'RULEEOF'
TRIG="999"
PREREQ="/bin/sh"
RULEEOF
	cat >> "$rules_dir/testrule" <<EOF
LOG_FILE="$logfile"
LOG_TAG="testrule"
MATCHED_HOSTS="192.0.2.1 192.0.2.1 192.0.2.1"
EOF
	chmod 644 "$rules_dir/testrule"
	chown root "$rules_dir/testrule"
	# pressure.conf says trip=1 (low), but rule file should override
	local press_conf="$TEST_TMPDIR/pressure.conf"
	echo "testrule  trip=1" > "$press_conf"
	chown root "$press_conf"
	chmod 640 "$press_conf"
	declare -gA _PRESS_WEIGHT _PRESS_TRIP _PRESS_SKIP_ALERT _PRESS_RULE_EMAIL
	_load_pressure_conf "$press_conf"
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

# --- Pressure decay integration ---

@test "check: decayed events prevent ban that raw count would trigger" {
	# Scenario: 4 old events (2 half-lives ago) + 2 new events
	# Without decay: 6 events * weight 1 = 6.0 >= trip 5 → BAN
	# With decay: 4 * 0.25 + 2 * 1.0 = 3.0 < trip 5 → NO BAN
	local rules_dir="$TEST_TMPDIR/rules_decay"
	mkdir -p "$rules_dir"
	local logfile="$TEST_TMPDIR/test_decay.log"
	echo "test line" > "$logfile"
	# UTIME=1000, half_life=300, so 2 half-lives ago = 1000 - 600 = 400
	# seed 4 old events at t=400
	local i
	for i in 1 2 3 4; do
		state_pressure_append "$INSTALL_PATH" "400" "192.0.2.1" "testrule_decay" "1"
	done
	cat > "$rules_dir/testrule_decay" <<EOF
PRESSURE_TRIP="5"
PREREQ="/bin/sh"
LOG_FILE="$logfile"
LOG_TAG="testrule_decay"
MATCHED_HOSTS="192.0.2.1 192.0.2.1"
EOF
	chmod 644 "$rules_dir/testrule_decay"
	chown root "$rules_dir/testrule_decay"
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
	run check
	assert_success
	# 4 old + 2 new = 6 events total, but decayed pressure ~3.0 < 5 → no ban
	assert_output --partial "0 bans executed"
}

@test "check: fresh events exceed trip point and trigger ban" {
	# Scenario: 6 fresh events (at t=now) with weight 1
	# Pressure: 6 * 1.0 = 6.0 >= trip 5 → BAN
	local rules_dir="$TEST_TMPDIR/rules_fresh"
	mkdir -p "$rules_dir"
	local logfile="$TEST_TMPDIR/test_fresh.log"
	echo "test line" > "$logfile"
	cat > "$rules_dir/testrule_fresh" <<EOF
PRESSURE_TRIP="5"
PREREQ="/bin/sh"
LOG_FILE="$logfile"
LOG_TAG="testrule_fresh"
MATCHED_HOSTS="192.0.2.1 192.0.2.1 192.0.2.1 192.0.2.1 192.0.2.1 192.0.2.1"
EOF
	chmod 644 "$rules_dir/testrule_fresh"
	chown root "$rules_dir/testrule_fresh"
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
	run check
	assert_success
	# 6 fresh events * weight 1 = 6.0 >= 5 → ban
	assert_output --partial "1 bans executed"
}

@test "check: PRESSURE_WEIGHT from pressure.conf affects ban decision" {
	bfd_require_bash42
	# Scenario: 2 events with weight=5 (from pressure.conf)
	# Pressure: 2 * 5.0 = 10.0 >= trip 8 → BAN
	# Without weight override: 2 * 1.0 = 2.0 < 8 → NO BAN
	local rules_dir="$TEST_TMPDIR/rules_weight"
	mkdir -p "$rules_dir"
	local logfile="$TEST_TMPDIR/test_weight.log"
	echo "test line" > "$logfile"
	cat > "$rules_dir/testrule_weight" <<EOF
PRESSURE_TRIP="8"
PREREQ="/bin/sh"
LOG_FILE="$logfile"
LOG_TAG="testrule_weight"
MATCHED_HOSTS="192.0.2.1 192.0.2.1"
EOF
	chmod 644 "$rules_dir/testrule_weight"
	chown root "$rules_dir/testrule_weight"
	# pressure.conf sets weight=5 for this rule
	local press_conf="$TEST_TMPDIR/pressure.conf"
	echo "testrule_weight  weight=5" > "$press_conf"
	chown root "$press_conf"
	chmod 640 "$press_conf"
	declare -gA _PRESS_WEIGHT _PRESS_TRIP _PRESS_SKIP_ALERT _PRESS_RULE_EMAIL
	_load_pressure_conf "$press_conf"
	RULES_PATH="$rules_dir"
	GLOB_PRESSURE_TRIP="999"
	GLOB_TRIG="999"
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
	run check
	assert_success
	# 2 events * weight 5 = 10.0 >= trip 8 → ban
	assert_output --partial "1 bans executed"
}

@test "LOG_IDLE_SUPPRESS: 0-event cycle with suppress=1 skips syslog" {
	local rules_dir="$TEST_TMPDIR/rules"
	mkdir -p "$rules_dir"
	_setup_check_env "$rules_dir"
	LOG_IDLE_SUPPRESS="1"
	OUTPUT_SYSLOG="1"
	: > "$OUTPUT_SYSLOG_FILE"
	: > "$BFD_LOG_PATH"
	check > /dev/null
	# log file should have the run-complete message
	grep -q "run complete:" "$BFD_LOG_PATH"
	# syslog should NOT have it
	[ "$(grep -c "run complete:" "$OUTPUT_SYSLOG_FILE")" -eq 0 ]
}

@test "LOG_IDLE_SUPPRESS: 0-event cycle with suppress=0 writes syslog" {
	local rules_dir="$TEST_TMPDIR/rules"
	mkdir -p "$rules_dir"
	_setup_check_env "$rules_dir"
	LOG_IDLE_SUPPRESS="0"
	OUTPUT_SYSLOG="1"
	: > "$OUTPUT_SYSLOG_FILE"
	: > "$BFD_LOG_PATH"
	check > /dev/null
	grep -q "run complete:" "$BFD_LOG_PATH"
	grep -q "run complete:" "$OUTPUT_SYSLOG_FILE"
}
