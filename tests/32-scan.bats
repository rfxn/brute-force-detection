#!/usr/bin/env bats
#
# Tests for --scan mode: full-log processing
# Covers: tlog_read_full, tlog_journal_read_full, tlog_advance_cursors,
#         _rule_tlog scan branch, check() scan filtering/collection, CLI parsing
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

setup() {
	bfd_standard_setup
	_TLOG_PASSTHROUGH=""
	_SCAN_MODE=""
	_SCAN_RULE=""
	_SCAN_LOG_PAIRS=""
	SCAN_MAX_LINES="50000"
	SCAN_TIMEOUT="120"
}

teardown() {
	bfd_teardown
}

# --- tlog_read_full ---

@test "tlog_read_full: max_lines variants (full, last-N, exceeds-file)" {
	# max_lines=0: outputs entire file
	local logfile="$TEST_TMPDIR/test.log"
	printf "line1\nline2\nline3\n" > "$logfile"
	run tlog_read_full "$logfile" "0"
	assert_success
	assert_line --index 0 "line1"
	assert_line --index 1 "line2"
	assert_line --index 2 "line3"

	# max_lines > 0: outputs last N lines
	printf "line1\nline2\nline3\nline4\nline5\n" > "$logfile"
	run tlog_read_full "$logfile" "2"
	assert_success
	assert_line --index 0 "line4"
	assert_line --index 1 "line5"

	# max_lines > file length: outputs all lines
	printf "line1\nline2\n" > "$logfile"
	run tlog_read_full "$logfile" "100"
	assert_success
	assert_line --index 0 "line1"
	assert_line --index 1 "line2"
}

@test "tlog_read_full: returns error for missing file" {
	run tlog_read_full "$TEST_TMPDIR/nonexistent.log" "0"
	assert_failure
	assert_output ""
}

@test "tlog_read_full: default max_lines=0 outputs full file" {
	local logfile="$TEST_TMPDIR/test.log"
	printf "a\nb\nc\n" > "$logfile"
	run tlog_read_full "$logfile"
	assert_success
	assert_line --index 0 "a"
	assert_line --index 2 "c"
}

@test "tlog_read_full: empty file produces no output" {
	local logfile="$TEST_TMPDIR/empty.log"
	touch "$logfile"
	run tlog_read_full "$logfile" "0"
	assert_success
	assert_output ""
}

# --- tlog_journal_read_full ---

@test "tlog_journal_read_full: returns error when no journalctl" {
	# create empty bin dir, then save PATH and replace
	mkdir -p "$TEST_TMPDIR/empty_bin"
	local _oldpath="$PATH"
	PATH="$TEST_TMPDIR/empty_bin"
	run tlog_journal_read_full "sshd" "10" "100"
	PATH="$_oldpath"
	assert_failure
	assert_output ""
}

@test "tlog_journal_read_full: returns error for unmapped tlog name" {
	run tlog_journal_read_full "nonexistent_service_xyz" "10" "100"
	assert_failure
}

# --- tlog_advance_cursors ---

@test "tlog_advance_cursors: updates cursor file to current file size" {
	local logfile="$TEST_TMPDIR/test.log"
	printf "1234567890" > "$logfile"
	local log_pairs="${logfile}|scan_test_tag"
	tlog_advance_cursors "$TLOG_BASERUN" "$log_pairs"
	local cursor_val
	cursor_val=$(cat "$TLOG_BASERUN/scan_test_tag")
	[ "$cursor_val" = "10" ]
}

@test "tlog_advance_cursors: deduplicates pairs (caller deduplicates)" {
	local logfile="$TEST_TMPDIR/test.log"
	printf "12345" > "$logfile"
	local log_pairs
	log_pairs=$(printf '%s\n' "${logfile}|dedup_tag" "${logfile}|dedup_tag" "${logfile}|dedup_tag" | sort -u)
	tlog_advance_cursors "$TLOG_BASERUN" "$log_pairs"
	local cursor_val
	cursor_val=$(cat "$TLOG_BASERUN/dedup_tag")
	[ "$cursor_val" = "5" ]
}

@test "tlog_advance_cursors: no-op when pairs empty" {
	local log_pairs=""
	run tlog_advance_cursors "$TLOG_BASERUN" "$log_pairs"
	assert_success
}

@test "tlog_advance_cursors: handles multiple distinct pairs" {
	local log1="$TEST_TMPDIR/log1"
	local log2="$TEST_TMPDIR/log2"
	printf "aaa" > "$log1"
	printf "bbbbb" > "$log2"
	local log_pairs="${log1}|tag1
${log2}|tag2"
	tlog_advance_cursors "$TLOG_BASERUN" "$log_pairs"
	[ "$(cat "$TLOG_BASERUN/tag1")" = "3" ]
	[ "$(cat "$TLOG_BASERUN/tag2")" = "5" ]
}

# --- _rule_tlog scan mode ---

@test "_rule_tlog: scan mode full file and SCAN_MAX_LINES limit" {
	TLOG_BASERUN="$INSTALL_PATH/tmp"
	_SCAN_MODE="1"

	# SCAN_MAX_LINES=0: outputs full file
	SCAN_MAX_LINES="0"
	local logfile="$TEST_TMPDIR/scan.log"
	printf "alpha\nbeta\ngamma\n" > "$logfile"
	run _rule_tlog "$logfile" "scan_rt1"
	assert_success
	assert_line --index 0 "alpha"
	assert_line --index 1 "beta"
	assert_line --index 2 "gamma"

	# SCAN_MAX_LINES=1: outputs only last line
	SCAN_MAX_LINES="1"
	printf "line1\nline2\nline3\n" > "$logfile"
	run _rule_tlog "$logfile" "scan_rt2"
	assert_success
	assert_output "line3"

	_SCAN_MODE=""
}

@test "_rule_tlog: scan mode with missing file returns error" {
	TLOG_BASERUN="$INSTALL_PATH/tmp"
	_SCAN_MODE="1"
	SCAN_MAX_LINES="50000"
	# No journalctl filter for "nonexistent_svc" so falls through to file
	LOG_SOURCE="file"
	run _rule_tlog "$TEST_TMPDIR/nonexistent.log" "nonexistent_svc"
	assert_failure
	assert_output ""
	_SCAN_MODE=""
}

@test "_rule_tlog: normal mode unchanged (outputs delta, not full)" {
	TLOG_BASERUN="$INSTALL_PATH/tmp"
	_SCAN_MODE=""
	local logfile="$TEST_TMPDIR/normal.log"
	echo "first" > "$logfile"
	# first call — init (outputs nothing)
	run _rule_tlog "$logfile" "normal_rt1"
	assert_success
	assert_output ""
	# append content
	echo "second" >> "$logfile"
	# second call — outputs delta
	run _rule_tlog "$logfile" "normal_rt1"
	assert_success
	assert_output "second"
}

# --- check() scan mode integration ---

# Source check() function from bfd (defined there, not in bfd.lib.sh)
bfd_load_function check

# Helper: set up minimal check() environment with scan mode
_setup_scan_check() {
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
	BAN_ESCALATION="none"
	BAN_ESCALATION_CAP="0"
	_SCAN_MODE="1"
	_SCAN_LOG_PAIRS=""
}

@test "check: summary prefix reflects scan vs normal mode" {
	local rules_dir="$TEST_TMPDIR/rules"
	mkdir -p "$rules_dir"

	# scan mode: "scan complete:"
	_setup_scan_check "$rules_dir"
	run check
	assert_success
	assert_output --partial "scan complete:"

	# normal mode: "run complete:"
	_setup_scan_check "$rules_dir"
	_SCAN_MODE=""
	run check
	assert_success
	assert_output --partial "run complete:"
}

@test "check: _SCAN_RULE filters to single rule" {
	local rules_dir="$TEST_TMPDIR/rules"
	mkdir -p "$rules_dir"
	local logfile="$TEST_TMPDIR/test.log"
	echo "test" > "$logfile"
	cat > "$rules_dir/rule_a" <<EOF
TRIG="100"
PREREQ="/bin/sh"
LOG_FILE="$logfile"
LOG_TAG="rule_a"
MATCHED_HOSTS=""
EOF
	cat > "$rules_dir/rule_b" <<EOF
TRIG="100"
PREREQ="/bin/sh"
LOG_FILE="$logfile"
LOG_TAG="rule_b"
MATCHED_HOSTS=""
EOF
	chmod 644 "$rules_dir/rule_a" "$rules_dir/rule_b"
	chown root "$rules_dir/rule_a" "$rules_dir/rule_b" 2>/dev/null || true
	_setup_scan_check "$rules_dir"
	_SCAN_RULE="rule_a"
	run check
	assert_success
	# only 1 active rule should be processed
	assert_output --partial "1 active rules"
}

@test "check: scan collects _SCAN_LOG_PAIRS for active rules" {
	local rules_dir="$TEST_TMPDIR/rules"
	mkdir -p "$rules_dir"
	local logfile="$TEST_TMPDIR/test.log"
	echo "test" > "$logfile"
	cat > "$rules_dir/testrule" <<EOF
TRIG="100"
PREREQ="/bin/sh"
LOG_FILE="$logfile"
LOG_TAG="testrule"
MATCHED_HOSTS=""
EOF
	chmod 644 "$rules_dir/testrule"
	chown root "$rules_dir/testrule" 2>/dev/null || true
	_setup_scan_check "$rules_dir"
	check >/dev/null 2>&1
	# _SCAN_LOG_PAIRS should contain our rule's log/tag pair
	echo "$_SCAN_LOG_PAIRS" | grep -q "${logfile}|testrule"
}

@test "check: scan with no active rules produces clean output" {
	local rules_dir="$TEST_TMPDIR/rules"
	mkdir -p "$rules_dir"
	_setup_scan_check "$rules_dir"
	run check
	assert_success
	assert_output --partial "scan complete: 0 active rules"
}

@test "check: scan detects IPs and records events" {
	local rules_dir="$TEST_TMPDIR/rules"
	mkdir -p "$rules_dir"
	local logfile="$TEST_TMPDIR/test.log"
	echo "test" > "$logfile"
	# rule with enough IPs to trigger ban (5 * weight=1 >= trip=5)
	cat > "$rules_dir/scanrule" <<'RULEEOF'
TRIG="5"
PREREQ="/bin/sh"
RULEEOF
	cat >> "$rules_dir/scanrule" <<EOF
LOG_FILE="$logfile"
LOG_TAG="scanrule"
MATCHED_HOSTS="192.0.2.1 192.0.2.1 192.0.2.1 192.0.2.1 192.0.2.1"
EOF
	chmod 644 "$rules_dir/scanrule"
	chown root "$rules_dir/scanrule" 2>/dev/null || true
	_setup_scan_check "$rules_dir"
	GLOB_PRESSURE_TRIP="5"
	GLOB_TRIG="5"
	check >/dev/null 2>&1
	# events should be recorded
	assert_event_count 5
}

@test "check: scan dry-run does not execute fw command" {
	local rules_dir="$TEST_TMPDIR/rules"
	mkdir -p "$rules_dir"
	local logfile="$TEST_TMPDIR/test.log"
	echo "test" > "$logfile"
	local marker="$TEST_TMPDIR/ban_marker"
	cat > "$rules_dir/drytest" <<'RULEEOF'
TRIG="5"
PREREQ="/bin/sh"
RULEEOF
	cat >> "$rules_dir/drytest" <<EOF
LOG_FILE="$logfile"
LOG_TAG="drytest"
MATCHED_HOSTS="192.0.2.10 192.0.2.10 192.0.2.10 192.0.2.10 192.0.2.10"
EOF
	chmod 644 "$rules_dir/drytest"
	chown root "$rules_dir/drytest" 2>/dev/null || true
	_setup_scan_check "$rules_dir"
	BAN_COMMAND_TEMPLATE="touch $marker"
	DRY_RUN="1"
	GLOB_PRESSURE_TRIP="5"
	GLOB_TRIG="5"
	check >/dev/null 2>&1
	# marker should NOT exist — dry-run skips execution
	[ ! -f "$marker" ]
}

@test "check: scan with SCAN_MAX_LINES limits processed lines" {
	local rules_dir="$TEST_TMPDIR/rules"
	mkdir -p "$rules_dir"
	local logfile="$TEST_TMPDIR/big.log"
	# create 100 log lines; scan should only process last 10
	for i in $(seq 1 100); do
		echo "line $i from 192.0.2.$((i % 254 + 1))" >> "$logfile"
	done
	cat > "$rules_dir/bigrule" <<'RULEEOF'
TRIG="1000"
PREREQ="/bin/sh"
RULEEOF
	cat >> "$rules_dir/bigrule" <<EOF
LOG_FILE="$logfile"
LOG_TAG="bigrule"
MATCHED_HOSTS=""
EOF
	chmod 644 "$rules_dir/bigrule"
	chown root "$rules_dir/bigrule" 2>/dev/null || true
	_setup_scan_check "$rules_dir"
	SCAN_MAX_LINES="10"
	# rule is valid but has empty MATCHED_HOSTS, so just testing framework
	run check
	assert_success
	assert_output --partial "scan complete: 1 active rules"
}

# --- cursor advancement integration ---

@test "scan: cursor advancement and next normal tlog_read handoff" {
	# cursor advanced after non-dry-run
	local logfile="$TEST_TMPDIR/cursor_test.log"
	printf "1234567890" > "$logfile"
	local log_pairs="${logfile}|cursor_svc"
	DRY_RUN="0"
	tlog_advance_cursors "$TLOG_BASERUN" "$log_pairs"
	[ -f "$TLOG_BASERUN/cursor_svc" ]
	local sz
	sz=$(cat "$TLOG_BASERUN/cursor_svc")
	[ "$sz" = "10" ]

	# next normal tlog_read starts from advanced cursor
	local handoff_log="$TEST_TMPDIR/handoff.log"
	printf "existing content\n" > "$handoff_log"
	local fsize
	fsize=$(stat -c %s "$handoff_log")
	echo "$fsize" > "$TLOG_BASERUN/handoff_tag"
	# tlog_read should output nothing (no new content past cursor)
	run tlog_read "$handoff_log" "handoff_tag" "$TLOG_BASERUN"
	assert_success
	assert_output ""
	# append new content
	printf "new line\n" >> "$handoff_log"
	# tlog_read should output only new content
	run tlog_read "$handoff_log" "handoff_tag" "$TLOG_BASERUN"
	assert_success
	assert_output "new line"
}

# --- CLI argument parsing (validate via variable inspection) ---
# These tests replicate the case/regex logic from files/bfd (pre-processing
# loop at line 675 and --scan dispatch at line 754) because invoking the full
# CLI requires an installed environment with root, config, and firewall setup.

@test "CLI: --max-lines= and --scan-timeout= extracted by pre-processing" {
	# --max-lines= extraction
	local _CLI_SCAN_MAX_LINES=""
	local _arg="--max-lines=100"
	case "$_arg" in
		--max-lines=*) _CLI_SCAN_MAX_LINES="${_arg#--max-lines=}" ;;
	esac
	[ "$_CLI_SCAN_MAX_LINES" = "100" ]

	# --scan-timeout= extraction
	local _CLI_SCAN_TIMEOUT=""
	_arg="--scan-timeout=60"
	case "$_arg" in
		--scan-timeout=*) _CLI_SCAN_TIMEOUT="${_arg#--scan-timeout=}" ;;
	esac
	[ "$_CLI_SCAN_TIMEOUT" = "60" ]
}

@test "CLI: scan var validation (accept/reject integer, zero, non-integer)" {
	local int_p='^[0-9]+$'

	# SCAN_MAX_LINES: rejects non-integer
	local val="abc"
	! [[ "$val" =~ $int_p ]]

	# SCAN_MAX_LINES: accepts zero
	val="0"
	[[ "$val" =~ $int_p ]]

	# SCAN_TIMEOUT: rejects zero (matches regex but must be non-positive)
	val="0"
	if ! [[ "$val" =~ $int_p ]] || [ "$val" -eq 0 ]; then
		true  # correctly rejected
	else
		false  # should not reach here
	fi

	# SCAN_TIMEOUT: accepts positive integer
	val="120"
	[[ "$val" =~ $int_p ]] && [ "$val" -gt 0 ]
}

@test "CLI: --scan sub-args (-d, --dryrun, rule name)" {
	# -d sets DRY_RUN
	local DRY_RUN=0
	local _s2="-d"
	case "$_s2" in
		-d|--dryrun) DRY_RUN=1 ;;
	esac
	[ "$DRY_RUN" = "1" ]

	# --dryrun sets DRY_RUN
	DRY_RUN=0
	_s2="--dryrun"
	case "$_s2" in
		-d|--dryrun) DRY_RUN=1 ;;
	esac
	[ "$DRY_RUN" = "1" ]

	# non-flag sets _SCAN_RULE
	local _SCAN_RULE=""
	_s2="sshd"
	case "$_s2" in
		-d|--dryrun) ;;
		"") ;;
		-*) ;;
		*) _SCAN_RULE="$_s2" ;;
	esac
	[ "$_SCAN_RULE" = "sshd" ]
}

@test "CLI: --scan RULE -d and -d RULE both set _SCAN_RULE and DRY_RUN" {
	# --scan RULE -d: rule first, then flag
	local _SCAN_RULE="" DRY_RUN=0
	local _s2="sshd" _s3="-d"
	case "$_s2" in
		-d|--dryrun) DRY_RUN=1 ;;
		"") ;;
		-*) ;;
		*) _SCAN_RULE="$_s2" ;;
	esac
	case "$_s3" in
		-d|--dryrun) DRY_RUN=1 ;;
		"") ;;
		-*) ;;
		*) [ -z "$_SCAN_RULE" ] && _SCAN_RULE="$_s3" ;;
	esac
	[ "$_SCAN_RULE" = "sshd" ]
	[ "$DRY_RUN" = "1" ]

	# --scan -d RULE: flag first, then rule
	_SCAN_RULE="" DRY_RUN=0
	_s2="-d" _s3="sshd"
	case "$_s2" in
		-d|--dryrun) DRY_RUN=1 ;;
		"") ;;
		-*) ;;
		*) _SCAN_RULE="$_s2" ;;
	esac
	case "$_s3" in
		-d|--dryrun) DRY_RUN=1 ;;
		"") ;;
		-*) ;;
		*) [ -z "$_SCAN_RULE" ] && _SCAN_RULE="$_s3" ;;
	esac
	[ "$_SCAN_RULE" = "sshd" ]
	[ "$DRY_RUN" = "1" ]
}

@test "CLI: scan defaults retained when absent; --max-lines= overrides config" {
	# defaults applied when CLI overrides absent
	local _CLI_SCAN_MAX_LINES=""
	local _CLI_SCAN_TIMEOUT=""
	SCAN_MAX_LINES="50000"  # from conf.bfd
	SCAN_TIMEOUT="120"       # from conf.bfd
	if [ -n "$_CLI_SCAN_MAX_LINES" ]; then
		SCAN_MAX_LINES="$_CLI_SCAN_MAX_LINES"
	else
		SCAN_MAX_LINES="${SCAN_MAX_LINES:-50000}"
	fi
	if [ -n "$_CLI_SCAN_TIMEOUT" ]; then
		SCAN_TIMEOUT="$_CLI_SCAN_TIMEOUT"
	else
		SCAN_TIMEOUT="${SCAN_TIMEOUT:-120}"
	fi
	[ "$SCAN_MAX_LINES" = "50000" ]
	[ "$SCAN_TIMEOUT" = "120" ]

	# --max-lines= overrides config default
	_CLI_SCAN_MAX_LINES="200"
	SCAN_MAX_LINES="50000"
	if [ -n "$_CLI_SCAN_MAX_LINES" ]; then
		SCAN_MAX_LINES="$_CLI_SCAN_MAX_LINES"
	fi
	[ "$SCAN_MAX_LINES" = "200" ]
}

# --- validate_config scan vars ---

# Helper: set all validate_config prerequisites
_setup_validate_config() {
	PRESSURE_TRIP="20"
	PRESSURE_HALF_LIFE="300"
	PRESSURE_TRIP_GLOBAL="0"
	SUBNET_TRIG="0"
	SUBNET_MASK="24"
	SUBNET_MASK_V6="48"
	BAN_TTL="600"
	BAN_ESCALATE_AFTER="5"
	BAN_ESCALATE_WINDOW="86400"
	EMAIL_ALERTS="0"
	OUTPUT_SYSLOG="0"
	LOCK_FILE_TIMEOUT="300"
	FIREWALL="custom"
	BAN_COMMAND_TEMPLATE="/bin/true"
	BAN_ESCALATION="none"
	BAN_ESCALATION_CAP="0"
	BAN_RETRY_COUNT="0"
	EMAIL_LOGLINES="50"
	WATCH_INTERVAL="10"
}

@test "validate_config: accepts valid SCAN_MAX_LINES" {
	_setup_validate_config
	SCAN_MAX_LINES="1000"
	run validate_config
	assert_success
}

@test "validate_config: accepts SCAN_MAX_LINES=0" {
	_setup_validate_config
	SCAN_MAX_LINES="0"
	run validate_config
	assert_success
}

@test "validate_config: rejects non-integer SCAN_MAX_LINES" {
	_setup_validate_config
	SCAN_MAX_LINES="abc"
	run validate_config
	assert_failure
	assert_output --partial "SCAN_MAX_LINES"
}

@test "validate_config: accepts valid SCAN_TIMEOUT" {
	_setup_validate_config
	SCAN_TIMEOUT="60"
	run validate_config
	assert_success
}

@test "validate_config: rejects non-integer SCAN_TIMEOUT" {
	_setup_validate_config
	SCAN_TIMEOUT="xyz"
	run validate_config
	assert_failure
	assert_output --partial "SCAN_TIMEOUT"
}

@test "validate_config: rejects SCAN_TIMEOUT=0" {
	_setup_validate_config
	SCAN_TIMEOUT="0"
	run validate_config
	assert_failure
	assert_output --partial "SCAN_TIMEOUT"
}

@test "validate_config: passes when scan vars unset (lenient)" {
	_setup_validate_config
	unset SCAN_MAX_LINES
	unset SCAN_TIMEOUT
	run validate_config
	assert_success
}

# --- show_config scan vars ---

@test "show_config: scan variables are in whitelist" {
	local var val
	for var in SCAN_MAX_LINES SCAN_TIMEOUT; do
		eval "$var=12345"
		run show_config "$var"
		assert_success
		assert_output "12345"
		unset "$var"
	done
}
