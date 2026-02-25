#!/usr/bin/env bats
#
# Test suite for --verbose / -V flag and vout() function
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

setup() {
	bfd_standard_setup
	TRIG="15"
	TRIG_WINDOW="300"
	TRIG_GLOBAL="0"
	BAN_DURATION="300"
	BAN_PERMANENT_AFTER="5"
	BAN_PERMANENT_WINDOW="86400"
	BAN_ESCALATION="none"
	BAN_ESCALATION_CAP="86400"
	EMAIL_ALERTS="0"
	EMAIL_ADDRESS="root"
	EMAIL_SUBJECT="Test"
	EMAIL_LOGLINES="50"
	LOG_SOURCE="auto"
	AUTH_LOG_PATH="/var/log/secure"
	KERNEL_LOG_PATH="/var/log/messages"
	MAIL_LOG_PATH="/var/log/maillog"
	OUTPUT_SYSLOG="1"
	LOCK_FILE_TIMEOUT="300"
	WATCH_INTERVAL="10"
	GLOB_TRIG="$TRIG"
	FIREWALL="custom"

	# create rules directory with a test rule
	RULES_PATH="$INSTALL_PATH/rules"
	mkdir -p "$RULES_PATH"
}

teardown() {
	bfd_teardown
}

# --- vout function ---

@test "vout: outputs when VERBOSE=1" {
	VERBOSE=1
	run vout "test message"
	assert_success
	assert_output "test message"
}

@test "vout: silent when VERBOSE=0" {
	VERBOSE=0
	run vout "test message"
	assert_success
	assert_output ""
}

@test "vout: silent when VERBOSE unset" {
	unset VERBOSE
	run vout "test message"
	assert_success
	assert_output ""
}

@test "vout: returns 0 always" {
	VERBOSE=0
	run vout "test message"
	assert_success

	VERBOSE=1
	run vout "test message"
	assert_success
}

@test "vout: handles multiple arguments" {
	VERBOSE=1
	run vout "hello" "world"
	assert_success
	assert_output "hello world"
}

# --- --verbose flag parsing ---

@test "--verbose flag: parsed in pre-process loop" {
	# simulate the pre-process loop
	VERBOSE=0
	OUTPUT_FORMAT="table"
	declare -a _bfd_args=()
	for _arg in "--verbose" "-l"; do
		case "$_arg" in
			--json) OUTPUT_FORMAT="json" ;;
			--csv)  OUTPUT_FORMAT="csv" ;;
			--verbose|-V) VERBOSE=1 ;;
			*)      _bfd_args+=("$_arg") ;;
		esac
	done
	[ "$VERBOSE" = "1" ]
	[ "${#_bfd_args[@]}" -eq 1 ]
	[ "${_bfd_args[0]}" = "-l" ]
}

@test "-V flag: parsed as --verbose alias" {
	VERBOSE=0
	OUTPUT_FORMAT="table"
	declare -a _bfd_args=()
	for _arg in "-V" "-c"; do
		case "$_arg" in
			--json) OUTPUT_FORMAT="json" ;;
			--csv)  OUTPUT_FORMAT="csv" ;;
			--verbose|-V) VERBOSE=1 ;;
			*)      _bfd_args+=("$_arg") ;;
		esac
	done
	[ "$VERBOSE" = "1" ]
	[ "${#_bfd_args[@]}" -eq 1 ]
	[ "${_bfd_args[0]}" = "-c" ]
}

# --- verbose in show_status ---

@test "show_status: verbose shows detection method" {
	VERBOSE=1
	run show_status "$INSTALL_PATH"
	assert_success
	assert_output --partial "(detected via:"
}

@test "show_status: non-verbose hides detection method" {
	VERBOSE=0
	run show_status "$INSTALL_PATH"
	assert_success
	refute_output --partial "(detected via:"
}

# --- verbose in health_check ---

@test "health_check: verbose shows binary paths" {
	VERBOSE=1
	run health_check "$INSTALL_PATH"
	assert_success
	assert_output --partial "command: awk ="
	assert_output --partial "command: grep ="
}

@test "health_check: non-verbose hides binary paths" {
	VERBOSE=0
	run health_check "$INSTALL_PATH"
	assert_success
	refute_output --partial "command: awk ="
}

# --- verbose in process_unbans ---

@test "process_unbans: verbose shows per-unban detail" {
	VERBOSE=1
	local now
	now=$(date +"%s")
	local past=$((now - 100))
	echo "$past $now 192.0.2.1 sshd 22" >> "$INSTALL_PATH/tmp/bans.active"
	# make the ban appear expired by setting expiry in the past
	local expired=$((now - 10))
	: > "$INSTALL_PATH/tmp/bans.active"
	echo "$past $expired 192.0.2.1 sshd 22" >> "$INSTALL_PATH/tmp/bans.active"
	run process_unbans "$INSTALL_PATH" "$now"
	assert_success
	assert_output --partial "unban: 192.0.2.1 expired (sshd)"
}

@test "process_unbans: non-verbose hides per-unban detail" {
	VERBOSE=0
	local now
	now=$(date +"%s")
	local past=$((now - 100))
	local expired=$((now - 10))
	echo "$past $expired 192.0.2.1 sshd 22" >> "$INSTALL_PATH/tmp/bans.active"
	run process_unbans "$INSTALL_PATH" "$now"
	assert_success
	refute_output --partial "unban: 192.0.2.1 expired"
}
