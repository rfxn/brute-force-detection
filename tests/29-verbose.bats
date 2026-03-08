#!/usr/bin/env bats
#
# Test suite for --verbose / -V flag and vout() function
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

setup() {
	bfd_standard_setup
	PRESSURE_TRIP="15"
	PRESSURE_HALF_LIFE="300"
	PRESSURE_TRIP_GLOBAL="0"
	BAN_TTL="300"
	BAN_ESCALATE_AFTER="5"
	BAN_ESCALATE_WINDOW="86400"
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
	GLOB_PRESSURE_TRIP="$PRESSURE_TRIP"
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

# --- verbose pressure in check() ---

# Helper: set up common check() test environment
_check_verbose_setup() {
	PRESSURE_TRIP="100"
	GLOB_PRESSURE_TRIP="100"
	PRESSURE_HALF_LIFE="300"
	PRESSURE_TRIP_GLOBAL="0"
	EMAIL_ALERTS="0"
	SUBNET_TRIG="0"
	DRY_RUN=1
	UTIME=$(date +"%s")
	IGNORE_HOST_FILES="$INSTALL_PATH/exclude.files"
	touch "$IGNORE_HOST_FILES"
	LO_HOSTS="$INSTALL_PATH/ignore.hosts.local"
	touch "$LO_HOSTS"
	_COUNTRY_CACHE_FILE=""
	_IGNORE_CACHE_FILE=""
	# source the check function from files/bfd
	bfd_load_function check
}

_make_rule_body() {
	local ip="${1:-192.0.2.50}" weight="${2:-3}"
	local logf="$INSTALL_PATH/tmp/test.log"
	touch "$logf"
	printf 'PREREQ=""\nLOG_FILE="%s"\nLOG_TAG="test"\nMATCHED_HOSTS="%s"\nPRESSURE_WEIGHT="%s"\n' "$logf" "$ip" "$weight"
}

@test "check verbose: per-IP pressure line shown when VERBOSE=1" {
	VERBOSE=1
	ELOG_VERBOSE=1
	_check_verbose_setup
	create_mock_rule "testrule" "$(_make_rule_body)"
	run check
	assert_success
	assert_output --partial "pressure="
	assert_output --partial "weight="
}

@test "check verbose: weight arrow shown when country multiplier applied" {
	VERBOSE=1
	ELOG_VERBOSE=1
	_check_verbose_setup
	# create a mock country database with high multiplier for 192.0.2.x
	# 192.0.2.0 = 3221225984; range covers .0-.255
	echo "3221225984 3221226239 XX" > "$INSTALL_PATH/ipcountry.dat"
	echo "XX=30" > "$INSTALL_PATH/pressure-country.conf"
	create_mock_rule "testrule" "$(_make_rule_body)"
	run check
	assert_success
	assert_output --partial "->"
}

@test "check verbose: global pressure ban line shown" {
	VERBOSE=1
	ELOG_VERBOSE=1
	_check_verbose_setup
	PRESSURE_TRIP_GLOBAL="1"
	# seed enough events to trigger global
	local i
	for i in $(seq 1 20); do
		state_pressure_append "$INSTALL_PATH" "$((UTIME - i))" "192.0.2.60" "sshd" "1" "3"
	done
	create_mock_rule "testrule" "$(_make_rule_body 192.0.2.60 1)"
	run check
	assert_success
	assert_output --partial "global pressure="
}

@test "check verbose: no pressure output when VERBOSE=0" {
	VERBOSE=0
	ELOG_VERBOSE=0
	_check_verbose_setup
	create_mock_rule "testrule" "$(_make_rule_body)"
	run check
	assert_success
	refute_output --partial "pressure="
}
