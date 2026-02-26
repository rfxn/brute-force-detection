#!/usr/bin/env bats
#
# Test suite for validate_config()
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

setup() {
	bfd_common_setup
}

teardown() {
	bfd_teardown
}

# helper: set all config to valid defaults, then override one field
run_validate() {
	(
		PRESSURE_TRIP="15"
		PRESSURE_HALF_LIFE="300"
		PRESSURE_TRIP_GLOBAL="0"
		BAN_TTL="300"
		BAN_ESCALATE_AFTER="5"
		BAN_ESCALATE_WINDOW="86400"
		UNBAN_COMMAND_TEMPLATE=""
		EMAIL_ALERTS="0"
		EMAIL_ADDRESS="root@localhost"
		LOCK_FILE_TIMEOUT="300"
		BAN_COMMAND_TEMPLATE="/etc/apf/apf -d test"
		FIREWALL="custom"
		INSTALL_PATH="$TEST_TMPDIR"
		eval "$1"
		validate_config
	) >/dev/null 2>&1
}

# helper: capture stdout+stderr for warning checks
run_validate_output() {
	(
		PRESSURE_TRIP="15"
		PRESSURE_HALF_LIFE="300"
		PRESSURE_TRIP_GLOBAL="0"
		BAN_TTL="300"
		BAN_ESCALATE_AFTER="5"
		BAN_ESCALATE_WINDOW="86400"
		UNBAN_COMMAND_TEMPLATE=""
		EMAIL_ALERTS="0"
		EMAIL_ADDRESS="root@localhost"
		LOCK_FILE_TIMEOUT="300"
		BAN_COMMAND_TEMPLATE="/etc/apf/apf -d test"
		FIREWALL="custom"
		INSTALL_PATH="$TEST_TMPDIR"
		eval "$1"
		validate_config
	) 2>&1
}

@test "validate_config: valid config passes" {
	run run_validate ""
	assert_success
}

@test "validate_config: PRESSURE_TRIP=abc rejects" {
	run run_validate 'PRESSURE_TRIP="abc"'
	assert_failure
}

@test "validate_config: PRESSURE_TRIP=0 rejects" {
	run run_validate 'PRESSURE_TRIP="0"'
	assert_failure
}

@test "validate_config: PRESSURE_TRIP= rejects" {
	run run_validate 'PRESSURE_TRIP=""'
	assert_failure
}

@test "validate_config: PRESSURE_TRIP=15 passes" {
	run run_validate 'PRESSURE_TRIP="15"'
	assert_success
}

@test "validate_config: PRESSURE_TRIP=1 passes" {
	run run_validate 'PRESSURE_TRIP="1"'
	assert_success
}

@test "validate_config: EMAIL_ALERTS=2 rejects" {
	run run_validate 'EMAIL_ALERTS="2"'
	assert_failure
}

@test "validate_config: EMAIL_ALERTS=abc rejects" {
	run run_validate 'EMAIL_ALERTS="abc"'
	assert_failure
}

@test "validate_config: EMAIL_ALERTS=0 passes" {
	run run_validate 'EMAIL_ALERTS="0"'
	assert_success
}

@test "validate_config: EMAIL_ALERTS=1 passes" {
	run run_validate 'EMAIL_ALERTS="1"'
	assert_success
}

@test "validate_config: EMAIL_ALERTS=1 EMAIL_ADDRESS= rejects" {
	run run_validate 'EMAIL_ALERTS="1"; EMAIL_ADDRESS=""'
	assert_failure
}

@test "validate_config: OUTPUT_SYSLOG=0 passes" {
	run run_validate 'OUTPUT_SYSLOG="0"'
	assert_success
}

@test "validate_config: OUTPUT_SYSLOG=1 passes" {
	run run_validate 'OUTPUT_SYSLOG="1"'
	assert_success
}

@test "validate_config: OUTPUT_SYSLOG=2 rejects" {
	run run_validate 'OUTPUT_SYSLOG="2"'
	assert_failure
}

@test "validate_config: OUTPUT_SYSLOG=abc rejects" {
	run run_validate 'OUTPUT_SYSLOG="abc"'
	assert_failure
}

@test "validate_config: TIMEOUT=0 rejects" {
	run run_validate 'LOCK_FILE_TIMEOUT="0"'
	assert_failure
}

@test "validate_config: TIMEOUT=abc rejects" {
	run run_validate 'LOCK_FILE_TIMEOUT="abc"'
	assert_failure
}

@test "validate_config: TIMEOUT= rejects" {
	run run_validate 'LOCK_FILE_TIMEOUT=""'
	assert_failure
}

@test "validate_config: TIMEOUT=300 passes" {
	run run_validate 'LOCK_FILE_TIMEOUT="300"'
	assert_success
}

@test "validate_config: empty BAN_COMMAND rejects" {
	run run_validate 'BAN_COMMAND_TEMPLATE=""'
	assert_failure
}

@test "validate_config: bad INSTALL_PATH rejects" {
	run run_validate 'INSTALL_PATH="/nonexistent/path"'
	assert_failure
}

@test "validate_config: BFD_LOG_PATH= rejects" {
	run run_validate 'BFD_LOG_PATH=""'
	assert_failure
}

# --- PRESSURE_HALF_LIFE ---

@test "validate_config: PRESSURE_HALF_LIFE=300 passes" {
	run run_validate 'PRESSURE_HALF_LIFE="300"'
	assert_success
}

@test "validate_config: PRESSURE_HALF_LIFE=0 rejects" {
	run run_validate 'PRESSURE_HALF_LIFE="0"'
	assert_failure
}

@test "validate_config: PRESSURE_HALF_LIFE=abc rejects" {
	run run_validate 'PRESSURE_HALF_LIFE="abc"'
	assert_failure
}

@test "validate_config: PRESSURE_HALF_LIFE= rejects" {
	run run_validate 'PRESSURE_HALF_LIFE=""'
	assert_failure
}

# --- PRESSURE_TRIP_GLOBAL ---

@test "validate_config: PRESSURE_TRIP_GLOBAL=0 passes (disabled)" {
	run run_validate 'PRESSURE_TRIP_GLOBAL="0"'
	assert_success
}

@test "validate_config: PRESSURE_TRIP_GLOBAL=10 passes" {
	run run_validate 'PRESSURE_TRIP_GLOBAL="10"'
	assert_success
}

@test "validate_config: PRESSURE_TRIP_GLOBAL=abc rejects" {
	run run_validate 'PRESSURE_TRIP_GLOBAL="abc"'
	assert_failure
}

@test "validate_config: PRESSURE_TRIP_GLOBAL= rejects" {
	run run_validate 'PRESSURE_TRIP_GLOBAL=""'
	assert_failure
}

@test "validate_config: PRESSURE_TRIP_GLOBAL=-1 rejects" {
	run run_validate 'PRESSURE_TRIP_GLOBAL="-1"'
	assert_failure
}


# --- backward compat: old variable names still accepted ---

@test "validate_config: old TRIG= accepted via fallback to PRESSURE_TRIP" {
	run run_validate 'unset PRESSURE_TRIP; TRIG="10"'
	assert_success
}

@test "validate_config: old TRIG_WINDOW= accepted via fallback to PRESSURE_HALF_LIFE" {
	run run_validate 'unset PRESSURE_HALF_LIFE; TRIG_WINDOW="300"'
	assert_success
}

@test "validate_config: old BAN_DURATION= accepted via fallback to BAN_TTL" {
	run run_validate 'unset BAN_TTL; BAN_DURATION="300"; UNBAN_COMMAND_TEMPLATE="echo test"'
	assert_success
}

# --- BAN_TTL ---

@test "validate_config: BAN_TTL=300 passes" {
	run run_validate 'BAN_TTL="300"; UNBAN_COMMAND_TEMPLATE="echo test"'
	assert_success
}

@test "validate_config: BAN_TTL=0 passes (permanent)" {
	run run_validate 'BAN_TTL="0"'
	assert_success
}

@test "validate_config: BAN_TTL=abc rejects" {
	run run_validate 'BAN_TTL="abc"'
	assert_failure
}

# --- BAN_ESCALATE_AFTER ---

@test "validate_config: BAN_ESCALATE_AFTER=5 passes" {
	run run_validate 'BAN_ESCALATE_AFTER="5"; UNBAN_COMMAND_TEMPLATE="echo test"'
	assert_success
}

@test "validate_config: BAN_ESCALATE_AFTER=0 passes (disabled)" {
	run run_validate 'BAN_ESCALATE_AFTER="0"; UNBAN_COMMAND_TEMPLATE="echo test"'
	assert_success
}

@test "validate_config: BAN_ESCALATE_AFTER=abc rejects" {
	run run_validate 'BAN_ESCALATE_AFTER="abc"'
	assert_failure
}

# --- BAN_ESCALATE_WINDOW ---

@test "validate_config: BAN_ESCALATE_WINDOW=86400 passes" {
	run run_validate 'BAN_ESCALATE_WINDOW="86400"; UNBAN_COMMAND_TEMPLATE="echo test"'
	assert_success
}

@test "validate_config: BAN_ESCALATE_WINDOW=0 rejects" {
	run run_validate 'BAN_ESCALATE_WINDOW="0"'
	assert_failure
}

@test "validate_config: BAN_ESCALATE_WINDOW=abc rejects" {
	run run_validate 'BAN_ESCALATE_WINDOW="abc"'
	assert_failure
}

# --- UNBAN_COMMAND warning ---

@test "validate_config: warns when BAN_TTL>0 and UNBAN_COMMAND empty" {
	run run_validate_output 'BAN_TTL="300"; UNBAN_COMMAND_TEMPLATE=""'
	assert_success
	assert_output --partial "warning"
	assert_output --partial "UNBAN_COMMAND"
}

# --- WATCH_INTERVAL ---

@test "validate_config: WATCH_INTERVAL=10 passes" {
	run run_validate 'WATCH_INTERVAL="10"'
	assert_success
}

@test "validate_config: WATCH_INTERVAL=1 passes" {
	run run_validate 'WATCH_INTERVAL="1"'
	assert_success
}

@test "validate_config: WATCH_INTERVAL=0 rejects" {
	run run_validate 'WATCH_INTERVAL="0"'
	assert_failure
}

@test "validate_config: WATCH_INTERVAL=abc rejects" {
	run run_validate 'WATCH_INTERVAL="abc"'
	assert_failure
}

@test "validate_config: WATCH_INTERVAL= uses default (passes)" {
	run run_validate 'WATCH_INTERVAL=""'
	assert_success
}

@test "validate_config: WATCH_INTERVAL unset uses default (passes)" {
	run run_validate 'unset WATCH_INTERVAL'
	assert_success
}

# --- BAN_ESCALATION ---

@test "validate_config: BAN_ESCALATION=none passes" {
	run run_validate 'BAN_ESCALATION="none"'
	assert_success
}

@test "validate_config: BAN_ESCALATION=linear passes" {
	run run_validate 'BAN_ESCALATION="linear"'
	assert_success
}

@test "validate_config: BAN_ESCALATION=double passes" {
	run run_validate 'BAN_ESCALATION="double"'
	assert_success
}

@test "validate_config: BAN_ESCALATION=exponential accepted (backward compat)" {
	run run_validate 'BAN_ESCALATION="exponential"'
	assert_success
}

@test "validate_config: BAN_ESCALATION=bogus rejects" {
	run run_validate 'BAN_ESCALATION="bogus"'
	assert_failure
}

@test "validate_config: BAN_ESCALATION unset uses default (passes)" {
	run run_validate 'unset BAN_ESCALATION'
	assert_success
}

@test "validate_config: BAN_ESCALATION_CAP=86400 passes" {
	run run_validate 'BAN_ESCALATION_CAP="86400"'
	assert_success
}

@test "validate_config: BAN_ESCALATION_CAP=0 passes" {
	run run_validate 'BAN_ESCALATION_CAP="0"'
	assert_success
}

@test "validate_config: BAN_ESCALATION_CAP=abc rejects" {
	run run_validate 'BAN_ESCALATION_CAP="abc"'
	assert_failure
}

# ============================================================
# SUBNET_TRIG / SUBNET_MASK / SUBNET_MASK_V6 validation
# ============================================================

@test "validate_config: SUBNET_TRIG=0 passes" {
	run run_validate 'SUBNET_TRIG="0"'
	assert_success
}

@test "validate_config: SUBNET_TRIG=5 passes" {
	run run_validate 'SUBNET_TRIG="5"'
	assert_success
}

@test "validate_config: SUBNET_TRIG=abc rejects" {
	run run_validate 'SUBNET_TRIG="abc"'
	assert_failure
}

@test "validate_config: SUBNET_MASK=24 passes" {
	run run_validate 'SUBNET_MASK="24"'
	assert_success
}

@test "validate_config: SUBNET_MASK=7 rejects (below minimum)" {
	run run_validate 'SUBNET_MASK="7"'
	assert_failure
}

@test "validate_config: SUBNET_MASK=33 rejects (above maximum)" {
	run run_validate 'SUBNET_MASK="33"'
	assert_failure
}

@test "validate_config: SUBNET_MASK_V6=48 passes" {
	run run_validate 'SUBNET_MASK_V6="48"'
	assert_success
}

@test "validate_config: SUBNET_MASK_V6=50 rejects (not multiple of 16)" {
	run run_validate 'SUBNET_MASK_V6="50"'
	assert_failure
}

@test "validate_config: SUBNET_MASK_V6 unset uses default (passes)" {
	run run_validate 'unset SUBNET_MASK_V6'
	assert_success
}

# --- BAN_RETRY_COUNT ---

@test "validate_config: BAN_RETRY_COUNT=0 passes" {
	run run_validate 'BAN_RETRY_COUNT="0"'
	assert_success
}

@test "validate_config: BAN_RETRY_COUNT=2 passes" {
	run run_validate 'BAN_RETRY_COUNT="2"'
	assert_success
}

@test "validate_config: BAN_RETRY_COUNT=abc rejects" {
	run run_validate 'BAN_RETRY_COUNT="abc"'
	assert_failure
}

@test "validate_config: BAN_RETRY_COUNT= uses default (passes)" {
	run run_validate 'BAN_RETRY_COUNT=""'
	assert_success
}

# --- EMAIL_LOGLINES ---

@test "validate_config: EMAIL_LOGLINES=50 passes" {
	run run_validate 'EMAIL_LOGLINES="50"'
	assert_success
}

@test "validate_config: EMAIL_LOGLINES=1 passes" {
	run run_validate 'EMAIL_LOGLINES="1"'
	assert_success
}

@test "validate_config: EMAIL_LOGLINES=0 rejects" {
	run run_validate 'EMAIL_LOGLINES="0"'
	assert_failure
}

@test "validate_config: EMAIL_LOGLINES=abc rejects" {
	run run_validate 'EMAIL_LOGLINES="abc"'
	assert_failure
}

@test "validate_config: EMAIL_LOGLINES= uses default (passes)" {
	run run_validate 'EMAIL_LOGLINES=""'
	assert_success
}

# --- show_config injection tests (Phase 26) ---

@test "show_config: rejects \$(cmd) injection attempt" {
	PRESSURE_TRIP="15"
	run show_config '$(touch /tmp/pwned)'
	assert_failure
	assert_output --partial "unknown config variable"
	[ ! -f "/tmp/pwned" ]
}

@test "show_config: rejects backtick injection attempt" {
	PRESSURE_TRIP="15"
	run show_config '`touch /tmp/pwned2`'
	assert_failure
	assert_output --partial "unknown config variable"
	[ ! -f "/tmp/pwned2" ]
}

# --- _hc_config case statement tests (Phase 27) ---

@test "_hc_config: validates log paths with case statement" {
	AUTH_LOG_PATH="/var/log/auth.log"
	KERNEL_LOG_PATH=""
	MAIL_LOG_PATH="/var/log/mail.log"
	_hc_pass=0
	_hc_warn=0
	_hc_fail=0
	BAN_COMMAND_TEMPLATE="/bin/true"
	UNBAN_COMMAND_TEMPLATE="/bin/true"
	BAN_COMMAND_V6_TEMPLATE=""
	UNBAN_COMMAND_V6_TEMPLATE=""
	_FW_BACKEND="custom"
	# just test config section's log path logic
	run _hc_config
	assert_output --partial "KERNEL_LOG_PATH: not configured"
}

# --- _save_rule_vars / _restore_rule_vars / _clear_rule_vars ---

@test "_save/_restore_rule_vars: round-trip preserves values" {
	PREREQ="/usr/sbin/sshd" LOG_FILE="/var/log/auth.log" TRIG="10"
	LOG_TAG="sshd" PORTS="22" MATCHED_HOSTS="192.0.2.4" IGNOREREGEX="^ignore"
	PRESSURE_WEIGHT="3" PRESSURE_TRIP="10"
	_save_rule_vars
	PREREQ="" LOG_FILE="" TRIG="" LOG_TAG="" PORTS="" MATCHED_HOSTS="" IGNOREREGEX=""
	PRESSURE_WEIGHT="" PRESSURE_TRIP=""
	_restore_rule_vars
	[ "$PREREQ" = "/usr/sbin/sshd" ]
	[ "$LOG_FILE" = "/var/log/auth.log" ]
	[ "$TRIG" = "10" ]
	[ "$LOG_TAG" = "sshd" ]
	[ "$PORTS" = "22" ]
	[ "$MATCHED_HOSTS" = "192.0.2.4" ]
	[ "$IGNOREREGEX" = "^ignore" ]
	[ "$PRESSURE_WEIGHT" = "3" ]
	[ "$PRESSURE_TRIP" = "10" ]
}

@test "_clear_rule_vars: clears all rule variables" {
	PREREQ="/usr/sbin/sshd" LOG_FILE="/var/log/auth.log" TRIG="10"
	LOG_TAG="sshd" PORTS="22" MATCHED_HOSTS="192.0.2.4" IGNOREREGEX="^ignore"
	SKIP_ALERT="1" RULE_EMAIL="test@example.com"
	PRESSURE_WEIGHT="3" PRESSURE_TRIP="10"
	_clear_rule_vars
	[ -z "$PREREQ" ]
	[ -z "$LOG_FILE" ]
	[ -z "$TRIG" ]
	[ -z "$LOG_TAG" ]
	[ -z "$PORTS" ]
	[ -z "$MATCHED_HOSTS" ]
	[ -z "$IGNOREREGEX" ]
	[ -z "$SKIP_ALERT" ]
	[ -z "$RULE_EMAIL" ]
	[ -z "$PRESSURE_WEIGHT" ]
	[ -z "$PRESSURE_TRIP" ]
}

# --- _rule_is_active ---

@test "_rule_is_active: active when PREREQ exists" {
	PREREQ="$TEST_TMPDIR/fake_binary"
	touch "$PREREQ"
	run _rule_is_active
	assert_success
}

@test "_rule_is_active: inactive when PREREQ missing" {
	PREREQ="$TEST_TMPDIR/nonexistent"
	run _rule_is_active
	assert_failure
}

@test "_rule_is_active: inactive when PREREQ empty" {
	PREREQ=""
	run _rule_is_active
	assert_failure
}

# --- show_config with BAN_COMMAND case mapping (F-019 regression) ---

@test "show_config: BAN_COMMAND returns raw template via case mapping" {
	BAN_COMMAND_TEMPLATE='/sbin/iptables -I INPUT -s $ATTACK_HOST -j DROP'
	run show_config "BAN_COMMAND"
	assert_success
	assert_output '/sbin/iptables -I INPUT -s $ATTACK_HOST -j DROP'
}

@test "show_config: dump all includes BAN_COMMAND mapped value" {
	BAN_COMMAND_TEMPLATE='/sbin/iptables -I INPUT -s $ATTACK_HOST -j DROP'
	UNBAN_COMMAND_TEMPLATE=""
	BAN_COMMAND_V6_TEMPLATE=""
	UNBAN_COMMAND_V6_TEMPLATE=""
	PRESSURE_TRIP="20"
	run show_config
	assert_success
	assert_output --partial 'BAN_COMMAND=/sbin/iptables -I INPUT -s $ATTACK_HOST -j DROP'
}
