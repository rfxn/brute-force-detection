#!/usr/bin/env bats
#
# Test suite for Phase 18 CLI evolution functions
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

setup() {
	TEST_TMPDIR=$(mktemp -d)
	INSTALL_PATH="$TEST_TMPDIR/bfd"
	mkdir -p "$INSTALL_PATH"
	state_init "$INSTALL_PATH"

	# minimal config for functions that need it
	BFD_LOG_PATH="$TEST_TMPDIR/bfd_log"
	touch "$BFD_LOG_PATH"
	OUTPUT_SYSLOG="0"
	OUTPUT_SYSLOG_FILE="$TEST_TMPDIR/syslog"
	TRIG="15"
	TRIG_WINDOW="300"
	TRIG_GLOBAL="0"
	BAN_DURATION="300"
	BAN_PERMANENT_AFTER="5"
	BAN_PERMANENT_WINDOW="86400"
	BAN_RETRY_COUNT="0"
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
	BAN_COMMAND_TEMPLATE="/bin/true"
	UNBAN_COMMAND_TEMPLATE="/bin/true"
	BAN_COMMAND_V6_TEMPLATE=""
	UNBAN_COMMAND_V6_TEMPLATE=""
	GLOB_TRIG="$TRIG"
	# firewall backend — custom mode for test compatibility
	_FW_BACKEND="custom"

	# create rules directory with a test rule
	RULES_PATH="$INSTALL_PATH/rules"
	mkdir -p "$RULES_PATH"
	# sshd rule that's "active" (REQ points to an existing binary)
	cat > "$RULES_PATH/sshd" <<-'RULE'
	REQ="/bin/sh"
	LP="/var/log/auth.log"
	TLOG_TF="sshd"
	TRIG="5"
	PORTS="22"
	ARG_VAL=""
	RULE
	chmod 644 "$RULES_PATH/sshd"
	chown root "$RULES_PATH/sshd" 2>/dev/null || true
}

teardown() {
	rm -rf "$TEST_TMPDIR"
}

# --- show_status ---

@test "show_status: displays header with date" {
	run show_status "$INSTALL_PATH"
	assert_success
	assert_line --index 0 --regexp 'BFD Status'
}

@test "show_status: reports active bans count" {
	echo "1700000000 0 10.0.0.1 sshd 22" >> "$INSTALL_PATH/tmp/bans.active"
	echo "1700000000 1800000000 10.0.0.2 sshd 22" >> "$INSTALL_PATH/tmp/bans.active"
	run show_status "$INSTALL_PATH"
	assert_success
	assert_output --partial "2 (1 temporary, 1 permanent)"
}

@test "show_status: reports events count" {
	local now
	now=$(date +"%s")
	echo "$now 10.0.0.1 sshd" >> "$INSTALL_PATH/tmp/events.dat"
	echo "$now 10.0.0.2 sshd" >> "$INSTALL_PATH/tmp/events.dat"
	echo "$now 10.0.0.3 postfix" >> "$INSTALL_PATH/tmp/events.dat"
	run show_status "$INSTALL_PATH"
	assert_success
	assert_output --partial "3 across 2 services"
}

@test "show_status: reports active rules" {
	run show_status "$INSTALL_PATH"
	assert_success
	# sshd rule is active (REQ=/bin/sh exists)
	assert_output --partial "Active Rules:"
}

@test "show_status: reports zero bans when empty" {
	run show_status "$INSTALL_PATH"
	assert_success
	assert_output --partial "0 (0 temporary, 0 permanent)"
}

# --- show_service_status ---

@test "show_service_status: displays service header" {
	run show_service_status "$INSTALL_PATH" "sshd"
	assert_success
	assert_output --partial "BFD Status: sshd"
}

@test "show_service_status: shows threshold and ports" {
	run show_service_status "$INSTALL_PATH" "sshd"
	assert_success
	assert_output --partial "Threshold:      5 failures"
	assert_output --partial "Ports:          22"
}

@test "show_service_status: shows events for service" {
	local now
	now=$(date +"%s")
	echo "$now 10.0.0.1 sshd" >> "$INSTALL_PATH/tmp/events.dat"
	echo "$now 10.0.0.2 sshd" >> "$INSTALL_PATH/tmp/events.dat"
	echo "$now 10.0.0.3 postfix" >> "$INSTALL_PATH/tmp/events.dat"
	run show_service_status "$INSTALL_PATH" "sshd"
	assert_success
	assert_output --partial "2 from 2 unique IPs"
}

@test "show_service_status: shows active bans for service" {
	local now
	now=$(date +"%s")
	echo "$now 0 10.0.0.1 sshd 22" >> "$INSTALL_PATH/tmp/bans.active"
	run show_service_status "$INSTALL_PATH" "sshd"
	assert_success
	assert_output --partial "Active bans:    1"
	assert_output --partial "10.0.0.1 (permanent)"
}

@test "show_service_status: error for unknown service" {
	run show_service_status "$INSTALL_PATH" "nonexistent"
	assert_failure
	assert_output --partial "no rule found"
}

# --- show_config ---

@test "show_config: dumps all variables" {
	run show_config
	assert_success
	assert_output --partial "TRIG=15"
	assert_output --partial "TRIG_WINDOW=300"
	assert_output --partial "BAN_DURATION=300"
	assert_output --partial "EMAIL_ALERTS=0"
}

@test "show_config: shows single variable" {
	run show_config "TRIG"
	assert_success
	assert_output "15"
}

@test "show_config: shows empty for unset variable" {
	run show_config "NONEXISTENT_VAR"
	assert_success
	assert_output ""
}

# --- flush_bans ---

@test "flush_bans: no active bans" {
	run flush_bans "$INSTALL_PATH" "all" "1700000000"
	assert_success
	assert_output "No active bans."
}

@test "flush_bans: temp mode skips permanent bans" {
	echo "1700000000 0 10.0.0.1 sshd 22" >> "$INSTALL_PATH/tmp/bans.active"
	echo "1700000000 1800000000 10.0.0.2 sshd 22" >> "$INSTALL_PATH/tmp/bans.active"
	run flush_bans "$INSTALL_PATH" "temp" "1700000000"
	assert_success
	assert_output --partial "1 bans removed."
	# permanent ban should remain
	run cat "$INSTALL_PATH/tmp/bans.active"
	assert_output --partial "10.0.0.1"
}

@test "flush_bans: all mode removes everything" {
	echo "1700000000 0 10.0.0.1 sshd 22" >> "$INSTALL_PATH/tmp/bans.active"
	echo "1700000000 1800000000 10.0.0.2 sshd 22" >> "$INSTALL_PATH/tmp/bans.active"
	run flush_bans "$INSTALL_PATH" "all" "1700000000"
	assert_success
	assert_output --partial "2 bans removed."
}

@test "flush_bans: records unban in history" {
	echo "1700000000 1800000000 10.0.0.2 sshd 22" >> "$INSTALL_PATH/tmp/bans.active"
	flush_bans "$INSTALL_PATH" "temp" "1700000000"
	run cat "$INSTALL_PATH/tmp/bans.history"
	assert_output --partial "10.0.0.2"
	assert_output --partial "unban"
}

# --- search_ip ---

@test "search_ip: shows not banned for unknown IP" {
	run search_ip "$INSTALL_PATH" "10.0.0.99"
	assert_success
	assert_output --partial "IP Report: 10.0.0.99"
	assert_output --partial "not banned"
}

@test "search_ip: shows permanent ban status" {
	echo "1700000000 0 10.0.0.1 sshd 22" >> "$INSTALL_PATH/tmp/bans.active"
	run search_ip "$INSTALL_PATH" "10.0.0.1"
	assert_success
	assert_output --partial "BANNED (permanent"
}

@test "search_ip: shows ban history" {
	local now
	now=$(date +"%s")
	echo "$now 0 10.0.0.1 sshd ban" >> "$INSTALL_PATH/tmp/bans.history"
	run search_ip "$INSTALL_PATH" "10.0.0.1"
	assert_success
	assert_output --partial "Ban history:"
	assert_output --partial "1 bans in 24h"
}

@test "search_ip: shows events" {
	local now
	now=$(date +"%s")
	echo "$now 10.0.0.1 sshd" >> "$INSTALL_PATH/tmp/events.dat"
	echo "$now 10.0.0.1 sshd" >> "$INSTALL_PATH/tmp/events.dat"
	run search_ip "$INSTALL_PATH" "10.0.0.1"
	assert_success
	assert_output --partial "2 failures"
}

@test "search_ip: shows attack pool triggers" {
	echo "1700000000 10.0.0.1 sshd" >> "$INSTALL_PATH/stats/attack.pool"
	echo "1700000001 10.0.0.1 sshd" >> "$INSTALL_PATH/stats/attack.pool"
	run search_ip "$INSTALL_PATH" "10.0.0.1"
	assert_success
	assert_output --partial "2 total triggers"
}

@test "search_ip: rejects invalid IP" {
	run search_ip "$INSTALL_PATH" "not-an-ip"
	assert_failure
	assert_output --partial "invalid IP"
}

# --- list_rules ---

@test "list_rules: lists rules with status" {
	run list_rules "$INSTALL_PATH"
	assert_success
	assert_output --partial "sshd"
	assert_output --partial "active"
}

@test "list_rules: counts active and total" {
	run list_rules "$INSTALL_PATH"
	assert_success
	assert_output --partial "1 active, 0 inactive (1 total)"
}

@test "list_rules: shows inactive rule" {
	cat > "$RULES_PATH/fakeservice" <<-'RULE'
	REQ="/nonexistent/binary"
	LP="/var/log/fake.log"
	TLOG_TF="fake"
	ARG_VAL=""
	RULE
	chmod 644 "$RULES_PATH/fakeservice"
	chown root "$RULES_PATH/fakeservice" 2>/dev/null || true
	run list_rules "$INSTALL_PATH"
	assert_success
	assert_output --partial "fakeservice"
	assert_output --partial "inactive"
	assert_output --partial "1 active, 1 inactive (2 total)"
}

# --- show_rule ---

@test "show_rule: shows rule details" {
	run show_rule "$INSTALL_PATH" "sshd"
	assert_success
	assert_output --partial "Rule: sshd"
	assert_output --partial "Threshold:  5"
	assert_output --partial "Ports:      22"
}

@test "show_rule: error for missing rule" {
	run show_rule "$INSTALL_PATH" "nonexistent"
	assert_failure
	assert_output --partial "not found"
}

# --- list_bans_json ---

@test "list_bans_json: empty array for no bans" {
	run list_bans_json "$INSTALL_PATH"
	assert_success
	assert_output --partial "["
	assert_output --partial "]"
}

@test "list_bans_json: formats ban as JSON object" {
	echo "1700000000 0 10.0.0.1 sshd 22" >> "$INSTALL_PATH/tmp/bans.active"
	run list_bans_json "$INSTALL_PATH"
	assert_success
	assert_output --partial '"ip": "10.0.0.1"'
	assert_output --partial '"service": "sshd"'
	assert_output --partial '"expires": "permanent"'
}

@test "list_bans_json: multiple bans separated by comma" {
	echo "1700000000 0 10.0.0.1 sshd 22" >> "$INSTALL_PATH/tmp/bans.active"
	echo "1700000000 1800000000 10.0.0.2 postfix 25" >> "$INSTALL_PATH/tmp/bans.active"
	run list_bans_json "$INSTALL_PATH"
	assert_success
	assert_output --partial '"ip": "10.0.0.1"'
	assert_output --partial '"ip": "10.0.0.2"'
	assert_output --partial ","
}

# --- list_bans_csv ---

@test "list_bans_csv: header only for no bans" {
	run list_bans_csv "$INSTALL_PATH"
	assert_success
	assert_output "ip,service,ports,banned,expires"
}

@test "list_bans_csv: formats ban as CSV row" {
	echo "1700000000 0 10.0.0.1 sshd 22" >> "$INSTALL_PATH/tmp/bans.active"
	run list_bans_csv "$INSTALL_PATH"
	assert_success
	assert_line --index 0 "ip,service,ports,banned,expires"
	assert_line --index 1 --partial "10.0.0.1,sshd,22,"
	assert_line --index 1 --partial ",permanent"
}

# --- attackpool IP search integration ---

@test "search_ip: IPv6 address works" {
	local now
	now=$(date +"%s")
	echo "$now 0 2001:db8::1 sshd 22" >> "$INSTALL_PATH/tmp/bans.active"
	run search_ip "$INSTALL_PATH" "2001:db8::1"
	assert_success
	assert_output --partial "BANNED (permanent"
}
