#!/usr/bin/env bats
#
# Test suite for Phase 18 CLI evolution functions
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

	# create rules directory with a test rule
	RULES_PATH="$INSTALL_PATH/rules"
	mkdir -p "$RULES_PATH"
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
	bfd_teardown
}

# --- show_status ---

@test "show_status: displays header with date" {
	run show_status "$INSTALL_PATH"
	assert_success
	assert_line --index 0 --regexp 'BFD Status'
}

@test "show_status: reports active bans count" {
	echo "1700000000 0 192.0.2.1 sshd 22" >> "$INSTALL_PATH/tmp/bans.active"
	echo "1700000000 1800000000 192.0.2.2 sshd 22" >> "$INSTALL_PATH/tmp/bans.active"
	run show_status "$INSTALL_PATH"
	assert_success
	assert_output --partial "2 (1 temporary, 1 permanent)"
}

@test "show_status: reports events count" {
	local now
	now=$(date +"%s")
	echo "$now 192.0.2.1 sshd" >> "$INSTALL_PATH/tmp/events.dat"
	echo "$now 192.0.2.2 sshd" >> "$INSTALL_PATH/tmp/events.dat"
	echo "$now 192.0.2.3 postfix" >> "$INSTALL_PATH/tmp/events.dat"
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
	echo "$now 192.0.2.1 sshd" >> "$INSTALL_PATH/tmp/events.dat"
	echo "$now 192.0.2.2 sshd" >> "$INSTALL_PATH/tmp/events.dat"
	echo "$now 192.0.2.3 postfix" >> "$INSTALL_PATH/tmp/events.dat"
	run show_service_status "$INSTALL_PATH" "sshd"
	assert_success
	assert_output --partial "2 from 2 unique IPs"
}

@test "show_service_status: shows active bans for service" {
	local now
	now=$(date +"%s")
	echo "$now 0 192.0.2.1 sshd 22" >> "$INSTALL_PATH/tmp/bans.active"
	run show_service_status "$INSTALL_PATH" "sshd"
	assert_success
	assert_output --partial "Active bans:    1"
	assert_output --partial "192.0.2.1 (permanent)"
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

@test "show_config: rejects unknown variable" {
	run show_config "NONEXISTENT_VAR"
	assert_failure
	assert_output --partial "unknown config variable"
}

# --- flush_bans ---

@test "flush_bans: no active bans" {
	run flush_bans "$INSTALL_PATH" "all" "1700000000"
	assert_success
	assert_output "No active bans."
}

@test "flush_bans: temp mode skips permanent bans" {
	echo "1700000000 0 192.0.2.1 sshd 22" >> "$INSTALL_PATH/tmp/bans.active"
	echo "1700000000 1800000000 192.0.2.2 sshd 22" >> "$INSTALL_PATH/tmp/bans.active"
	run flush_bans "$INSTALL_PATH" "temp" "1700000000"
	assert_success
	assert_output --partial "1 bans removed."
	# permanent ban should remain
	run cat "$INSTALL_PATH/tmp/bans.active"
	assert_output --partial "192.0.2.1"
}

@test "flush_bans: all mode removes everything" {
	echo "1700000000 0 192.0.2.1 sshd 22" >> "$INSTALL_PATH/tmp/bans.active"
	echo "1700000000 1800000000 192.0.2.2 sshd 22" >> "$INSTALL_PATH/tmp/bans.active"
	run flush_bans "$INSTALL_PATH" "all" "1700000000"
	assert_success
	assert_output --partial "2 bans removed."
}

@test "flush_bans: records unban in history" {
	echo "1700000000 1800000000 192.0.2.2 sshd 22" >> "$INSTALL_PATH/tmp/bans.active"
	flush_bans "$INSTALL_PATH" "temp" "1700000000"
	run cat "$INSTALL_PATH/tmp/bans.history"
	assert_output --partial "192.0.2.2"
	assert_output --partial "unban"
}

# --- search_ip ---

@test "search_ip: shows not banned for unknown IP" {
	run search_ip "$INSTALL_PATH" "192.0.2.99"
	assert_success
	assert_output --partial "IP Report: 192.0.2.99"
	assert_output --partial "not banned"
}

@test "search_ip: shows permanent ban status" {
	echo "1700000000 0 192.0.2.1 sshd 22" >> "$INSTALL_PATH/tmp/bans.active"
	run search_ip "$INSTALL_PATH" "192.0.2.1"
	assert_success
	assert_output --partial "BANNED (permanent"
}

@test "search_ip: shows ban history" {
	local now
	now=$(date +"%s")
	echo "$now 0 192.0.2.1 sshd ban" >> "$INSTALL_PATH/tmp/bans.history"
	run search_ip "$INSTALL_PATH" "192.0.2.1"
	assert_success
	assert_output --partial "Ban history:"
	assert_output --partial "1 bans in 24h"
}

@test "search_ip: shows events" {
	local now
	now=$(date +"%s")
	echo "$now 192.0.2.1 sshd" >> "$INSTALL_PATH/tmp/events.dat"
	echo "$now 192.0.2.1 sshd" >> "$INSTALL_PATH/tmp/events.dat"
	run search_ip "$INSTALL_PATH" "192.0.2.1"
	assert_success
	assert_output --partial "2 failures"
}

@test "search_ip: shows attack pool triggers" {
	echo "1700000000 192.0.2.1 sshd" >> "$INSTALL_PATH/stats/attack.pool"
	echo "1700000001 192.0.2.1 sshd" >> "$INSTALL_PATH/stats/attack.pool"
	run search_ip "$INSTALL_PATH" "192.0.2.1"
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

# --- list_bans (table format) ---

@test "list_bans: no active bans" {
	run list_bans "$INSTALL_PATH"
	assert_success
	assert_output "No active bans."
}

@test "list_bans: single ban shows table" {
	echo "1700000000 0 192.0.2.1 sshd 22" >> "$INSTALL_PATH/tmp/bans.active"
	run list_bans "$INSTALL_PATH"
	assert_success
	assert_output --partial "Active bans"
	assert_output --partial "192.0.2.1"
	assert_output --partial "sshd"
}

@test "list_bans: multiple bans all shown" {
	echo "1700000000 0 192.0.2.1 sshd 22" >> "$INSTALL_PATH/tmp/bans.active"
	echo "1700000000 1800000000 192.0.2.2 postfix 25" >> "$INSTALL_PATH/tmp/bans.active"
	run list_bans "$INSTALL_PATH"
	assert_success
	assert_output --partial "192.0.2.1"
	assert_output --partial "192.0.2.2"
}

# --- _json_escape ---

@test "_json_escape: no special chars unchanged" {
	run _json_escape "hello"
	assert_output "hello"
}

@test "_json_escape: backslash escaped" {
	run _json_escape 'back\slash'
	assert_output 'back\\slash'
}

@test "_json_escape: double-quote escaped" {
	run _json_escape 'say "hi"'
	assert_output 'say \"hi\"'
}

@test "_json_escape: empty string" {
	run _json_escape ""
	assert_output ""
}

@test "_json_escape: mixed escaping" {
	run _json_escape 'a\b"c'
	assert_output 'a\\b\"c'
}

# --- flush_bans: non-standard mode ---

@test "flush_bans: non-standard mode acts as temp mode" {
	echo "1700000000 0 192.0.2.1 sshd 22" >> "$INSTALL_PATH/tmp/bans.active"
	echo "1700000000 1800000000 192.0.2.2 sshd 22" >> "$INSTALL_PATH/tmp/bans.active"
	run flush_bans "$INSTALL_PATH" "perm" "1700000000"
	assert_success
	assert_output --partial "1 bans removed."
	# permanent ban should remain
	run cat "$INSTALL_PATH/tmp/bans.active"
	assert_output --partial "192.0.2.1"
}

# --- list_bans_json ---

@test "list_bans_json: empty array for no bans" {
	run list_bans_json "$INSTALL_PATH"
	assert_success
	local stripped
	stripped=$(echo "$output" | tr -d '[:space:]')
	[ "$stripped" = "[]" ]
}

@test "list_bans_json: formats ban as JSON object" {
	echo "1700000000 0 192.0.2.1 sshd 22" >> "$INSTALL_PATH/tmp/bans.active"
	run list_bans_json "$INSTALL_PATH"
	assert_success
	assert_output --partial '"ip": "192.0.2.1"'
	assert_output --partial '"service": "sshd"'
	assert_output --partial '"ports": "22"'
	assert_output --partial '"expires": "permanent"'
	# verify it starts with [ and ends with ]
	local first_char last_char
	first_char=$(echo "$output" | head -1 | tr -d '[:space:]')
	last_char=$(echo "$output" | tail -1 | tr -d '[:space:]')
	[ "$first_char" = "[" ]
	[ "$last_char" = "]" ]
}

@test "list_bans_json: multiple bans separated by comma" {
	echo "1700000000 0 192.0.2.1 sshd 22" >> "$INSTALL_PATH/tmp/bans.active"
	echo "1700000000 1800000000 192.0.2.2 postfix 25" >> "$INSTALL_PATH/tmp/bans.active"
	run list_bans_json "$INSTALL_PATH"
	assert_success
	assert_output --partial '"ip": "192.0.2.1"'
	assert_output --partial '"ip": "192.0.2.2"'
	# count JSON objects — should have exactly 2
	local obj_count
	obj_count=$(echo "$output" | grep -c '"ip":')
	[ "$obj_count" -eq 2 ]
}

# --- list_bans_csv ---

@test "list_bans_csv: header only for no bans" {
	run list_bans_csv "$INSTALL_PATH"
	assert_success
	assert_output "ip,service,ports,banned,expires"
}

@test "list_bans_csv: formats ban as CSV row" {
	echo "1700000000 0 192.0.2.1 sshd 22" >> "$INSTALL_PATH/tmp/bans.active"
	run list_bans_csv "$INSTALL_PATH"
	assert_success
	assert_line --index 0 "ip,service,ports,banned,expires"
	assert_line --index 1 --partial "192.0.2.1,sshd,22,"
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

# --- Exit code and POSIX compliance tests (Phase 27) ---

@test "exit code variables are defined and numeric" {
	[ -n "$EXIT_OK" ]
	[ -n "$EXIT_CONFIG_ERROR" ]
	[ -n "$EXIT_LOCK_ERROR" ]
	[ -n "$EXIT_PREREQ_ERROR" ]
	# verify they are valid integers
	[ "$EXIT_OK" -eq 0 ]
	[ "$EXIT_CONFIG_ERROR" -ge 1 ]
	[ "$EXIT_LOCK_ERROR" -ge 1 ]
	[ "$EXIT_PREREQ_ERROR" -ge 1 ]
}

@test "_fw_custom_ban: eval with security comment does not break execution" {
	BAN_COMMAND_TEMPLATE="/bin/true"
	BAN_COMMAND_V6_TEMPLATE=""
	run _fw_custom_ban "192.0.2.1" "sshd" "22"
	assert_success
}

# --- detect_run_mode ---

@test "detect_run_mode: returns cron when /etc/cron.d/bfd exists" {
	# /etc/cron.d/bfd is typically present in the test container
	if [ ! -f /etc/cron.d/bfd ]; then
		mkdir -p /etc/cron.d
		echo "# test" > /etc/cron.d/bfd
	fi
	run detect_run_mode
	assert_success
	assert_output "cron"
}

@test "detect_run_mode: returns unknown when no scheduler found" {
	# temporarily hide the cron file
	local had_cron=0
	if [ -f /etc/cron.d/bfd ]; then
		had_cron=1
		mv /etc/cron.d/bfd /etc/cron.d/bfd.test_backup
	fi
	run detect_run_mode
	if [ "$had_cron" -eq 1 ]; then
		mv /etc/cron.d/bfd.test_backup /etc/cron.d/bfd
	fi
	assert_success
	assert_output "unknown"
}

@test "detect_run_mode: output is single line" {
	run detect_run_mode
	assert_success
	local line_count
	line_count=$(echo "$output" | wc -l)
	[ "$line_count" -eq 1 ]
}

@test "show_status: displays mode line" {
	run show_status "$INSTALL_PATH"
	assert_success
	assert_output --partial "Mode:"
}

@test "show_status: displays active bans line" {
	run show_status "$INSTALL_PATH"
	assert_success
	assert_output --partial "Active bans:"
}

@test "show_status: displays events line" {
	run show_status "$INSTALL_PATH"
	assert_success
	assert_output --partial "Events (24h):"
}
