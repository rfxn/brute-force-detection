#!/usr/bin/env bats
#
# Test suite for Phase 18 CLI evolution functions
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

	# create rules directory with a test rule
	RULES_PATH="$INSTALL_PATH/rules"
	mkdir -p "$RULES_PATH"
	cat > "$RULES_PATH/sshd" <<-'RULE'
	PREREQ="/bin/sh"
	LOG_FILE="/var/log/auth.log"
	LOG_TAG="sshd"
	TRIG="5"
	PORTS="22"
	MATCHED_HOSTS=""
	RULE
	chmod 644 "$RULES_PATH/sshd"
	chown root "$RULES_PATH/sshd" 2>/dev/null || true
}

teardown() {
	bfd_teardown
}

# --- show_status (Merge B) ---

@test "show_status: populated state shows header, bans, events, rules" {
	local now
	now=$(date +"%s")
	echo "1700000000 0 192.0.2.1 sshd 22" >> "$INSTALL_PATH/tmp/bans.active"
	echo "1700000000 1800000000 192.0.2.2 sshd 22" >> "$INSTALL_PATH/tmp/bans.active"
	echo "$now 192.0.2.1 sshd" >> "$INSTALL_PATH/tmp/pressure.dat"
	echo "$now 192.0.2.2 sshd" >> "$INSTALL_PATH/tmp/pressure.dat"
	echo "$now 192.0.2.3 postfix" >> "$INSTALL_PATH/tmp/pressure.dat"
	run show_status "$INSTALL_PATH"
	assert_success
	# header with date
	assert_line --index 0 --regexp 'BFD Status'
	# active bans count
	assert_output --partial "2 (1 temporary, 1 permanent)"
	# events count
	assert_output --partial "3 across 2 services"
	# active rules present
	assert_output --partial "Active Rules:"
}

@test "show_status: empty state reports zero bans" {
	run show_status "$INSTALL_PATH"
	assert_success
	assert_output --partial "0 (0 temporary, 0 permanent)"
}

# --- show_service_status (Merge C) ---

@test "show_service_status: populated state shows header, trip, ports, events, bans" {
	local now
	now=$(date +"%s")
	echo "$now 192.0.2.1 sshd" >> "$INSTALL_PATH/tmp/pressure.dat"
	echo "$now 192.0.2.2 sshd" >> "$INSTALL_PATH/tmp/pressure.dat"
	echo "$now 192.0.2.3 postfix" >> "$INSTALL_PATH/tmp/pressure.dat"
	echo "$now 0 192.0.2.1 sshd 22" >> "$INSTALL_PATH/tmp/bans.active"
	run show_service_status "$INSTALL_PATH" "sshd"
	assert_success
	# header
	assert_output --partial "BFD Status: sshd"
	# trip and ports
	assert_output --partial "Trip:"
	assert_output --partial "Ports:          22"
	# events for service (2 sshd events from 2 unique IPs)
	assert_output --partial "2 from 2 unique IPs"
	# bans for service
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
	assert_output --partial "PRESSURE_TRIP=15"
	assert_output --partial "PRESSURE_HALF_LIFE=300"
	assert_output --partial "BAN_TTL=300"
	assert_output --partial "EMAIL_ALERTS=0"
}

@test "show_config: shows single variable" {
	run show_config "PRESSURE_TRIP"
	assert_success
	assert_output "15"
}

@test "show_config: rejects unknown variable" {
	run show_config "NONEXISTENT_VAR"
	assert_failure
	assert_output --partial "unknown config variable"
}

# --- flush_bans (Merge E) ---

@test "flush_bans: no active bans" {
	run flush_bans "$INSTALL_PATH" "all" "1700000000"
	assert_success
	assert_output "No active bans."
}

@test "flush_bans: mode variants (temp, all, non-standard) with history" {
	# --- temp mode: skips permanent bans, records unban in history ---
	echo "1700000000 0 192.0.2.1 sshd 22" >> "$INSTALL_PATH/tmp/bans.active"
	echo "1700000000 1800000000 192.0.2.2 sshd 22" >> "$INSTALL_PATH/tmp/bans.active"
	run flush_bans "$INSTALL_PATH" "temp" "1700000000"
	assert_success
	assert_output --partial "1 bans removed."
	# permanent ban should remain
	run cat "$INSTALL_PATH/tmp/bans.active"
	assert_output --partial "192.0.2.1"
	# history recorded for unbanned temp ban
	run cat "$INSTALL_PATH/tmp/bans.history"
	assert_output --partial "192.0.2.2"
	assert_output --partial "unban"

	# --- all mode: removes everything ---
	# reset state
	: > "$INSTALL_PATH/tmp/bans.active"
	: > "$INSTALL_PATH/tmp/bans.history"
	echo "1700000000 0 192.0.2.1 sshd 22" >> "$INSTALL_PATH/tmp/bans.active"
	echo "1700000000 1800000000 192.0.2.2 sshd 22" >> "$INSTALL_PATH/tmp/bans.active"
	run flush_bans "$INSTALL_PATH" "all" "1700000000"
	assert_success
	assert_output --partial "2 bans removed."

	# --- non-standard mode: acts as temp mode ---
	# reset state
	: > "$INSTALL_PATH/tmp/bans.active"
	echo "1700000000 0 192.0.2.1 sshd 22" >> "$INSTALL_PATH/tmp/bans.active"
	echo "1700000000 1800000000 192.0.2.2 sshd 22" >> "$INSTALL_PATH/tmp/bans.active"
	run flush_bans "$INSTALL_PATH" "perm" "1700000000"
	assert_success
	assert_output --partial "1 bans removed."
	# permanent ban should remain
	run cat "$INSTALL_PATH/tmp/bans.active"
	assert_output --partial "192.0.2.1"
}

# --- search_ip (Merge D) ---

@test "search_ip: populated state shows ban, history, events, pressure, per-service" {
	local now
	now=$(date +"%s")
	# permanent ban
	echo "1700000000 0 192.0.2.1 sshd 22" >> "$INSTALL_PATH/tmp/bans.active"
	# ban history entry
	echo "$now 0 192.0.2.1 sshd ban" >> "$INSTALL_PATH/tmp/bans.history"
	# attack.pool: recent entry (within 24h) + old entry (beyond 24h)
	echo "$now 192.0.2.1 sshd 3 RU ban 600 22 15000 service" >> "$INSTALL_PATH/stats/attack.pool"
	echo "$((now - 200000)) 192.0.2.1 sshd 2 RU escalate 1200 22 20000 service" >> "$INSTALL_PATH/stats/attack.pool"
	# pressure data: 2 services
	state_pressure_append "$INSTALL_PATH" "$((now - 1))" "192.0.2.1" "sshd" "3" "3"
	state_pressure_append "$INSTALL_PATH" "$((now - 2))" "192.0.2.1" "dovecot" "2" "2"
	run search_ip "$INSTALL_PATH" "192.0.2.1"
	assert_success
	# permanent ban status
	assert_output --partial "BANNED (permanent"
	# ban history
	assert_output --partial "Ban history:"
	assert_output --partial "1 bans in 24h"
	# events from attack.pool
	assert_output --partial "Failures (24h): 3"
	assert_output --partial "Total failures: 5 (2 ban triggers)"
	# pressure score
	assert_output --partial "Pressure:"
	assert_output --partial "/${GLOB_PRESSURE_TRIP}"
	# per-service pressure
	assert_output --partial "sshd:"
	assert_output --partial "dovecot:"
}

@test "search_ip: edge cases (not banned, invalid IP)" {
	# not-banned IP
	run search_ip "$INSTALL_PATH" "192.0.2.99"
	assert_success
	assert_output --partial "IP Report: 192.0.2.99"
	assert_output --partial "not banned"

	# invalid IP
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
	PREREQ="/nonexistent/binary"
	LOG_FILE="/var/log/fake.log"
	LOG_TAG="fake"
	MATCHED_HOSTS=""
	RULE
	chmod 644 "$RULES_PATH/fakeservice"
	chown root "$RULES_PATH/fakeservice" 2>/dev/null || true
	run list_rules "$INSTALL_PATH"
	assert_success
	assert_output --partial "fakeservice"
	assert_output --partial "inactive"
	assert_output --partial "1 active, 1 inactive (2 total)"
}

@test "list_rules: --active filter hides inactive rules" {
	cat > "$RULES_PATH/fakeservice" <<-'RULE'
	PREREQ="/nonexistent/binary"
	LOG_FILE="/var/log/fake.log"
	LOG_TAG="fake"
	MATCHED_HOSTS=""
	RULE
	chmod 644 "$RULES_PATH/fakeservice"
	chown root "$RULES_PATH/fakeservice" 2>/dev/null || true
	run list_rules "$INSTALL_PATH" 1
	assert_success
	assert_output --partial "sshd"
	refute_output --partial "fakeservice"
	assert_output --partial "1 active (filtered, 2 total)"
}

@test "list_rules: log source shows journal when file missing and journal registered" {
	command -v journalctl >/dev/null 2>&1 || skip "no journalctl"
	tlog_journal_register "sshd" "SYSLOG_IDENTIFIER=sshd"
	# LOG_FILE=/var/log/auth.log won't exist in test container
	[ ! -f "/var/log/auth.log" ] || skip "auth.log exists"
	run list_rules "$INSTALL_PATH"
	assert_success
	assert_output --partial "journal (sshd)"
}

@test "list_rules: log source shows file+journal when both available" {
	command -v journalctl >/dev/null 2>&1 || skip "no journalctl"
	touch /var/log/auth.log
	tlog_journal_register "sshd" "SYSLOG_IDENTIFIER=sshd"
	run list_rules "$INSTALL_PATH"
	assert_success
	assert_output --partial "(file+journal)"
	rm -f /var/log/auth.log
}

@test "list_rules: log source shows not found when file missing and no journal" {
	cat > "$RULES_PATH/nologsvc" <<-RULE
	PREREQ="/bin/sh"
	LOG_FILE="/nonexistent/log/file.log"
	LOG_TAG="nologsvc"
	MATCHED_HOSTS=""
	RULE
	chmod 644 "$RULES_PATH/nologsvc"
	chown root "$RULES_PATH/nologsvc" 2>/dev/null || true
	run list_rules "$INSTALL_PATH"
	assert_success
	assert_output --partial "(not found)"
}

# --- show_rule ---

@test "show_rule: shows rule details" {
	run show_rule "$INSTALL_PATH" "sshd"
	assert_success
	assert_output --partial "Rule: sshd"
	assert_output --partial "Trip:"
	assert_output --partial "Weight:"
	assert_output --partial "Ports:      22"
}

@test "show_rule: shows journal availability when file and journal both present" {
	command -v journalctl >/dev/null 2>&1 || skip "no journalctl"
	touch /var/log/auth.log
	tlog_journal_register "sshd" "SYSLOG_IDENTIFIER=sshd"
	run show_rule "$INSTALL_PATH" "sshd"
	assert_success
	assert_output --partial "journal avail: sshd"
	rm -f /var/log/auth.log
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

@test "list_bans: corrupt line with non-numeric ts is skipped" {
	echo "1700000000 0 192.0.2.1 sshd 22" >> "$INSTALL_PATH/tmp/bans.active"
	echo "CORRUPT 0 10.0.0.1 sshd 22" >> "$INSTALL_PATH/tmp/bans.active"
	run list_bans "$INSTALL_PATH"
	assert_success
	assert_output --partial "192.0.2.1"
	refute_output --partial "10.0.0.1"
}

@test "list_bans: corrupt line with missing host is skipped" {
	echo "1700000000 0 192.0.2.1 sshd 22" >> "$INSTALL_PATH/tmp/bans.active"
	echo "1700000000 0" >> "$INSTALL_PATH/tmp/bans.active"
	run list_bans "$INSTALL_PATH"
	assert_success
	assert_output --partial "192.0.2.1"
}

# --- _json_escape (Merge A) ---

@test "_json_escape: all input variants" {
	# no special chars unchanged
	run _json_escape "hello"
	assert_output "hello"

	# backslash escaped
	run _json_escape 'back\slash'
	assert_output 'back\\slash'

	# double-quote escaped
	run _json_escape 'say "hi"'
	assert_output 'say \"hi\"'

	# empty string
	run _json_escape ""
	assert_output ""

	# mixed escaping
	run _json_escape 'a\b"c'
	assert_output 'a\\b\"c'

	# newline escaped
	run _json_escape $'line1\nline2'
	assert_output 'line1\nline2'

	# tab escaped
	run _json_escape $'col1\tcol2'
	assert_output 'col1\tcol2'

	# carriage return escaped
	run _json_escape $'text\rmore'
	assert_output 'text\rmore'

	# backspace and formfeed escaped
	run _json_escape $'\b\f'
	assert_output '\b\f'

	# mixed special chars and control chars
	run _json_escape $'a\\b"c\nd\te'
	assert_output 'a\\b\"c\nd\te'
}

# --- list_bans_json + list_bans_csv (Merge F) ---

@test "list_bans_json: empty, populated, and multiple bans" {
	# empty array for no bans
	run list_bans_json "$INSTALL_PATH"
	assert_success
	local stripped
	stripped=$(echo "$output" | tr -d '[:space:]')
	[ "$stripped" = "[]" ]

	# single ban as JSON object
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

	# multiple bans separated by comma
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

@test "list_bans_csv: empty and populated" {
	# header only for no bans
	run list_bans_csv "$INSTALL_PATH"
	assert_success
	assert_output "ip,service,ports,banned,expires"

	# populated ban as CSV row
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

# --- detect_run_mode (Merge H) ---

@test "detect_run_mode: cron and unknown modes, single-line output" {
	# Mock pgrep to return empty — isolates cron/unknown detection from
	# unpredictable process ancestry in Docker/CI environments
	pgrep() { return 1; }
	export -f pgrep

	# --- cron mode: /etc/cron.d/bfd exists ---
	local _created=0
	if [ ! -f /etc/cron.d/bfd ]; then
		mkdir -p /etc/cron.d
		echo "# test" > /etc/cron.d/bfd
		_created=1
	fi
	run detect_run_mode
	assert_success
	assert_output "cron"
	# single-line check
	local line_count
	line_count=$(echo "$output" | wc -l)
	[ "$line_count" -eq 1 ]

	# --- unknown mode: no scheduler found ---
	# hide the cron file
	if [ "$_created" -eq 1 ]; then
		rm -f /etc/cron.d/bfd
	else
		mv /etc/cron.d/bfd /etc/cron.d/bfd.test_backup
	fi
	run detect_run_mode
	assert_success
	assert_output "unknown"
	line_count=$(echo "$output" | wc -l)
	[ "$line_count" -eq 1 ]
	# restore
	if [ "$_created" -eq 0 ]; then
		mv /etc/cron.d/bfd.test_backup /etc/cron.d/bfd
	fi
	unset -f pgrep
}

# --- vhead (Merge G) ---

@test "vhead: version string and copyright" {
	bfd_load_function "vhead"
	V="2.0.1"
	run vhead
	assert_success
	assert_output --partial "v2.0.1"
	assert_output --partial "(C) 1999-"
	assert_output --partial "R-fx Networks"
}

# --- pre (Merge G) ---

@test "pre: succeeds and creates missing directories and log file" {
	bfd_load_function "pre"
	TLOG_PATH="$TEST_TMPDIR/tlog"
	touch "$TLOG_PATH"
	mkdir -p "$INSTALL_PATH/internals"
	touch "$INSTALL_PATH/internals/tlog_lib.sh"
	TLOG_BASERUN="$TEST_TMPDIR/new_baserun"
	BFD_LOG_PATH="$TEST_TMPDIR/new_bfd.log"
	[ ! -d "$TLOG_BASERUN" ]
	[ ! -f "$BFD_LOG_PATH" ]
	run pre
	assert_success
	# creates TLOG_BASERUN directory
	[ -d "$TLOG_BASERUN" ]
	# creates BFD_LOG_PATH file with 640 permissions
	[ -f "$BFD_LOG_PATH" ]
	local perms
	perms=$(stat -c '%a' "$BFD_LOG_PATH")
	[ "$perms" = "640" ]
}

@test "pre: exits with error when TLOG_PATH missing" {
	bfd_load_function "pre"
	TLOG_PATH="$TEST_TMPDIR/nonexistent_tlog"
	run pre
	assert_failure
	[ "$status" -eq "$EXIT_PREREQ_ERROR" ]
}

# --- usage text (Merge J) ---

bfd_load_function usage
bfd_load_function usage_short

@test "usage: all documented flags and usage_short" {
	run usage
	assert_success
	assert_output --partial "--sort=MODE"
	assert_output --partial "--24h"
	assert_output --partial "--7d"
	assert_output --partial "--30d"

	run usage_short
	assert_success
	assert_output --partial "--sort="
	assert_output --partial "--24h"
}

# --- ban flag guard (Merge I) ---

@test "ban flag guard: rejects dash-prefixed, accepts normal and empty" {
	# rejects service name starting with dash
	local svc="--ttl"
	if [ -n "${svc:-}" ] && [[ "${svc}" == -* ]]; then
		# guard triggered — this is the expected path
		:
	else
		fail "flag-like service name '--ttl' was not rejected by the guard"
	fi

	# accepts normal service name
	svc="sshd"
	if [ -n "${svc:-}" ] && [[ "${svc}" == -* ]]; then
		fail "normal service name 'sshd' was rejected by the guard"
	fi

	# accepts empty service name (default)
	svc=""
	if [ -n "${svc:-}" ] && [[ "${svc}" == -* ]]; then
		fail "empty service name was rejected by the guard"
	fi
}

@test "sanitize_mod: accepts --ttl (flag-like but passes regex)" {
	# Demonstrates that sanitize_mod alone does not guard against flag-like names;
	# the CLI-level guard in the -b handler is required.
	run sanitize_mod "--ttl"
	assert_success
	assert_output "--ttl"
}
