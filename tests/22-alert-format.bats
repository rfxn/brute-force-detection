#!/usr/bin/env bats
#
# Tests for Phase 15: alert system rewrite
# format_duration, format_alert_entry, format_alert_body, send_alerts
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

setup() {
	bfd_standard_setup
	UTIME="1000"
	BAN_COMMAND_TEMPLATE="echo ban \$ATTACK_HOST"
	BAN_ESCALATE_AFTER="5"
	BAN_ESCALATE_WINDOW="86400"
	EMAIL_ALERTS="1"
	EMAIL_ADDRESS="root"
	EMAIL_SUBJECT="Brute Force Warning for testhost"
	EMAIL_TEMPLATE="$PROJECT_ROOT/files/alert.bfd"
	TIME_ZONE="-0600"
	HOSTNAME="testhost"
	PRESSURE_HALF_LIFE="300"
}

teardown() {
	bfd_teardown
}

# --- format_duration ---

@test "format_duration: 0 returns permanent" {
	run format_duration 0
	assert_success
	assert_output "permanent"
}

@test "format_duration: 30 returns 30s" {
	run format_duration 30
	assert_success
	assert_output "30s"
}

@test "format_duration: 60 returns 1m" {
	run format_duration 60
	assert_success
	assert_output "1m"
}

@test "format_duration: 90 returns 1m 30s" {
	run format_duration 90
	assert_success
	assert_output "1m 30s"
}

@test "format_duration: 300 returns 5m" {
	run format_duration 300
	assert_success
	assert_output "5m"
}

@test "format_duration: 3600 returns 1h" {
	run format_duration 3600
	assert_success
	assert_output "1h"
}

@test "format_duration: 3661 returns 1h 1m" {
	run format_duration 3661
	assert_success
	assert_output "1h 1m"
}

@test "format_duration: 86400 returns 24h" {
	run format_duration 86400
	assert_success
	assert_output "24h"
}

# --- format_alert_entry ---

@test "format_alert_entry: single ban has no prefix" {
	run format_alert_entry 1 1 "192.0.2.1" "sshd" "22" "5000" "1300" "ban" "0" "5" "300"
	assert_success
	refute_output --partial "--- Ban"
	assert_output --partial "Host:       192.0.2.1"
	assert_output --partial "Service:    sshd (port 22)"
}

@test "format_alert_entry: multi-ban has prefix" {
	run format_alert_entry 2 3 "192.0.2.1" "sshd" "22" "5000" "1300" "ban" "0" "5" "300"
	assert_success
	assert_output --partial "--- Ban 2 of 3 ---"
}

@test "format_alert_entry: permanent ban shows Permanent" {
	run format_alert_entry 1 1 "192.0.2.1" "sshd" "22" "5000" "0" "ban" "0" "5" "300"
	assert_success
	assert_output --partial "Ban:        Permanent"
	refute_output --partial "expires"
}

@test "format_alert_entry: temporary ban shows duration and expiry" {
	run format_alert_entry 1 1 "192.0.2.1" "sshd" "22" "5000" "1300" "ban" "0" "5" "300"
	assert_success
	assert_output --partial "Temporary (5m)"
	assert_output --partial "expires"
}

@test "format_alert_entry: escalated ban shows escalation" {
	run format_alert_entry 1 1 "192.0.2.1" "sshd" "22" "5000" "0" "escalate" "4" "5" "300"
	assert_success
	assert_output --partial "Permanent (escalated from repeat offenses)"
}

@test "format_alert_entry: shows pressure and trip" {
	run format_alert_entry 1 1 "192.0.2.1" "sshd" "22" "5000" "0" "ban" "0" "5" "300"
	assert_success
	assert_output --partial "Pressure:"
	assert_output --partial "weight 1, half-life 300s"
}

@test "format_alert_entry: shows history when BAN_ESCALATE_AFTER set" {
	run format_alert_entry 1 1 "192.0.2.1" "sshd" "22" "5000" "0" "ban" "2" "5" "300"
	assert_success
	assert_output --partial "History:    2 previous ban(s)"
	assert_output --partial "permanent at 5"
}

@test "format_alert_entry: no history line when BAN_ESCALATE_AFTER=0" {
	BAN_ESCALATE_AFTER="0"
	run format_alert_entry 1 1 "192.0.2.1" "sshd" "22" "5000" "0" "ban" "0" "5" "300"
	assert_success
	refute_output --partial "History:"
}

@test "format_alert_entry: shows reconstructed command" {
	BAN_COMMAND_TEMPLATE="echo ban \$ATTACK_HOST"
	run format_alert_entry 1 1 "192.0.2.1" "sshd" "22" "5000" "0" "ban" "0" "5" "300"
	assert_success
	assert_output --partial "Command:    echo ban 192.0.2.1"
}

@test "format_alert_entry: all ports shows 'all ports'" {
	run format_alert_entry 1 1 "192.0.2.1" "sshd" "all" "5000" "0" "ban" "0" "5" "300"
	assert_success
	assert_output --partial "Service:    sshd (all ports)"
}

@test "format_alert_entry: multi-port display" {
	run format_alert_entry 1 1 "192.0.2.1" "dovecot" "110,143,993,995" "10000" "0" "ban" "0" "10" "300"
	assert_success
	assert_output --partial "Service:    dovecot (port 110,143,993,995)"
}

@test "format_alert_entry: escalated duration shows base context" {
	BAN_TTL="300"
	BAN_ESCALATION="linear"
	# expiry = 1000 + 600 = 1600, duration = 600, base = 300, recent > 0
	run format_alert_entry 1 1 "192.0.2.1" "sshd" "22" "5000" "1600" "ban" "1" "5" "300"
	assert_success
	assert_output --partial "Temporary (10m, escalated from 5m)"
}

@test "format_alert_entry: non-escalated ban does not show escalation context" {
	BAN_TTL="300"
	BAN_ESCALATION="none"
	run format_alert_entry 1 1 "192.0.2.1" "sshd" "22" "5000" "1300" "ban" "0" "5" "300"
	assert_success
	assert_output --partial "Temporary (5m)"
	refute_output --partial "escalated from"
}

# --- format_alert_body ---

@test "format_alert_body: empty file returns nothing" {
	local af="$TEST_TMPDIR/alerts_empty"
	touch "$af"
	run format_alert_body "$af" "50"
	assert_success
	assert_output ""
}

@test "format_alert_body: single entry produces output" {
	local af="$TEST_TMPDIR/alerts_single"
	echo "192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|root|5|300" > "$af"
	run format_alert_body "$af" "50"
	assert_success
	assert_output --partial "Host:       192.0.2.1"
	assert_output --partial "Service:    sshd"
	refute_output --partial "hosts banned"
}

@test "format_alert_body: multi entry shows count header" {
	local af="$TEST_TMPDIR/alerts_multi"
	echo "192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|root|5|300" > "$af"
	echo "192.0.2.2|dovecot|143|10000|0|ban|0|/dev/null|root|10|300" >> "$af"
	run format_alert_body "$af" "50"
	assert_success
	assert_output --partial "2 hosts banned in this check cycle."
	assert_output --partial "--- Ban 1 of 2 ---"
	assert_output --partial "--- Ban 2 of 2 ---"
}

@test "format_alert_body: missing log file shows journal message" {
	local af="$TEST_TMPDIR/alerts_nolog"
	echo "192.0.2.1|sshd|22|5000|0|ban|0||root|5|300" > "$af"
	run format_alert_body "$af" "50"
	assert_success
	assert_output --partial "logs via systemd journal"
}

@test "format_alert_body: existing log file extracts lines" {
	local logfile="$TEST_TMPDIR/test.log"
	echo "Feb 22 14:29:58 host sshd[1234]: Failed password for root from 192.0.2.1" > "$logfile"
	echo "Feb 22 14:29:59 host sshd[1235]: Failed password for admin from 192.0.2.1" >> "$logfile"
	echo "Feb 22 14:30:00 host sshd[1236]: Failed password for test from 192.0.2.2" >> "$logfile"
	local af="$TEST_TMPDIR/alerts_log"
	echo "192.0.2.1|sshd|22|5000|0|ban|0|$logfile|root|5|300" > "$af"
	run format_alert_body "$af" "50"
	assert_success
	assert_output --partial "Source logs from 'sshd':"
	assert_output --partial "192.0.2.1"
	refute_output --partial "192.0.2.2"
}

@test "format_alert_body: multi entry log section includes host labels" {
	local logfile="$TEST_TMPDIR/test.log"
	echo "192.0.2.1 sshd line" > "$logfile"
	echo "192.0.2.2 dovecot line" >> "$logfile"
	local af="$TEST_TMPDIR/alerts_multi_log"
	echo "192.0.2.1|sshd|22|5000|0|ban|0|$logfile|root|5|300" > "$af"
	echo "192.0.2.2|dovecot|143|10000|0|ban|0|$logfile|root|10|300" >> "$af"
	run format_alert_body "$af" "50"
	assert_success
	assert_output --partial "Source logs from 'sshd' [192.0.2.1]:"
	assert_output --partial "Source logs from 'dovecot' [192.0.2.2]:"
}

# --- send_alerts ---

@test "send_alerts: empty file sends no mail" {
	local af="$TEST_TMPDIR/alerts_empty"
	touch "$af"
	# create a mock mail that records calls
	local mail_log="$TEST_TMPDIR/mail_calls"
	mkdir -p "$TEST_TMPDIR/bin"
	cat > "$TEST_TMPDIR/bin/mail" <<'MOCK'
#!/bin/bash
echo "$@" >> "$MAIL_LOG"
cat >> "$MAIL_LOG"
MOCK
	chmod +x "$TEST_TMPDIR/bin/mail"
	export PATH="$TEST_TMPDIR/bin:$PATH"
	export MAIL_LOG="$mail_log"
	send_alerts "$af" "$EMAIL_SUBJECT" "$EMAIL_TEMPLATE" "50"
	[ ! -f "$mail_log" ]
}

@test "send_alerts: single entry sends one mail with unchanged subject" {
	local af="$TEST_TMPDIR/alerts_one"
	echo "192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|root|5|300" > "$af"
	# mock mail
	local mail_log="$TEST_TMPDIR/mail_calls"
	mkdir -p "$TEST_TMPDIR/bin"
	cat > "$TEST_TMPDIR/bin/mail" <<'MOCK'
#!/bin/bash
echo "CALL: $@" >> "$MAIL_LOG"
cat >> "$MAIL_LOG"
MOCK
	chmod +x "$TEST_TMPDIR/bin/mail"
	export PATH="$TEST_TMPDIR/bin:$PATH"
	export MAIL_LOG="$mail_log"
	send_alerts "$af" "$EMAIL_SUBJECT" "$EMAIL_TEMPLATE" "50"
	[ -f "$mail_log" ]
	# subject should NOT have "(N bans)" suffix
	run grep "CALL:" "$mail_log"
	assert_output --partial "Brute Force Warning for testhost"
	refute_output --partial "bans)"
}

@test "send_alerts: multiple entries same recipient sends one mail with ban count" {
	local af="$TEST_TMPDIR/alerts_multi"
	echo "192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|root|5|300" > "$af"
	echo "192.0.2.2|dovecot|143|10000|0|ban|0|/dev/null|root|10|300" >> "$af"
	# mock mail
	local mail_log="$TEST_TMPDIR/mail_calls"
	mkdir -p "$TEST_TMPDIR/bin"
	cat > "$TEST_TMPDIR/bin/mail" <<'MOCK'
#!/bin/bash
echo "CALL: $@" >> "$MAIL_LOG"
cat >> "$MAIL_LOG"
MOCK
	chmod +x "$TEST_TMPDIR/bin/mail"
	export PATH="$TEST_TMPDIR/bin:$PATH"
	export MAIL_LOG="$mail_log"
	send_alerts "$af" "$EMAIL_SUBJECT" "$EMAIL_TEMPLATE" "50"
	[ -f "$mail_log" ]
	# subject should have "(2 bans)" suffix
	run grep "CALL:" "$mail_log"
	assert_output --partial "(2 bans)"
	# should only be one CALL (one email)
	local call_count
	call_count=$(grep -c "CALL:" "$mail_log")
	[ "$call_count" -eq 1 ]
}

@test "send_alerts: different recipients get separate emails" {
	local af="$TEST_TMPDIR/alerts_diff"
	echo "192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|admin@example.com|5|300" > "$af"
	echo "192.0.2.2|dovecot|143|10000|0|ban|0|/dev/null|security@example.com|10|300" >> "$af"
	# mock mail
	local mail_log="$TEST_TMPDIR/mail_calls"
	mkdir -p "$TEST_TMPDIR/bin"
	cat > "$TEST_TMPDIR/bin/mail" <<'MOCK'
#!/bin/bash
echo "CALL: $@" >> "$MAIL_LOG"
cat >> "$MAIL_LOG"
MOCK
	chmod +x "$TEST_TMPDIR/bin/mail"
	export PATH="$TEST_TMPDIR/bin:$PATH"
	export MAIL_LOG="$mail_log"
	send_alerts "$af" "$EMAIL_SUBJECT" "$EMAIL_TEMPLATE" "50"
	[ -f "$mail_log" ]
	# should be two CALL entries (two separate emails)
	local call_count
	call_count=$(grep -c "CALL:" "$mail_log")
	[ "$call_count" -eq 2 ]
}

@test "send_alerts: RULE_EMAIL override routes to different recipient" {
	local af="$TEST_TMPDIR/alerts_rule_email"
	echo "192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|special@example.com|5|300" > "$af"
	# mock mail
	local mail_log="$TEST_TMPDIR/mail_calls"
	mkdir -p "$TEST_TMPDIR/bin"
	cat > "$TEST_TMPDIR/bin/mail" <<'MOCK'
#!/bin/bash
echo "CALL: $@" >> "$MAIL_LOG"
cat >> "$MAIL_LOG"
MOCK
	chmod +x "$TEST_TMPDIR/bin/mail"
	export PATH="$TEST_TMPDIR/bin:$PATH"
	export MAIL_LOG="$mail_log"
	send_alerts "$af" "$EMAIL_SUBJECT" "$EMAIL_TEMPLATE" "50"
	run grep "CALL:" "$mail_log"
	assert_output --partial "special@example.com"
}

@test "send_alerts: single-ban backward compat sets ATTACK_HOST global" {
	local af="$TEST_TMPDIR/alerts_compat"
	echo "192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|root|5|300" > "$af"
	# mock mail (just succeed)
	mkdir -p "$TEST_TMPDIR/bin"
	echo '#!/bin/bash' > "$TEST_TMPDIR/bin/mail"
	echo 'cat > /dev/null' >> "$TEST_TMPDIR/bin/mail"
	chmod +x "$TEST_TMPDIR/bin/mail"
	export PATH="$TEST_TMPDIR/bin:$PATH"
	send_alerts "$af" "$EMAIL_SUBJECT" "$EMAIL_TEMPLATE" "50"
	[ "$ATTACK_HOST" = "192.0.2.1" ]
	[ "$MOD" = "sshd" ]
	[ "$ATTACK_COUNT" = "5000" ]
}

# --- check() pipeline integration ---

# Source check() function from bfd
eval "$(awk '/^check\(\)/ { p=1 } p { print; if (/^\}$/) exit }' "$PROJECT_ROOT/files/bfd")"

_setup_check_env() {
	local rules_dir="$1"
	RULES_PATH="$rules_dir"
	GLOB_PRESSURE_TRIP="5"
	PRESSURE_HALF_LIFE="300"
	PRESSURE_TRIP_GLOBAL="0"
	UTIME="1000"
	IGNORE_HOST_FILES="$TEST_TMPDIR/exclude.files"
	LO_HOSTS="$TEST_TMPDIR/lo_hosts"
	touch "$IGNORE_HOST_FILES" "$LO_HOSTS"
	BAN_COMMAND_TEMPLATE="true"
	BAN_COMMAND_V6_TEMPLATE=""
	DRY_RUN="0"
	BAN_TTL="0"
	BAN_ESCALATE_AFTER="0"
	BAN_ESCALATE_WINDOW="86400"
	SKIP_ALERT=""
	RULE_EMAIL=""
	EMAIL_ADDRESS="root"
	EMAIL_TEMPLATE="$PROJECT_ROOT/files/alert.bfd"
	EMAIL_SUBJECT="Test Alert"
	EMAIL_LOGLINES="50"
	LOG_SOURCE="file"
	# mock mail command
	mkdir -p "$TEST_TMPDIR/bin"
	echo '#!/bin/bash' > "$TEST_TMPDIR/bin/mail"
	echo 'cat > /dev/null' >> "$TEST_TMPDIR/bin/mail"
	chmod +x "$TEST_TMPDIR/bin/mail"
	export PATH="$TEST_TMPDIR/bin:$PATH"
}

@test "pipeline: alerts file populated after ban with EMAIL_ALERTS=1" {
	local rules_dir="$TEST_TMPDIR/rules"
	mkdir -p "$rules_dir"
	local logfile="$TEST_TMPDIR/test.log"
	echo "test line" > "$logfile"
	cat > "$rules_dir/testrule" <<'RULEEOF'
TRIG="2"
REQ="/bin/sh"
RULEEOF
	cat >> "$rules_dir/testrule" <<EOF
LP="$logfile"
TLOG_TF="testrule"
ARG_VAL="192.0.2.1 192.0.2.1 192.0.2.1"
EOF
	_setup_check_env "$rules_dir"
	EMAIL_ALERTS="1"
	# run check — it creates and cleans up alerts file
	# we can verify that mail was called via the mock
	local mail_log="$TEST_TMPDIR/mail_calls"
	cat > "$TEST_TMPDIR/bin/mail" <<'MOCK'
#!/bin/bash
echo "CALLED" >> "$MAIL_LOG"
cat > /dev/null
MOCK
	chmod +x "$TEST_TMPDIR/bin/mail"
	export MAIL_LOG="$mail_log"
	check >/dev/null 2>&1
	# mail should have been called
	[ -f "$mail_log" ]
}

@test "pipeline: SKIP_ALERT=1 suppresses alert entry" {
	local rules_dir="$TEST_TMPDIR/rules"
	mkdir -p "$rules_dir"
	local logfile="$TEST_TMPDIR/test.log"
	echo "test line" > "$logfile"
	cat > "$rules_dir/testrule" <<'RULEEOF'
TRIG="2"
SKIP_ALERT="1"
REQ="/bin/sh"
RULEEOF
	cat >> "$rules_dir/testrule" <<EOF
LP="$logfile"
TLOG_TF="testrule"
ARG_VAL="192.0.2.1 192.0.2.1 192.0.2.1"
EOF
	_setup_check_env "$rules_dir"
	EMAIL_ALERTS="1"
	local mail_log="$TEST_TMPDIR/mail_calls"
	cat > "$TEST_TMPDIR/bin/mail" <<'MOCK'
#!/bin/bash
echo "CALLED" >> "$MAIL_LOG"
cat > /dev/null
MOCK
	chmod +x "$TEST_TMPDIR/bin/mail"
	export MAIL_LOG="$mail_log"
	check >/dev/null 2>&1
	# mail should NOT have been called
	[ ! -f "$mail_log" ]
}

@test "pipeline: DRY_RUN=1 suppresses alert entry" {
	local rules_dir="$TEST_TMPDIR/rules"
	mkdir -p "$rules_dir"
	local logfile="$TEST_TMPDIR/test.log"
	echo "test line" > "$logfile"
	cat > "$rules_dir/testrule" <<'RULEEOF'
TRIG="2"
REQ="/bin/sh"
RULEEOF
	cat >> "$rules_dir/testrule" <<EOF
LP="$logfile"
TLOG_TF="testrule"
ARG_VAL="192.0.2.1 192.0.2.1 192.0.2.1"
EOF
	_setup_check_env "$rules_dir"
	EMAIL_ALERTS="1"
	DRY_RUN="1"
	local mail_log="$TEST_TMPDIR/mail_calls"
	cat > "$TEST_TMPDIR/bin/mail" <<'MOCK'
#!/bin/bash
echo "CALLED" >> "$MAIL_LOG"
cat > /dev/null
MOCK
	chmod +x "$TEST_TMPDIR/bin/mail"
	export MAIL_LOG="$mail_log"
	check >/dev/null 2>&1
	# mail should NOT have been called
	[ ! -f "$mail_log" ]
}

@test "pipeline: EMAIL_ALERTS=0 skips send_alerts entirely" {
	local rules_dir="$TEST_TMPDIR/rules"
	mkdir -p "$rules_dir"
	local logfile="$TEST_TMPDIR/test.log"
	echo "test line" > "$logfile"
	cat > "$rules_dir/testrule" <<'RULEEOF'
TRIG="2"
REQ="/bin/sh"
RULEEOF
	cat >> "$rules_dir/testrule" <<EOF
LP="$logfile"
TLOG_TF="testrule"
ARG_VAL="192.0.2.1 192.0.2.1 192.0.2.1"
EOF
	_setup_check_env "$rules_dir"
	EMAIL_ALERTS="0"
	local mail_log="$TEST_TMPDIR/mail_calls"
	cat > "$TEST_TMPDIR/bin/mail" <<'MOCK'
#!/bin/bash
echo "CALLED" >> "$MAIL_LOG"
cat > /dev/null
MOCK
	chmod +x "$TEST_TMPDIR/bin/mail"
	export MAIL_LOG="$mail_log"
	check >/dev/null 2>&1
	# mail should NOT have been called
	[ ! -f "$mail_log" ]
}

@test "pipeline: alerts file cleaned up after run" {
	local rules_dir="$TEST_TMPDIR/rules"
	mkdir -p "$rules_dir"
	_setup_check_env "$rules_dir"
	EMAIL_ALERTS="1"
	check >/dev/null 2>&1
	# no leftover .alerts.* files
	local leftover
	leftover=$(find "$INSTALL_PATH/tmp" -name '.alerts.*' 2>/dev/null | wc -l)
	[ "$leftover" -eq 0 ]
}
