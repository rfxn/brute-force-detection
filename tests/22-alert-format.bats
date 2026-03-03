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

# --- expand_command_template ---

@test "expand_command_template: single var ATTACK_HOST" {
	ATTACK_HOST="192.0.2.1"
	MOD=""
	PORTS=""
	run expand_command_template 'ban $ATTACK_HOST'
	assert_success
	assert_output "ban 192.0.2.1"
}

@test "expand_command_template: all three vars" {
	ATTACK_HOST="192.0.2.1"
	MOD="sshd"
	PORTS="22,80"
	run expand_command_template 'iptables -s $ATTACK_HOST -m $MOD -p $PORTS'
	assert_success
	assert_output "iptables -s 192.0.2.1 -m sshd -p 22,80"
}

@test "expand_command_template: IPv6 address" {
	ATTACK_HOST="2001:db8::1"
	MOD=""
	PORTS=""
	run expand_command_template 'ip6tables -s $ATTACK_HOST'
	assert_success
	assert_output "ip6tables -s 2001:db8::1"
}

@test "expand_command_template: multi-port PORTS" {
	ATTACK_HOST=""
	MOD=""
	PORTS="22,25,80"
	run expand_command_template 'block $PORTS'
	assert_success
	assert_output "block 22,25,80"
}

@test "expand_command_template: empty variables" {
	ATTACK_HOST=""
	MOD=""
	PORTS=""
	run expand_command_template 'ban $ATTACK_HOST'
	assert_success
	assert_output "ban "
}

@test "expand_command_template: no variables in template" {
	ATTACK_HOST="192.0.2.1"
	MOD="sshd"
	PORTS="22"
	run expand_command_template '/usr/sbin/iptables -F'
	assert_success
	assert_output "/usr/sbin/iptables -F"
}

@test "expand_command_template: variable appears twice" {
	ATTACK_HOST="192.0.2.1"
	MOD=""
	PORTS=""
	run expand_command_template '$ATTACK_HOST to $ATTACK_HOST'
	assert_success
	assert_output "192.0.2.1 to 192.0.2.1"
}

# --- extract_command_template ---

@test "extract_command_template: extracts unquoted value" {
	local tmpconf="$TEST_TMPDIR/test.conf"
	echo 'BAN_COMMAND=/sbin/iptables -I INPUT -s $ATTACK_HOST -j DROP' > "$tmpconf"
	run extract_command_template "$tmpconf" "BAN_COMMAND"
	assert_output '/sbin/iptables -I INPUT -s $ATTACK_HOST -j DROP'
}

@test "extract_command_template: extracts quoted value" {
	local tmpconf="$TEST_TMPDIR/test.conf"
	echo 'BAN_COMMAND="/etc/apf/apf -d $ATTACK_HOST {bfd.$MOD}"' > "$tmpconf"
	run extract_command_template "$tmpconf" "BAN_COMMAND"
	assert_output '/etc/apf/apf -d $ATTACK_HOST {bfd.$MOD}'
}

@test "extract_command_template: takes last occurrence" {
	local tmpconf="$TEST_TMPDIR/test.conf"
	printf 'BAN_COMMAND="first"\nBAN_COMMAND="second"\n' > "$tmpconf"
	run extract_command_template "$tmpconf" "BAN_COMMAND"
	assert_output "second"
}

@test "extract_command_template: returns empty for missing var" {
	local tmpconf="$TEST_TMPDIR/test.conf"
	echo 'OTHER_VAR="value"' > "$tmpconf"
	run extract_command_template "$tmpconf" "BAN_COMMAND"
	assert_output ""
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
	echo "192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|root|5|300|3" > "$af"
	run format_alert_body "$af" "50"
	assert_success
	assert_output --partial "Host:       192.0.2.1"
	assert_output --partial "Service:    sshd"
	assert_output --partial "weight 3"
	refute_output --partial "hosts banned"
}

@test "format_alert_body: multi entry shows count header" {
	local af="$TEST_TMPDIR/alerts_multi"
	echo "192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|root|5|300|3" > "$af"
	echo "192.0.2.2|dovecot|143|10000|0|ban|0|/dev/null|root|10|300|2" >> "$af"
	run format_alert_body "$af" "50"
	assert_success
	assert_output --partial "2 hosts banned in this check cycle."
	assert_output --partial "--- Ban 1 of 2 ---"
	assert_output --partial "--- Ban 2 of 2 ---"
	assert_output --partial "weight 3"
	assert_output --partial "weight 2"
}

@test "format_alert_body: missing log file shows journal message" {
	local af="$TEST_TMPDIR/alerts_nolog"
	echo "192.0.2.1|sshd|22|5000|0|ban|0||root|5|300|1" > "$af"
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
	echo "192.0.2.1|sshd|22|5000|0|ban|0|$logfile|root|5|300|3" > "$af"
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
	echo "192.0.2.1|sshd|22|5000|0|ban|0|$logfile|root|5|300|3" > "$af"
	echo "192.0.2.2|dovecot|143|10000|0|ban|0|$logfile|root|10|300|2" >> "$af"
	run format_alert_body "$af" "50"
	assert_success
	assert_output --partial "Source logs from 'sshd' [192.0.2.1]:"
	assert_output --partial "Source logs from 'dovecot' [192.0.2.2]:"
}

@test "format_alert_body: redacts password values in log lines" {
	local logfile="$TEST_TMPDIR/test.log"
	echo "Feb 22 14:29:58 host sshd[1234]: password=secret123 for root from 192.0.2.1" > "$logfile"
	echo "Feb 22 14:29:59 host sshd[1235]: passwd: badpass from 192.0.2.1" >> "$logfile"
	echo "Feb 22 14:30:00 host sshd[1236]: Passphrase=mysecret from 192.0.2.1" >> "$logfile"
	local af="$TEST_TMPDIR/alerts_redact"
	echo "192.0.2.1|sshd|22|5000|0|ban|0|$logfile|root|5|300|3" > "$af"
	run format_alert_body "$af" "50"
	assert_success
	assert_output --partial "password=<REDACTED>"
	assert_output --partial "passwd=<REDACTED>"
	assert_output --partial "Passphrase=<REDACTED>"
	refute_output --partial "secret123"
	refute_output --partial "badpass"
	refute_output --partial "mysecret"
}

@test "format_alert_body: redacts Authorization headers in log lines" {
	local logfile="$TEST_TMPDIR/test.log"
	echo "Feb 22 14:29:58 host nginx: Authorization: Basic dXNlcjpwYXNz from 192.0.2.1" > "$logfile"
	local af="$TEST_TMPDIR/alerts_auth"
	echo "192.0.2.1|nginx|80|5000|0|ban|0|$logfile|root|5|300|3" > "$af"
	run format_alert_body "$af" "50"
	assert_success
	assert_output --partial "Authorization: <REDACTED>"
	refute_output --partial "dXNlcjpwYXNz"
}

@test "format_alert_body: preserves normal auth failure lines" {
	local logfile="$TEST_TMPDIR/test.log"
	echo "Feb 22 14:29:58 host sshd[1234]: Failed password for root from 192.0.2.1 port 22 ssh2" > "$logfile"
	local af="$TEST_TMPDIR/alerts_normal"
	echo "192.0.2.1|sshd|22|5000|0|ban|0|$logfile|root|5|300|3" > "$af"
	run format_alert_body "$af" "50"
	assert_success
	assert_output --partial "Failed password for root from 192.0.2.1"
}

@test "format_alert_body: missing weight field defaults to 1" {
	local af="$TEST_TMPDIR/alerts_no_weight"
	echo "192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|root|5|300" > "$af"
	run format_alert_body "$af" "50"
	assert_success
	assert_output --partial "weight 1"
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
	echo "192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|root|5|300|3" > "$af"
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
	echo "192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|root|5|300|3" > "$af"
	echo "192.0.2.2|dovecot|143|10000|0|ban|0|/dev/null|root|10|300|2" >> "$af"
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
	echo "192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|admin@example.com|5|300|3" > "$af"
	echo "192.0.2.2|dovecot|143|10000|0|ban|0|/dev/null|security@example.com|10|300|2" >> "$af"
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
	echo "192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|special@example.com|5|300|3" > "$af"
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
	echo "192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|root|5|300|3" > "$af"
	_setup_mock_mail_silent
	send_alerts "$af" "$EMAIL_SUBJECT" "$EMAIL_TEMPLATE" "50"
	[ "$ATTACK_HOST" = "192.0.2.1" ]
	[ "$MOD" = "sshd" ]
	# ATTACK_COUNT = pressure_scaled / 1000 (approximate event count)
	[ "$ATTACK_COUNT" = "5" ]
}

@test "send_alerts: ATTACK_COUNT minimum is 1 even for low pressure" {
	local af="$TEST_TMPDIR/alerts_lowpressure"
	echo "192.0.2.1|sshd|22|500|0|ban|0|/dev/null|root|5|300|1" > "$af"
	_setup_mock_mail_silent
	send_alerts "$af" "$EMAIL_SUBJECT" "$EMAIL_TEMPLATE" "50"
	# 500/1000 = 0 → clamped to 1
	[ "$ATTACK_COUNT" = "1" ]
}

# --- check() pipeline integration ---

# Source check() function from bfd
bfd_load_function check

# _setup_mock_mail_silent: create mock mail that silently discards input
_setup_mock_mail_silent() {
	mkdir -p "$TEST_TMPDIR/bin"
	echo '#!/bin/bash' > "$TEST_TMPDIR/bin/mail"
	echo 'cat > /dev/null' >> "$TEST_TMPDIR/bin/mail"
	chmod +x "$TEST_TMPDIR/bin/mail"
	export PATH="$TEST_TMPDIR/bin:$PATH"
}

# _setup_mock_mail_log: create mock mail that logs calls to $MAIL_LOG
_setup_mock_mail_log() {
	mkdir -p "$TEST_TMPDIR/bin"
	cat > "$TEST_TMPDIR/bin/mail" <<'MOCK'
#!/bin/bash
echo "CALLED" >> "$MAIL_LOG"
cat > /dev/null
MOCK
	chmod +x "$TEST_TMPDIR/bin/mail"
	export PATH="$TEST_TMPDIR/bin:$PATH"
}

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
	_setup_mock_mail_silent
}

@test "pipeline: alerts file populated after ban with EMAIL_ALERTS=1" {
	local rules_dir="$TEST_TMPDIR/rules"
	mkdir -p "$rules_dir"
	local logfile="$TEST_TMPDIR/test.log"
	echo "test line" > "$logfile"
	cat > "$rules_dir/testrule" <<'RULEEOF'
TRIG="2"
PREREQ="/bin/sh"
RULEEOF
	cat >> "$rules_dir/testrule" <<EOF
LOG_FILE="$logfile"
LOG_TAG="testrule"
MATCHED_HOSTS="192.0.2.1 192.0.2.1 192.0.2.1"
EOF
	_setup_check_env "$rules_dir"
	EMAIL_ALERTS="1"
	local mail_log="$TEST_TMPDIR/mail_calls"
	export MAIL_LOG="$mail_log"
	_setup_mock_mail_log
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
PREREQ="/bin/sh"
RULEEOF
	cat >> "$rules_dir/testrule" <<EOF
LOG_FILE="$logfile"
LOG_TAG="testrule"
MATCHED_HOSTS="192.0.2.1 192.0.2.1 192.0.2.1"
EOF
	_setup_check_env "$rules_dir"
	EMAIL_ALERTS="1"
	local mail_log="$TEST_TMPDIR/mail_calls"
	export MAIL_LOG="$mail_log"
	_setup_mock_mail_log
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
PREREQ="/bin/sh"
RULEEOF
	cat >> "$rules_dir/testrule" <<EOF
LOG_FILE="$logfile"
LOG_TAG="testrule"
MATCHED_HOSTS="192.0.2.1 192.0.2.1 192.0.2.1"
EOF
	_setup_check_env "$rules_dir"
	EMAIL_ALERTS="1"
	DRY_RUN="1"
	local mail_log="$TEST_TMPDIR/mail_calls"
	export MAIL_LOG="$mail_log"
	_setup_mock_mail_log
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
PREREQ="/bin/sh"
RULEEOF
	cat >> "$rules_dir/testrule" <<EOF
LOG_FILE="$logfile"
LOG_TAG="testrule"
MATCHED_HOSTS="192.0.2.1 192.0.2.1 192.0.2.1"
EOF
	_setup_check_env "$rules_dir"
	EMAIL_ALERTS="0"
	local mail_log="$TEST_TMPDIR/mail_calls"
	export MAIL_LOG="$mail_log"
	_setup_mock_mail_log
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
