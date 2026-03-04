#!/usr/bin/env bats
#
# Tests for alert formatting and delivery:
# expand_command_template, extract_command_template, format_duration, send_alerts
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
	ALERT_TEMPLATE_DIR="$PROJECT_ROOT/files/alert"
	EMAIL_FORMAT="text"
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

# --- send_alerts ---

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
echo "CALL: $@" >> "$MAIL_LOG"
cat >> "$MAIL_LOG"
MOCK
	chmod +x "$TEST_TMPDIR/bin/mail"
	export PATH="$TEST_TMPDIR/bin:$PATH"
}

@test "send_alerts: empty file sends no mail" {
	local af="$TEST_TMPDIR/alerts_empty"
	touch "$af"
	local mail_log="$TEST_TMPDIR/mail_calls"
	export MAIL_LOG="$mail_log"
	_setup_mock_mail_log
	send_alerts "$af" "$EMAIL_SUBJECT" "50"
	[ ! -f "$mail_log" ]
}

@test "send_alerts: single entry sends one mail with unchanged subject" {
	local af="$TEST_TMPDIR/alerts_one"
	echo "192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|root|5|300|3" > "$af"
	local mail_log="$TEST_TMPDIR/mail_calls"
	export MAIL_LOG="$mail_log"
	_setup_mock_mail_log
	send_alerts "$af" "$EMAIL_SUBJECT" "50"
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
	local mail_log="$TEST_TMPDIR/mail_calls"
	export MAIL_LOG="$mail_log"
	_setup_mock_mail_log
	send_alerts "$af" "$EMAIL_SUBJECT" "50"
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
	local mail_log="$TEST_TMPDIR/mail_calls"
	export MAIL_LOG="$mail_log"
	_setup_mock_mail_log
	send_alerts "$af" "$EMAIL_SUBJECT" "50"
	[ -f "$mail_log" ]
	# should be two CALL entries (two separate emails)
	local call_count
	call_count=$(grep -c "CALL:" "$mail_log")
	[ "$call_count" -eq 2 ]
}

@test "send_alerts: RULE_EMAIL override routes to different recipient" {
	local af="$TEST_TMPDIR/alerts_rule_email"
	echo "192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|special@example.com|5|300|3" > "$af"
	local mail_log="$TEST_TMPDIR/mail_calls"
	export MAIL_LOG="$mail_log"
	_setup_mock_mail_log
	send_alerts "$af" "$EMAIL_SUBJECT" "50"
	run grep "CALL:" "$mail_log"
	assert_output --partial "special@example.com"
}

@test "send_alerts: single-ban backward compat sets ATTACK_HOST global" {
	local af="$TEST_TMPDIR/alerts_compat"
	echo "192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|root|5|300|3" > "$af"
	_setup_mock_mail_silent
	send_alerts "$af" "$EMAIL_SUBJECT" "50"
	[ "$ATTACK_HOST" = "192.0.2.1" ]
	[ "$MOD" = "sshd" ]
	# ATTACK_COUNT = pressure_scaled / 1000 (approximate event count)
	[ "$ATTACK_COUNT" = "5" ]
}

@test "send_alerts: ATTACK_COUNT minimum is 1 even for low pressure" {
	local af="$TEST_TMPDIR/alerts_lowpressure"
	echo "192.0.2.1|sshd|22|500|0|ban|0|/dev/null|root|5|300|1" > "$af"
	_setup_mock_mail_silent
	send_alerts "$af" "$EMAIL_SUBJECT" "50"
	# 500/1000 = 0 -> clamped to 1
	[ "$ATTACK_COUNT" = "1" ]
}

@test "send_alerts: invalid template dir returns error" {
	ALERT_TEMPLATE_DIR="$TEST_TMPDIR/nonexistent"
	local af="$TEST_TMPDIR/alerts_one"
	echo "192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|root|5|300|3" > "$af"
	_setup_mock_mail_silent
	run send_alerts "$af" "$EMAIL_SUBJECT" "50"
	assert_failure
}

# --- check() pipeline integration ---

# Source check() function from bfd
bfd_load_function check

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
	ALERT_TEMPLATE_DIR="$PROJECT_ROOT/files/alert"
	EMAIL_FORMAT="text"
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

# --- check() digest integration ---

# helper: create a rule that triggers a ban for a given IP
_make_trigger_rule() {
	local rules_dir="$1" name="$2" ip="$3" logfile="$4"
	echo "test line" > "$logfile"
	cat > "$rules_dir/$name" <<'RULEEOF'
TRIG="2"
PREREQ="/bin/sh"
RULEEOF
	cat >> "$rules_dir/$name" <<EOF
LOG_FILE="$logfile"
LOG_TAG="$name"
MATCHED_HOSTS="$ip $ip $ip"
EOF
}

@test "pipeline: EMAIL_DIGEST=timed spools alerts instead of sending" {
	local rules_dir="$TEST_TMPDIR/rules"
	mkdir -p "$rules_dir"
	local logfile="$TEST_TMPDIR/test.log"
	_make_trigger_rule "$rules_dir" "testrule" "192.0.2.1" "$logfile"
	_setup_check_env "$rules_dir"
	EMAIL_ALERTS="1"
	EMAIL_DIGEST="timed"
	EMAIL_DIGEST_INTERVAL="999999"
	ALERT_SPOOL_FILE="$INSTALL_PATH/tmp/.alert_spool"
	local mail_log="$TEST_TMPDIR/mail_calls"
	export MAIL_LOG="$mail_log"
	_setup_mock_mail_log
	check >/dev/null 2>&1
	# mail should NOT have been called — alerts go to spool
	[ ! -f "$mail_log" ]
	# spool should have content: epoch prefix + 12 pipe-delimited fields = 13 total
	[ -f "$ALERT_SPOOL_FILE" ]
	[ -s "$ALERT_SPOOL_FILE" ]
	local field_count
	field_count=$(head -1 "$ALERT_SPOOL_FILE" | awk -F'|' '{print NF}')
	[ "$field_count" -eq 13 ]
}

@test "pipeline: digest accumulation across two check() cycles" {
	local rules_dir="$TEST_TMPDIR/rules"
	mkdir -p "$rules_dir"
	local logfile="$TEST_TMPDIR/test.log"
	_make_trigger_rule "$rules_dir" "testrule" "192.0.2.1" "$logfile"
	_setup_check_env "$rules_dir"
	EMAIL_ALERTS="1"
	EMAIL_DIGEST="timed"
	EMAIL_DIGEST_INTERVAL="999999"
	ALERT_SPOOL_FILE="$INSTALL_PATH/tmp/.alert_spool"
	local mail_log="$TEST_TMPDIR/mail_calls"
	export MAIL_LOG="$mail_log"
	_setup_mock_mail_log
	# first check cycle — bans 192.0.2.1
	check >/dev/null 2>&1
	# switch IP for second cycle (first is already banned)
	cat >> "$rules_dir/testrule" <<'EOF2'
MATCHED_HOSTS="198.51.100.5 198.51.100.5 198.51.100.5"
EOF2
	check >/dev/null 2>&1
	# mail still not called
	[ ! -f "$mail_log" ]
	# spool should have 2 lines
	local spool_lines
	spool_lines=$(wc -l < "$ALERT_SPOOL_FILE")
	[ "$spool_lines" -eq 2 ]
}

@test "pipeline: SKIP_ALERT=1 excludes entry from digest spool" {
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
	EMAIL_DIGEST="timed"
	EMAIL_DIGEST_INTERVAL="999999"
	ALERT_SPOOL_FILE="$INSTALL_PATH/tmp/.alert_spool"
	_setup_mock_mail_silent
	check >/dev/null 2>&1
	# spool should be empty or missing
	if [ -f "$ALERT_SPOOL_FILE" ]; then
		[ ! -s "$ALERT_SPOOL_FILE" ]
	fi
}

@test "pipeline: RULE_EMAIL routing preserved through digest spool" {
	local rules_dir="$TEST_TMPDIR/rules"
	mkdir -p "$rules_dir"
	local logfile1="$TEST_TMPDIR/test1.log"
	local logfile2="$TEST_TMPDIR/test2.log"
	echo "test" > "$logfile1"
	echo "test" > "$logfile2"
	# rule 1: routes to admin@example.com
	cat > "$rules_dir/rule_a" <<RULEEOF
TRIG="2"
PREREQ="/bin/sh"
RULE_EMAIL="admin@example.com"
LOG_FILE="$logfile1"
LOG_TAG="rule_a"
MATCHED_HOSTS="192.0.2.1 192.0.2.1 192.0.2.1"
RULEEOF
	# rule 2: routes to ops@example.com
	cat > "$rules_dir/rule_b" <<RULEEOF
TRIG="2"
PREREQ="/bin/sh"
RULE_EMAIL="ops@example.com"
LOG_FILE="$logfile2"
LOG_TAG="rule_b"
MATCHED_HOSTS="198.51.100.5 198.51.100.5 198.51.100.5"
RULEEOF
	_setup_check_env "$rules_dir"
	EMAIL_ALERTS="1"
	EMAIL_DIGEST="timed"
	EMAIL_DIGEST_INTERVAL="999999"
	ALERT_SPOOL_FILE="$INSTALL_PATH/tmp/.alert_spool"
	_setup_mock_mail_silent
	check >/dev/null 2>&1
	[ -s "$ALERT_SPOOL_FILE" ]
	# field 10 (recipient) in 13-field spool format = epoch|host|mod|ports|pressure|expiry|action|recent|logfile|recipient|trip|hl|weight
	run awk -F'|' '{print $10}' "$ALERT_SPOOL_FILE"
	assert_output --partial "admin@example.com"
	assert_output --partial "ops@example.com"
}

@test "pipeline: digest flush sends accumulated spool via mail" {
	local rules_dir="$TEST_TMPDIR/rules"
	mkdir -p "$rules_dir"
	# no rules — check() produces no new bans but triggers digest check
	_setup_check_env "$rules_dir"
	EMAIL_ALERTS="1"
	EMAIL_DIGEST="timed"
	EMAIL_DIGEST_INTERVAL="900"
	ALERT_SPOOL_FILE="$INSTALL_PATH/tmp/.alert_spool"
	ALERT_TEMPLATE_DIR="$PROJECT_ROOT/files/alert"
	local mail_log="$TEST_TMPDIR/mail_calls"
	export MAIL_LOG="$mail_log"
	_setup_mock_mail_log
	# pre-populate spool with an old entry (>900s ago)
	local now old_epoch
	now=$(date +%s)
	old_epoch=$((now - 1000))
	echo "${old_epoch}|192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|root|10|300|1" > "$ALERT_SPOOL_FILE"
	check >/dev/null 2>&1
	# mail should have been called (digest flushed)
	[ -f "$mail_log" ]
	# spool should be empty after flush
	[ ! -s "$ALERT_SPOOL_FILE" ]
}

@test "pipeline: scan mode force-flushes digest spool" {
	bfd_load_function _alert_digest_flush_now "$PROJECT_ROOT/files/alert_lib.sh"
	ALERT_SPOOL_FILE="$TEST_TMPDIR/spool"
	ALERT_TEMPLATE_DIR="$PROJECT_ROOT/files/alert"
	EMAIL_ALERTS="1"
	EMAIL_SUBJECT="BFD Alert"
	EMAIL_LOGLINES="50"
	EMAIL_FORMAT="text"
	local mail_log="$TEST_TMPDIR/mail_calls"
	export MAIL_LOG="$mail_log"
	_setup_mock_mail_log
	# pre-populate spool (simulates accumulated alerts during scan)
	local now
	now=$(date +%s)
	echo "${now}|192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|root|10|300|1" > "$ALERT_SPOOL_FILE"
	_alert_digest_flush_now
	# mail should have been called
	[ -f "$mail_log" ]
	# spool should be empty
	[ ! -s "$ALERT_SPOOL_FILE" ]
}

@test "pipeline: cron.daily truncates stale digest spool (>24h)" {
	local spool_file="$INSTALL_PATH/tmp/.alert_spool"
	mkdir -p "$INSTALL_PATH/tmp"
	echo "stale entry" > "$spool_file"
	# make the file look 25 hours old
	touch -d "25 hours ago" "$spool_file"
	# inline cron.daily spool logic
	local _spool_age
	_spool_age=$(( $(date +%s) - $(stat -c %Y "$spool_file" 2>/dev/null || echo 0) ))
	if [ "$_spool_age" -gt 86400 ]; then
		: > "$spool_file"
	fi
	# file exists but is empty
	[ -f "$spool_file" ]
	[ ! -s "$spool_file" ]
}

@test "pipeline: cron.daily preserves fresh digest spool (<24h)" {
	local spool_file="$INSTALL_PATH/tmp/.alert_spool"
	mkdir -p "$INSTALL_PATH/tmp"
	echo "fresh entry" > "$spool_file"
	# file is just created — fresh
	local _spool_age
	_spool_age=$(( $(date +%s) - $(stat -c %Y "$spool_file" 2>/dev/null || echo 0) ))
	if [ "$_spool_age" -gt 86400 ]; then
		: > "$spool_file"
	fi
	# file should still have content
	[ -s "$spool_file" ]
}
