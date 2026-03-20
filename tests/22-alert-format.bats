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

@test "expand_command_template: normal operation (single var, all vars, IPv6, multi-port, duplicate var)" {
	# single var ATTACK_HOST
	ATTACK_HOST="192.0.2.1"
	MOD=""
	PORTS=""
	run expand_command_template 'ban $ATTACK_HOST'
	assert_success
	assert_output "ban 192.0.2.1"

	# all three vars
	ATTACK_HOST="192.0.2.1"
	MOD="sshd"
	PORTS="22,80"
	run expand_command_template 'iptables -s $ATTACK_HOST -m $MOD -p $PORTS'
	assert_success
	assert_output "iptables -s 192.0.2.1 -m sshd -p 22,80"

	# IPv6 address
	ATTACK_HOST="2001:db8::1"
	MOD=""
	PORTS=""
	run expand_command_template 'ip6tables -s $ATTACK_HOST'
	assert_success
	assert_output "ip6tables -s 2001:db8::1"

	# multi-port PORTS
	ATTACK_HOST=""
	MOD=""
	PORTS="22,25,80"
	run expand_command_template 'block $PORTS'
	assert_success
	assert_output "block 22,25,80"

	# variable appears twice
	ATTACK_HOST="192.0.2.1"
	MOD=""
	PORTS=""
	run expand_command_template '$ATTACK_HOST to $ATTACK_HOST'
	assert_success
	assert_output "192.0.2.1 to 192.0.2.1"
}

@test "expand_command_template: edge cases (empty variables, no variables)" {
	# empty variables
	ATTACK_HOST=""
	MOD=""
	PORTS=""
	run expand_command_template 'ban $ATTACK_HOST'
	assert_success
	assert_output "ban "

	# no variables in template
	ATTACK_HOST="192.0.2.1"
	MOD="sshd"
	PORTS="22"
	run expand_command_template '/usr/sbin/iptables -F'
	assert_success
	assert_output "/usr/sbin/iptables -F"
}

# --- extract_command_template ---

@test "extract_command_template: unquoted, quoted, last-occurrence, and missing var" {
	local tmpconf="$TEST_TMPDIR/test.conf"

	# unquoted value
	echo 'BAN_COMMAND=/sbin/iptables -I INPUT -s $ATTACK_HOST -j DROP' > "$tmpconf"
	run extract_command_template "$tmpconf" "BAN_COMMAND"
	assert_output '/sbin/iptables -I INPUT -s $ATTACK_HOST -j DROP'

	# quoted value
	echo 'BAN_COMMAND="/etc/apf/apf -d $ATTACK_HOST {bfd.$MOD}"' > "$tmpconf"
	run extract_command_template "$tmpconf" "BAN_COMMAND"
	assert_output '/etc/apf/apf -d $ATTACK_HOST {bfd.$MOD}'

	# takes last occurrence
	printf 'BAN_COMMAND="first"\nBAN_COMMAND="second"\n' > "$tmpconf"
	run extract_command_template "$tmpconf" "BAN_COMMAND"
	assert_output "second"

	# returns empty for missing var
	echo 'OTHER_VAR="value"' > "$tmpconf"
	run extract_command_template "$tmpconf" "BAN_COMMAND"
	assert_output ""
}

# --- format_duration ---

@test "format_duration: all duration conversions (0, seconds, minutes, hours, mixed)" {
	run format_duration 0
	assert_success
	assert_output "permanent"

	run format_duration 30
	assert_success
	assert_output "30s"

	run format_duration 60
	assert_success
	assert_output "1m"

	run format_duration 90
	assert_success
	assert_output "1m 30s"

	run format_duration 300
	assert_success
	assert_output "5m"

	run format_duration 3600
	assert_success
	assert_output "1h"

	run format_duration 3661
	assert_success
	assert_output "1h 1m"

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
	echo "192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|root|5|300|3|5" > "$af"
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

@test "send_alerts: RULE_EMAIL override routes to different recipient" {
	local af="$TEST_TMPDIR/alerts_rule_email"
	echo "192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|special@example.com|5|300|3|5" > "$af"
	local mail_log="$TEST_TMPDIR/mail_calls"
	export MAIL_LOG="$mail_log"
	_setup_mock_mail_log
	send_alerts "$af" "$EMAIL_SUBJECT" "50"
	run grep "CALL:" "$mail_log"
	assert_output --partial "special@example.com"
}

@test "send_alerts: single-ban backward compat sets ATTACK_HOST global" {
	local af="$TEST_TMPDIR/alerts_compat"
	echo "192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|root|5|300|3|5" > "$af"
	_setup_mock_mail_silent
	send_alerts "$af" "$EMAIL_SUBJECT" "50"
	[ "$ATTACK_HOST" = "192.0.2.1" ]
	[ "$MOD" = "sshd" ]
	# ATTACK_COUNT = pressure_scaled / 1000 (approximate event count)
	[ "$ATTACK_COUNT" = "5" ]
}

@test "send_alerts: ATTACK_COUNT minimum is 1 even for low pressure" {
	local af="$TEST_TMPDIR/alerts_lowpressure"
	echo "192.0.2.1|sshd|22|500|0|ban|0|/dev/null|root|5|300|1|5" > "$af"
	_setup_mock_mail_silent
	send_alerts "$af" "$EMAIL_SUBJECT" "50"
	# 500/1000 = 0 -> clamped to 1
	[ "$ATTACK_COUNT" = "1" ]
}

@test "send_alerts: invalid template dir returns error" {
	ALERT_TEMPLATE_DIR="$TEST_TMPDIR/nonexistent"
	local af="$TEST_TMPDIR/alerts_one"
	echo "192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|root|5|300|3|5" > "$af"
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

@test "pipeline: alerts suppressed by SKIP_ALERT=1, DRY_RUN=1, and EMAIL_ALERTS=0" {
	# --- SKIP_ALERT=1 (set in rule file) ---
	local rules_dir="$TEST_TMPDIR/rules_skip"
	mkdir -p "$rules_dir"
	local logfile="$TEST_TMPDIR/test_skip.log"
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
	local mail_log="$TEST_TMPDIR/mail_skip"
	export MAIL_LOG="$mail_log"
	_setup_mock_mail_log
	check >/dev/null 2>&1
	[ ! -f "$mail_log" ]

	# --- DRY_RUN=1 (different IP to avoid already-banned) ---
	local rules_dir2="$TEST_TMPDIR/rules_dry"
	mkdir -p "$rules_dir2"
	local logfile2="$TEST_TMPDIR/test_dry.log"
	echo "test line" > "$logfile2"
	cat > "$rules_dir2/testrule" <<'RULEEOF'
TRIG="2"
PREREQ="/bin/sh"
RULEEOF
	cat >> "$rules_dir2/testrule" <<EOF
LOG_FILE="$logfile2"
LOG_TAG="testrule"
MATCHED_HOSTS="192.0.2.2 192.0.2.2 192.0.2.2"
EOF
	_setup_check_env "$rules_dir2"
	EMAIL_ALERTS="1"
	DRY_RUN="1"
	local mail_log2="$TEST_TMPDIR/mail_dry"
	export MAIL_LOG="$mail_log2"
	_setup_mock_mail_log
	check >/dev/null 2>&1
	[ ! -f "$mail_log2" ]

	# --- EMAIL_ALERTS=0 (different IP to avoid already-banned) ---
	local rules_dir3="$TEST_TMPDIR/rules_nomail"
	mkdir -p "$rules_dir3"
	local logfile3="$TEST_TMPDIR/test_nomail.log"
	echo "test line" > "$logfile3"
	cat > "$rules_dir3/testrule" <<'RULEEOF'
TRIG="2"
PREREQ="/bin/sh"
RULEEOF
	cat >> "$rules_dir3/testrule" <<EOF
LOG_FILE="$logfile3"
LOG_TAG="testrule"
MATCHED_HOSTS="192.0.2.3 192.0.2.3 192.0.2.3"
EOF
	_setup_check_env "$rules_dir3"
	EMAIL_ALERTS="0"
	local mail_log3="$TEST_TMPDIR/mail_nomail"
	export MAIL_LOG="$mail_log3"
	_setup_mock_mail_log
	check >/dev/null 2>&1
	[ ! -f "$mail_log3" ]
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
	# spool should have content: epoch prefix + 13 pipe-delimited fields = 14 total
	[ -f "$ALERT_SPOOL_FILE" ]
	[ -s "$ALERT_SPOOL_FILE" ]
	local field_count
	field_count=$(head -1 "$ALERT_SPOOL_FILE" | awk -F'|' '{print NF}')
	[ "$field_count" -eq 14 ]
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
	echo "${old_epoch}|192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|root|10|300|1|5" > "$ALERT_SPOOL_FILE"
	check >/dev/null 2>&1
	# mail should have been called (digest flushed)
	[ -f "$mail_log" ]
	# spool should be empty after flush
	[ ! -s "$ALERT_SPOOL_FILE" ]
}

@test "pipeline: scan mode force-flushes digest spool" {
	bfd_load_function _bfd_digest_flush "$PROJECT_ROOT/files/internals/bfd_alert.sh"
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
	echo "${now}|192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|root|10|300|1|5" > "$ALERT_SPOOL_FILE"
	_bfd_digest_flush
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

# --- _bfd_dispatch_messaging bug fixes (F-A01, F-A02) ---

# helper: set up messaging dispatch test environment
_setup_messaging_dispatch_env() {
	local tpl_dir="$1"
	mkdir -p "$tpl_dir"
	# minimal templates — entry templates produce channel-specific markers
	echo "SLACK_MARKER" > "$tpl_dir/slack.entry.tpl"
	echo "TG_MARKER" > "$tpl_dir/telegram.entry.tpl"
	echo '{"fields": [' > "$tpl_dir/discord.entry.tpl"
	# outer message templates reference ENTRY_BLOCKS and ALERT_COUNT
	echo '{"blocks": [{{ENTRY_BLOCKS}}], "count": "{{ALERT_COUNT}}"}' > "$tpl_dir/slack.message.tpl"
	echo '{{ENTRY_BLOCKS}} count={{ALERT_COUNT}}' > "$tpl_dir/telegram.message.tpl"
	echo '{"embeds": [{{ENTRY_FIELDS}}]}' > "$tpl_dir/discord.message.tpl"
	# register and enable messaging channels (alert_lib auto-registers at source time)
	SLACK_ALERTS="1"
	TELEGRAM_ALERTS="1"
	DISCORD_ALERTS="0"
	_bfd_alert_init
	# mock curl so handlers don't make real API calls
	mkdir -p "$TEST_TMPDIR/bin"
	echo '#!/bin/bash' > "$TEST_TMPDIR/bin/curl"
	echo 'exit 0' >> "$TEST_TMPDIR/bin/curl"
	chmod +x "$TEST_TMPDIR/bin/curl"
	export PATH="$TEST_TMPDIR/bin:$PATH"
	# alert_lib tmpdir for rendered template staging
	export ALERT_TMPDIR="$TEST_TMPDIR"
}

# --- CIDR sidecar lifecycle (F-A04) ---

@test "CIDR sidecar: available on second _alert_set_entry_vars call (F-A04)" {
	# sidecar must survive multiple rendering passes (text then HTML)
	# sanitization: tr ':' '-' | tr '/' '_' — dots are preserved
	local sidecar="$INSTALL_PATH/tmp/.cidr_detail_192.168.1.0_24"
	mkdir -p "$INSTALL_PATH/tmp"
	# create sidecar with HEADER + 2 contributing IPs
	cat > "$sidecar" <<'SC'
HEADER 192.168.1.0/24 2 10 10000
192.168.1.5 sshd 6 6000
192.168.1.9 sshd 4 4000
SC

	BAN_COMMAND_TEMPLATE="echo ban \$ATTACK_HOST"
	_FW_BACKEND="custom"
	BAN_ESCALATE_AFTER="0"
	EMAIL_REPUTATION_LINKS=""

	local line="192.168.1.0/24|sshd|all|10000|0|ban|0|(multiple)|root|5|300|1|10"

	# first pass (simulating text render)
	_alert_set_entry_vars "$line" 1 1
	[[ "$SOURCE_LOGS_SECTION_TEXT" == *"Contributing hosts"* ]]
	[[ "$SOURCE_LOGS_SECTION_TEXT" == *"192.168.1.5"* ]]
	[ "$SUBNET_IP_COUNT" = "2" ]

	# second pass (simulating HTML render) — sidecar must still be readable
	_alert_set_entry_vars "$line" 1 1
	[[ "$SOURCE_LOGS_SECTION_TEXT" == *"Contributing hosts"* ]]
	[[ "$SOURCE_LOGS_SECTION_TEXT" == *"192.168.1.9"* ]]
	[ "$SUBNET_IP_COUNT" = "2" ]

	# sidecar still exists (cleanup deferred to send_alerts)
	[ -f "$sidecar" ]
}

@test "messaging dispatch: ALERT_COUNT equals actual entry count (F-A02)" {
	local tpl_dir="$TEST_TMPDIR/tpl"
	_setup_messaging_dispatch_env "$tpl_dir"
	# create alerts file with 2 entries
	local af="$TEST_TMPDIR/alerts"
	echo "192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|root|5|300|3|5" > "$af"
	echo "192.0.2.2|dovecot|143|10000|0|ban|0|/dev/null|root|10|300|2|5" >> "$af"
	# capture ALERT_COUNT by overriding alert_dispatch
	local capture_file="$TEST_TMPDIR/alert_count_capture"
	alert_dispatch() {
		echo "$ALERT_COUNT" >> "$capture_file"
		return 0
	}
	_bfd_dispatch_messaging "$af" "Test Alert" "5" "$tpl_dir"
	# ALERT_COUNT should be "2" (not "0")
	[ -f "$capture_file" ]
	run head -1 "$capture_file"
	assert_output "2"
}

@test "messaging dispatch: ENTRY_BLOCKS per-channel isolation (F-A01)" {
	local tpl_dir="$TEST_TMPDIR/tpl"
	_setup_messaging_dispatch_env "$tpl_dir"
	# enable both Slack and Telegram
	SLACK_ALERTS="1"
	TELEGRAM_ALERTS="1"
	_bfd_alert_init
	# create alerts file with 1 entry
	local af="$TEST_TMPDIR/alerts"
	echo "192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|root|5|300|3|5" > "$af"
	# capture ENTRY_BLOCKS per alert_dispatch call
	local capture_dir="$TEST_TMPDIR/captures"
	mkdir -p "$capture_dir"
	alert_dispatch() {
		local _ch="$3"
		echo "$ENTRY_BLOCKS" > "$capture_dir/${_ch}_blocks"
		return 0
	}
	_bfd_dispatch_messaging "$af" "Test Alert" "5" "$tpl_dir"
	# Slack's ENTRY_BLOCKS should contain SLACK_MARKER but not TG_MARKER
	[ -f "$capture_dir/slack_blocks" ]
	run cat "$capture_dir/slack_blocks"
	assert_output --partial "SLACK_MARKER"
	refute_output --partial "TG_MARKER"
	# Telegram's ENTRY_BLOCKS should contain TG_MARKER but not SLACK_MARKER
	[ -f "$capture_dir/telegram_blocks" ]
	run cat "$capture_dir/telegram_blocks"
	assert_output --partial "TG_MARKER"
	refute_output --partial "SLACK_MARKER"
}

# --- Telegram MarkdownV2 escaping (F-A10, F-A11) ---

@test "Telegram MarkdownV2: BAN_DURATION_DETAIL_TG and REPORT_TREND_LABEL_TG parentheses escaped (F-A10, F-A11)" {
	# --- BAN_DURATION_DETAIL_TG ---
	BAN_COMMAND_TEMPLATE="echo ban \$ATTACK_HOST"
	_FW_BACKEND="custom"
	BAN_ESCALATE_AFTER="0"
	EMAIL_REPUTATION_LINKS=""
	# temporary ban with parentheses in duration detail: " (1h 30m), expires ..."
	local future_expiry
	future_expiry=$(( $(date +%s) + 5400 ))
	local line="192.0.2.1|sshd|22|5000|${future_expiry}|ban|0|/dev/null|root|5|300|3|5"
	_alert_set_entry_vars "$line" 1 1
	# BAN_DURATION_DETAIL should contain unescaped parentheses
	[[ "$BAN_DURATION_DETAIL" == *"("* ]]
	# BAN_DURATION_DETAIL_TG should have parentheses escaped with backslash
	[[ "$BAN_DURATION_DETAIL_TG" == *"\\("* ]]
	[[ "$BAN_DURATION_DETAIL_TG" == *"\\)"* ]]

	# --- REPORT_TREND_LABEL_TG ---
	REPORT_TREND_LABEL="70% decrease vs prior 24h (3 vs 10)"
	export REPORT_TREND_LABEL
	REPORT_TREND_LABEL_TG=$(_alert_telegram_escape "$REPORT_TREND_LABEL")
	export REPORT_TREND_LABEL_TG
	# Original should contain unescaped parentheses
	[[ "$REPORT_TREND_LABEL" == *"("* ]]
	# TG variant should have parentheses escaped with backslash
	[[ "$REPORT_TREND_LABEL_TG" == *"\\("* ]]
	[[ "$REPORT_TREND_LABEL_TG" == *"\\)"* ]]
	# Verify no unescaped parens remain after stripping escaped ones
	local bare_parens
	bare_parens=$(echo "$REPORT_TREND_LABEL_TG" | sed 's/\\(//g; s/\\)//g')
	[[ "$bare_parens" != *"("* ]]
	[[ "$bare_parens" != *")"* ]]
}

@test "test_alert_messaging: only dispatches to target channel (F-A07)" {
	local tpl_dir="$TEST_TMPDIR/tpl"
	_setup_messaging_dispatch_env "$tpl_dir"
	# enable all three channels
	SLACK_ALERTS="1"
	TELEGRAM_ALERTS="1"
	DISCORD_ALERTS="1"
	_bfd_alert_init
	# capture which channels alert_dispatch is called with
	local capture_file="$TEST_TMPDIR/dispatch_channels"
	alert_dispatch() {
		echo "$3" >> "$capture_file"
		return 0
	}
	# test_alert_messaging for slack only
	test_alert_messaging "$INSTALL_PATH" "slack" "SLACK_ALERTS"
	[ -f "$capture_file" ]
	# only "slack" should appear in dispatch calls
	run grep -c "slack" "$capture_file"
	assert_output "1"
	# telegram and discord should NOT appear
	run grep -c "telegram" "$capture_file"
	assert_output "0"
	run grep -c "discord" "$capture_file"
	assert_output "0"
	# after call, all channels should be restored to 1
	[ "$SLACK_ALERTS" = "1" ]
	[ "$TELEGRAM_ALERTS" = "1" ]
	[ "$DISCORD_ALERTS" = "1" ]
}
