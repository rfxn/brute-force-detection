#!/usr/bin/env bats
#
# Test suite for alert delivery, messaging dispatch, and digest mode
# Split from 37-alert-engine.bats for parallel execution efficiency
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

setup() {
	bfd_common_setup
	INSTALL_PATH="$TEST_TMPDIR/bfd"
	mkdir -p "$INSTALL_PATH"
}

teardown() {
	bfd_teardown
}

# ===================================================================
# _alert_email_local — local MTA delivery
# ===================================================================

# helper: create mock mail binary that logs calls
_setup_mock_mail() {
	mkdir -p "$TEST_TMPDIR/bin"
	cat > "$TEST_TMPDIR/bin/mail" <<'MOCK'
#!/bin/bash
echo "MAIL_CALL: $@" >> "$MAIL_LOG"
cat >> "$MAIL_LOG"
MOCK
	chmod +x "$TEST_TMPDIR/bin/mail"
	export PATH="$TEST_TMPDIR/bin:$PATH"
	export MAIL_LOG="$TEST_TMPDIR/mail_log"
}

# helper: create mock sendmail binary that logs calls
_setup_mock_sendmail() {
	mkdir -p "$TEST_TMPDIR/bin"
	cat > "$TEST_TMPDIR/bin/sendmail" <<'MOCK'
#!/bin/bash
echo "SENDMAIL_CALL: $@" >> "$SENDMAIL_LOG"
cat >> "$SENDMAIL_LOG"
MOCK
	chmod +x "$TEST_TMPDIR/bin/sendmail"
	export PATH="$TEST_TMPDIR/bin:$PATH"
	export SENDMAIL_LOG="$TEST_TMPDIR/sendmail_log"
}

# helper: create mock curl binary that logs calls
_setup_mock_curl() {
	mkdir -p "$TEST_TMPDIR/bin"
	cat > "$TEST_TMPDIR/bin/curl" <<'MOCK'
#!/bin/bash
echo "CURL_CALL: $@" >> "$CURL_LOG"
MOCK
	chmod +x "$TEST_TMPDIR/bin/curl"
	export PATH="$TEST_TMPDIR/bin:$PATH"
	export CURL_LOG="$TEST_TMPDIR/curl_log"
}

# helper: create text and html test files
_create_test_bodies() {
	echo "Plain text alert body" > "$TEST_TMPDIR/text_body"
	echo "<html><body>HTML alert body</body></html>" > "$TEST_TMPDIR/html_body"
}

@test "_alert_email_local: text format pipes to mail -s" {
	_setup_mock_mail
	_create_test_bodies
	_alert_email_local "root" "Test Subject" "$TEST_TMPDIR/text_body" "$TEST_TMPDIR/html_body" "text"
	[ -f "$MAIL_LOG" ]
	run grep "MAIL_CALL:" "$MAIL_LOG"
	assert_output --partial "-s"
	assert_output --partial "Test Subject"
	assert_output --partial "root"
	run grep "Plain text alert body" "$MAIL_LOG"
	assert_success
}

@test "_alert_email_local: html format uses sendmail -t -oi" {
	_setup_mock_sendmail
	_create_test_bodies
	_alert_email_local "root" "Test Subject" "$TEST_TMPDIR/text_body" "$TEST_TMPDIR/html_body" "html"
	[ -f "$SENDMAIL_LOG" ]
	run grep "SENDMAIL_CALL:" "$SENDMAIL_LOG"
	assert_output --partial "-t -oi"
	run grep "Content-Type: text/html" "$SENDMAIL_LOG"
	assert_success
	# HTML body is base64-encoded (RFC 5321 line length compliance)
	run grep "Content-Transfer-Encoding: base64" "$SENDMAIL_LOG"
	assert_success
}

@test "_alert_email_local: both format uses sendmail with MIME" {
	_setup_mock_sendmail
	_create_test_bodies
	_alert_email_local "root" "Test Subject" "$TEST_TMPDIR/text_body" "$TEST_TMPDIR/html_body" "both"
	[ -f "$SENDMAIL_LOG" ]
	run grep "multipart/alternative" "$SENDMAIL_LOG"
	assert_success
	run grep "Plain text alert body" "$SENDMAIL_LOG"
	assert_success
	# HTML body is base64-encoded (RFC 5321 line length compliance)
	run grep "Content-Transfer-Encoding: base64" "$SENDMAIL_LOG"
	assert_success
}

@test "_alert_email_local: html falls back to text when sendmail missing" {
	_setup_mock_mail
	# ensure no sendmail in PATH
	rm -f "$TEST_TMPDIR/bin/sendmail" 2>/dev/null || true
	_create_test_bodies
	_alert_email_local "root" "Test Subject" "$TEST_TMPDIR/text_body" "$TEST_TMPDIR/html_body" "html"
	# should have used mail instead
	[ -f "$MAIL_LOG" ]
	run grep "MAIL_CALL:" "$MAIL_LOG"
	assert_success
}

@test "_alert_email_local: returns 1 when mail binary missing" {
	# create a minimal PATH with essential binaries but without mail/sendmail
	local _saved_path="$PATH"
	mkdir -p "$TEST_TMPDIR/safebin"
	for cmd in date hostname cat printf rm; do
		local real_path
		real_path=$(command -v "$cmd" 2>/dev/null || true)
		[ -n "$real_path" ] && ln -sf "$real_path" "$TEST_TMPDIR/safebin/$cmd"
	done
	export PATH="$TEST_TMPDIR/safebin"
	_create_test_bodies
	run _alert_email_local "root" "Test Subject" "$TEST_TMPDIR/text_body" "$TEST_TMPDIR/html_body" "text"
	export PATH="$_saved_path"
	assert_failure
}

@test "_alert_email_local: From header uses ALERT_SMTP_FROM when set" {
	_setup_mock_sendmail
	_create_test_bodies
	ALERT_SMTP_FROM="alerts@example.com"
	_alert_email_local "root" "Test Subject" "$TEST_TMPDIR/text_body" "$TEST_TMPDIR/html_body" "html"
	run grep "From: alerts@example.com" "$SENDMAIL_LOG"
	assert_success
	unset ALERT_SMTP_FROM
}

@test "_alert_email_local: From header uses hostname fallback when ALERT_SMTP_FROM empty" {
	_setup_mock_sendmail
	_create_test_bodies
	unset ALERT_SMTP_FROM
	_alert_email_local "root" "Test Subject" "$TEST_TMPDIR/text_body" "$TEST_TMPDIR/html_body" "html"
	run grep "From: root@" "$SENDMAIL_LOG"
	assert_success
}

# ===================================================================
# _alert_email_relay — SMTP relay delivery
# ===================================================================

@test "_alert_email_relay: port/TLS behavior for smtps, port 25, and port 587" {
	# smtps://...465 — includes --ssl-reqd plus full argument check
	_setup_mock_curl
	ALERT_SMTP_RELAY="smtps://smtp.example.com:465"
	ALERT_SMTP_FROM="alerts@example.com"
	ALERT_SMTP_USER="user"
	ALERT_SMTP_PASS="pass"
	echo "RFC822 message" > "$TEST_TMPDIR/msg_file"
	_alert_email_relay "root" "Test Subject" "$TEST_TMPDIR/msg_file"
	[ -f "$CURL_LOG" ]
	run grep "CURL_CALL:" "$CURL_LOG"
	assert_output --partial "--url"
	assert_output --partial "smtps://smtp.example.com:465"
	assert_output --partial "--ssl-reqd"
	assert_output --partial "--mail-from"
	assert_output --partial "alerts@example.com"
	assert_output --partial "--mail-rcpt"
	assert_output --partial "root"
	assert_output --partial "-K"
	assert_output --partial "--upload-file"

	# smtp://...25 — skips --ssl-reqd
	> "$CURL_LOG"
	ALERT_SMTP_RELAY="smtp://relay.internal:25"
	echo "msg" > "$TEST_TMPDIR/msg_file"
	_alert_email_relay "root" "Subject" "$TEST_TMPDIR/msg_file"
	[ -f "$CURL_LOG" ]
	run grep "CURL_CALL:" "$CURL_LOG"
	assert_output --partial "smtp://relay.internal:25"
	refute_output --partial "--ssl-reqd"

	# smtp://...587 — includes --ssl-reqd
	> "$CURL_LOG"
	ALERT_SMTP_RELAY="smtp://relay.example.com:587"
	echo "msg" > "$TEST_TMPDIR/msg_file"
	_alert_email_relay "root" "Subject" "$TEST_TMPDIR/msg_file"
	[ -f "$CURL_LOG" ]
	run grep "CURL_CALL:" "$CURL_LOG"
	assert_output --partial "--ssl-reqd"

	unset ALERT_SMTP_RELAY ALERT_SMTP_FROM ALERT_SMTP_USER ALERT_SMTP_PASS
}

@test "_alert_email_relay: returns 1 when ALERT_SMTP_FROM missing" {
	unset ALERT_SMTP_FROM
	ALERT_SMTP_RELAY="smtps://smtp.example.com:465"
	ALERT_SMTP_USER="user"
	ALERT_SMTP_PASS="pass"
	echo "msg" > "$TEST_TMPDIR/msg_file"
	run _alert_email_relay "root" "Subject" "$TEST_TMPDIR/msg_file"
	assert_failure
	unset ALERT_SMTP_RELAY ALERT_SMTP_USER ALERT_SMTP_PASS
}

@test "_alert_email_relay: returns 1 when curl binary missing" {
	# create a minimal PATH with essential binaries but without curl
	local _saved_path="$PATH"
	mkdir -p "$TEST_TMPDIR/nocurl"
	for cmd in date hostname cat printf rm; do
		local real_path
		real_path=$(command -v "$cmd" 2>/dev/null || true)
		[ -n "$real_path" ] && ln -sf "$real_path" "$TEST_TMPDIR/nocurl/$cmd"
	done
	export PATH="$TEST_TMPDIR/nocurl"
	ALERT_SMTP_RELAY="smtps://smtp.example.com:465"
	ALERT_SMTP_FROM="alerts@example.com"
	ALERT_SMTP_USER="user"
	ALERT_SMTP_PASS="pass"
	echo "msg" > "$TEST_TMPDIR/msg_file"
	run _alert_email_relay "root" "Subject" "$TEST_TMPDIR/msg_file"
	export PATH="$_saved_path"
	assert_failure
	unset ALERT_SMTP_RELAY ALERT_SMTP_FROM ALERT_SMTP_USER ALERT_SMTP_PASS
}

@test "_alert_email_relay: returns 1 on curl failure" {
	mkdir -p "$TEST_TMPDIR/bin"
	echo '#!/bin/bash' > "$TEST_TMPDIR/bin/curl"
	echo 'exit 67' >> "$TEST_TMPDIR/bin/curl"
	chmod +x "$TEST_TMPDIR/bin/curl"
	export PATH="$TEST_TMPDIR/bin:$PATH"
	ALERT_SMTP_RELAY="smtps://smtp.example.com:465"
	ALERT_SMTP_FROM="alerts@example.com"
	ALERT_SMTP_USER="user"
	ALERT_SMTP_PASS="pass"
	echo "msg" > "$TEST_TMPDIR/msg_file"
	run _alert_email_relay "root" "Subject" "$TEST_TMPDIR/msg_file"
	assert_failure
	unset ALERT_SMTP_RELAY ALERT_SMTP_FROM ALERT_SMTP_USER ALERT_SMTP_PASS
}

@test "_alert_email_relay: auth-free relay omits --user" {
	_setup_mock_curl
	ALERT_SMTP_RELAY="smtp://relay.internal:25"
	ALERT_SMTP_FROM="alerts@example.com"
	unset ALERT_SMTP_USER ALERT_SMTP_PASS
	echo "msg" > "$TEST_TMPDIR/msg_file"
	_alert_email_relay "root" "Subject" "$TEST_TMPDIR/msg_file"
	[ -f "$CURL_LOG" ]
	run grep "CURL_CALL:" "$CURL_LOG"
	assert_output --partial "--mail-from"
	refute_output --partial "--user"
}

@test "_alert_email_relay: curl failure includes stderr detail" {
	mkdir -p "$TEST_TMPDIR/bin"
	cat > "$TEST_TMPDIR/bin/curl" <<'MOCK'
#!/bin/bash
echo "curl: (67) Access denied" >&2
exit 67
MOCK
	chmod +x "$TEST_TMPDIR/bin/curl"
	export PATH="$TEST_TMPDIR/bin:$PATH"
	ALERT_SMTP_RELAY="smtps://smtp.example.com:465"
	ALERT_SMTP_FROM="alerts@example.com"
	ALERT_SMTP_USER="user"
	ALERT_SMTP_PASS="pass"
	echo "msg" > "$TEST_TMPDIR/msg_file"
	run _alert_email_relay "root" "Subject" "$TEST_TMPDIR/msg_file"
	assert_failure
	# shared alert_lib writes error to stderr (captured by run)
	assert_output --partial "curl exit 67"
	assert_output --partial "Access denied"
	unset ALERT_SMTP_RELAY ALERT_SMTP_FROM ALERT_SMTP_USER ALERT_SMTP_PASS
}

# ===================================================================
# _alert_deliver_email — delivery router
# ===================================================================

@test "_alert_deliver_email: empty ALERT_SMTP_RELAY routes to local path" {
	_setup_mock_mail
	_create_test_bodies
	unset ALERT_SMTP_RELAY
	_alert_deliver_email "root" "Test Subject" "$TEST_TMPDIR/text_body" "$TEST_TMPDIR/html_body" "text"
	[ -f "$MAIL_LOG" ]
	run grep "MAIL_CALL:" "$MAIL_LOG"
	assert_success
}

@test "_alert_deliver_email: ALERT_SMTP_RELAY set routes to relay path" {
	_setup_mock_curl
	_create_test_bodies
	ALERT_SMTP_RELAY="smtps://smtp.example.com:465"
	ALERT_SMTP_FROM="alerts@example.com"
	ALERT_SMTP_USER="user"
	ALERT_SMTP_PASS="pass"
	_alert_deliver_email "root" "Test Subject" "$TEST_TMPDIR/text_body" "$TEST_TMPDIR/html_body" "text"
	[ -f "$CURL_LOG" ]
	run grep "CURL_CALL:" "$CURL_LOG"
	assert_output --partial "smtps://smtp.example.com:465"
	unset ALERT_SMTP_RELAY ALERT_SMTP_FROM ALERT_SMTP_USER ALERT_SMTP_PASS
}

@test "_alert_deliver_email: relay path builds full message with headers" {
	_setup_mock_curl
	_create_test_bodies
	ALERT_SMTP_RELAY="smtps://smtp.example.com:465"
	ALERT_SMTP_FROM="alerts@example.com"
	ALERT_SMTP_USER="user"
	ALERT_SMTP_PASS="pass"
	# capture the message file before it's deleted by using a recording curl
	mkdir -p "$TEST_TMPDIR/bin"
	cat > "$TEST_TMPDIR/bin/curl" <<'MOCK'
#!/bin/bash
# find --upload-file arg and copy its contents
while [ $# -gt 0 ]; do
	if [ "$1" = "--upload-file" ]; then
		cp "$2" "$CURL_LOG.msg"
		break
	fi
	shift
done
echo "ok" >> "$CURL_LOG"
MOCK
	chmod +x "$TEST_TMPDIR/bin/curl"
	_alert_deliver_email "root" "Test Subject" "$TEST_TMPDIR/text_body" "$TEST_TMPDIR/html_body" "text"
	[ -f "$CURL_LOG.msg" ]
	run grep "^From: alerts@example.com" "$CURL_LOG.msg"
	assert_success
	run grep "^To: root" "$CURL_LOG.msg"
	assert_success
	run grep "^Subject: Test Subject" "$CURL_LOG.msg"
	assert_success
	run grep "^Date:" "$CURL_LOG.msg"
	assert_success
	unset ALERT_SMTP_RELAY ALERT_SMTP_FROM ALERT_SMTP_USER ALERT_SMTP_PASS
}

# ===================================================================
# send_alerts integration (new pipeline)
# ===================================================================

@test "send_alerts integration: single entry text format calls mail" {
	_setup_mock_mail
	ALERT_TEMPLATE_DIR="$PROJECT_ROOT/files/alert"
	EMAIL_FORMAT="text"
	local af="$TEST_TMPDIR/alerts_one"
	echo "192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|root|5|300|3|5" > "$af"
	send_alerts "$af" "BFD Alert" "50"
	[ -f "$MAIL_LOG" ]
	run grep "MAIL_CALL:" "$MAIL_LOG"
	assert_output --partial "BFD Alert"
}

@test "send_alerts integration: multi entry subject has ban count" {
	_setup_mock_mail
	ALERT_TEMPLATE_DIR="$PROJECT_ROOT/files/alert"
	EMAIL_FORMAT="text"
	local af="$TEST_TMPDIR/alerts_multi"
	echo "192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|root|5|300|3|5" > "$af"
	echo "192.0.2.2|dovecot|143|10000|0|ban|0|/dev/null|root|10|300|2|5" >> "$af"
	send_alerts "$af" "BFD Alert" "50"
	run grep "MAIL_CALL:" "$MAIL_LOG"
	assert_output --partial "(2 bans)"
}

@test "send_alerts integration: multi recipient sends separate emails" {
	_setup_mock_mail
	ALERT_TEMPLATE_DIR="$PROJECT_ROOT/files/alert"
	EMAIL_FORMAT="text"
	local af="$TEST_TMPDIR/alerts_multi_recip"
	echo "192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|admin@example.com|5|300|3|5" > "$af"
	echo "192.0.2.2|dovecot|143|10000|0|ban|0|/dev/null|ops@example.com|10|300|2|5" >> "$af"
	send_alerts "$af" "BFD Alert" "50"
	local call_count
	call_count=$(grep -c "MAIL_CALL:" "$MAIL_LOG")
	[ "$call_count" -eq 2 ]
}

@test "send_alerts integration: format=both uses sendmail with MIME" {
	_setup_mock_sendmail
	ALERT_TEMPLATE_DIR="$PROJECT_ROOT/files/alert"
	EMAIL_FORMAT="both"
	local af="$TEST_TMPDIR/alerts_both"
	echo "192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|root|5|300|3|5" > "$af"
	send_alerts "$af" "BFD Alert" "50"
	[ -f "$SENDMAIL_LOG" ]
	run grep "multipart/alternative" "$SENDMAIL_LOG"
	assert_success
}

# ===================================================================
# Digest mode — _bfd_spool_append
# ===================================================================

# helper: mock send_alerts that records calls
_setup_mock_send_alerts() {
	export DIGEST_CALLS_LOG="$TEST_TMPDIR/digest_calls.log"
	export DIGEST_FLUSH_DIR="$TEST_TMPDIR/digest_flush"
	mkdir -p "$DIGEST_FLUSH_DIR"
	# override send_alerts
	send_alerts() {
		local _af="$1" _subj="$2" _ll="$3"
		local _n
		_n=$(wc -l < "$_af")
		echo "SEND_ALERTS: count=$_n subject=$_subj loglines=$_ll" >> "$DIGEST_CALLS_LOG"
		cp "$_af" "$DIGEST_FLUSH_DIR/flush_$(date +%s%N).dat"
	}
}

@test "_bfd_spool_append: append, no-op on empty, and append to existing" {
	# Scenario 1: appends timestamped entries to spool
	ALERT_SPOOL_FILE="$TEST_TMPDIR/spool"
	local af="$TEST_TMPDIR/alerts"
	cat > "$af" <<'EOF'
192.0.2.1|sshd|22|5000|0|ban|0||root|10|300|1|5
198.51.100.5|dovecot|143|8000|0|ban|0||root|10|300|2|5
EOF
	_bfd_spool_append "$af"
	[ -f "$ALERT_SPOOL_FILE" ]
	local count
	count=$(wc -l < "$ALERT_SPOOL_FILE")
	[ "$count" -eq 2 ]
	# each line should start with epoch (10+ digits) followed by pipe
	local _ep_pat='^[0-9]{10,}\|'
	while IFS= read -r line; do
		[[ "$line" =~ $_ep_pat ]]
	done < "$ALERT_SPOOL_FILE"

	# Scenario 2: no-op on empty file
	rm -f "$ALERT_SPOOL_FILE"
	local af2="$TEST_TMPDIR/empty_alerts"
	: > "$af2"
	_bfd_spool_append "$af2"
	# spool should not exist (never written)
	[ ! -f "$ALERT_SPOOL_FILE" ]

	# Scenario 3: appends to existing spool
	ALERT_SPOOL_FILE="$TEST_TMPDIR/spool3"
	# pre-populate with one line
	echo "1000000000|203.0.113.1|postfix|25|3000|0|ban|0||root|10|300|1|5" > "$ALERT_SPOOL_FILE"
	local af3="$TEST_TMPDIR/alerts3"
	echo "192.0.2.1|sshd|22|5000|0|ban|0||root|10|300|1|5" > "$af3"
	_bfd_spool_append "$af3"
	count=$(wc -l < "$ALERT_SPOOL_FILE")
	[ "$count" -eq 2 ]
}

# ===================================================================
# Digest mode — _bfd_digest_check
# ===================================================================

@test "_bfd_digest_check: no-op when EMAIL_DIGEST=cycle" {
	EMAIL_DIGEST="cycle"
	ALERT_SPOOL_FILE="$TEST_TMPDIR/spool"
	echo "1000000000|192.0.2.1|sshd|22|5000|0|ban|0||root|10|300|1|5" > "$ALERT_SPOOL_FILE"
	_setup_mock_send_alerts
	_bfd_digest_check
	[ ! -f "$DIGEST_CALLS_LOG" ]
}

@test "_bfd_digest_check: no-op on empty spool" {
	EMAIL_DIGEST="timed"
	EMAIL_DIGEST_INTERVAL="900"
	ALERT_SPOOL_FILE="$TEST_TMPDIR/spool_empty"
	: > "$ALERT_SPOOL_FILE"
	_setup_mock_send_alerts
	_bfd_digest_check
	[ ! -f "$DIGEST_CALLS_LOG" ]
}

@test "_bfd_digest_check: no-op on missing spool" {
	EMAIL_DIGEST="timed"
	EMAIL_DIGEST_INTERVAL="900"
	ALERT_SPOOL_FILE="$TEST_TMPDIR/nonexistent_spool"
	_setup_mock_send_alerts
	_bfd_digest_check
	[ ! -f "$DIGEST_CALLS_LOG" ]
}

@test "_bfd_digest_check: does not flush before interval" {
	EMAIL_DIGEST="timed"
	EMAIL_DIGEST_INTERVAL="900"
	EMAIL_ALERTS="1"
	ALERT_SPOOL_FILE="$TEST_TMPDIR/spool"
	# spool only 100s old
	local now
	now=$(date +%s)
	local old_epoch=$((now - 100))
	echo "${old_epoch}|192.0.2.1|sshd|22|5000|0|ban|0||root|10|300|1|5" > "$ALERT_SPOOL_FILE"
	_setup_mock_send_alerts
	_bfd_digest_check
	# should NOT have flushed
	[ ! -f "$DIGEST_CALLS_LOG" ]
	# spool should still have content
	[ -s "$ALERT_SPOOL_FILE" ]
}

@test "_bfd_digest_check: flushes when interval expired" {
	EMAIL_DIGEST="timed"
	EMAIL_DIGEST_INTERVAL="900"
	EMAIL_ALERTS="1"
	EMAIL_SUBJECT="BFD Alert"
	EMAIL_LOGLINES="50"
	ALERT_SPOOL_FILE="$TEST_TMPDIR/spool"
	ALERT_TEMPLATE_DIR="$PROJECT_ROOT/files/alert"
	# spool 1000s old (> 900s interval)
	local now
	now=$(date +%s)
	local old_epoch=$((now - 1000))
	echo "${old_epoch}|192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|root|10|300|1|5" > "$ALERT_SPOOL_FILE"
	_setup_mock_send_alerts
	_bfd_digest_check
	# should have flushed
	[ -f "$DIGEST_CALLS_LOG" ]
	run grep "SEND_ALERTS:" "$DIGEST_CALLS_LOG"
	assert_success
	assert_output --partial "count=1"
	# spool should be empty
	[ ! -s "$ALERT_SPOOL_FILE" ]
}

# ===================================================================
# Digest mode — _bfd_digest_flush
# ===================================================================

@test "_bfd_digest_flush: sends all entries and truncates spool" {
	EMAIL_ALERTS="1"
	EMAIL_SUBJECT="BFD Alert"
	EMAIL_LOGLINES="50"
	ALERT_SPOOL_FILE="$TEST_TMPDIR/spool"
	ALERT_TEMPLATE_DIR="$PROJECT_ROOT/files/alert"
	local now
	now=$(date +%s)
	echo "${now}|192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|root|10|300|1|5" > "$ALERT_SPOOL_FILE"
	echo "${now}|198.51.100.5|dovecot|143|8000|0|ban|0|/dev/null|root|10|300|2|5" >> "$ALERT_SPOOL_FILE"
	_setup_mock_send_alerts
	_bfd_digest_flush
	# should have sent
	[ -f "$DIGEST_CALLS_LOG" ]
	run grep "SEND_ALERTS:" "$DIGEST_CALLS_LOG"
	assert_success
	assert_output --partial "count=2"
	# spool should be empty
	[ ! -s "$ALERT_SPOOL_FILE" ]
}

@test "_bfd_digest_flush: strips epoch prefix from flush file" {
	EMAIL_ALERTS="1"
	EMAIL_SUBJECT="BFD Alert"
	EMAIL_LOGLINES="50"
	ALERT_SPOOL_FILE="$TEST_TMPDIR/spool"
	ALERT_TEMPLATE_DIR="$PROJECT_ROOT/files/alert"
	local now
	now=$(date +%s)
	echo "${now}|192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|root|10|300|1|5" > "$ALERT_SPOOL_FILE"
	_setup_mock_send_alerts
	_bfd_digest_flush
	# check that flush file had 13 fields (epoch stripped, fail_count preserved)
	local flush_file
	flush_file=$(ls "$DIGEST_FLUSH_DIR"/flush_*.dat 2>/dev/null | head -1)
	[ -n "$flush_file" ]
	local field_count
	field_count=$(head -1 "$flush_file" | awk -F'|' '{print NF}')
	[ "$field_count" -eq 13 ]
}

@test "_bfd_digest_flush: no-op when EMAIL_ALERTS=0" {
	EMAIL_ALERTS="0"
	ALERT_SPOOL_FILE="$TEST_TMPDIR/spool"
	local now
	now=$(date +%s)
	echo "${now}|192.0.2.1|sshd|22|5000|0|ban|0||root|10|300|1|5" > "$ALERT_SPOOL_FILE"
	_setup_mock_send_alerts
	_bfd_digest_flush
	[ ! -f "$DIGEST_CALLS_LOG" ]
	# spool untouched
	[ -s "$ALERT_SPOOL_FILE" ]
}

@test "_bfd_digest_flush: no-op on empty spool" {
	EMAIL_ALERTS="1"
	ALERT_SPOOL_FILE="$TEST_TMPDIR/spool_empty"
	: > "$ALERT_SPOOL_FILE"
	_setup_mock_send_alerts
	_bfd_digest_flush
	[ ! -f "$DIGEST_CALLS_LOG" ]
}

@test "_bfd_digest_flush: safe to call multiple times" {
	EMAIL_ALERTS="1"
	EMAIL_SUBJECT="BFD Alert"
	EMAIL_LOGLINES="50"
	ALERT_SPOOL_FILE="$TEST_TMPDIR/spool"
	ALERT_TEMPLATE_DIR="$PROJECT_ROOT/files/alert"
	local now
	now=$(date +%s)
	echo "${now}|192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|root|10|300|1|5" > "$ALERT_SPOOL_FILE"
	_setup_mock_send_alerts
	_bfd_digest_flush
	_bfd_digest_flush
	# should have only one SEND_ALERTS call (second was no-op)
	local call_count
	call_count=$(grep -c "SEND_ALERTS:" "$DIGEST_CALLS_LOG")
	[ "$call_count" -eq 1 ]
}

# ===================================================================
# Integration: send_alerts MIME structure and relay delivery
# ===================================================================

@test "send_alerts integration: format=both MIME has text and HTML parts" {
	_setup_mock_sendmail
	ALERT_TEMPLATE_DIR="$PROJECT_ROOT/files/alert"
	EMAIL_FORMAT="both"
	local af="$TEST_TMPDIR/alerts_mime"
	echo "192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|root|5|300|3|5" > "$af"
	send_alerts "$af" "BFD Alert" "50"
	[ -f "$SENDMAIL_LOG" ]
	# MIME boundary present
	run grep "multipart/alternative" "$SENDMAIL_LOG"
	assert_success
	# both content types present
	run grep "Content-Type: text/plain" "$SENDMAIL_LOG"
	assert_success
	run grep "Content-Type: text/html" "$SENDMAIL_LOG"
	assert_success
}

@test "send_alerts integration: relay path renders templates and calls curl" {
	# create recording curl that captures the uploaded message
	mkdir -p "$TEST_TMPDIR/bin"
	cat > "$TEST_TMPDIR/bin/curl" <<'MOCK'
#!/bin/bash
while [ $# -gt 0 ]; do
	if [ "$1" = "--upload-file" ]; then
		cp "$2" "$CURL_LOG.msg"
		break
	fi
	shift
done
echo "ok" >> "$CURL_LOG"
MOCK
	chmod +x "$TEST_TMPDIR/bin/curl"
	export PATH="$TEST_TMPDIR/bin:$PATH"
	export CURL_LOG="$TEST_TMPDIR/curl_log"
	ALERT_TEMPLATE_DIR="$PROJECT_ROOT/files/alert"
	EMAIL_FORMAT="text"
	SMTP_RELAY="smtps://smtp.example.com:465"
	SMTP_FROM="alerts@example.com"
	SMTP_USER="user"
	SMTP_PASS="pass"
	_bfd_alert_init
	local af="$TEST_TMPDIR/alerts_relay"
	echo "192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|root|5|300|3|5" > "$af"
	send_alerts "$af" "BFD Alert" "50"
	# curl was called
	[ -f "$CURL_LOG" ]
	# captured message has RFC822 headers
	[ -f "$CURL_LOG.msg" ]
	run grep "^From: alerts@example.com" "$CURL_LOG.msg"
	assert_success
	run grep "^Subject: BFD Alert" "$CURL_LOG.msg"
	assert_success
	# message has multipart MIME structure (relay always builds full MIME)
	run grep "multipart/alternative" "$CURL_LOG.msg"
	assert_success
	unset SMTP_RELAY SMTP_FROM SMTP_USER SMTP_PASS ALERT_SMTP_RELAY ALERT_SMTP_FROM ALERT_SMTP_USER ALERT_SMTP_PASS
}

@test "digest flush: sends via relay when SMTP_RELAY set" {
	# create recording curl
	mkdir -p "$TEST_TMPDIR/bin"
	cat > "$TEST_TMPDIR/bin/curl" <<'MOCK'
#!/bin/bash
echo "CURL_CALL: $@" >> "$CURL_LOG"
MOCK
	chmod +x "$TEST_TMPDIR/bin/curl"
	export PATH="$TEST_TMPDIR/bin:$PATH"
	export CURL_LOG="$TEST_TMPDIR/curl_log"
	EMAIL_ALERTS="1"
	EMAIL_SUBJECT="BFD Alert"
	EMAIL_LOGLINES="50"
	EMAIL_FORMAT="text"
	ALERT_SPOOL_FILE="$TEST_TMPDIR/spool"
	ALERT_TEMPLATE_DIR="$PROJECT_ROOT/files/alert"
	SMTP_RELAY="smtps://smtp.example.com:465"
	SMTP_FROM="alerts@example.com"
	SMTP_USER="user"
	SMTP_PASS="pass"
	_bfd_alert_init
	local now
	now=$(date +%s)
	echo "${now}|192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|root|10|300|1|5" > "$ALERT_SPOOL_FILE"
	_bfd_digest_flush
	# curl should have been called with relay URL
	[ -f "$CURL_LOG" ]
	run grep "CURL_CALL:" "$CURL_LOG"
	assert_output --partial "smtps://smtp.example.com:465"
	# spool should be empty
	[ ! -s "$ALERT_SPOOL_FILE" ]
	unset SMTP_RELAY SMTP_FROM SMTP_USER SMTP_PASS ALERT_SMTP_RELAY ALERT_SMTP_FROM ALERT_SMTP_USER ALERT_SMTP_PASS
}

# ===================================================================
# _bfd_alert_init — channel registration & env mapping
# ===================================================================

@test "_bfd_alert_init: maps SLACK env vars" {
	SLACK_MODE="bot"
	SLACK_WEBHOOK_URL="https://hooks.slack.com/services/T/B/X"
	SLACK_TOKEN="xoxb-test"
	SLACK_CHANNEL="#alerts"
	SLACK_ALERTS="1"
	_bfd_alert_init
	[ "$ALERT_SLACK_MODE" = "bot" ]
	[ "$ALERT_SLACK_WEBHOOK_URL" = "https://hooks.slack.com/services/T/B/X" ]
	[ "$ALERT_SLACK_TOKEN" = "xoxb-test" ]
	[ "$ALERT_SLACK_CHANNEL" = "#alerts" ]
	alert_channel_enabled "slack"
	unset SLACK_MODE SLACK_WEBHOOK_URL SLACK_TOKEN SLACK_CHANNEL SLACK_ALERTS
	unset ALERT_SLACK_MODE ALERT_SLACK_WEBHOOK_URL ALERT_SLACK_TOKEN ALERT_SLACK_CHANNEL
}

@test "_bfd_alert_init: maps TELEGRAM env vars" {
	TELEGRAM_BOT_TOKEN="123456:ABC"
	TELEGRAM_CHAT_ID="-100123"
	TELEGRAM_ALERTS="1"
	_bfd_alert_init
	[ "$ALERT_TELEGRAM_BOT_TOKEN" = "123456:ABC" ]
	[ "$ALERT_TELEGRAM_CHAT_ID" = "-100123" ]
	alert_channel_enabled "telegram"
	unset TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID TELEGRAM_ALERTS
	unset ALERT_TELEGRAM_BOT_TOKEN ALERT_TELEGRAM_CHAT_ID
}

@test "_bfd_alert_init: maps DISCORD env vars" {
	DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/123/abc"
	DISCORD_ALERTS="1"
	_bfd_alert_init
	[ "$ALERT_DISCORD_WEBHOOK_URL" = "https://discord.com/api/webhooks/123/abc" ]
	alert_channel_enabled "discord"
	unset DISCORD_WEBHOOK_URL DISCORD_ALERTS
	unset ALERT_DISCORD_WEBHOOK_URL
}

@test "_bfd_alert_init: disabled channels stay disabled" {
	SLACK_ALERTS="0"
	TELEGRAM_ALERTS="0"
	DISCORD_ALERTS="0"
	_bfd_alert_init
	! alert_channel_enabled "slack"
	! alert_channel_enabled "telegram"
	! alert_channel_enabled "discord"
	unset SLACK_ALERTS TELEGRAM_ALERTS DISCORD_ALERTS
}

@test "_bfd_alert_init: re-disables channels on reload" {
	SLACK_ALERTS="1"
	SLACK_WEBHOOK_URL="https://hooks.slack.com/services/T/B/X"
	_bfd_alert_init
	alert_channel_enabled "slack"
	# simulate reload: user disables slack
	SLACK_ALERTS="0"
	_bfd_alert_init
	! alert_channel_enabled "slack"
	unset SLACK_ALERTS SLACK_WEBHOOK_URL ALERT_SLACK_MODE ALERT_SLACK_WEBHOOK_URL ALERT_SLACK_TOKEN ALERT_SLACK_CHANNEL
}

# ===================================================================
# _bfd_dispatch_messaging — messaging dispatch
# ===================================================================

@test "_bfd_dispatch_messaging: no-op when no channels enabled" {
	SLACK_ALERTS="0"
	TELEGRAM_ALERTS="0"
	DISCORD_ALERTS="0"
	_bfd_alert_init
	local af="$TEST_TMPDIR/alerts"
	echo "192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|root|10|300|1|5" > "$af"
	local tpl_dir="$PROJECT_ROOT/files/alert"
	run _bfd_dispatch_messaging "$af" "Test Subject" "5" "$tpl_dir"
	assert_success
	unset SLACK_ALERTS TELEGRAM_ALERTS DISCORD_ALERTS
}

@test "_bfd_dispatch_messaging: no-op with empty alerts file" {
	SLACK_ALERTS="1"
	SLACK_WEBHOOK_URL="https://hooks.slack.com/services/T/B/X"
	_bfd_alert_init
	local af="$TEST_TMPDIR/alerts_empty"
	: > "$af"
	local tpl_dir="$PROJECT_ROOT/files/alert"
	run _bfd_dispatch_messaging "$af" "Test Subject" "5" "$tpl_dir"
	assert_success
	unset SLACK_ALERTS SLACK_WEBHOOK_URL ALERT_SLACK_MODE ALERT_SLACK_WEBHOOK_URL ALERT_SLACK_TOKEN ALERT_SLACK_CHANNEL
}

@test "_bfd_dispatch_messaging: renders slack entry template" {
	# Mock curl to capture payload (Slack webhook returns literal "ok")
	local curl_log="$TEST_TMPDIR/curl_calls"
	curl() { echo "CURL_CALL: $*" >> "$curl_log"; echo 'ok'; return 0; }
	export -f curl
	SLACK_ALERTS="1"
	SLACK_WEBHOOK_URL="https://hooks.slack.com/services/T/B/X"
	_bfd_alert_init
	local af="$TEST_TMPDIR/alerts"
	echo "192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|root|10|300|1|5" > "$af"
	local tpl_dir="$PROJECT_ROOT/files/alert"
	_bfd_dispatch_messaging "$af" "Test Subject" "5" "$tpl_dir"
	[ -f "$curl_log" ]
	# curl was called with the webhook URL
	run grep "CURL_CALL:" "$curl_log"
	assert_output --partial "hooks.slack.com"
	unset SLACK_ALERTS SLACK_WEBHOOK_URL ALERT_SLACK_MODE ALERT_SLACK_WEBHOOK_URL ALERT_SLACK_TOKEN ALERT_SLACK_CHANNEL
	unset -f curl
}

@test "_bfd_dispatch_messaging: renders discord entry template" {
	local curl_log="$TEST_TMPDIR/curl_calls"
	curl() { echo "CURL_CALL: $*" >> "$curl_log"; return 0; }
	export -f curl
	DISCORD_ALERTS="1"
	DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/123/abc"
	_bfd_alert_init
	local af="$TEST_TMPDIR/alerts"
	echo "192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|root|10|300|1|5" > "$af"
	local tpl_dir="$PROJECT_ROOT/files/alert"
	_bfd_dispatch_messaging "$af" "Test Subject" "5" "$tpl_dir"
	[ -f "$curl_log" ]
	run grep "CURL_CALL:" "$curl_log"
	assert_output --partial "discord.com"
	unset DISCORD_ALERTS DISCORD_WEBHOOK_URL ALERT_DISCORD_WEBHOOK_URL
	unset -f curl
}

@test "_bfd_dispatch_messaging: cleans up ENTRY_BLOCKS after dispatch" {
	curl() { echo 'ok'; return 0; }
	export -f curl
	SLACK_ALERTS="1"
	SLACK_WEBHOOK_URL="https://hooks.slack.com/services/T/B/X"
	_bfd_alert_init
	local af="$TEST_TMPDIR/alerts"
	echo "192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|root|10|300|1|5" > "$af"
	local tpl_dir="$PROJECT_ROOT/files/alert"
	_bfd_dispatch_messaging "$af" "Test Subject" "5" "$tpl_dir"
	# ENTRY_BLOCKS should be unset after dispatch (cleanup)
	[ -z "${ENTRY_BLOCKS:-}" ]
	unset SLACK_ALERTS SLACK_WEBHOOK_URL ALERT_SLACK_MODE ALERT_SLACK_WEBHOOK_URL ALERT_SLACK_TOKEN ALERT_SLACK_CHANNEL
	unset -f curl
}

# ===================================================================
# _bfd_digest_flush — messaging channel awareness
# ===================================================================

@test "_bfd_digest_flush: flushes when only messaging enabled (no email)" {
	EMAIL_ALERTS="0"
	SLACK_ALERTS="1"
	SLACK_WEBHOOK_URL="https://hooks.slack.com/services/T/B/X"
	TELEGRAM_ALERTS="0"
	DISCORD_ALERTS="0"
	_bfd_alert_init
	ALERT_SPOOL_FILE="$TEST_TMPDIR/spool"
	ALERT_TEMPLATE_DIR="$PROJECT_ROOT/files/alert"
	EMAIL_SUBJECT="BFD Alert"
	EMAIL_LOGLINES="5"
	# mock curl for Slack webhook delivery
	curl() { echo 'ok'; return 0; }
	export -f curl
	# mock mail (send_alerts callback may invoke it)
	mail() { return 0; }
	export -f mail
	# pre-populate spool
	local now
	now=$(date +%s)
	echo "${now}|192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|root|10|300|1|5" > "$ALERT_SPOOL_FILE"
	_bfd_digest_flush
	# spool should be empty (flushed)
	[ ! -s "$ALERT_SPOOL_FILE" ]
	unset EMAIL_ALERTS SLACK_ALERTS SLACK_WEBHOOK_URL TELEGRAM_ALERTS DISCORD_ALERTS
	unset ALERT_SLACK_MODE ALERT_SLACK_WEBHOOK_URL ALERT_SLACK_TOKEN ALERT_SLACK_CHANNEL
	unset -f curl mail
}

@test "_bfd_digest_flush: does not flush when all channels disabled" {
	EMAIL_ALERTS="0"
	SLACK_ALERTS="0"
	TELEGRAM_ALERTS="0"
	DISCORD_ALERTS="0"
	ALERT_SPOOL_FILE="$TEST_TMPDIR/spool"
	echo "1234567890|192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|root|10|300|1|5" > "$ALERT_SPOOL_FILE"
	_bfd_digest_flush
	# spool should NOT be empty (preserved for when re-enabled)
	[ -s "$ALERT_SPOOL_FILE" ]
	unset EMAIL_ALERTS SLACK_ALERTS TELEGRAM_ALERTS DISCORD_ALERTS
}

# ===================================================================
# _hc_alerts — messaging health checks
# ===================================================================

@test "_hc_alerts: slack enabled with webhook shows PASS" {
	EMAIL_ALERTS="0"
	SLACK_ALERTS="1"
	SLACK_MODE="webhook"
	SLACK_WEBHOOK_URL="https://hooks.slack.com/services/T/B/X"
	run _hc_alerts
	assert_output --partial "[PASS] Slack alerts: enabled"
	assert_output --partial "[PASS] Slack webhook URL: configured"
	unset SLACK_ALERTS SLACK_MODE SLACK_WEBHOOK_URL
}

@test "_hc_alerts: slack enabled without webhook shows FAIL" {
	EMAIL_ALERTS="0"
	SLACK_ALERTS="1"
	SLACK_MODE="webhook"
	SLACK_WEBHOOK_URL=""
	run _hc_alerts
	assert_output --partial "[FAIL] Slack webhook URL: SLACK_WEBHOOK_URL not set"
	unset SLACK_ALERTS SLACK_MODE SLACK_WEBHOOK_URL
}

@test "_hc_alerts: slack bot mode missing token shows FAIL" {
	EMAIL_ALERTS="0"
	SLACK_ALERTS="1"
	SLACK_MODE="bot"
	SLACK_TOKEN=""
	SLACK_CHANNEL="#test"
	run _hc_alerts
	assert_output --partial "[FAIL] Slack token: SLACK_TOKEN not set"
	unset SLACK_ALERTS SLACK_MODE SLACK_TOKEN SLACK_CHANNEL
}

@test "_hc_alerts: telegram enabled with config shows PASS" {
	export EMAIL_ALERTS="0"
	TELEGRAM_ALERTS="1"
	TELEGRAM_BOT_TOKEN="123456:ABC"
	TELEGRAM_CHAT_ID="-100123"
	run _hc_alerts
	assert_output --partial "[PASS] Telegram alerts: enabled"
	assert_output --partial "[PASS] Telegram bot token: configured"
	assert_output --partial "[PASS] Telegram chat ID: configured"
	unset TELEGRAM_ALERTS TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID
}

@test "_hc_alerts: telegram missing token shows FAIL" {
	export EMAIL_ALERTS="0"
	TELEGRAM_ALERTS="1"
	TELEGRAM_BOT_TOKEN=""
	TELEGRAM_CHAT_ID="-100123"
	run _hc_alerts
	assert_output --partial "[FAIL] Telegram bot token: TELEGRAM_BOT_TOKEN not set"
	unset TELEGRAM_ALERTS TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID
}

@test "_hc_alerts: discord enabled with webhook shows PASS" {
	export EMAIL_ALERTS="0"
	DISCORD_ALERTS="1"
	DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/123/abc"
	run _hc_alerts
	assert_output --partial "[PASS] Discord alerts: enabled"
	assert_output --partial "[PASS] Discord webhook URL: configured"
	unset DISCORD_ALERTS DISCORD_WEBHOOK_URL
}

@test "_hc_alerts: discord missing webhook shows FAIL" {
	export EMAIL_ALERTS="0"
	DISCORD_ALERTS="1"
	DISCORD_WEBHOOK_URL=""
	run _hc_alerts
	assert_output --partial "[FAIL] Discord webhook URL: DISCORD_WEBHOOK_URL not set"
	unset DISCORD_ALERTS DISCORD_WEBHOOK_URL
}

# ===================================================================
# show_config — messaging variables in whitelist
# ===================================================================

@test "show_config: messaging variables are in whitelist" {
	local var val
	for var in SLACK_ALERTS TELEGRAM_ALERTS DISCORD_ALERTS; do
		eval "$var=test_val"
		run show_config "$var"
		assert_success
		assert_output "test_val"
		unset "$var"
	done
	# secret vars are recognized but masked
	SLACK_WEBHOOK_URL="test_val"
	run show_config "SLACK_WEBHOOK_URL"
	assert_success
	assert_output "****"
	unset SLACK_WEBHOOK_URL
}

# ===================================================================
# test_alert — messaging type dispatch
# ===================================================================

@test "test_alert: unknown type shows error with messaging types" {
	run test_alert "$INSTALL_PATH" "fax"
	assert_failure
	assert_output --partial "email, slack, telegram, discord"
}

@test "test_alert: empty type lists messaging types in hint" {
	run test_alert "$INSTALL_PATH" ""
	assert_failure
	assert_output --partial "email, slack, telegram, discord"
}
