#!/usr/bin/env bats
#
# Test suite for detect_log_paths()
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

@test "detect_log_paths: configured paths exist - no change" {
	AUTH_LOG_PATH="$TEST_TMPDIR/secure"
	KERNEL_LOG_PATH="$TEST_TMPDIR/messages"
	MAIL_LOG_PATH="$TEST_TMPDIR/maillog"
	OUTPUT_SYSLOG_FILE="$KERNEL_LOG_PATH"
	touch "$TEST_TMPDIR/secure" "$TEST_TMPDIR/messages" "$TEST_TMPDIR/maillog"

	detect_log_paths

	[ "$AUTH_LOG_PATH" = "$TEST_TMPDIR/secure" ]
	[ "$KERNEL_LOG_PATH" = "$TEST_TMPDIR/messages" ]
	[ "$MAIL_LOG_PATH" = "$TEST_TMPDIR/maillog" ]
	[ "$OUTPUT_SYSLOG_FILE" = "$TEST_TMPDIR/messages" ]
}

@test "detect_log_paths: nonexistent paths with no fallback - unchanged" {
	# Skip if Debian/Ubuntu fallback paths exist on this system
	if [ -f "/var/log/auth.log" ] || [ -f "/var/log/syslog" ] || [ -f "/var/log/mail.log" ]; then
		skip "system has Debian log paths, testing fallback instead"
	fi

	AUTH_LOG_PATH="/nonexistent/secure"
	KERNEL_LOG_PATH="/nonexistent/messages"
	MAIL_LOG_PATH="/nonexistent/maillog"
	OUTPUT_SYSLOG_FILE="$KERNEL_LOG_PATH"

	detect_log_paths

	[ "$AUTH_LOG_PATH" = "/nonexistent/secure" ]
	[ "$KERNEL_LOG_PATH" = "/nonexistent/messages" ]
	[ "$MAIL_LOG_PATH" = "/nonexistent/maillog" ]
}

@test "detect_log_paths: AUTH fallback to auth.log on Debian" {
	if [ ! -f "/var/log/auth.log" ]; then
		skip "not a Debian/Ubuntu system"
	fi
	AUTH_LOG_PATH="/nonexistent/secure"

	detect_log_paths

	[ "$AUTH_LOG_PATH" = "/var/log/auth.log" ]
}

@test "detect_log_paths: KERNEL fallback to syslog on Debian" {
	if [ ! -f "/var/log/syslog" ]; then
		skip "not a Debian/Ubuntu system"
	fi
	KERNEL_LOG_PATH="/nonexistent/messages"
	OUTPUT_SYSLOG_FILE="$KERNEL_LOG_PATH"

	detect_log_paths

	[ "$KERNEL_LOG_PATH" = "/var/log/syslog" ]
	[ "$OUTPUT_SYSLOG_FILE" = "/var/log/syslog" ]
}

@test "detect_log_paths: MAIL fallback to mail.log on Debian" {
	if [ ! -f "/var/log/mail.log" ]; then
		skip "not a Debian/Ubuntu system"
	fi
	MAIL_LOG_PATH="/nonexistent/maillog"

	detect_log_paths

	[ "$MAIL_LOG_PATH" = "/var/log/mail.log" ]
}
