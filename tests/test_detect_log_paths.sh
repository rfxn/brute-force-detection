#!/bin/bash
#
# Test suite for detect_log_paths()
#
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=files/bfd.lib.sh
. "$SCRIPT_DIR/../files/bfd.lib.sh"

PASS=0
FAIL=0

assert_eq() {
	local desc="$1" expected="$2" actual="$3"
	if [ "$expected" = "$actual" ]; then
		PASS=$((PASS + 1))
	else
		FAIL=$((FAIL + 1))
		echo "FAIL: $desc (expected '$expected', got '$actual')"
	fi
}

summary() {
	echo "---"
	echo "$0: Passed=$PASS Failed=$FAIL"
	if [ "$FAIL" -gt 0 ]; then
		exit 1
	fi
}

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo "=== detect_log_paths tests ==="

# Test 1: configured paths exist — no change
AUTH_LOG_PATH="$TMPDIR/secure"
KERNEL_LOG_PATH="$TMPDIR/messages"
MAIL_LOG_PATH="$TMPDIR/maillog"
OUTPUT_SYSLOG_FILE="$KERNEL_LOG_PATH"
touch "$TMPDIR/secure" "$TMPDIR/messages" "$TMPDIR/maillog"

detect_log_paths

assert_eq "AUTH stays when file exists" "$TMPDIR/secure" "$AUTH_LOG_PATH"
assert_eq "KERNEL stays when file exists" "$TMPDIR/messages" "$KERNEL_LOG_PATH"
assert_eq "MAIL stays when file exists" "$TMPDIR/maillog" "$MAIL_LOG_PATH"
assert_eq "SYSLOG_FILE stays when kernel exists" "$TMPDIR/messages" "$OUTPUT_SYSLOG_FILE"

# Test 2: configured paths don't exist, fallbacks don't exist either — no crash, values unchanged
AUTH_LOG_PATH="/nonexistent/secure"
KERNEL_LOG_PATH="/nonexistent/messages"
MAIL_LOG_PATH="/nonexistent/maillog"
OUTPUT_SYSLOG_FILE="$KERNEL_LOG_PATH"

detect_log_paths

# If Debian paths exist on this system, they'll be used; otherwise values stay
if [ -f "/var/log/auth.log" ]; then
	assert_eq "AUTH falls back to auth.log on Debian" "/var/log/auth.log" "$AUTH_LOG_PATH"
else
	assert_eq "AUTH unchanged when no fallback" "/nonexistent/secure" "$AUTH_LOG_PATH"
fi

if [ -f "/var/log/syslog" ]; then
	assert_eq "KERNEL falls back to syslog on Debian" "/var/log/syslog" "$KERNEL_LOG_PATH"
else
	assert_eq "KERNEL unchanged when no fallback" "/nonexistent/messages" "$KERNEL_LOG_PATH"
fi

if [ -f "/var/log/mail.log" ]; then
	assert_eq "MAIL falls back to mail.log on Debian" "/var/log/mail.log" "$MAIL_LOG_PATH"
else
	assert_eq "MAIL unchanged when no fallback" "/nonexistent/maillog" "$MAIL_LOG_PATH"
fi

echo ""
summary
