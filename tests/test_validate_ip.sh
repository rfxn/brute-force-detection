#!/bin/bash
#
# Test suite for validate_ip() and sanitize_mod()
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

assert_rc() {
	local desc="$1" expected_rc="$2"
	shift 2
	"$@" >/dev/null 2>&1
	local rc=$?
	if [ "$rc" -eq "$expected_rc" ]; then
		PASS=$((PASS + 1))
	else
		FAIL=$((FAIL + 1))
		echo "FAIL: $desc (expected rc=$expected_rc, got rc=$rc)"
	fi
}

summary() {
	echo "---"
	echo "$0: Passed=$PASS Failed=$FAIL"
	if [ "$FAIL" -gt 0 ]; then
		exit 1
	fi
}

echo "=== validate_ip tests ==="

# valid IPs
assert_eq "valid 1.2.3.4" "1.2.3.4" "$(validate_ip "1.2.3.4")"
assert_eq "valid 0.0.0.0" "0.0.0.0" "$(validate_ip "0.0.0.0")"
assert_eq "valid 255.255.255.255" "255.255.255.255" "$(validate_ip "255.255.255.255")"
assert_eq "valid 192.168.1.1" "192.168.1.1" "$(validate_ip "192.168.1.1")"
assert_eq "valid 10.0.0.1" "10.0.0.1" "$(validate_ip "10.0.0.1")"
assert_eq "valid 172.16.0.255" "172.16.0.255" "$(validate_ip "172.16.0.255")"

assert_rc "valid IP returns 0" 0 validate_ip "1.2.3.4"

# invalid IPs - out of range
assert_eq "invalid 256.1.1.1" "" "$(validate_ip "256.1.1.1")"
assert_eq "invalid 1.2.3.999" "" "$(validate_ip "1.2.3.999")"
assert_eq "invalid 999.999.999.999" "" "$(validate_ip "999.999.999.999")"
assert_eq "invalid 300.0.0.1" "" "$(validate_ip "300.0.0.1")"

assert_rc "invalid IP returns 1" 1 validate_ip "256.1.1.1"

# invalid IPs - wrong format
assert_eq "empty string" "" "$(validate_ip "")"
assert_eq "alpha string" "" "$(validate_ip "abc")"
assert_eq "too few octets" "" "$(validate_ip "1.2.3")"
assert_eq "too many octets" "" "$(validate_ip "1.2.3.4.5")"
assert_eq "trailing dot" "" "$(validate_ip "1.2.3.4.")"
assert_eq "leading dot" "" "$(validate_ip ".1.2.3.4")"

# injection attempts
assert_eq "injection semicolon" "" "$(validate_ip "1.2.3.4;rm -rf /")"
assert_eq "injection dollar" "" "$(validate_ip '1.2.3.4$(whoami)')"
assert_eq "injection backtick" "" "$(validate_ip '1.2.3.4`id`')"
assert_eq "injection pipe" "" "$(validate_ip "1.2.3.4|cat /etc/passwd")"
assert_eq "injection newline" "" "$(validate_ip "1.2.3.4
5.6.7.8")"

echo ""
echo "=== sanitize_mod tests ==="

# valid module names
assert_eq "valid sshd" "sshd" "$(sanitize_mod "sshd")"
assert_eq "valid exim_authfail" "exim_authfail" "$(sanitize_mod "exim_authfail")"
assert_eq "valid asterisk-iax" "asterisk-iax" "$(sanitize_mod "asterisk-iax")"
assert_eq "valid rh_imapd" "rh_imapd" "$(sanitize_mod "rh_imapd")"
assert_eq "valid vsftpd2" "vsftpd2" "$(sanitize_mod "vsftpd2")"

assert_rc "valid mod returns 0" 0 sanitize_mod "sshd"

# invalid module names
assert_eq "invalid mod semicolon" "" "$(sanitize_mod "sshd;evil")"
assert_eq "invalid mod space" "" "$(sanitize_mod "sshd evil")"
assert_eq "invalid mod slash" "" "$(sanitize_mod "../etc/passwd")"
assert_eq "invalid mod dollar" "" "$(sanitize_mod 'sshd$x')"
assert_eq "invalid mod empty" "" "$(sanitize_mod "")"

assert_rc "invalid mod returns 1" 1 sanitize_mod "sshd;evil"

echo ""
summary
