#!/bin/bash
#
# Test suite for validate_config()
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

echo "=== validate_config tests ==="

# helper: set all config to valid defaults, then override one field
run_validate() {
	(
		TRIG="15"
		EMAIL_ALERTS="0"
		LOCK_FILE_TIMEOUT="300"
		BAN_COMMAND_TEMPLATE="/etc/apf/apf -d test"
		INSTALL_PATH="$TMPDIR"
		# apply overrides
		eval "$1"
		validate_config
	) >/dev/null 2>&1
	echo $?
}

# valid config
assert_eq "valid config passes" "0" "$(run_validate "")"

# TRIG validation
assert_eq "TRIG=abc rejects" "1" "$(run_validate 'TRIG="abc"')"
assert_eq "TRIG=0 rejects" "1" "$(run_validate 'TRIG="0"')"
assert_eq "TRIG= rejects" "1" "$(run_validate 'TRIG=""')"
assert_eq "TRIG=15 passes" "0" "$(run_validate 'TRIG="15"')"
assert_eq "TRIG=1 passes" "0" "$(run_validate 'TRIG="1"')"

# EMAIL_ALERTS validation
assert_eq "EMAIL_ALERTS=2 rejects" "1" "$(run_validate 'EMAIL_ALERTS="2"')"
assert_eq "EMAIL_ALERTS=abc rejects" "1" "$(run_validate 'EMAIL_ALERTS="abc"')"
assert_eq "EMAIL_ALERTS=0 passes" "0" "$(run_validate 'EMAIL_ALERTS="0"')"
assert_eq "EMAIL_ALERTS=1 passes" "0" "$(run_validate 'EMAIL_ALERTS="1"')"

# LOCK_FILE_TIMEOUT validation
assert_eq "TIMEOUT=0 rejects" "1" "$(run_validate 'LOCK_FILE_TIMEOUT="0"')"
assert_eq "TIMEOUT=abc rejects" "1" "$(run_validate 'LOCK_FILE_TIMEOUT="abc"')"
assert_eq "TIMEOUT= rejects" "1" "$(run_validate 'LOCK_FILE_TIMEOUT=""')"
assert_eq "TIMEOUT=300 passes" "0" "$(run_validate 'LOCK_FILE_TIMEOUT="300"')"

# BAN_COMMAND validation
assert_eq "empty BAN_COMMAND rejects" "1" "$(run_validate 'BAN_COMMAND_TEMPLATE=""')"

# INSTALL_PATH validation
assert_eq "bad INSTALL_PATH rejects" "1" "$(run_validate 'INSTALL_PATH="/nonexistent/path"')"

echo ""
summary
