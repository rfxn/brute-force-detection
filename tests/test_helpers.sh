#!/bin/bash
#
# Shared test helper functions for BFD test suite
#
# Source this file from test scripts:
#   SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
#   . "$SCRIPT_DIR/test_helpers.sh"
#

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

assert_match() {
	local desc="$1" pattern="$2" actual="$3"
	if [[ "$actual" =~ $pattern ]]; then
		PASS=$((PASS + 1))
	else
		FAIL=$((FAIL + 1))
		echo "FAIL: $desc (pattern '$pattern' did not match '$actual')"
	fi
}

summary() {
	echo "---"
	echo "$0: Passed=$PASS Failed=$FAIL"
	if [ "$FAIL" -gt 0 ]; then
		exit 1
	fi
}
