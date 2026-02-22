#!/bin/bash
#
# BFD test suite runner — discovers and runs all test_*.sh files
#
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_FILES=0
FAILED_FILES=""

for test_file in "$SCRIPT_DIR"/test_*.sh; do
	[ -f "$test_file" ] || continue
	name=$(basename "$test_file")
	# skip the helpers file
	if [ "$name" = "test_helpers.sh" ]; then
		continue
	fi
	TOTAL_FILES=$((TOTAL_FILES + 1))
	echo "=== Running $name ==="
	output=$(bash "$test_file" 2>&1)
	rc=$?
	# extract pass/fail counts from summary line
	pass=$(echo "$output" | grep -E "^$test_file: Passed=" | sed 's/.*Passed=\([0-9]*\).*/\1/')
	fail=$(echo "$output" | grep -E "^$test_file: Passed=" | sed 's/.*Failed=\([0-9]*\).*/\1/')
	if [ -z "$pass" ]; then
		# try without full path (some tests use $0 which is the basename)
		pass=$(echo "$output" | grep -E "Passed=" | tail -1 | sed 's/.*Passed=\([0-9]*\).*/\1/')
		fail=$(echo "$output" | grep -E "Failed=" | tail -1 | sed 's/.*Failed=\([0-9]*\).*/\1/')
	fi
	if [ -n "$pass" ]; then
		TOTAL_PASS=$((TOTAL_PASS + pass))
	fi
	if [ -n "$fail" ]; then
		TOTAL_FAIL=$((TOTAL_FAIL + fail))
	fi
	if [ "$rc" -ne 0 ]; then
		FAILED_FILES="$FAILED_FILES $name"
		# show failure details
		echo "$output" | grep "^FAIL:"
	fi
	echo ""
done

echo "==============================="
echo "Total: $TOTAL_FILES files, $TOTAL_PASS passed, $TOTAL_FAIL failed"
if [ -n "$FAILED_FILES" ]; then
	echo "Failed files:$FAILED_FILES"
	exit 1
fi
echo "All tests passed."
exit 0
