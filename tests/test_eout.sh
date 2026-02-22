#!/bin/bash
#
# Test suite for eout()
#
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=tests/test_helpers.sh
. "$SCRIPT_DIR/test_helpers.sh"
# shellcheck source=files/bfd.lib.sh
. "$SCRIPT_DIR/../files/bfd.lib.sh"

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

BFD_LOG_PATH="$TMPDIR/bfd_log"
OUTPUT_SYSLOG="0"
OUTPUT_SYSLOG_FILE="$TMPDIR/syslog"
touch "$BFD_LOG_PATH" "$OUTPUT_SYSLOG_FILE"

echo "=== eout tests ==="

# Test 1: basic output to stdout
out=$(eout "test message")
assert_match "stdout contains message" "test message" "$out"

# Test 2: stdout output includes timestamp format (Mon DD HH:MM:SS)
assert_match "stdout has timestamp" "^[A-Z][a-z]{2} [ 0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}" "$out"

# Test 3: stdout output includes hostname and pid
assert_match "stdout has bfd pid" "bfd\([0-9]+\):" "$out"

# Test 4: no log write without 'le' flag
: > "$BFD_LOG_PATH"
eout "no-log message" > /dev/null
lines=$(wc -l < "$BFD_LOG_PATH")
assert_eq "no le flag: nothing in log" "0" "$lines"

# Test 5: 'le' flag writes to BFD_LOG_PATH
: > "$BFD_LOG_PATH"
eout "logged message" "le" > /dev/null
lines=$(wc -l < "$BFD_LOG_PATH")
assert_eq "le flag: line written to log" "1" "$lines"

# Test 6: log file contains the message
content=$(cat "$BFD_LOG_PATH")
assert_match "log contains message" "logged message" "$content"

# Test 7: syslog output disabled
: > "$OUTPUT_SYSLOG_FILE"
OUTPUT_SYSLOG="0"
eout "no syslog" "le" > /dev/null
lines=$(wc -l < "$OUTPUT_SYSLOG_FILE")
assert_eq "syslog off: nothing in syslog" "0" "$lines"

# Test 8: syslog output enabled
: > "$OUTPUT_SYSLOG_FILE"
OUTPUT_SYSLOG="1"
eout "syslog message" "le" > /dev/null
lines=$(wc -l < "$OUTPUT_SYSLOG_FILE")
assert_eq "syslog on: line written" "1" "$lines"

# Test 9: syslog file contains the message
content=$(cat "$OUTPUT_SYSLOG_FILE")
assert_match "syslog contains message" "syslog message" "$content"
OUTPUT_SYSLOG="0"

# Test 10: empty arg produces no output
out=$(eout "")
assert_eq "empty arg: no output" "" "$out"

# Test 11: empty arg does not write to log
: > "$BFD_LOG_PATH"
eout "" "le" > /dev/null
lines=$(wc -l < "$BFD_LOG_PATH")
assert_eq "empty arg: no log write" "0" "$lines"

echo ""
summary
