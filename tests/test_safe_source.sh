#!/bin/bash
#
# Test suite for safe_source()
#
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=tests/test_helpers.sh
. "$SCRIPT_DIR/test_helpers.sh"
# shellcheck source=files/bfd.lib.sh
. "$SCRIPT_DIR/../files/bfd.lib.sh"

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# eout dependencies
BFD_LOG_PATH="$TMPDIR/bfd_log"
OUTPUT_SYSLOG="0"
OUTPUT_SYSLOG_FILE="$TMPDIR/syslog"
touch "$BFD_LOG_PATH" "$OUTPUT_SYSLOG_FILE"

echo "=== safe_source tests ==="

# Test 1: source a valid root-owned, non-world-writable file
echo 'SAFE_SOURCE_TEST_VAR="loaded"' > "$TMPDIR/good.conf"
chmod 640 "$TMPDIR/good.conf"
SAFE_SOURCE_TEST_VAR=""
assert_rc "valid file returns 0" 0 safe_source "$TMPDIR/good.conf" "test:good"
safe_source "$TMPDIR/good.conf" "test:good" >/dev/null 2>&1
assert_eq "valid file sets variable" "loaded" "$SAFE_SOURCE_TEST_VAR"

# Test 2: nonexistent file fails
assert_rc "missing file returns 1" 1 safe_source "$TMPDIR/no_such_file" "test:missing"

# Test 3: world-writable file fails
echo 'SAFE_SOURCE_TEST_VAR="bad"' > "$TMPDIR/world_writable.conf"
chmod 666 "$TMPDIR/world_writable.conf"
SAFE_SOURCE_TEST_VAR=""
assert_rc "world-writable returns 1" 1 safe_source "$TMPDIR/world_writable.conf" "test:writable"
assert_eq "world-writable: variable not set" "" "$SAFE_SOURCE_TEST_VAR"

# Test 4: file with perms 644 (world-readable but not writable) succeeds
echo 'SAFE_SOURCE_TEST_VAR="ok644"' > "$TMPDIR/readable.conf"
chmod 644 "$TMPDIR/readable.conf"
SAFE_SOURCE_TEST_VAR=""
assert_rc "644 perms returns 0" 0 safe_source "$TMPDIR/readable.conf" "test:644"
safe_source "$TMPDIR/readable.conf" "test:644" >/dev/null 2>&1
assert_eq "644 file sets variable" "ok644" "$SAFE_SOURCE_TEST_VAR"

# Test 5: file with perms 777 (world-writable) fails
echo 'SAFE_SOURCE_TEST_VAR="bad777"' > "$TMPDIR/all_perms.conf"
chmod 777 "$TMPDIR/all_perms.conf"
SAFE_SOURCE_TEST_VAR=""
assert_rc "777 perms returns 1" 1 safe_source "$TMPDIR/all_perms.conf" "test:777"
assert_eq "777: variable not set" "" "$SAFE_SOURCE_TEST_VAR"

# Test 6: file with perms 643 (world-writable+exec) fails
echo 'SAFE_SOURCE_TEST_VAR="bad643"' > "$TMPDIR/writable643.conf"
chmod 643 "$TMPDIR/writable643.conf"
SAFE_SOURCE_TEST_VAR=""
assert_rc "643 perms returns 1" 1 safe_source "$TMPDIR/writable643.conf" "test:643"

# Test 7: file with perms 641 (world-exec, not writable) succeeds
echo 'SAFE_SOURCE_TEST_VAR="ok641"' > "$TMPDIR/exec641.conf"
chmod 641 "$TMPDIR/exec641.conf"
SAFE_SOURCE_TEST_VAR=""
assert_rc "641 perms returns 0" 0 safe_source "$TMPDIR/exec641.conf" "test:641"

echo ""
summary
