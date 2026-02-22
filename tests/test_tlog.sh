#!/bin/bash
#
# Test suite for tlog (track log)
#
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=tests/test_helpers.sh
. "$SCRIPT_DIR/test_helpers.sh"

TLOG="$SCRIPT_DIR/../files/tlog"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# override BASERUN via environment so tlog uses our temp dir
export BASERUN="$TMPDIR/tracking"
mkdir -p "$BASERUN"

echo "=== tlog tests ==="

# Test 1: first run — initializes tracking file, outputs nothing
echo "line one" > "$TMPDIR/test.log"
out=$("$TLOG" "$TMPDIR/test.log" "test1")
assert_eq "first run: no output" "" "$out"
stored=$(cat "$BASERUN/test1")
fsize=$(stat -c %s "$TMPDIR/test.log" 2>/dev/null || wc -c < "$TMPDIR/test.log")
assert_eq "first run: tracking file has size" "$fsize" "$stored"

# Test 2: log grows — outputs only the new content
echo "line two" >> "$TMPDIR/test.log"
out=$("$TLOG" "$TMPDIR/test.log" "test1")
assert_eq "growth: outputs new line" "line two" "$out"

# Test 3: no change — no output
out=$("$TLOG" "$TMPDIR/test.log" "test1")
assert_eq "no change: no output" "" "$out"

# Test 4: more growth — outputs only newest
echo "line three" >> "$TMPDIR/test.log"
echo "line four" >> "$TMPDIR/test.log"
out=$("$TLOG" "$TMPDIR/test.log" "test1")
# should contain both new lines
case "$out" in
	*"line three"*"line four"*)
		PASS=$((PASS + 1))
		;;
	*)
		FAIL=$((FAIL + 1))
		echo "FAIL: multi-growth: expected 'line three' and 'line four' in output, got '$out'"
		;;
esac

# Test 5: log rotation — current file is smaller than tracked size
# Simulate rotation: rename current to .1, create new smaller file
cp "$TMPDIR/test.log" "$TMPDIR/test.log.1"
echo "new after rotation" > "$TMPDIR/test.log"
out=$("$TLOG" "$TMPDIR/test.log" "test1")
# should contain content from the new file
case "$out" in
	*"new after rotation"*)
		PASS=$((PASS + 1))
		;;
	*)
		FAIL=$((FAIL + 1))
		echo "FAIL: rotation: expected 'new after rotation' in output, got '$out'"
		;;
esac
rm -f "$TMPDIR/test.log.1"

# Test 6: missing file — exits with error
out=$("$TLOG" "$TMPDIR/no_such_file" "test_missing" 2>&1)
rc=$?
assert_eq "missing file: non-zero exit" "1" "$rc"

# Test 7: missing arguments — shows usage
out=$("$TLOG" 2>&1)
rc=$?
assert_eq "no args: non-zero exit" "1" "$rc"
case "$out" in
	*"usage"*)
		PASS=$((PASS + 1))
		;;
	*)
		FAIL=$((FAIL + 1))
		echo "FAIL: no args: expected 'usage' in output, got '$out'"
		;;
esac

echo ""
summary
