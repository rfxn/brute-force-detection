#!/bin/bash
#
# Test suite for format_table()
#
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=tests/test_helpers.sh
. "$SCRIPT_DIR/test_helpers.sh"
# shellcheck source=files/bfd.lib.sh
. "$SCRIPT_DIR/../files/bfd.lib.sh"

echo "=== format_table tests ==="

# Test 1: pipe-delimited input produces output without pipe characters
input="col1|col2|col3"
out=$(echo "$input" | format_table)
# output should not contain pipe delimiters
case "$out" in
	*"|"*)
		FAIL=$((FAIL + 1))
		echo "FAIL: output still contains pipe delimiter"
		;;
	*)
		PASS=$((PASS + 1))
		;;
esac

# Test 2: output preserves all field values
assert_match "output has col1" "col1" "$out"
assert_match "output has col2" "col2" "$out"
assert_match "output has col3" "col3" "$out"

# Test 3: multi-line input
input=$(printf "a|b|c\nd|e|f\n")
out=$(echo "$input" | format_table)
line_count=$(echo "$out" | wc -l)
assert_eq "multi-line: 2 lines" "2" "$line_count"

# Test 4: single field (no pipes)
out=$(echo "nopipes" | format_table)
assert_eq "single field: unchanged" "nopipes" "$out"

# Test 5: empty input
out=$(echo "" | format_table)
assert_eq "empty input: empty output" "" "$out"

# Test 6: header + data row alignment (both have same field count)
input=$(printf "NAME|COUNT|STATUS\nalpha|42|active\n")
out=$(echo "$input" | format_table)
assert_match "header field NAME present" "NAME" "$out"
assert_match "data field alpha present" "alpha" "$out"
assert_match "data field 42 present" "42" "$out"

echo ""
summary
