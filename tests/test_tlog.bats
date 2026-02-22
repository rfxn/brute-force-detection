#!/usr/bin/env bats
#
# Test suite for tlog (track log)
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'

setup() {
	SCRIPT_DIR="$(cd "$(dirname "${BATS_TEST_FILENAME}")" && pwd)"
	TLOG="$SCRIPT_DIR/../files/tlog"
	TEST_TMPDIR=$(mktemp -d)
	export BASERUN="$TEST_TMPDIR/tracking"
	mkdir -p "$BASERUN"
}

teardown() {
	rm -rf "$TEST_TMPDIR"
}

@test "tlog: first run initializes tracking file and outputs nothing" {
	echo "line one" > "$TEST_TMPDIR/test.log"
	run "$TLOG" "$TEST_TMPDIR/test.log" "test1"
	assert_success
	assert_output ""
	local stored fsize
	stored=$(cat "$BASERUN/test1")
	fsize=$(stat -c %s "$TEST_TMPDIR/test.log" 2>/dev/null || wc -c < "$TEST_TMPDIR/test.log")
	[ "$stored" = "$fsize" ]
}

@test "tlog: log growth outputs only new content" {
	echo "line one" > "$TEST_TMPDIR/test.log"
	"$TLOG" "$TEST_TMPDIR/test.log" "test2" >/dev/null
	echo "line two" >> "$TEST_TMPDIR/test.log"
	run "$TLOG" "$TEST_TMPDIR/test.log" "test2"
	assert_success
	assert_output "line two"
}

@test "tlog: no change produces no output" {
	echo "line one" > "$TEST_TMPDIR/test.log"
	"$TLOG" "$TEST_TMPDIR/test.log" "test3" >/dev/null
	run "$TLOG" "$TEST_TMPDIR/test.log" "test3"
	assert_success
	assert_output ""
}

@test "tlog: multiple new lines all output" {
	echo "line one" > "$TEST_TMPDIR/test.log"
	"$TLOG" "$TEST_TMPDIR/test.log" "test4" >/dev/null
	echo "line three" >> "$TEST_TMPDIR/test.log"
	echo "line four" >> "$TEST_TMPDIR/test.log"
	run "$TLOG" "$TEST_TMPDIR/test.log" "test4"
	assert_success
	assert_output --partial "line three"
	assert_output --partial "line four"
}

@test "tlog: log rotation outputs new file content" {
	# build up a large tracked size
	local i
	for i in $(seq 1 20); do echo "padding line $i" >> "$TEST_TMPDIR/test.log"; done
	"$TLOG" "$TEST_TMPDIR/test.log" "test5" >/dev/null
	for i in $(seq 21 40); do echo "padding line $i" >> "$TEST_TMPDIR/test.log"; done
	"$TLOG" "$TEST_TMPDIR/test.log" "test5" >/dev/null
	# simulate rotation: rename to .1, write small new file
	cp "$TEST_TMPDIR/test.log" "$TEST_TMPDIR/test.log.1"
	echo "new after rotation" > "$TEST_TMPDIR/test.log"
	run "$TLOG" "$TEST_TMPDIR/test.log" "test5"
	assert_success
	assert_output --partial "new after rotation"
}

@test "tlog: missing file exits with error" {
	run "$TLOG" "$TEST_TMPDIR/no_such_file" "test_missing"
	assert_failure
}

@test "tlog: missing arguments shows usage" {
	run "$TLOG"
	assert_failure
	assert_output --partial "usage"
}
