#!/usr/bin/env bats
#
# Test suite for tlog (track log) — subprocess and tlog_read() library function
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

setup() {
	bfd_common_setup
	TLOG="$PROJECT_ROOT/files/tlog"
	export BASERUN="$TEST_TMPDIR/tracking"
	mkdir -p "$BASERUN"
}

teardown() {
	bfd_teardown
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

# --- tlog_read() library function tests ---

@test "tlog_read: first run initializes tracking and outputs nothing" {
	echo "line one" > "$TEST_TMPDIR/test.log"
	run tlog_read "$TEST_TMPDIR/test.log" "lib_test1" "$BASERUN"
	assert_success
	assert_output ""
	local stored fsize
	stored=$(cat "$BASERUN/lib_test1")
	fsize=$(stat -c %s "$TEST_TMPDIR/test.log" 2>/dev/null || wc -c < "$TEST_TMPDIR/test.log")
	[ "$stored" = "$fsize" ]
}

@test "tlog_read: log growth outputs only new content" {
	echo "line one" > "$TEST_TMPDIR/test.log"
	tlog_read "$TEST_TMPDIR/test.log" "lib_test2" "$BASERUN" >/dev/null
	echo "line two" >> "$TEST_TMPDIR/test.log"
	run tlog_read "$TEST_TMPDIR/test.log" "lib_test2" "$BASERUN"
	assert_success
	assert_output "line two"
}

@test "tlog_read: no change produces no output" {
	echo "line one" > "$TEST_TMPDIR/test.log"
	tlog_read "$TEST_TMPDIR/test.log" "lib_test3" "$BASERUN" >/dev/null
	run tlog_read "$TEST_TMPDIR/test.log" "lib_test3" "$BASERUN"
	assert_success
	assert_output ""
}

@test "tlog_read: multiple new lines all output" {
	echo "line one" > "$TEST_TMPDIR/test.log"
	tlog_read "$TEST_TMPDIR/test.log" "lib_test4" "$BASERUN" >/dev/null
	echo "line three" >> "$TEST_TMPDIR/test.log"
	echo "line four" >> "$TEST_TMPDIR/test.log"
	run tlog_read "$TEST_TMPDIR/test.log" "lib_test4" "$BASERUN"
	assert_success
	assert_output --partial "line three"
	assert_output --partial "line four"
}

@test "tlog_read: log rotation outputs new file content" {
	local i
	for i in $(seq 1 20); do echo "padding line $i" >> "$TEST_TMPDIR/test.log"; done
	tlog_read "$TEST_TMPDIR/test.log" "lib_test5" "$BASERUN" >/dev/null
	for i in $(seq 21 40); do echo "padding line $i" >> "$TEST_TMPDIR/test.log"; done
	tlog_read "$TEST_TMPDIR/test.log" "lib_test5" "$BASERUN" >/dev/null
	cp "$TEST_TMPDIR/test.log" "$TEST_TMPDIR/test.log.1"
	echo "new after rotation" > "$TEST_TMPDIR/test.log"
	run tlog_read "$TEST_TMPDIR/test.log" "lib_test5" "$BASERUN"
	assert_success
	assert_output --partial "new after rotation"
}

@test "tlog_read: missing file returns error" {
	run tlog_read "$TEST_TMPDIR/no_such_file" "lib_test_missing" "$BASERUN"
	assert_failure
}

@test "tlog_read: missing baserun returns error" {
	echo "test" > "$TEST_TMPDIR/test.log"
	run tlog_read "$TEST_TMPDIR/test.log" "lib_test_nobase" "$TEST_TMPDIR/nonexistent"
	assert_failure
}

# --- _rule_tlog() wrapper tests ---

@test "_rule_tlog: returns delta on growth" {
	TLOG_BASERUN="$BASERUN"
	_TLOG_PASSTHROUGH=""
	echo "line one" > "$TEST_TMPDIR/test.log"
	# first call — init tracking, outputs nothing
	run _rule_tlog "$TEST_TMPDIR/test.log" "rt_test1"
	assert_success
	assert_output ""
	# append and call again — should output new content
	echo "line two" >> "$TEST_TMPDIR/test.log"
	run _rule_tlog "$TEST_TMPDIR/test.log" "rt_test1"
	assert_success
	assert_output "line two"
}

@test "_rule_tlog: returns nothing on first run" {
	TLOG_BASERUN="$BASERUN"
	_TLOG_PASSTHROUGH=""
	echo "some content" > "$TEST_TMPDIR/test.log"
	run _rule_tlog "$TEST_TMPDIR/test.log" "rt_test2"
	assert_success
	assert_output ""
}

@test "_rule_tlog: PASSTHROUGH=1 outputs entire file" {
	_TLOG_PASSTHROUGH="1"
	echo "full file content" > "$TEST_TMPDIR/test.log"
	run _rule_tlog "$TEST_TMPDIR/test.log" "rt_test3"
	assert_success
	assert_output "full file content"
	_TLOG_PASSTHROUGH=""
}

@test "_rule_tlog: PASSTHROUGH=/path outputs specific file" {
	local alt_file="$TEST_TMPDIR/alt.log"
	echo "alternate content" > "$alt_file"
	_TLOG_PASSTHROUGH="$alt_file"
	run _rule_tlog "$TEST_TMPDIR/test.log" "rt_test4"
	assert_success
	assert_output "alternate content"
	_TLOG_PASSTHROUGH=""
}

@test "_rule_tlog: handles missing log file" {
	TLOG_BASERUN="$BASERUN"
	_TLOG_PASSTHROUGH=""
	run _rule_tlog "$TEST_TMPDIR/nonexistent.log" "rt_test5"
	assert_failure
	assert_output --partial "not a valid file"
}

@test "_rule_tlog: handles missing baserun" {
	TLOG_BASERUN="$TEST_TMPDIR/nonexistent_dir"
	_TLOG_PASSTHROUGH=""
	echo "test" > "$TEST_TMPDIR/test.log"
	run _rule_tlog "$TEST_TMPDIR/test.log" "rt_test6"
	assert_failure
	assert_output --partial "not a valid operating path"
}
