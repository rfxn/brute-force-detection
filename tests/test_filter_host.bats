#!/usr/bin/env bats
#
# Test suite for filter_host()
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

setup() {
	TEST_TMPDIR=$(mktemp -d)
	# eout dependencies
	BFD_LOG_PATH="$TEST_TMPDIR/bfd.log"
	touch "$BFD_LOG_PATH"
	OUTPUT_SYSLOG="0"
	OUTPUT_SYSLOG_FILE="/dev/null"
	# create ignore infrastructure
	IGNORE_LIST="$TEST_TMPDIR/ignore.hosts"
	IGNORE_HOST_FILES="$TEST_TMPDIR/exclude.files"
	LO_HOSTS="$TEST_TMPDIR/ignore.hosts.local"
	touch "$IGNORE_LIST" "$IGNORE_HOST_FILES" "$LO_HOSTS"
}

teardown() {
	rm -rf "$TEST_TMPDIR"
}

# --- basic pass-through ---

@test "filter_host: returns 0 for host not in any ignore list" {
	run filter_host "10.0.0.1" "$IGNORE_HOST_FILES" "$LO_HOSTS"
	assert_success
}

@test "filter_host: returns 0 when ignore files do not exist" {
	run filter_host "10.0.0.1" "$TEST_TMPDIR/nonexistent" "$TEST_TMPDIR/also_nonexistent"
	assert_success
}

# --- ignore list matching ---

@test "filter_host: returns 1 for host in ignore list" {
	echo "10.0.0.1" > "$IGNORE_LIST"
	echo "$IGNORE_LIST" > "$IGNORE_HOST_FILES"
	run filter_host "10.0.0.1" "$IGNORE_HOST_FILES" "$LO_HOSTS"
	[ "$status" -eq 1 ]
}

@test "filter_host: does not match partial IPs in ignore list" {
	echo "10.0.0.1" > "$IGNORE_LIST"
	echo "$IGNORE_LIST" > "$IGNORE_HOST_FILES"
	run filter_host "10.0.0.10" "$IGNORE_HOST_FILES" "$LO_HOSTS"
	assert_success
}

@test "filter_host: skips comment lines in ignore list" {
	echo "# 10.0.0.1" > "$IGNORE_LIST"
	echo "$IGNORE_LIST" > "$IGNORE_HOST_FILES"
	run filter_host "10.0.0.1" "$IGNORE_HOST_FILES" "$LO_HOSTS"
	assert_success
}

@test "filter_host: skips comment lines in exclude files" {
	echo "10.0.0.1" > "$IGNORE_LIST"
	echo "# $IGNORE_LIST" > "$IGNORE_HOST_FILES"
	run filter_host "10.0.0.1" "$IGNORE_HOST_FILES" "$LO_HOSTS"
	assert_success
}

@test "filter_host: multiple ignore files checked" {
	local list2="$TEST_TMPDIR/ignore2.hosts"
	echo "10.0.0.1" > "$list2"
	echo "$IGNORE_LIST" > "$IGNORE_HOST_FILES"
	echo "$list2" >> "$IGNORE_HOST_FILES"
	run filter_host "10.0.0.1" "$IGNORE_HOST_FILES" "$LO_HOSTS"
	[ "$status" -eq 1 ]
}

# --- local address matching ---

@test "filter_host: returns 2 for local address" {
	echo "192.168.1.1" > "$LO_HOSTS"
	run filter_host "192.168.1.1" "$IGNORE_HOST_FILES" "$LO_HOSTS"
	[ "$status" -eq 2 ]
}

@test "filter_host: non-local address passes" {
	echo "192.168.1.1" > "$LO_HOSTS"
	run filter_host "10.0.0.1" "$IGNORE_HOST_FILES" "$LO_HOSTS"
	assert_success
}

@test "filter_host: multiple local addresses checked" {
	printf "192.168.1.1\n10.0.0.1\n172.16.0.1\n" > "$LO_HOSTS"
	run filter_host "172.16.0.1" "$IGNORE_HOST_FILES" "$LO_HOSTS"
	[ "$status" -eq 2 ]
}

@test "filter_host: ignore list takes priority over local check" {
	echo "10.0.0.1" > "$IGNORE_LIST"
	echo "$IGNORE_LIST" > "$IGNORE_HOST_FILES"
	echo "10.0.0.1" > "$LO_HOSTS"
	# should return 1 (ignored) not 2 (local) since ignore is checked first
	run filter_host "10.0.0.1" "$IGNORE_HOST_FILES" "$LO_HOSTS"
	[ "$status" -eq 1 ]
}

@test "filter_host: empty lo_hosts file passes" {
	> "$LO_HOSTS"
	run filter_host "10.0.0.1" "$IGNORE_HOST_FILES" "$LO_HOSTS"
	assert_success
}
