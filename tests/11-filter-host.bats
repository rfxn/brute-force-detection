#!/usr/bin/env bats
#
# Test suite for filter_host()
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

setup() {
	bfd_common_setup
	# create ignore infrastructure
	IGNORE_LIST="$TEST_TMPDIR/ignore.hosts"
	IGNORE_HOST_FILES="$TEST_TMPDIR/exclude.files"
	LO_HOSTS="$TEST_TMPDIR/ignore.hosts.local"
	touch "$IGNORE_LIST" "$IGNORE_HOST_FILES" "$LO_HOSTS"
}

teardown() {
	bfd_teardown
}

# --- basic pass-through ---

@test "filter_host: returns 0 for host not in any ignore list" {
	run filter_host "192.0.2.1" "$IGNORE_HOST_FILES" "$LO_HOSTS"
	assert_success
}

@test "filter_host: returns 0 when ignore files do not exist" {
	run filter_host "192.0.2.1" "$TEST_TMPDIR/nonexistent" "$TEST_TMPDIR/also_nonexistent"
	assert_success
}

# --- ignore list matching ---

@test "filter_host: returns 1 for host in ignore list" {
	echo "192.0.2.1" > "$IGNORE_LIST"
	echo "$IGNORE_LIST" > "$IGNORE_HOST_FILES"
	run filter_host "192.0.2.1" "$IGNORE_HOST_FILES" "$LO_HOSTS"
	[ "$status" -eq 1 ]
}

@test "filter_host: does not match partial IPs in ignore list" {
	echo "192.0.2.1" > "$IGNORE_LIST"
	echo "$IGNORE_LIST" > "$IGNORE_HOST_FILES"
	run filter_host "192.0.2.10" "$IGNORE_HOST_FILES" "$LO_HOSTS"
	assert_success
}

@test "filter_host: skips comment lines in ignore list" {
	echo "# 192.0.2.1" > "$IGNORE_LIST"
	echo "$IGNORE_LIST" > "$IGNORE_HOST_FILES"
	run filter_host "192.0.2.1" "$IGNORE_HOST_FILES" "$LO_HOSTS"
	assert_success
}

@test "filter_host: skips comment lines in exclude files" {
	echo "192.0.2.1" > "$IGNORE_LIST"
	echo "# $IGNORE_LIST" > "$IGNORE_HOST_FILES"
	run filter_host "192.0.2.1" "$IGNORE_HOST_FILES" "$LO_HOSTS"
	assert_success
}

@test "filter_host: multiple ignore files checked" {
	local list2="$TEST_TMPDIR/ignore2.hosts"
	echo "192.0.2.1" > "$list2"
	echo "$IGNORE_LIST" > "$IGNORE_HOST_FILES"
	echo "$list2" >> "$IGNORE_HOST_FILES"
	run filter_host "192.0.2.1" "$IGNORE_HOST_FILES" "$LO_HOSTS"
	[ "$status" -eq 1 ]
}

# --- local address matching ---

@test "filter_host: returns 2 for local address" {
	echo "203.0.113.1" > "$LO_HOSTS"
	run filter_host "203.0.113.1" "$IGNORE_HOST_FILES" "$LO_HOSTS"
	[ "$status" -eq 2 ]
}

@test "filter_host: non-local address passes" {
	echo "203.0.113.1" > "$LO_HOSTS"
	run filter_host "192.0.2.1" "$IGNORE_HOST_FILES" "$LO_HOSTS"
	assert_success
}

@test "filter_host: multiple local addresses checked" {
	printf "203.0.113.1\n192.0.2.1\n198.51.100.1\n" > "$LO_HOSTS"
	run filter_host "198.51.100.1" "$IGNORE_HOST_FILES" "$LO_HOSTS"
	[ "$status" -eq 2 ]
}

@test "filter_host: ignore list takes priority over local check" {
	echo "192.0.2.1" > "$IGNORE_LIST"
	echo "$IGNORE_LIST" > "$IGNORE_HOST_FILES"
	echo "192.0.2.1" > "$LO_HOSTS"
	# should return 1 (ignored) not 2 (local) since ignore is checked first
	run filter_host "192.0.2.1" "$IGNORE_HOST_FILES" "$LO_HOSTS"
	[ "$status" -eq 1 ]
}

@test "filter_host: empty lo_hosts file passes" {
	> "$LO_HOSTS"
	run filter_host "192.0.2.1" "$IGNORE_HOST_FILES" "$LO_HOSTS"
	assert_success
}

# --- local address population pipeline ---

@test "lo_hosts pipeline: captures both IPv4 and IPv6 from ip addr output" {
	# simulate ip addr list output
	local fake_ip_output
	fake_ip_output=$(printf '%s\n' \
		"1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536" \
		"    inet 127.0.0.1/8 scope host lo" \
		"    inet6 ::1/128 scope host" \
		"2: eth0: <BROADCAST,MULTICAST,UP>" \
		"    inet 203.0.113.100/24 brd 203.0.113.255 scope global eth0" \
		"    inet6 fe80::1/64 scope link")
	echo "$fake_ip_output" | grep -E 'inet6? ' | tr '/' ' ' | awk '{print$2}' > "$LO_HOSTS"
	run cat "$LO_HOSTS"
	assert_output --partial "127.0.0.1"
	assert_output --partial "::1"
	assert_output --partial "203.0.113.100"
	assert_output --partial "fe80::1"
}

@test "lo_hosts pipeline: IPv4 local address blocks detection via filter_host" {
	# populate LO_HOSTS as the pipeline would
	printf "127.0.0.1\n203.0.113.100\n::1\n" > "$LO_HOSTS"
	run filter_host "203.0.113.100" "$IGNORE_HOST_FILES" "$LO_HOSTS"
	[ "$status" -eq 2 ]
}
