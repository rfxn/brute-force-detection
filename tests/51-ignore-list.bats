#!/usr/bin/env bats
#
# Test suite for ignore list CRUD functions:
#   ignore_add, ignore_remove, ignore_list, ignore_check
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

setup() {
	bfd_standard_setup
	# Create default ignore.hosts with shipped entries
	mkdir -p "$INSTALL_PATH"
	printf '%s\n' "127.0.0.1" "::1" > "$INSTALL_PATH/ignore.hosts"
}

teardown() {
	bfd_teardown
}

# --- ignore_add tests ---

@test "ignore_add: adds IPv4 address" {
	run ignore_add "$INSTALL_PATH" "192.0.2.1"
	assert_success
	assert_output "192.0.2.1: added to ignore list"
	grep -q "192.0.2.1" "$INSTALL_PATH/ignore.hosts"
}

@test "ignore_add: adds IPv6 address" {
	run ignore_add "$INSTALL_PATH" "2001:db8::1"
	assert_success
	assert_output --partial "added to ignore list"
	grep -q "2001:db8::1" "$INSTALL_PATH/ignore.hosts"
}

@test "ignore_add: adds CIDR with normalization" {
	run ignore_add "$INSTALL_PATH" "10.0.0.5/8"
	assert_success
	grep -q "10.0.0.0/8" "$INSTALL_PATH/ignore.hosts"
}

@test "ignore_add: adds entry with comment" {
	run ignore_add "$INSTALL_PATH" "192.0.2.100" "test server"
	assert_success
	grep -q "192.0.2.100.*# test server" "$INSTALL_PATH/ignore.hosts"
}

@test "ignore_add: rejects duplicate" {
	run ignore_add "$INSTALL_PATH" "127.0.0.1"
	[ "$status" -eq 2 ]
	assert_output --partial "already in ignore list"
}

@test "ignore_add: rejects invalid input" {
	run ignore_add "$INSTALL_PATH" "not-an-ip"
	assert_failure
	assert_output --partial "invalid IP or CIDR"
}

@test "ignore_add: rejects IPv6 CIDR" {
	run ignore_add "$INSTALL_PATH" "2001:db8::/32"
	# validate_cidr only accepts IPv4 CIDR; ip_to_subnet for IPv6 needs
	# group-aligned masks, but validate_cidr rejects the input first
	assert_failure
}

@test "ignore_add: creates file if missing" {
	rm -f "$INSTALL_PATH/ignore.hosts"
	run ignore_add "$INSTALL_PATH" "192.0.2.50"
	assert_success
	[ -f "$INSTALL_PATH/ignore.hosts" ]
}

# --- ignore_remove tests ---

@test "ignore_remove: removes existing entry" {
	run ignore_remove "$INSTALL_PATH" "127.0.0.1"
	assert_success
	assert_output "127.0.0.1: removed from ignore list"
	! grep -q "^127.0.0.1$" "$INSTALL_PATH/ignore.hosts"
}

@test "ignore_remove: reports not found" {
	run ignore_remove "$INSTALL_PATH" "8.8.8.8"
	assert_failure
	assert_output --partial "not in ignore list"
}

@test "ignore_remove: preserves other entries" {
	ignore_add "$INSTALL_PATH" "192.0.2.1"
	run ignore_remove "$INSTALL_PATH" "127.0.0.1"
	assert_success
	grep -q "192.0.2.1" "$INSTALL_PATH/ignore.hosts"
	grep -q "::1" "$INSTALL_PATH/ignore.hosts"
}

# --- ignore_list tests ---

@test "ignore_list: shows entries skipping comments" {
	printf '# this is a comment\n' >> "$INSTALL_PATH/ignore.hosts"
	run ignore_list "$INSTALL_PATH"
	assert_success
	assert_output --partial "127.0.0.1"
	assert_output --partial "::1"
	refute_output --partial "# this is a comment"
}

@test "ignore_list: reports empty file" {
	printf '' > "$INSTALL_PATH/ignore.hosts"
	run ignore_list "$INSTALL_PATH"
	assert_output --partial "no entries"
}

# --- ignore_check tests ---

@test "ignore_check: finds exact IP match" {
	run ignore_check "$INSTALL_PATH" "127.0.0.1"
	assert_success
	assert_output "127.0.0.1: ignored"
}

@test "ignore_check: finds CIDR containment" {
	ignore_add "$INSTALL_PATH" "10.0.0.0/8"
	run ignore_check "$INSTALL_PATH" "10.0.0.50"
	assert_success
	assert_output --partial "matched 10.0.0.0/8"
}

@test "ignore_check: reports not ignored" {
	run ignore_check "$INSTALL_PATH" "8.8.8.8"
	assert_failure
	assert_output ""
}

@test "ignore_check: validates input IP" {
	run ignore_check "$INSTALL_PATH" "not-valid"
	assert_failure
	assert_output --partial "invalid IP"
}
