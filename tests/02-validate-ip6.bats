#!/usr/bin/env bats
#
# Tests for validate_ip6() and validate_ip_any()
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

# --- validate_ip6: valid addresses ---

@test "validate_ip6: full address" {
	run validate_ip6 "2001:0db8:0000:0000:0000:0000:0000:0001"
	assert_success
	assert_output "2001:0db8:0000:0000:0000:0000:0000:0001"
}

@test "validate_ip6: compressed address" {
	run validate_ip6 "2001:db8::1"
	assert_success
	assert_output "2001:db8::1"
}

@test "validate_ip6: loopback (::1)" {
	run validate_ip6 "::1"
	assert_success
	assert_output "::1"
}

@test "validate_ip6: all-zeros (::)" {
	run validate_ip6 "::"
	assert_success
	assert_output "::"
}

@test "validate_ip6: all-zeros expanded" {
	run validate_ip6 "0:0:0:0:0:0:0:0"
	assert_success
	assert_output "0:0:0:0:0:0:0:0"
}

@test "validate_ip6: max address (all ffff)" {
	run validate_ip6 "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
	assert_success
	assert_output "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
}

@test "validate_ip6: link-local" {
	run validate_ip6 "fe80::1"
	assert_success
	assert_output "fe80::1"
}

@test "validate_ip6: zone ID stripped" {
	run validate_ip6 "fe80::1%eth0"
	assert_success
	assert_output "fe80::1"
}

@test "validate_ip6: mixed case" {
	run validate_ip6 "2001:DB8::1"
	assert_success
	assert_output "2001:DB8::1"
}

@test "validate_ip6: :: at end" {
	run validate_ip6 "2001:db8::"
	assert_success
	assert_output "2001:db8::"
}

@test "validate_ip6: :: at beginning with groups" {
	run validate_ip6 "::ffff:1234"
	assert_success
	assert_output "::ffff:1234"
}

@test "validate_ip6: typical global unicast" {
	run validate_ip6 "2607:f8b0:4004:800::200e"
	assert_success
	assert_output "2607:f8b0:4004:800::200e"
}

# --- validate_ip6: invalid addresses ---

@test "validate_ip6: empty string" {
	run validate_ip6 ""
	assert_failure
}

@test "validate_ip6: alpha only (no colons)" {
	run validate_ip6 "abcdefgh"
	assert_failure
}

@test "validate_ip6: too many groups (9)" {
	run validate_ip6 "1:2:3:4:5:6:7:8:9"
	assert_failure
}

@test "validate_ip6: too few groups without ::" {
	run validate_ip6 "1:2:3:4:5:6:7"
	assert_failure
}

@test "validate_ip6: group with >4 hex digits" {
	run validate_ip6 "2001:0db80:0000:0000:0000:0000:0000:0001"
	assert_failure
}

@test "validate_ip6: triple colon" {
	run validate_ip6 "2001:::1"
	assert_failure
}

@test "validate_ip6: multiple :: occurrences" {
	run validate_ip6 "2001::db8::1"
	assert_failure
}

@test "validate_ip6: leading single colon (not ::)" {
	run validate_ip6 ":2001:db8::1"
	assert_failure
}

@test "validate_ip6: trailing single colon (not ::)" {
	run validate_ip6 "2001:db8:1:"
	assert_failure
}

@test "validate_ip6: no colon at all (number)" {
	run validate_ip6 "12345678"
	assert_failure
}

@test "validate_ip6: IPv4 address rejected" {
	run validate_ip6 "192.168.1.1"
	assert_failure
}

@test "validate_ip6: injection attempt (semicolon)" {
	run validate_ip6 "2001:db8::1;ls"
	assert_failure
}

@test "validate_ip6: injection attempt (dollar)" {
	run validate_ip6 '2001:db8::$HOME'
	assert_failure
}

@test "validate_ip6: injection attempt (backtick)" {
	run validate_ip6 '2001:db8::`id`'
	assert_failure
}

@test "validate_ip6: non-hex characters (g)" {
	run validate_ip6 "2001:db8::gggg"
	assert_failure
}

@test "validate_ip6: too many groups with ::" {
	run validate_ip6 "1:2:3:4:5:6:7::8"
	assert_failure
}

# --- validate_ip_any ---

@test "validate_ip_any: IPv4 returns IPv4" {
	run validate_ip_any "192.168.1.100"
	assert_success
	assert_output "192.168.1.100"
}

@test "validate_ip_any: IPv6 returns IPv6" {
	run validate_ip_any "2001:db8::1"
	assert_success
	assert_output "2001:db8::1"
}

@test "validate_ip_any: invalid returns failure" {
	run validate_ip_any "not-an-ip"
	assert_failure
}

@test "validate_ip_any: loopback IPv6" {
	run validate_ip_any "::1"
	assert_success
	assert_output "::1"
}

@test "validate_ip_any: IPv4 preferred over ambiguous" {
	run validate_ip_any "10.0.0.1"
	assert_success
	assert_output "10.0.0.1"
}
