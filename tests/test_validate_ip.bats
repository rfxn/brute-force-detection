#!/usr/bin/env bats
#
# Test suite for validate_ip() and sanitize_mod()
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

# --- validate_ip: valid IPs ---

@test "validate_ip: valid 1.2.3.4" {
	run validate_ip "1.2.3.4"
	assert_success
	assert_output "1.2.3.4"
}

@test "validate_ip: valid 0.0.0.0" {
	run validate_ip "0.0.0.0"
	assert_success
	assert_output "0.0.0.0"
}

@test "validate_ip: valid 255.255.255.255" {
	run validate_ip "255.255.255.255"
	assert_success
	assert_output "255.255.255.255"
}

@test "validate_ip: valid 192.168.1.1" {
	run validate_ip "192.168.1.1"
	assert_success
	assert_output "192.168.1.1"
}

@test "validate_ip: valid 10.0.0.1" {
	run validate_ip "10.0.0.1"
	assert_success
	assert_output "10.0.0.1"
}

@test "validate_ip: valid 172.16.0.255" {
	run validate_ip "172.16.0.255"
	assert_success
	assert_output "172.16.0.255"
}

# --- validate_ip: invalid IPs (out of range) ---

@test "validate_ip: invalid 256.1.1.1" {
	run validate_ip "256.1.1.1"
	assert_failure
	assert_output ""
}

@test "validate_ip: invalid 1.2.3.999" {
	run validate_ip "1.2.3.999"
	assert_failure
	assert_output ""
}

@test "validate_ip: invalid 999.999.999.999" {
	run validate_ip "999.999.999.999"
	assert_failure
	assert_output ""
}

@test "validate_ip: invalid 300.0.0.1" {
	run validate_ip "300.0.0.1"
	assert_failure
	assert_output ""
}

# --- validate_ip: invalid IPs (wrong format) ---

@test "validate_ip: empty string" {
	run validate_ip ""
	assert_failure
	assert_output ""
}

@test "validate_ip: alpha string" {
	run validate_ip "abc"
	assert_failure
	assert_output ""
}

@test "validate_ip: too few octets" {
	run validate_ip "1.2.3"
	assert_failure
	assert_output ""
}

@test "validate_ip: too many octets" {
	run validate_ip "1.2.3.4.5"
	assert_failure
	assert_output ""
}

@test "validate_ip: trailing dot" {
	run validate_ip "1.2.3.4."
	assert_failure
	assert_output ""
}

@test "validate_ip: leading dot" {
	run validate_ip ".1.2.3.4"
	assert_failure
	assert_output ""
}

# --- validate_ip: injection attempts ---

@test "validate_ip: injection semicolon" {
	run validate_ip "1.2.3.4;rm -rf /"
	assert_failure
	assert_output ""
}

@test "validate_ip: injection dollar" {
	run validate_ip '1.2.3.4$(whoami)'
	assert_failure
	assert_output ""
}

@test "validate_ip: injection backtick" {
	run validate_ip '1.2.3.4`id`'
	assert_failure
	assert_output ""
}

@test "validate_ip: injection pipe" {
	run validate_ip "1.2.3.4|cat /etc/passwd"
	assert_failure
	assert_output ""
}

@test "validate_ip: injection newline" {
	local input
	input=$(printf '1.2.3.4\n5.6.7.8')
	run validate_ip "$input"
	assert_failure
	assert_output ""
}

# --- sanitize_mod: valid names ---

@test "sanitize_mod: valid sshd" {
	run sanitize_mod "sshd"
	assert_success
	assert_output "sshd"
}

@test "sanitize_mod: valid exim_authfail" {
	run sanitize_mod "exim_authfail"
	assert_success
	assert_output "exim_authfail"
}

@test "sanitize_mod: valid asterisk-iax" {
	run sanitize_mod "asterisk-iax"
	assert_success
	assert_output "asterisk-iax"
}

@test "sanitize_mod: valid rh_imapd" {
	run sanitize_mod "rh_imapd"
	assert_success
	assert_output "rh_imapd"
}

@test "sanitize_mod: valid vsftpd2" {
	run sanitize_mod "vsftpd2"
	assert_success
	assert_output "vsftpd2"
}

# --- sanitize_mod: invalid names ---

@test "sanitize_mod: invalid semicolon" {
	run sanitize_mod "sshd;evil"
	assert_failure
	assert_output ""
}

@test "sanitize_mod: invalid space" {
	run sanitize_mod "sshd evil"
	assert_failure
	assert_output ""
}

@test "sanitize_mod: invalid slash" {
	run sanitize_mod "../etc/passwd"
	assert_failure
	assert_output ""
}

@test "sanitize_mod: invalid dollar" {
	run sanitize_mod 'sshd$x'
	assert_failure
	assert_output ""
}

@test "sanitize_mod: invalid empty" {
	run sanitize_mod ""
	assert_failure
	assert_output ""
}
