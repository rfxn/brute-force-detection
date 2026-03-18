#!/usr/bin/env bats
#
# Test suite for validate_ip() and sanitize_mod()
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

# --- validate_ip: valid IPs ---

@test "validate_ip: valid 192.0.2.4" {
	run validate_ip "192.0.2.4"
	assert_success
	assert_output "192.0.2.4"
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
	run validate_ip "192.0.2.4.5"
	assert_failure
	assert_output ""
}

@test "validate_ip: trailing dot" {
	run validate_ip "192.0.2.4."
	assert_failure
	assert_output ""
}

@test "validate_ip: leading dot" {
	run validate_ip ".192.0.2.4"
	assert_failure
	assert_output ""
}

# --- validate_ip: injection attempts ---

@test "validate_ip: injection semicolon" {
	run validate_ip "192.0.2.4;rm -rf /"
	assert_failure
	assert_output ""
}

@test "validate_ip: injection dollar" {
	run validate_ip '192.0.2.4$(whoami)'
	assert_failure
	assert_output ""
}

@test "validate_ip: injection backtick" {
	run validate_ip '192.0.2.4`id`'
	assert_failure
	assert_output ""
}

@test "validate_ip: injection pipe" {
	run validate_ip "192.0.2.4|cat /etc/passwd"
	assert_failure
	assert_output ""
}

@test "validate_ip: injection newline" {
	local input
	input=$(printf '192.0.2.4\n198.51.100.8')
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

# --- sanitize_ports: valid inputs ---

@test "sanitize_ports: valid single port" {
	run sanitize_ports "22"
	assert_success
	assert_output "22"
}

@test "sanitize_ports: valid multi port" {
	run sanitize_ports "22,80,443"
	assert_success
	assert_output "22,80,443"
}

@test "sanitize_ports: valid keyword all" {
	run sanitize_ports "all"
	assert_success
	assert_output "all"
}

@test "sanitize_ports: valid large port 65535" {
	run sanitize_ports "65535"
	assert_success
	assert_output "65535"
}

# --- sanitize_ports: invalid inputs ---

@test "sanitize_ports: invalid empty string" {
	run sanitize_ports ""
	assert_failure
	assert_output ""
}

@test "sanitize_ports: invalid semicolon injection" {
	run sanitize_ports "22;rm -rf /"
	assert_failure
	assert_output ""
}

@test "sanitize_ports: invalid backtick injection" {
	run sanitize_ports '22`id`'
	assert_failure
	assert_output ""
}

@test "sanitize_ports: invalid space" {
	run sanitize_ports "22 80"
	assert_failure
	assert_output ""
}

@test "sanitize_ports: invalid dollar injection" {
	run sanitize_ports '$(whoami)'
	assert_failure
	assert_output ""
}

@test "sanitize_ports: invalid pipe" {
	run sanitize_ports "22|nc"
	assert_failure
	assert_output ""
}

@test "sanitize_ports: invalid mixed all with port" {
	run sanitize_ports "all,22"
	assert_failure
	assert_output ""
}

@test "sanitize_ports: invalid space after comma" {
	run sanitize_ports "22, 80"
	assert_failure
	assert_output ""
}
