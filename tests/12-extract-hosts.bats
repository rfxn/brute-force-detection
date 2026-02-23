#!/usr/bin/env bats

load 'helpers/bfd-common'

setup() {
	bfd_standard_setup
	IGNOREREGEX=""
}

teardown() {
	bfd_teardown
}

@test "extract_hosts: basic IP extraction from sshd failure" {
	local input="Feb 22 10:15:03 myhost sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2"
	local result
	result=$(echo "$input" | extract_hosts "sshd.*Failed password for .* from <HOST>")
	[ "$result" = "192.168.1.100" ]
}

@test "extract_hosts: multiple patterns match different failure types" {
	local input
	input=$(printf '%s\n' \
		"Feb 22 10:15:03 myhost sshd[12345]: Invalid user admin from 10.0.0.5 port 54321 ssh2" \
		"Feb 22 10:15:05 myhost sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2")
	local result
	result=$(echo "$input" | extract_hosts \
		"sshd.*Invalid user .* from <HOST>" \
		"sshd.*Failed password for .* from <HOST>")
	local count
	count=$(echo "$result" | wc -l)
	[ "$count" -eq 2 ]
	echo "$result" | grep -qF "10.0.0.5"
	echo "$result" | grep -qF "192.168.1.100"
}

@test "extract_hosts: strips ::ffff: prefix" {
	local input="Feb 22 10:15:03 myhost sshd[12345]: Failed password for root from ::ffff:10.0.0.1 port 22 ssh2"
	local result
	result=$(echo "$input" | extract_hosts "sshd.*Failed password for .* from <HOST>")
	[ "$result" = "10.0.0.1" ]
}

@test "extract_hosts: strips brackets around IP" {
	local input="Feb 22 10:15:03 myhost postfix/smtpd[12345]: warning: [192.168.1.50]: SASL PLAIN authentication failed"
	local result
	result=$(echo "$input" | extract_hosts "\[<HOST>\].*SASL.*authentication failed")
	[ "$result" = "192.168.1.50" ]
}

@test "extract_hosts: rejects invalid IP (999.999.999.999)" {
	local input="Feb 22 10:15:03 myhost sshd[12345]: Failed password for root from 999.999.999.999 port 22 ssh2"
	local result
	result=$(echo "$input" | extract_hosts "sshd.*Failed password for .* from <HOST>")
	[ -z "$result" ]
}

@test "extract_hosts: empty input returns nothing" {
	local result
	result=$(echo "" | extract_hosts "sshd.*Failed password for .* from <HOST>")
	[ -z "$result" ]
}

@test "extract_hosts: no matches returns nothing" {
	local input="Feb 22 10:15:03 myhost sshd[12345]: Accepted publickey for user from 10.0.0.1 port 22 ssh2"
	local result
	result=$(echo "$input" | extract_hosts "sshd.*Failed password for .* from <HOST>")
	[ -z "$result" ]
}

@test "extract_hosts: IGNOREREGEX excludes matching lines" {
	IGNOREREGEX="no auth attempts"
	local input
	input=$(printf '%s\n' \
		"Feb 22 myhost dovecot: pop3-login: Aborted login (auth failed, 1 attempts): user=<admin>, rip=192.168.1.100, lip=10.0.0.1" \
		"Feb 22 myhost dovecot: pop3-login: Aborted login (no auth attempts): user=<>, rip=10.0.0.5, lip=10.0.0.1")
	local result
	result=$(echo "$input" | extract_hosts "pop3-login.*auth failed.*rip=<HOST>")
	[ "$result" = "192.168.1.100" ]
}

@test "extract_hosts: multiple IPs from multiple lines" {
	local input
	input=$(printf '%s\n' \
		"Feb 22 myhost sshd[1]: Failed password for root from 10.0.0.1 port 22 ssh2" \
		"Feb 22 myhost sshd[2]: Failed password for root from 10.0.0.2 port 22 ssh2" \
		"Feb 22 myhost sshd[3]: Failed password for root from 10.0.0.3 port 22 ssh2")
	local result
	result=$(echo "$input" | extract_hosts "sshd.*Failed password for .* from <HOST>")
	local count
	count=$(echo "$result" | wc -l)
	[ "$count" -eq 3 ]
}

@test "extract_hosts: duplicate IPs preserved for counting" {
	local input
	input=$(printf '%s\n' \
		"Feb 22 myhost sshd[1]: Failed password for root from 192.168.1.1 port 22 ssh2" \
		"Feb 22 myhost sshd[2]: Failed password for admin from 192.168.1.1 port 22 ssh2" \
		"Feb 22 myhost sshd[3]: Failed password for user from 192.168.1.1 port 22 ssh2")
	local result
	result=$(echo "$input" | extract_hosts "sshd.*Failed password for .* from <HOST>")
	local count
	count=$(echo "$result" | wc -l)
	[ "$count" -eq 3 ]
	local unique
	unique=$(echo "$result" | sort -u | wc -l)
	[ "$unique" -eq 1 ]
}

@test "extract_hosts: IP in brackets (postfix style)" {
	local input="Feb 22 myhost postfix/smtpd[9876]: warning: unknown[10.20.30.40]: SASL LOGIN authentication failed: authentication failure"
	local result
	result=$(echo "$input" | extract_hosts "\[<HOST>\].*SASL.*authentication failed")
	[ "$result" = "10.20.30.40" ]
}

@test "extract_hosts: IP after rip= (dovecot style)" {
	local input="Feb 22 myhost dovecot: imap-login: Aborted login (auth failed, 1 attempts): user=<test>, method=PLAIN, rip=172.16.0.50, lip=10.0.0.1"
	local result
	result=$(echo "$input" | extract_hosts "imap-login.*auth failed.*rip=<HOST>")
	[ "$result" = "172.16.0.50" ]
}

@test "extract_hosts: IP in single quotes (asterisk style)" {
	local input="[2024-02-22 10:15:03] NOTICE[12345] chan_sip.c: Wrong password for user 'admin' from '203.0.113.50':5060"
	local result
	result=$(echo "$input" | extract_hosts "Wrong password.*'<HOST>'")
	[ "$result" = "203.0.113.50" ]
}

@test "extract_hosts: IGNOREREGEX excludes all lines returns nothing" {
	IGNOREREGEX="sshd"
	local input="Feb 22 myhost sshd[1]: Failed password for root from 10.0.0.1 port 22 ssh2"
	local result
	result=$(echo "$input" | extract_hosts "sshd.*Failed password for .* from <HOST>")
	[ -z "$result" ]
}

@test "extract_hosts: pattern with special regex chars in context" {
	local input="2024-01-21 23:09:19 ERR [panel] [Action Log] Failed login attempt with login 'admin' from IP 203.0.113.10"
	local result
	result=$(echo "$input" | extract_hosts "Failed login attempt .* from IP <HOST>")
	[ "$result" = "203.0.113.10" ]
}

# --- IPv6 extraction tests ---

@test "extract_hosts: IPv6 from sshd log" {
	local input="Feb 22 10:15:03 myhost sshd[12345]: Failed password for root from 2001:db8::1 port 22 ssh2"
	local result
	result=$(echo "$input" | extract_hosts "sshd.*Failed password for .* from <HOST>")
	[ "$result" = "2001:db8::1" ]
}

@test "extract_hosts: IPv6 in brackets" {
	local input="Feb 22 10:15:03 myhost postfix/smtpd[9876]: warning: unknown[2001:db8::abcd]: SASL LOGIN authentication failed: authentication failure"
	local result
	result=$(echo "$input" | extract_hosts "\[<HOST>\].*SASL.*authentication failed")
	[ "$result" = "2001:db8::abcd" ]
}

@test "extract_hosts: IPv6 after rip= (dovecot)" {
	local input="Feb 22 10:15:03 myhost dovecot: pop3-login: Aborted login (auth failed, 1 attempts): user=<admin>, method=PLAIN, rip=2001:db8::ff, lip=::1"
	local result
	result=$(echo "$input" | extract_hosts "pop3-login.*auth failed.*rip=<HOST>")
	[ "$result" = "2001:db8::ff" ]
}

@test "extract_hosts: ::ffff: prefix still strips to IPv4" {
	local input="Feb 22 10:15:03 myhost sshd[12345]: Failed password for root from ::ffff:192.168.1.1 port 22 ssh2"
	local result
	result=$(echo "$input" | extract_hosts "sshd.*Failed password for .* from <HOST>")
	[ "$result" = "192.168.1.1" ]
}

@test "extract_hosts: mixed IPv4+IPv6 both extracted" {
	local input
	input=$(printf '%s\n' \
		"Feb 22 myhost sshd[1]: Failed password for root from 10.0.0.1 port 22 ssh2" \
		"Feb 22 myhost sshd[2]: Failed password for admin from 2001:db8::99 port 22 ssh2")
	local result
	result=$(echo "$input" | extract_hosts "sshd.*Failed password for .* from <HOST>")
	local count
	count=$(echo "$result" | wc -l)
	[ "$count" -eq 2 ]
	echo "$result" | grep -qF "10.0.0.1"
	echo "$result" | grep -qF "2001:db8::99"
}

@test "extract_hosts: invalid IPv6 rejected" {
	local input="Feb 22 10:15:03 myhost sshd[12345]: Failed password for root from 2001:db8:::bad port 22 ssh2"
	local result
	result=$(echo "$input" | extract_hosts "sshd.*Failed password for .* from <HOST>")
	[ -z "$result" ]
}

@test "extract_hosts: full IPv6 address" {
	local input="Feb 22 10:15:03 myhost sshd[12345]: Failed password for root from 2001:0db8:0000:0000:0000:0000:0000:0001 port 22 ssh2"
	local result
	result=$(echo "$input" | extract_hosts "sshd.*Failed password for .* from <HOST>")
	[ "$result" = "2001:0db8:0000:0000:0000:0000:0000:0001" ]
}

@test "extract_hosts: IPv6 loopback ::1" {
	local input="Feb 22 10:15:03 myhost sshd[12345]: Failed password for root from ::1 port 22 ssh2"
	local result
	result=$(echo "$input" | extract_hosts "sshd.*Failed password for .* from <HOST>")
	[ "$result" = "::1" ]
}
