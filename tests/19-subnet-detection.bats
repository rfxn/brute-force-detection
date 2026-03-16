#!/usr/bin/env bats
#
# Test suite for Phase 23 — subnet aggregation & distributed attack detection
# Tests: ip_to_subnet, count_subnet_attackers, check_distributed
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

setup() {
	bfd_standard_setup
	BAN_DURATION="300"
	BAN_PERMANENT_AFTER="0"
	BAN_PERMANENT_WINDOW="86400"
	BAN_ESCALATION="none"
	BAN_ESCALATION_CAP="0"
	EMAIL_ALERTS="0"
	DRY_RUN=0
	SUBNET_TRIG="3"
	SUBNET_MASK="24"
	SUBNET_MASK_V6="48"
}

teardown() {
	bfd_teardown
}

# ============================================================
# ip_to_subnet
# ============================================================

@test "ip_to_subnet: IPv4 /24" {
	run ip_to_subnet "203.0.113.100" "24"
	assert_success
	assert_output "203.0.113.0/24"
}

@test "ip_to_subnet: IPv4 /16" {
	run ip_to_subnet "198.51.100.40" "16"
	assert_success
	assert_output "198.51.0.0/16"
}

@test "ip_to_subnet: IPv4 /8" {
	run ip_to_subnet "198.51.100.130" "8"
	assert_success
	assert_output "198.0.0.0/8"
}

@test "ip_to_subnet: IPv4 /32" {
	run ip_to_subnet "192.0.2.4" "32"
	assert_success
	assert_output "192.0.2.4/32"
}

@test "ip_to_subnet: IPv4 /20 non-octet-aligned" {
	run ip_to_subnet "198.51.100.130" "20"
	assert_success
	assert_output "198.51.96.0/20"
}

@test "ip_to_subnet: IPv4 mask below /8 returns IP with mask" {
	run ip_to_subnet "198.51.100.130" "4"
	assert_success
	assert_output "198.51.100.130/4"
}

@test "ip_to_subnet: IPv6 /48 with ::" {
	run ip_to_subnet "2001:db8:1234:5678::1" "48"
	assert_success
	assert_output "2001:db8:1234::/48"
}

@test "ip_to_subnet: IPv6 /32 with ::" {
	run ip_to_subnet "2001:db8:abcd:ef01::1" "32"
	assert_success
	assert_output "2001:db8::/32"
}

@test "ip_to_subnet: IPv6 /64 full form" {
	run ip_to_subnet "2001:db8:1234:5678:9abc:def0:1234:5678" "64"
	assert_success
	assert_output "2001:db8:1234:5678::/64"
}

# ============================================================
# count_subnet_attackers
# ============================================================

@test "count_subnet_attackers: finds IPv4 subnet with 3 unique IPs" {
	local now=1000000
	local events_file="$INSTALL_PATH/tmp/pressure.dat"
	echo "$now 192.0.2.1 sshd" >> "$events_file"
	echo "$now 192.0.2.2 sshd" >> "$events_file"
	echo "$now 192.0.2.3 sshd" >> "$events_file"

	run count_subnet_attackers "$INSTALL_PATH" "300" "$now" "24" "48" "3"
	assert_success
	assert_output --partial "192.0.2.0/24 sshd 3"
}

@test "count_subnet_attackers: respects window cutoff" {
	local now=1000000
	local events_file="$INSTALL_PATH/tmp/pressure.dat"
	# events outside window (window=300, cutoff=999700)
	echo "999600 192.0.2.1 sshd" >> "$events_file"
	echo "999600 192.0.2.2 sshd" >> "$events_file"
	echo "999600 192.0.2.3 sshd" >> "$events_file"

	run count_subnet_attackers "$INSTALL_PATH" "300" "$now" "24" "48" "3"
	assert_success
	assert_output ""
}

@test "count_subnet_attackers: per-service isolation" {
	local now=1000000
	local events_file="$INSTALL_PATH/tmp/pressure.dat"
	# 3 IPs for sshd
	echo "$now 192.0.2.1 sshd" >> "$events_file"
	echo "$now 192.0.2.2 sshd" >> "$events_file"
	echo "$now 192.0.2.3 sshd" >> "$events_file"
	# 1 IP for dovecot (same subnet, but different service)
	echo "$now 192.0.2.4 dovecot" >> "$events_file"

	run count_subnet_attackers "$INSTALL_PATH" "300" "$now" "24" "48" "3"
	assert_success
	assert_output --partial "192.0.2.0/24 sshd 3"
	refute_output --partial "dovecot"
}

@test "count_subnet_attackers: IPv6 subnet detection" {
	local now=1000000
	local events_file="$INSTALL_PATH/tmp/pressure.dat"
	echo "$now 2001:db8:1234::1 sshd" >> "$events_file"
	echo "$now 2001:db8:1234::2 sshd" >> "$events_file"
	echo "$now 2001:db8:1234::3 sshd" >> "$events_file"

	run count_subnet_attackers "$INSTALL_PATH" "300" "$now" "24" "48" "3"
	assert_success
	assert_output --partial "2001:db8:1234::/48 sshd 3"
}

@test "count_subnet_attackers: empty pressure.dat produces no output" {
	run count_subnet_attackers "$INSTALL_PATH" "300" "1000000" "24" "48" "3"
	assert_success
	assert_output ""
}

# ============================================================
# check_distributed
# ============================================================

@test "check_distributed: bans subnet when threshold met" {
	local now=1000000
	local events_file="$INSTALL_PATH/tmp/pressure.dat"
	local alerts_file="$TEST_TMPDIR/alerts"
	touch "$alerts_file"

	# seed 5 unique IPs from same /24
	local i
	for i in 1 2 3 4 5; do
		echo "$now 198.51.100.${i} sshd" >> "$events_file"
	done

	SUBNET_TRIG="3"
	SUBNET_MASK="24"
	SUBNET_MASK_V6="48"
	TRIG_WINDOW="300"

	run check_distributed "$INSTALL_PATH" "$TRIG_WINDOW" "$now" "$alerts_file"
	assert_success
	# last line of output is the ban count (avoid --index -1 for bash 4.1)
	[ "${lines[$(( ${#lines[@]} - 1 ))]}" = "1" ]

	# verify bans.active has CIDR entry
	run cat "$INSTALL_PATH/tmp/bans.active"
	assert_output --partial "198.51.100.0/24"
}

@test "check_distributed: skips already-banned subnet" {
	local now=1000000
	local events_file="$INSTALL_PATH/tmp/pressure.dat"
	local alerts_file="$TEST_TMPDIR/alerts"
	touch "$alerts_file"

	for i in 1 2 3; do
		echo "$now 198.51.100.${i} sshd" >> "$events_file"
	done

	# pre-populate bans.active with this subnet
	state_bans_active_append "$INSTALL_PATH" "$now" "0" "198.51.100.0/24" "sshd" "all"

	SUBNET_TRIG="3"
	SUBNET_MASK="24"
	SUBNET_MASK_V6="48"
	TRIG_WINDOW="300"

	run check_distributed "$INSTALL_PATH" "$TRIG_WINDOW" "$now" "$alerts_file"
	assert_success
	# last line of output is the ban count (avoid --index -1 for bash 4.1)
	[ "${lines[$(( ${#lines[@]} - 1 ))]}" = "0" ]
}

@test "check_distributed: no bans when SUBNET_TRIG not met" {
	local now=1000000
	local events_file="$INSTALL_PATH/tmp/pressure.dat"
	local alerts_file="$TEST_TMPDIR/alerts"
	touch "$alerts_file"

	# only 2 unique IPs, but SUBNET_TRIG=3
	echo "$now 198.51.100.1 sshd" >> "$events_file"
	echo "$now 198.51.100.2 sshd" >> "$events_file"

	SUBNET_TRIG="3"
	SUBNET_MASK="24"
	SUBNET_MASK_V6="48"
	TRIG_WINDOW="300"

	run check_distributed "$INSTALL_PATH" "$TRIG_WINDOW" "$now" "$alerts_file"
	assert_success
	assert_output "0"
}

@test "check_distributed: records action=ban in bans.history" {
	local now=1000000
	local events_file="$INSTALL_PATH/tmp/pressure.dat"
	local alerts_file="$TEST_TMPDIR/alerts"
	touch "$alerts_file"

	for i in 1 2 3; do
		echo "$now 203.0.113.${i} dovecot" >> "$events_file"
	done

	SUBNET_TRIG="3"
	SUBNET_MASK="24"
	SUBNET_MASK_V6="48"
	TRIG_WINDOW="300"

	check_distributed "$INSTALL_PATH" "$TRIG_WINDOW" "$now" "$alerts_file" >/dev/null

	run cat "$INSTALL_PATH/tmp/bans.history"
	assert_output --partial "203.0.113.0/24"
	assert_output --partial "ban"
}

@test "check_distributed: dry run records state but skips firewall command" {
	local now=1000000
	local events_file="$INSTALL_PATH/tmp/pressure.dat"
	local alerts_file="$TEST_TMPDIR/alerts"
	touch "$alerts_file"

	for i in 1 2 3; do
		echo "$now 198.51.100.${i} sshd" >> "$events_file"
	done

	SUBNET_TRIG="3"
	SUBNET_MASK="24"
	SUBNET_MASK_V6="48"
	TRIG_WINDOW="300"
	DRY_RUN=1

	run check_distributed "$INSTALL_PATH" "$TRIG_WINDOW" "$now" "$alerts_file"
	assert_success
	# dry-run: execute_ban returns 0, state is recorded (consistent with per-IP)
	# last line is ban count (avoid --index -1 for bash 4.1)
	[ "${lines[$(( ${#lines[@]} - 1 ))]}" = "1" ]
	assert_output --partial "dry-run"
}

@test "count_subnet_attackers: deduplicates same IP multiple events" {
	local now=1000000
	local events_file="$INSTALL_PATH/tmp/pressure.dat"
	# same IP appears 5 times, but only 2 unique IPs
	echo "$now 192.0.2.1 sshd" >> "$events_file"
	echo "$now 192.0.2.1 sshd" >> "$events_file"
	echo "$now 192.0.2.1 sshd" >> "$events_file"
	echo "$now 192.0.2.2 sshd" >> "$events_file"
	echo "$now 192.0.2.2 sshd" >> "$events_file"

	run count_subnet_attackers "$INSTALL_PATH" "300" "$now" "24" "48" "3"
	assert_success
	# only 2 unique IPs, threshold 3 — no output
	assert_output ""
}

@test "check_distributed: alert entry has (multiple) as LOG_FILE field" {
	local now=1000000
	local events_file="$INSTALL_PATH/tmp/pressure.dat"
	local alerts_file="$TEST_TMPDIR/alerts"
	touch "$alerts_file"

	for i in 1 2 3; do
		echo "$now 192.0.2.${i} sshd" >> "$events_file"
	done

	SUBNET_TRIG="3"
	SUBNET_MASK="24"
	SUBNET_MASK_V6="48"
	TRIG_WINDOW="300"
	EMAIL_ALERTS="1"
	EMAIL_ADDRESS="admin@example.com"

	check_distributed "$INSTALL_PATH" "$TRIG_WINDOW" "$now" "$alerts_file" >/dev/null

	# field 8 must be "(multiple)" — not empty — for correct distributed ban labeling
	run awk -F'|' '{print $8}' "$alerts_file"
	assert_output "(multiple)"
}

@test "check_distributed: ban expiry computed from BAN_DURATION" {
	local now=1000000
	local events_file="$INSTALL_PATH/tmp/pressure.dat"
	local alerts_file="$TEST_TMPDIR/alerts"
	touch "$alerts_file"

	for i in 1 2 3; do
		echo "$now 192.0.2.${i} sshd" >> "$events_file"
	done

	SUBNET_TRIG="3"
	SUBNET_MASK="24"
	SUBNET_MASK_V6="48"
	TRIG_WINDOW="300"
	BAN_DURATION="600"

	check_distributed "$INSTALL_PATH" "$TRIG_WINDOW" "$now" "$alerts_file" >/dev/null

	# verify expiry = now + BAN_DURATION = 1000600
	run cat "$INSTALL_PATH/tmp/bans.active"
	assert_output --partial "1000600"
}
