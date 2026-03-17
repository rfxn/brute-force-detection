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

@test "count_subnet_attackers: writes detail file with per-IP rows" {
	local now=1000000
	local events_file="$INSTALL_PATH/tmp/pressure.dat"
	local detail_file="$TEST_TMPDIR/detail.dat"
	# 3 unique IPs, IP .1 has 2 events (weight 2 and 3), .2 has 1 (weight 1), .3 has 1 (no weight field)
	echo "$now 192.0.2.1 sshd 2" >> "$events_file"
	echo "$now 192.0.2.1 sshd 3" >> "$events_file"
	echo "$now 192.0.2.2 sshd 1" >> "$events_file"
	echo "$now 192.0.2.3 sshd" >> "$events_file"

	run count_subnet_attackers "$INSTALL_PATH" "300" "$now" "24" "48" "3" "$detail_file"
	assert_success
	# stdout contract unchanged
	assert_output --partial "192.0.2.0/24 sshd 3"

	# detail file must exist with per-IP rows
	[ -f "$detail_file" ]
	# 3 unique IPs = 3 rows
	[ "$(wc -l < "$detail_file")" -eq 3 ]
	# verify IP .1: 2 failures, weighted sum = 2+3 = 5
	run grep "192.0.2.1" "$detail_file"
	assert_output "192.0.2.0/24 sshd 192.0.2.1 2 5"
	# verify IP .3: 1 failure, weight defaults to 1
	run grep "192.0.2.3" "$detail_file"
	assert_output "192.0.2.0/24 sshd 192.0.2.3 1 1"
}

@test "count_subnet_attackers: no detail file arg = backward compat" {
	local now=1000000
	local events_file="$INSTALL_PATH/tmp/pressure.dat"
	echo "$now 192.0.2.1 sshd" >> "$events_file"
	echo "$now 192.0.2.2 sshd" >> "$events_file"
	echo "$now 192.0.2.3 sshd" >> "$events_file"

	# call without 7th arg — must still work
	run count_subnet_attackers "$INSTALL_PATH" "300" "$now" "24" "48" "3"
	assert_success
	assert_output --partial "192.0.2.0/24 sshd 3"
}

@test "count_subnet_attackers: detail file excludes sub-threshold subnets" {
	local now=1000000
	local events_file="$INSTALL_PATH/tmp/pressure.dat"
	local detail_file="$TEST_TMPDIR/detail.dat"
	# subnet A: 3 IPs (meets threshold)
	echo "$now 192.0.2.1 sshd 1" >> "$events_file"
	echo "$now 192.0.2.2 sshd 1" >> "$events_file"
	echo "$now 192.0.2.3 sshd 1" >> "$events_file"
	# subnet B: 2 IPs (below threshold)
	echo "$now 10.0.0.1 sshd 1" >> "$events_file"
	echo "$now 10.0.0.2 sshd 1" >> "$events_file"

	run count_subnet_attackers "$INSTALL_PATH" "300" "$now" "24" "48" "3" "$detail_file"
	assert_success
	# only subnet A in detail — sub-threshold subnet B excluded
	[ -f "$detail_file" ]
	run cat "$detail_file"
	refute_output --partial "10.0.0"
	[ "$(wc -l < "$detail_file")" -eq 3 ]
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

	# field 4 = pressure_scaled (total_pressure * 1000) — 3 events at weight 1 = 3000
	run awk -F'|' '{print $4}' "$alerts_file"
	assert_output "3000"

	# field 13 = total_failures — 3 IPs, 1 event each = 3
	run awk -F'|' '{print $13}' "$alerts_file"
	assert_output "3"
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

# ============================================================
# check_distributed — CIDR alert enrichment
# ============================================================

@test "check_distributed: alert fields 4+13 carry aggregate values" {
	local now=1000000
	local events_file="$INSTALL_PATH/tmp/pressure.dat"
	local alerts_file="$TEST_TMPDIR/alerts"
	touch "$alerts_file"

	# 3 IPs: .1 has 2 events (weight 2 each), .2 has 1 (weight 1), .3 has 1 (weight 3)
	echo "$now 192.0.2.1 sshd 2" >> "$events_file"
	echo "$now 192.0.2.1 sshd 2" >> "$events_file"
	echo "$now 192.0.2.2 sshd 1" >> "$events_file"
	echo "$now 192.0.2.3 sshd 3" >> "$events_file"

	SUBNET_TRIG="3"
	SUBNET_MASK="24"
	SUBNET_MASK_V6="48"
	TRIG_WINDOW="300"
	EMAIL_ALERTS="1"
	EMAIL_ADDRESS="admin@example.com"

	check_distributed "$INSTALL_PATH" "$TRIG_WINDOW" "$now" "$alerts_file" >/dev/null

	# field 4 = total_pressure_raw * 1000 = (2+2+1+3) * 1000 = 8000
	local f4
	f4=$(awk -F'|' '{print $4}' "$alerts_file")
	[ "$f4" = "8000" ]

	# field 13 = total_failures = 4 (2+1+1)
	local f13
	f13=$(awk -F'|' '{print $13}' "$alerts_file")
	[ "$f13" = "4" ]
}

@test "check_distributed: writes sidecar file for alert renderer" {
	local now=1000000
	local events_file="$INSTALL_PATH/tmp/pressure.dat"
	local alerts_file="$TEST_TMPDIR/alerts"
	touch "$alerts_file"

	echo "$now 192.0.2.1 sshd 2" >> "$events_file"
	echo "$now 192.0.2.1 sshd 2" >> "$events_file"
	echo "$now 192.0.2.2 sshd 1" >> "$events_file"
	echo "$now 192.0.2.3 sshd 3" >> "$events_file"

	SUBNET_TRIG="3"
	SUBNET_MASK="24"
	SUBNET_MASK_V6="48"
	TRIG_WINDOW="300"
	EMAIL_ALERTS="1"
	EMAIL_ADDRESS="admin@example.com"
	SUBNET_ALERT_TOP_N="5"

	check_distributed "$INSTALL_PATH" "$TRIG_WINDOW" "$now" "$alerts_file" >/dev/null

	# sidecar file must exist
	local sidecar="$INSTALL_PATH/tmp/.cidr_detail_192.0.2.0_24"
	[ -f "$sidecar" ]

	# header line
	run head -1 "$sidecar"
	assert_output "HEADER 192.0.2.0/24 3 4 8000"

	# per-IP rows sorted by weighted sum descending — .1 has highest (4000)
	run sed -n '2p' "$sidecar"
	assert_output --partial "192.0.2.1"
}

@test "check_distributed: sidecar has OVERFLOW when IPs > TOP_N" {
	local now=1000000
	local events_file="$INSTALL_PATH/tmp/pressure.dat"
	local alerts_file="$TEST_TMPDIR/alerts"
	touch "$alerts_file"

	# 4 unique IPs but TOP_N=2
	local i
	for i in 1 2 3 4; do
		echo "$now 192.0.2.${i} sshd 1" >> "$events_file"
	done

	SUBNET_TRIG="3"
	SUBNET_MASK="24"
	SUBNET_MASK_V6="48"
	TRIG_WINDOW="300"
	EMAIL_ALERTS="1"
	EMAIL_ADDRESS="admin@example.com"
	SUBNET_ALERT_TOP_N="2"

	check_distributed "$INSTALL_PATH" "$TRIG_WINDOW" "$now" "$alerts_file" >/dev/null

	local sidecar="$INSTALL_PATH/tmp/.cidr_detail_192.0.2.0_24"
	[ -f "$sidecar" ]
	# header + 2 IP rows + OVERFLOW line = 4 lines
	[ "$(wc -l < "$sidecar")" -eq 4 ]
	run tail -1 "$sidecar"
	assert_output "OVERFLOW 2"
}

@test "check_distributed: sidecar filename sanitizes IPv6 colons" {
	local now=1000000
	local events_file="$INSTALL_PATH/tmp/pressure.dat"
	local alerts_file="$TEST_TMPDIR/alerts"
	touch "$alerts_file"

	echo "$now 2001:db8:1234::1 sshd 1" >> "$events_file"
	echo "$now 2001:db8:1234::2 sshd 1" >> "$events_file"
	echo "$now 2001:db8:1234::3 sshd 1" >> "$events_file"

	SUBNET_TRIG="3"
	SUBNET_MASK="24"
	SUBNET_MASK_V6="48"
	TRIG_WINDOW="300"
	EMAIL_ALERTS="1"
	EMAIL_ADDRESS="admin@example.com"
	SUBNET_ALERT_TOP_N="5"

	check_distributed "$INSTALL_PATH" "$TRIG_WINDOW" "$now" "$alerts_file" >/dev/null

	# colons replaced with -, slash replaced with _
	local sidecar="$INSTALL_PATH/tmp/.cidr_detail_2001-db8-1234--_48"
	[ -f "$sidecar" ]
}

@test "check_distributed: no sidecar when EMAIL_ALERTS=0" {
	local now=1000000
	local events_file="$INSTALL_PATH/tmp/pressure.dat"
	local alerts_file="$TEST_TMPDIR/alerts"
	touch "$alerts_file"

	for i in 1 2 3; do
		echo "$now 192.0.2.${i} sshd 1" >> "$events_file"
	done

	SUBNET_TRIG="3"
	SUBNET_MASK="24"
	SUBNET_MASK_V6="48"
	TRIG_WINDOW="300"
	EMAIL_ALERTS="0"

	check_distributed "$INSTALL_PATH" "$TRIG_WINDOW" "$now" "$alerts_file" >/dev/null

	# no sidecar written when alerts disabled
	[ ! -f "$INSTALL_PATH/tmp/.cidr_detail_192.0.2.0_24" ]
}
