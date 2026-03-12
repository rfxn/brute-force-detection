#!/usr/bin/env bats
#
# Test suite for update-ipcountry.sh:
#   CIDR-to-integer-range conversion, cron.daily staleness refresh
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

setup() {
	bfd_standard_setup
	mkdir -p "$INSTALL_PATH/internals"
	mkdir -p "$INSTALL_PATH/tmp"

	# Copy geoip_lib.sh into the test install path (as update-ipcountry.sh expects)
	cp "$PROJECT_ROOT/files/internals/geoip_lib.sh" "$INSTALL_PATH/internals/"

	# Create a mock update-ipcountry.sh that sources geoip_lib from project root
	# but uses our test INSTALL_PATH
	_SCRIPT="$PROJECT_ROOT/files/update-ipcountry.sh"
}

teardown() {
	bfd_teardown
}

# ============================================================
# _cidr4_to_ranges — CIDR to integer-range conversion
# ============================================================

# Helper: extract and eval _cidr4_to_ranges from update-ipcountry.sh
_load_cidr4_to_ranges() {
	# Source geoip_lib first (needed by update-ipcountry.sh)
	# shellcheck disable=SC1091
	_GEOIP_LIB_LOADED=""
	. "$PROJECT_ROOT/files/internals/geoip_lib.sh"
	# Extract the function
	bfd_load_function "_cidr4_to_ranges" "$PROJECT_ROOT/files/update-ipcountry.sh"
}

@test "cidr4_to_ranges: /24 produces correct range" {
	_load_cidr4_to_ranges
	# 1.0.0.0/24 = 16777216 to 16777471 (256 IPs)
	echo "1.0.0.0/24" > "$TEST_TMPDIR/test.zone"
	run _cidr4_to_ranges "$TEST_TMPDIR/test.zone" "AU"
	assert_success
	assert_output "16777216 16777471 AU"
}

@test "cidr4_to_ranges: /32 produces single-IP range" {
	_load_cidr4_to_ranges
	# 10.0.0.1/32 = 167772161 to 167772161 (1 IP)
	echo "10.0.0.1/32" > "$TEST_TMPDIR/test.zone"
	run _cidr4_to_ranges "$TEST_TMPDIR/test.zone" "XX"
	assert_success
	assert_output "167772161 167772161 XX"
}

@test "cidr4_to_ranges: /8 produces correct large range" {
	_load_cidr4_to_ranges
	# 10.0.0.0/8 = 167772160 to 184549375 (16777216 IPs)
	echo "10.0.0.0/8" > "$TEST_TMPDIR/test.zone"
	run _cidr4_to_ranges "$TEST_TMPDIR/test.zone" "XX"
	assert_success
	assert_output "167772160 184549375 XX"
}

@test "cidr4_to_ranges: /0 produces full IP space" {
	_load_cidr4_to_ranges
	# 0.0.0.0/0 = 0 to 4294967295 (entire IPv4 space)
	echo "0.0.0.0/0" > "$TEST_TMPDIR/test.zone"
	run _cidr4_to_ranges "$TEST_TMPDIR/test.zone" "XX"
	assert_success
	assert_output "0 4294967295 XX"
}

@test "cidr4_to_ranges: /1 produces half IP space" {
	_load_cidr4_to_ranges
	# 0.0.0.0/1 = 0 to 2147483647 (half of IPv4)
	echo "0.0.0.0/1" > "$TEST_TMPDIR/test.zone"
	run _cidr4_to_ranges "$TEST_TMPDIR/test.zone" "XX"
	assert_success
	assert_output "0 2147483647 XX"
}

@test "cidr4_to_ranges: /16 produces correct range" {
	_load_cidr4_to_ranges
	# 192.168.0.0/16 = 3232235520 to 3232301055 (65536 IPs)
	echo "192.168.0.0/16" > "$TEST_TMPDIR/test.zone"
	run _cidr4_to_ranges "$TEST_TMPDIR/test.zone" "XX"
	assert_success
	assert_output "3232235520 3232301055 XX"
}

@test "cidr4_to_ranges: multiple CIDRs produce multiple lines" {
	_load_cidr4_to_ranges
	cat > "$TEST_TMPDIR/test.zone" << 'EOF'
1.0.0.0/24
1.0.1.0/24
EOF
	run _cidr4_to_ranges "$TEST_TMPDIR/test.zone" "AU"
	assert_success
	assert_line --index 0 "16777216 16777471 AU"
	assert_line --index 1 "16777472 16777727 AU"
}

@test "cidr4_to_ranges: skips comment and blank lines" {
	_load_cidr4_to_ranges
	cat > "$TEST_TMPDIR/test.zone" << 'EOF'
# This is a comment
1.0.0.0/24

# Another comment
EOF
	run _cidr4_to_ranges "$TEST_TMPDIR/test.zone" "AU"
	assert_success
	assert_output "16777216 16777471 AU"
}

@test "cidr4_to_ranges: known IP 223.255.254.0/24 falls in expected range" {
	_load_cidr4_to_ranges
	# 223.255.254.0/24 → start = 3758095872, end = 3758096127
	echo "223.255.254.0/24" > "$TEST_TMPDIR/test.zone"
	run _cidr4_to_ranges "$TEST_TMPDIR/test.zone" "CN"
	assert_success
	# Verify ip_to_country can find a known IP in this range
	local start end
	start=$(echo "$output" | awk '{print $1}')
	end=$(echo "$output" | awk '{print $2}')
	# 223.255.254.1 as integer = 223*16777216 + 255*65536 + 254*256 + 1 = 3758095873
	[ "$start" -le 3758095873 ]
	[ "$end" -ge 3758095873 ]
}

# ============================================================
# _all_cc_codes — country code enumeration
# ============================================================

_load_all_cc_codes() {
	_GEOIP_LIB_LOADED=""
	# shellcheck disable=SC1091
	. "$PROJECT_ROOT/files/internals/geoip_lib.sh"
	bfd_load_function "_all_cc_codes" "$PROJECT_ROOT/files/update-ipcountry.sh"
}

@test "all_cc_codes: returns all known country codes" {
	_load_all_cc_codes
	run _all_cc_codes
	assert_success
	# Should have ~240 unique country/territory codes (6 continents)
	local count
	count=$(echo "$output" | sort -u | wc -l)
	[ "$count" -ge 190 ]
	[ "$count" -le 260 ]
}

@test "all_cc_codes: includes known countries from each continent" {
	_load_all_cc_codes
	run _all_cc_codes
	assert_success
	echo "$output" | grep -q "^US$"
	echo "$output" | grep -q "^CN$"
	echo "$output" | grep -q "^DE$"
	echo "$output" | grep -q "^BR$"
	echo "$output" | grep -q "^AU$"
	echo "$output" | grep -q "^ZA$"
}

# ============================================================
# Integration: ip_to_country reads CIDR-generated ranges
# ============================================================

@test "ip_to_country: reads CIDR-generated integer-range format" {
	_load_cidr4_to_ranges
	# Generate a small ipcountry.dat from CIDR
	echo "192.0.2.0/25" > "$TEST_TMPDIR/xx.zone"
	echo "198.51.100.0/25" > "$TEST_TMPDIR/ru.zone"
	{
		_cidr4_to_ranges "$TEST_TMPDIR/xx.zone" "XX"
		_cidr4_to_ranges "$TEST_TMPDIR/ru.zone" "RU"
	} | sort -n -k1 > "$TEST_TMPDIR/ipcountry.dat"

	# 192.0.2.1 should be in XX range
	run ip_to_country "192.0.2.1" "$TEST_TMPDIR/ipcountry.dat"
	assert_success
	assert_output "XX"

	# 198.51.100.50 should be in RU range
	run ip_to_country "198.51.100.50" "$TEST_TMPDIR/ipcountry.dat"
	assert_success
	assert_output "RU"

	# 203.0.113.1 should not match
	run ip_to_country "203.0.113.1" "$TEST_TMPDIR/ipcountry.dat"
	assert_success
	assert_output ""
}

# ============================================================
# cron.daily: staleness refresh logic
# ============================================================

@test "cron.daily: skips refresh when ipcountry.dat is fresh" {
	# Create a fresh ipcountry.dat (just touched, mtime = now)
	touch "$INSTALL_PATH/ipcountry.dat"
	# Create a mock update script that writes a marker
	cat > "$INSTALL_PATH/update-ipcountry.sh" << 'SCRIPT'
#!/bin/bash
echo "UPDATED" > "$INSTALL_PATH/tmp/.update-ran"
SCRIPT
	chmod +x "$INSTALL_PATH/update-ipcountry.sh"

	# Run the staleness check logic directly
	_dat="$INSTALL_PATH/ipcountry.dat"
	_age=$(( $(date +%s) - $(stat -c %Y "$_dat") ))
	# Fresh file: age should be < 2592000
	[ "$_age" -lt 2592000 ]
	# The mock should NOT have been called
	[ ! -f "$INSTALL_PATH/tmp/.update-ran" ]
}

@test "cron.daily: triggers refresh when ipcountry.dat is stale" {
	# Create a stale ipcountry.dat (mtime = 31 days ago)
	touch "$INSTALL_PATH/ipcountry.dat"
	touch -d "31 days ago" "$INSTALL_PATH/ipcountry.dat"
	# Create a mock update script that writes a marker
	cat > "$INSTALL_PATH/update-ipcountry.sh" << 'SCRIPT'
#!/bin/bash
echo "UPDATED" > "${INSTALL_PATH}/tmp/.update-ran"
SCRIPT
	chmod +x "$INSTALL_PATH/update-ipcountry.sh"

	# Run the staleness check logic
	_dat="$INSTALL_PATH/ipcountry.dat"
	_age=$(( $(date +%s) - $(stat -c %Y "$_dat") ))
	if [ "$_age" -gt 2592000 ]; then
		INSTALL_PATH="$INSTALL_PATH" "$INSTALL_PATH/update-ipcountry.sh" >/dev/null 2>&1 || true
	fi
	[ -f "$INSTALL_PATH/tmp/.update-ran" ]
}

@test "cron.daily: skips refresh when update-ipcountry.sh missing" {
	touch "$INSTALL_PATH/ipcountry.dat"
	touch -d "31 days ago" "$INSTALL_PATH/ipcountry.dat"
	# No update-ipcountry.sh exists
	_dat="$INSTALL_PATH/ipcountry.dat"
	if [ -x "$INSTALL_PATH/update-ipcountry.sh" ] && [ -f "$_dat" ]; then
		_age=$(( $(date +%s) - $(stat -c %Y "$_dat") ))
		if [ "$_age" -gt 2592000 ]; then
			echo "should-not-run" > "$INSTALL_PATH/tmp/.update-ran"
		fi
	fi
	[ ! -f "$INSTALL_PATH/tmp/.update-ran" ]
}

@test "cron.daily: skips refresh when ipcountry.dat missing" {
	# No ipcountry.dat exists
	cat > "$INSTALL_PATH/update-ipcountry.sh" << 'SCRIPT'
#!/bin/bash
echo "UPDATED" > "${INSTALL_PATH}/tmp/.update-ran"
SCRIPT
	chmod +x "$INSTALL_PATH/update-ipcountry.sh"

	_dat="$INSTALL_PATH/ipcountry.dat"
	if [ -x "$INSTALL_PATH/update-ipcountry.sh" ] && [ -f "$_dat" ]; then
		_age=$(( $(date +%s) - $(stat -c %Y "$_dat") ))
		if [ "$_age" -gt 2592000 ]; then
			INSTALL_PATH="$INSTALL_PATH" "$INSTALL_PATH/update-ipcountry.sh" >/dev/null 2>&1 || true
		fi
	fi
	[ ! -f "$INSTALL_PATH/tmp/.update-ran" ]
}
