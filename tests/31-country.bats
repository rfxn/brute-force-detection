#!/usr/bin/env bats
#
# Test suite for country multiplier functions:
#   ip_to_country(), country_weight(), pressure_effective_weight()
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

setup() {
	bfd_standard_setup
	# create a small test IP-to-country database (RFC 5737 ranges only)
	cat > "$INSTALL_PATH/ipcountry.dat" <<'EOF'
# Test IP-to-country database — RFC 5737 documentation ranges only
# 192.0.2.0-127 = XX (TEST-NET-1 lower half)
3221225984 3221226111 XX
# 192.0.2.128-255 = CN (TEST-NET-1 upper half)
3221226112 3221226239 CN
# 198.51.100.0-125 = RU (TEST-NET-2 partial)
3325256704 3325256829 RU
# 203.0.113.0-124 = US (TEST-NET-3 partial)
3405803776 3405803900 US
EOF

	# create a test weights file
	cat > "$INSTALL_PATH/pressure-country.conf" <<'EOF'
# Test country weights
CN=20
RU=15
US=10
XX=10
EOF
}

teardown() {
	bfd_teardown
}

# ============================================================
# ip_to_country()
# ============================================================

@test "ip_to_country: finds CN for 192.0.2.128 (upper half)" {
	run ip_to_country "192.0.2.128" "$INSTALL_PATH/ipcountry.dat"
	assert_success
	assert_output "CN"
}

@test "ip_to_country: finds XX for 192.0.2.1 (lower half)" {
	run ip_to_country "192.0.2.1" "$INSTALL_PATH/ipcountry.dat"
	assert_success
	assert_output "XX"
}

@test "ip_to_country: finds RU for 198.51.100.50" {
	run ip_to_country "198.51.100.50" "$INSTALL_PATH/ipcountry.dat"
	assert_success
	assert_output "RU"
}

@test "ip_to_country: finds US for 203.0.113.100" {
	run ip_to_country "203.0.113.100" "$INSTALL_PATH/ipcountry.dat"
	assert_success
	assert_output "US"
}

@test "ip_to_country: returns empty for unknown IP" {
	run ip_to_country "198.51.100.200" "$INSTALL_PATH/ipcountry.dat"
	assert_success
	assert_output ""
}

@test "ip_to_country: returns CC for IPv6 when db6 present" {
	# Create a small hex-range IPv6 database
	# 2001:0db8:: range = 20010db8 00000000 00000000 00000000
	cat > "$INSTALL_PATH/ipcountry6.dat" <<'EOF'
20010db8000000000000000000000000 20010db8ffffffffffffffffffffffff JP
20010db9000000000000000000000000 20010db9ffffffffffffffffffffffff DE
EOF
	run ip_to_country "2001:db8::1" "$INSTALL_PATH/ipcountry.dat"
	assert_success
	assert_output "JP"
}

@test "ip_to_country: returns empty for IPv6 when db6 absent" {
	# No ipcountry6.dat exists
	run ip_to_country "2001:db8::1" "$INSTALL_PATH/ipcountry.dat"
	assert_success
	assert_output ""
}

@test "ip_to_country: IPv6 abbreviation forms resolve correctly" {
	cat > "$INSTALL_PATH/ipcountry6.dat" <<'EOF'
20010db8000000000000000000000000 20010db8ffffffffffffffffffffffff JP
EOF
	# Full form
	run ip_to_country "2001:0db8:0000:0000:0000:0000:0000:0001" "$INSTALL_PATH/ipcountry.dat"
	assert_success
	assert_output "JP"
	# ::compressed
	run ip_to_country "2001:db8::1" "$INSTALL_PATH/ipcountry.dat"
	assert_success
	assert_output "JP"
	# Mixed case
	run ip_to_country "2001:0DB8::1" "$INSTALL_PATH/ipcountry.dat"
	assert_success
	assert_output "JP"
}

@test "ip_to_country: old raw-CIDR ipcountry6.dat returns empty (format guard)" {
	# Simulate old raw-CIDR format (contains colons)
	cat > "$INSTALL_PATH/ipcountry6.dat" <<'EOF'
2001:db8::/32 JP
2001:db9::/32 DE
EOF
	run ip_to_country "2001:db8::1" "$INSTALL_PATH/ipcountry.dat"
	assert_success
	assert_output ""
}

@test "ip_to_country: returns empty for missing DB file" {
	run ip_to_country "192.0.2.1" "/nonexistent/ipcountry.dat"
	assert_success
	assert_output ""
}

@test "ip_to_country: returns empty for empty DB file" {
	> "$INSTALL_PATH/ipcountry.dat"
	run ip_to_country "192.0.2.1" "$INSTALL_PATH/ipcountry.dat"
	assert_success
	assert_output ""
}

# ============================================================
# country_weight()
# ============================================================

@test "country_weight: returns 20 for CN" {
	run country_weight "CN" "$INSTALL_PATH/pressure-country.conf"
	assert_success
	assert_output "20"
}

@test "country_weight: returns 15 for RU" {
	run country_weight "RU" "$INSTALL_PATH/pressure-country.conf"
	assert_success
	assert_output "15"
}

@test "country_weight: returns 10 for US (1.0x)" {
	run country_weight "US" "$INSTALL_PATH/pressure-country.conf"
	assert_success
	assert_output "10"
}

@test "country_weight: returns 10 for unlisted country" {
	run country_weight "DE" "$INSTALL_PATH/pressure-country.conf"
	assert_success
	assert_output "10"
}

@test "country_weight: returns 10 for empty country code" {
	run country_weight "" "$INSTALL_PATH/pressure-country.conf"
	assert_success
	assert_output "10"
}

@test "country_weight: returns 10 for missing weights file" {
	run country_weight "CN" "/nonexistent/pressure-country.conf"
	assert_success
	assert_output "10"
}

# ============================================================
# pressure_effective_weight()
# ============================================================

@test "pressure_effective_weight: multiplies by country factor" {
	# CN = 20 (2.0x), rule weight = 3 → 3*20/10 = 6
	run pressure_effective_weight "3" "192.0.2.128" "$INSTALL_PATH"
	assert_success
	assert_output "6"
}

@test "pressure_effective_weight: RU factor applied" {
	# RU = 15 (1.5x), rule weight = 2 → 2*15/10 = 3
	run pressure_effective_weight "2" "198.51.100.50" "$INSTALL_PATH"
	assert_success
	assert_output "3"
}

@test "pressure_effective_weight: US factor is 1.0x (no change)" {
	# US = 10 (1.0x), rule weight = 3 → 3*10/10 = 3
	run pressure_effective_weight "3" "203.0.113.100" "$INSTALL_PATH"
	assert_success
	assert_output "3"
}

@test "pressure_effective_weight: unknown IP returns weight unchanged" {
	# unknown IP → no country → passthrough
	run pressure_effective_weight "3" "198.51.100.200" "$INSTALL_PATH"
	assert_success
	assert_output "3"
}

@test "pressure_effective_weight: missing DB returns weight unchanged" {
	rm -f "$INSTALL_PATH/ipcountry.dat"
	run pressure_effective_weight "3" "192.0.2.128" "$INSTALL_PATH"
	assert_success
	assert_output "3"
}

@test "pressure_effective_weight: missing weights file returns weight unchanged" {
	rm -f "$INSTALL_PATH/pressure-country.conf"
	run pressure_effective_weight "3" "192.0.2.128" "$INSTALL_PATH"
	assert_success
	assert_output "3"
}

@test "pressure_effective_weight: IPv6 returns weight unchanged" {
	run pressure_effective_weight "3" "2001:db8::1" "$INSTALL_PATH"
	assert_success
	assert_output "3"
}

@test "pressure_effective_weight: result minimum is 1" {
	# set a very low multiplier
	echo "XX=1" > "$INSTALL_PATH/pressure-country.conf"
	# weight=1, mult=1 → 1*1/10 = 0 → minimum 1
	run pressure_effective_weight "1" "192.0.2.1" "$INSTALL_PATH"
	assert_success
	assert_output "1"
}

# ============================================================
# ip_to_country() cache behavior (_COUNTRY_CACHE_FILE)
# ============================================================

@test "ip_to_country: cache miss populates cache file" {
	_COUNTRY_CACHE_FILE=$(mktemp "$TEST_TMPDIR/cc_cache.XXXXXX")
	run ip_to_country "192.0.2.128" "$INSTALL_PATH/ipcountry.dat"
	assert_success
	assert_output "CN"
	# verify cache was populated
	run grep -c "^192.0.2.128 " "$_COUNTRY_CACHE_FILE"
	assert_output "1"
	rm -f "$_COUNTRY_CACHE_FILE"
	_COUNTRY_CACHE_FILE=""
}

@test "ip_to_country: cache hit returns cached value over DB" {
	_COUNTRY_CACHE_FILE=$(mktemp "$TEST_TMPDIR/cc_cache.XXXXXX")
	# cache says ZZ, DB says CN for 192.0.2.128 — cache must win
	echo "192.0.2.128 ZZ" > "$_COUNTRY_CACHE_FILE"
	run ip_to_country "192.0.2.128" "$INSTALL_PATH/ipcountry.dat"
	assert_success
	assert_output "ZZ"
	rm -f "$_COUNTRY_CACHE_FILE"
	_COUNTRY_CACHE_FILE=""
}

@test "ip_to_country: cache stores sentinel for unknown IPs" {
	_COUNTRY_CACHE_FILE=$(mktemp "$TEST_TMPDIR/cc_cache.XXXXXX")
	run ip_to_country "198.51.100.200" "$INSTALL_PATH/ipcountry.dat"
	assert_success
	assert_output ""
	# verify sentinel "-" stored
	run grep "^198.51.100.200 " "$_COUNTRY_CACHE_FILE"
	assert_output "198.51.100.200 -"
	rm -f "$_COUNTRY_CACHE_FILE"
	_COUNTRY_CACHE_FILE=""
}

@test "ip_to_country: cached sentinel returns empty string" {
	_COUNTRY_CACHE_FILE=$(mktemp "$TEST_TMPDIR/cc_cache.XXXXXX")
	echo "198.51.100.200 -" > "$_COUNTRY_CACHE_FILE"
	run ip_to_country "198.51.100.200" "$INSTALL_PATH/ipcountry.dat"
	assert_success
	assert_output ""
	rm -f "$_COUNTRY_CACHE_FILE"
	_COUNTRY_CACHE_FILE=""
}

@test "ip_to_country: no cache when _COUNTRY_CACHE_FILE unset" {
	_COUNTRY_CACHE_FILE=""
	run ip_to_country "192.0.2.128" "$INSTALL_PATH/ipcountry.dat"
	assert_success
	assert_output "CN"
}

@test "ip_to_country: IPv6 cache hit after first lookup" {
	cat > "$INSTALL_PATH/ipcountry6.dat" <<'EOF'
20010db8000000000000000000000000 20010db8ffffffffffffffffffffffff JP
EOF
	_COUNTRY_CACHE_FILE=$(mktemp "$TEST_TMPDIR/cc_cache.XXXXXX")
	run ip_to_country "2001:db8::1" "$INSTALL_PATH/ipcountry.dat"
	assert_success
	assert_output "JP"
	# verify cache was populated with IPv6 entry
	run grep -c "^2001:db8::1 " "$_COUNTRY_CACHE_FILE"
	assert_output "1"
	# second lookup should hit cache
	run ip_to_country "2001:db8::1" "$INSTALL_PATH/ipcountry.dat"
	assert_success
	assert_output "JP"
	rm -f "$_COUNTRY_CACHE_FILE"
	_COUNTRY_CACHE_FILE=""
}

# ============================================================
# COUNTRY_DISPLAY enrichment via _alert_set_entry_vars()
# ============================================================

# helper: minimal _alert_set_entry_vars call with country lookup
_run_entry_vars_country() {
	local ip="$1"
	BAN_COMMAND_TEMPLATE="echo ban \$ATTACK_HOST"
	_FW_BACKEND="custom"
	BAN_ESCALATE_AFTER="0"
	BAN_ESCALATION="none"
	EMAIL_REPUTATION_LINKS=""
	local line="${ip}|sshd|22|5000|0|ban|0||root|10|300|1|5"
	_alert_set_entry_vars "$line" 1 1
}

@test "COUNTRY_DISPLAY: geoip_lib present shows 'China (CN)'" {
	# geoip_lib.sh is sourced by bfd.lib.sh; geoip_cc_name should be available
	declare -f geoip_cc_name >/dev/null 2>&1 || skip "geoip_lib not loaded"
	_run_entry_vars_country "192.0.2.128"
	[ "$COUNTRY_CODE" = "CN" ]
	[ "$COUNTRY_DISPLAY" = "China (CN)" ]
}

@test "COUNTRY_DISPLAY: geoip_lib present shows 'Russia (RU)'" {
	declare -f geoip_cc_name >/dev/null 2>&1 || skip "geoip_lib not loaded"
	_run_entry_vars_country "198.51.100.50"
	[ "$COUNTRY_CODE" = "RU" ]
	[ "$COUNTRY_DISPLAY" = "Russia (RU)" ]
}

@test "COUNTRY_DISPLAY: geoip_lib present shows 'United States (US)'" {
	declare -f geoip_cc_name >/dev/null 2>&1 || skip "geoip_lib not loaded"
	_run_entry_vars_country "203.0.113.100"
	[ "$COUNTRY_CODE" = "US" ]
	[ "$COUNTRY_DISPLAY" = "United States (US)" ]
}

@test "COUNTRY_DISPLAY: unknown IP shows '--'" {
	_run_entry_vars_country "198.51.100.200"
	[ "$COUNTRY_CODE" = "--" ]
	[ "$COUNTRY_DISPLAY" = "--" ]
}

@test "COUNTRY_DISPLAY: unknown CC returns bare code (geoip_cc_name passthrough)" {
	# XX is in our test DB but not in geoip_cc_name's case table — returns bare "XX"
	declare -f geoip_cc_name >/dev/null 2>&1 || skip "geoip_lib not loaded"
	_run_entry_vars_country "192.0.2.1"
	[ "$COUNTRY_CODE" = "XX" ]
	[ "$COUNTRY_DISPLAY" = "XX" ]
}

@test "COUNTRY_DISPLAY: graceful degradation without geoip_lib" {
	# temporarily unset geoip_cc_name to simulate lib not loaded
	local _saved_func
	_saved_func=$(declare -f geoip_cc_name 2>/dev/null) || true
	unset -f geoip_cc_name 2>/dev/null || true
	_run_entry_vars_country "192.0.2.128"
	[ "$COUNTRY_CODE" = "CN" ]
	[ "$COUNTRY_DISPLAY" = "CN" ]
	# restore function
	if [ -n "$_saved_func" ]; then
		eval "$_saved_func"
	fi
}

# ============================================================
# COUNTRY_DISPLAY_TG — Telegram MarkdownV2-escaped variant
# ============================================================

@test "COUNTRY_DISPLAY_TG: parentheses escaped for MarkdownV2" {
	declare -f geoip_cc_name >/dev/null 2>&1 || skip "geoip_lib not loaded"
	_run_entry_vars_country "192.0.2.128"
	[ "$COUNTRY_DISPLAY" = "China (CN)" ]
	[ "$COUNTRY_DISPLAY_TG" = 'China \(CN\)' ]
}

@test "COUNTRY_DISPLAY_TG: bare code without parens unchanged" {
	# temporarily unset geoip_cc_name to simulate lib not loaded
	local _saved_func
	_saved_func=$(declare -f geoip_cc_name 2>/dev/null) || true
	unset -f geoip_cc_name 2>/dev/null || true
	_run_entry_vars_country "192.0.2.128"
	[ "$COUNTRY_DISPLAY" = "CN" ]
	[ "$COUNTRY_DISPLAY_TG" = "CN" ]
	# restore function
	if [ -n "$_saved_func" ]; then
		eval "$_saved_func"
	fi
}

@test "COUNTRY_DISPLAY_TG: dash-dash unchanged" {
	_run_entry_vars_country "198.51.100.200"
	[ "$COUNTRY_DISPLAY" = "--" ]
	[ "$COUNTRY_DISPLAY_TG" = '\-\-' ]
}

# ============================================================
# _batch_ip_to_country()
# ============================================================

@test "_batch_ip_to_country: no-db fallback outputs 'IP -' for each IP" {
	local result
	result=$(printf '192.0.2.1\n192.0.2.2\n' | _batch_ip_to_country "/nonexistent/ipcountry.dat")
	echo "$result" | grep -q "192.0.2.1 -"
	echo "$result" | grep -q "192.0.2.2 -"
}

@test "_batch_ip_to_country: empty db file outputs 'IP -'" {
	> "$INSTALL_PATH/ipcountry.dat"
	local result
	result=$(printf '192.0.2.1\n' | _batch_ip_to_country "$INSTALL_PATH/ipcountry.dat")
	[ "$result" = "192.0.2.1 -" ]
}

@test "_batch_ip_to_country: single IPv4 match returns correct CC" {
	local result
	result=$(printf '192.0.2.128\n' | _batch_ip_to_country "$INSTALL_PATH/ipcountry.dat")
	[ "$result" = "192.0.2.128 CN" ]
}

@test "_batch_ip_to_country: multiple IPs resolved in one pass" {
	local result
	result=$(printf '192.0.2.1\n192.0.2.128\n198.51.100.50\n203.0.113.100\n' \
		| _batch_ip_to_country "$INSTALL_PATH/ipcountry.dat")
	echo "$result" | grep -q "192.0.2.1 XX"
	echo "$result" | grep -q "192.0.2.128 CN"
	echo "$result" | grep -q "198.51.100.50 RU"
	echo "$result" | grep -q "203.0.113.100 US"
}

@test "_batch_ip_to_country: unknown IP returns dash" {
	local result
	result=$(printf '10.0.0.1\n' | _batch_ip_to_country "$INSTALL_PATH/ipcountry.dat")
	[ "$result" = "10.0.0.1 -" ]
}

@test "_batch_ip_to_country: IPv6 returns dash when db6 absent" {
	local result
	result=$(printf '2001:db8::1\n' | _batch_ip_to_country "$INSTALL_PATH/ipcountry.dat")
	[ "$result" = "2001:db8::1 -" ]
}

@test "_batch_ip_to_country: IPv6 returns CC when db6 present" {
	cat > "$INSTALL_PATH/ipcountry6.dat" <<'EOF'
20010db8000000000000000000000000 20010db8ffffffffffffffffffffffff JP
EOF
	local result
	result=$(printf '2001:db8::1\n' | _batch_ip_to_country "$INSTALL_PATH/ipcountry.dat")
	[ "$result" = "2001:db8::1 JP" ]
}

@test "_batch_ip_to_country: mixed IPv4+IPv6 returns correct CCs for both" {
	cat > "$INSTALL_PATH/ipcountry6.dat" <<'EOF'
20010db8000000000000000000000000 20010db8ffffffffffffffffffffffff JP
EOF
	local result
	result=$(printf '192.0.2.128\n2001:db8::1\n198.51.100.50\n' \
		| _batch_ip_to_country "$INSTALL_PATH/ipcountry.dat")
	echo "$result" | grep -q "192.0.2.128 CN"
	echo "$result" | grep -q "2001:db8::1 JP"
	echo "$result" | grep -q "198.51.100.50 RU"
}

@test "_batch_ip_to_country: old raw-CIDR ipcountry6.dat falls back to dash" {
	cat > "$INSTALL_PATH/ipcountry6.dat" <<'EOF'
2001:db8::/32 JP
EOF
	local result
	result=$(printf '2001:db8::1\n' | _batch_ip_to_country "$INSTALL_PATH/ipcountry.dat")
	[ "$result" = "2001:db8::1 -" ]
}

@test "_batch_ip_to_country: empty input produces no output" {
	local result
	result=$(printf '' | _batch_ip_to_country "$INSTALL_PATH/ipcountry.dat")
	[ -z "$result" ]
}
