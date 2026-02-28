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

@test "ip_to_country: returns empty for IPv6" {
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
