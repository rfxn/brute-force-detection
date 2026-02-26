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
	# create a small test IP-to-country database
	cat > "$INSTALL_PATH/ipcountry.dat" <<'EOF'
# Test IP-to-country database
# 10.0.0.0/8 = CN (for testing — 167772160-184549375)
167772160 184549375 CN
# 192.0.2.0/24 = XX (RFC 5737 test range — 3221225984-3221226239)
3221225984 3221226239 XX
# 198.51.100.0/24 = RU (test range — 3325256704-3325256959)
3325256704 3325256959 RU
# 203.0.113.0/24 = US (test range — 3405803776-3405804031)
3405803776 3405804031 US
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

@test "ip_to_country: finds CN for 10.0.0.1" {
	run ip_to_country "10.0.0.1" "$INSTALL_PATH/ipcountry.dat"
	assert_success
	assert_output "CN"
}

@test "ip_to_country: finds XX for 192.0.2.1" {
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
	run ip_to_country "172.16.0.1" "$INSTALL_PATH/ipcountry.dat"
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
	run pressure_effective_weight "3" "10.0.0.1" "$INSTALL_PATH"
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
	run pressure_effective_weight "3" "172.16.0.1" "$INSTALL_PATH"
	assert_success
	assert_output "3"
}

@test "pressure_effective_weight: missing DB returns weight unchanged" {
	rm -f "$INSTALL_PATH/ipcountry.dat"
	run pressure_effective_weight "3" "10.0.0.1" "$INSTALL_PATH"
	assert_success
	assert_output "3"
}

@test "pressure_effective_weight: missing weights file returns weight unchanged" {
	rm -f "$INSTALL_PATH/pressure-country.conf"
	run pressure_effective_weight "3" "10.0.0.1" "$INSTALL_PATH"
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
