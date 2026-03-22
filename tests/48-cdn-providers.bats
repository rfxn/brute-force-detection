#!/usr/bin/env bats
#
# Test suite for bfd_cdn.sh:
#   CDN provider config parsing, CIDR-to-range conversion,
#   database compilation, and binary-search IP lookup.
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

setup() {
	bfd_standard_setup
	mkdir -p "$INSTALL_PATH/internals"
	mkdir -p "$INSTALL_PATH/tmp"

	# Source bfd_cdn.sh into the test namespace
	_BFD_CDN_LOADED=""
	# shellcheck disable=SC1091
	. "$PROJECT_ROOT/files/internals/bfd_cdn.sh"
}

teardown() {
	bfd_teardown
}

# ============================================================
# Config parsing — _cdn_load_providers
# ============================================================

@test "cdn_load_providers: loads valid providers from config" {
	cat > "$TEST_TMPDIR/cdn.conf" <<'EOF'
# Comment line
cloudflare  ignore   10  text  https://example.com/v4  https://example.com/v6
fastly      exclude  10  json  https://example.com/v4  -
EOF
	# Call directly (not via run) so global arrays/count propagate
	_cdn_load_providers "$TEST_TMPDIR/cdn.conf"
	[ "$_CDN_COUNT" -eq 2 ]
	[ "${_CDN_NAMES[0]}" = "cloudflare" ]
	[ "${_CDN_TREATMENTS[0]}" = "ignore" ]
	[ "${_CDN_MULTS[0]}" = "10" ]
	[ "${_CDN_FORMATS[0]}" = "text" ]
	[ "${_CDN_URLS_V4[0]}" = "https://example.com/v4" ]
	[ "${_CDN_URLS_V6[0]}" = "https://example.com/v6" ]
	[ "${_CDN_NAMES[1]}" = "fastly" ]
	[ "${_CDN_TREATMENTS[1]}" = "exclude" ]
	[ "${_CDN_URLS_V6[1]}" = "-" ]
}

@test "cdn_load_providers: skips comments and blank lines" {
	cat > "$TEST_TMPDIR/cdn.conf" <<'EOF'
# This is a comment

# Another comment
cloudflare  ignore  10  text  https://example.com/v4  -

EOF
	_cdn_load_providers "$TEST_TMPDIR/cdn.conf"
	[ "$_CDN_COUNT" -eq 1 ]
	[ "${_CDN_NAMES[0]}" = "cloudflare" ]
}

@test "cdn_load_providers: rejects invalid treatment" {
	cat > "$TEST_TMPDIR/cdn.conf" <<'EOF'
badprov  invalid  10  text  https://example.com/v4  -
goodprov  derate  5  text  https://example.com/v4  -
EOF
	_cdn_load_providers "$TEST_TMPDIR/cdn.conf"
	[ "$_CDN_COUNT" -eq 1 ]
	[ "${_CDN_NAMES[0]}" = "goodprov" ]
}

@test "cdn_load_providers: rejects invalid format" {
	cat > "$TEST_TMPDIR/cdn.conf" <<'EOF'
badformat  ignore  10  xml  https://example.com/v4  -
goodprov   derate  5   json  https://example.com/v4  -
EOF
	_cdn_load_providers "$TEST_TMPDIR/cdn.conf"
	[ "$_CDN_COUNT" -eq 1 ]
	[ "${_CDN_NAMES[0]}" = "goodprov" ]
}

@test "cdn_load_providers: returns 1 for missing file" {
	run _cdn_load_providers "$TEST_TMPDIR/nonexistent.conf"
	assert_failure
}

@test "cdn_load_providers: all three treatments accepted" {
	cat > "$TEST_TMPDIR/cdn.conf" <<'EOF'
prov1  ignore   10  text  https://example.com/v4  -
prov2  exclude  10  json  https://example.com/v4  -
prov3  derate    5  text  https://example.com/v4  -
EOF
	_cdn_load_providers "$TEST_TMPDIR/cdn.conf"
	[ "$_CDN_COUNT" -eq 3 ]
	[ "${_CDN_TREATMENTS[0]}" = "ignore" ]
	[ "${_CDN_TREATMENTS[1]}" = "exclude" ]
	[ "${_CDN_TREATMENTS[2]}" = "derate" ]
}

# ============================================================
# CIDR conversion — _cdn_cidr_to_range_v4
# ============================================================

@test "cdn_cidr_to_range_v4: /24 produces correct 256-IP range" {
	# 192.168.1.0/24: start = 192*16777216 + 168*65536 + 1*256 + 0 = 3232235776
	# end = 3232235776 + 256 - 1 = 3232236031
	run _cdn_cidr_to_range_v4 "192.168.1.0/24"
	assert_success
	assert_output "3232235776 3232236031"
}

@test "cdn_cidr_to_range_v4: /13 produces correct large range" {
	# 172.64.0.0/13: start = 172*16777216 + 64*65536 = 2889875456
	# end = 2889875456 + 2^19 - 1 = 2889875456 + 524287 = 2890399743
	run _cdn_cidr_to_range_v4 "172.64.0.0/13"
	assert_success
	assert_output "2889875456 2890399743"
}

@test "cdn_cidr_to_range_v4: /32 produces single-IP range" {
	# 10.0.0.1/32: int = 10*16777216 + 0 + 0 + 1 = 167772161
	run _cdn_cidr_to_range_v4 "10.0.0.1/32"
	assert_success
	assert_output "167772161 167772161"
}

@test "cdn_cidr_to_range_v4: multiple conversions yield correct math" {
	local cases=(
		"1.0.0.0/24:16777216 16777471"
		"0.0.0.0/0:0 4294967295"
		"192.0.2.0/25:3221225984 3221226111"
	)
	local entry cidr expected
	for entry in "${cases[@]}"; do
		echo "# Testing ${entry%%:*}" >&3
		cidr="${entry%%:*}"
		expected="${entry#*:}"
		run _cdn_cidr_to_range_v4 "$cidr"
		assert_success
		assert_output "$expected"
	done
}

# ============================================================
# CIDR conversion — _cdn_cidr_to_range_v6
# ============================================================

@test "cdn_cidr_to_range_v6: /32 produces correct hex range" {
	run _cdn_cidr_to_range_v6 "2400:cb00::/32"
	assert_success
	# 2400:cb00:: -> 2400cb00 + 24 zeros = 2400cb00000000000000000000000000
	# end: 2400cb00 + 24 f's = 2400cb00ffffffffffffffffffffffff
	assert_output "2400cb00000000000000000000000000 2400cb00ffffffffffffffffffffffff"
}

@test "cdn_cidr_to_range_v6: /48 produces correct hex range" {
	run _cdn_cidr_to_range_v6 "2001:db8:abcd::/48"
	assert_success
	assert_output "20010db8abcd00000000000000000000 20010db8abcdffffffffffffffffffff"
}

@test "cdn_cidr_to_range_v6: output is 32-char hex without colons" {
	run _cdn_cidr_to_range_v6 "2001:db8::/32"
	assert_success
	refute_output --partial ":"
	local start end
	start=$(echo "$output" | awk '{print $1}')
	end=$(echo "$output" | awk '{print $2}')
	[ "${#start}" -eq 32 ]
	[ "${#end}" -eq 32 ]
}

# ============================================================
# Single lookup — _cdn_lookup
# ============================================================

@test "cdn_lookup: finds IP inside IPv4 range" {
	# Build a small cdn.dat: 192.168.1.0/24 = 3232235776..3232236031
	cat > "$TEST_TMPDIR/cdn.dat" <<'EOF'
3232235776 3232236031 cloudflare ignore 10
EOF
	run _cdn_lookup "192.168.1.50" "$TEST_TMPDIR/cdn.dat"
	assert_success
	assert_output "cloudflare ignore 10"
}

@test "cdn_lookup: rejects IP outside IPv4 range" {
	cat > "$TEST_TMPDIR/cdn.dat" <<'EOF'
3232235776 3232236031 cloudflare ignore 10
EOF
	run _cdn_lookup "10.0.0.1" "$TEST_TMPDIR/cdn.dat"
	assert_failure
}

@test "cdn_lookup: binary search works with multiple sorted ranges" {
	cat > "$TEST_TMPDIR/cdn.dat" <<'EOF'
16777216 16777471 cloudflare ignore 10
167772160 167772415 fastly exclude 10
3232235776 3232236031 akamai derate 3
EOF
	# Hit the middle range (10.0.0.50 = 167772210)
	run _cdn_lookup "10.0.0.50" "$TEST_TMPDIR/cdn.dat"
	assert_success
	assert_output "fastly exclude 10"

	# Hit the last range (192.168.1.1 = 3232235777)
	run _cdn_lookup "192.168.1.1" "$TEST_TMPDIR/cdn.dat"
	assert_success
	assert_output "akamai derate 3"

	# Miss between ranges
	run _cdn_lookup "172.16.0.1" "$TEST_TMPDIR/cdn.dat"
	assert_failure
}

# ============================================================
# Batch lookup — _batch_cdn_lookup
# ============================================================

@test "batch_cdn_lookup: matches multiple IPs in single pass" {
	cat > "$TEST_TMPDIR/cdn.dat" <<'EOF'
16777216 16777471 cloudflare ignore 10
3232235776 3232236031 fastly exclude 10
EOF
	local result
	result=$(printf '%s\n' "1.0.0.1" "192.168.1.100" "8.8.8.8" | _batch_cdn_lookup "$TEST_TMPDIR/cdn.dat")
	# 1.0.0.1 = 16777217 -> in range, match cloudflare
	echo "$result" | grep -q "^1.0.0.1 cloudflare ignore 10$"
	# 192.168.1.100 = 3232235876 -> in range, match fastly
	echo "$result" | grep -q "^192.168.1.100 fastly exclude 10$"
	# 8.8.8.8 should NOT appear in output
	local miss_count
	miss_count=$(echo "$result" | grep -c "^8.8.8.8" || true)  # grep -c exits 1 on 0 matches
	[ "$miss_count" -eq 0 ]
}

@test "batch_cdn_lookup: returns nothing when no database exists" {
	local result
	result=$(echo "1.0.0.1" | _batch_cdn_lookup "$TEST_TMPDIR/nonexistent.dat")
	[ -z "$result" ]
}

# ============================================================
# Compile DB — _cdn_compile_db with mock text provider
# ============================================================

@test "cdn_compile_db: builds database from text provider via file URL" {
	# Create a mock CIDR file served via file://
	cat > "$TEST_TMPDIR/mock-cidrs.txt" <<'EOF'
192.168.1.0/24
10.0.0.0/24
EOF
	# Create config pointing to file:// URL
	cat > "$TEST_TMPDIR/cdn.conf" <<EOF
mockprov  ignore  10  text  file://$TEST_TMPDIR/mock-cidrs.txt  -
EOF
	# Call directly (not via run) so global variables propagate
	_cdn_compile_db "$TEST_TMPDIR/cdn.conf" "$TEST_TMPDIR/cdn.dat" "$TEST_TMPDIR/cdn6.dat"
	[ "$_CDN_BUILD_COUNT" -eq 1 ]
	[ "$_CDN_BUILD_RANGES" -eq 2 ]

	# Verify database content — sorted by start integer
	[ -f "$TEST_TMPDIR/cdn.dat" ]
	local line_count
	line_count=$(wc -l < "$TEST_TMPDIR/cdn.dat")
	[ "$line_count" -eq 2 ]

	# 10.0.0.0/24 = 167772160 167772415 should be first (smaller start)
	local first_line
	first_line=$(head -1 "$TEST_TMPDIR/cdn.dat")
	echo "$first_line" | grep -q "^167772160 167772415 mockprov ignore 10$"
}

@test "cdn_compile_db: builds database from JSON provider via file URL" {
	# Create a mock JSON response with embedded CIDRs
	cat > "$TEST_TMPDIR/mock-response.json" <<'EOF'
{
  "prefixes": [
    {"ip_prefix": "172.64.0.0/13"},
    {"ip_prefix": "198.51.100.0/24"}
  ]
}
EOF
	cat > "$TEST_TMPDIR/cdn.conf" <<EOF
jsonprov  derate  5  json  file://$TEST_TMPDIR/mock-response.json  -
EOF
	# Call directly (not via run) so global variables propagate
	_cdn_compile_db "$TEST_TMPDIR/cdn.conf" "$TEST_TMPDIR/cdn.dat" "$TEST_TMPDIR/cdn6.dat"
	[ "$_CDN_BUILD_COUNT" -eq 1 ]
	[ "$_CDN_BUILD_RANGES" -eq 2 ]

	# Verify lookup works on compiled database
	run _cdn_lookup "172.70.0.1" "$TEST_TMPDIR/cdn.dat"
	assert_success
	assert_output "jsonprov derate 5"
}

@test "cdn_compile_db: handles failed fetch gracefully" {
	cat > "$TEST_TMPDIR/cdn.conf" <<'EOF'
badprov  ignore  10  text  http://192.0.2.1/nonexistent  -
EOF
	# Override curl/wget to force failure
	CDN_CURL_BIN=""
	CDN_WGET_BIN=""
	# Call directly (not via run) so global variables propagate
	_cdn_compile_db "$TEST_TMPDIR/cdn.conf" "$TEST_TMPDIR/cdn.dat" "$TEST_TMPDIR/cdn6.dat"
	[ "$_CDN_BUILD_FAIL" -eq 1 ]
	[ "$_CDN_BUILD_COUNT" -eq 0 ]
}

@test "cdn_compile_db: empty config creates empty databases" {
	cat > "$TEST_TMPDIR/cdn.conf" <<'EOF'
# All commented out
EOF
	run _cdn_compile_db "$TEST_TMPDIR/cdn.conf" "$TEST_TMPDIR/cdn.dat" "$TEST_TMPDIR/cdn6.dat"
	assert_success
	[ -f "$TEST_TMPDIR/cdn.dat" ]
	[ ! -s "$TEST_TMPDIR/cdn.dat" ]
}
