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

# ============================================================
# pressure-country.conf format migration
# ============================================================

@test "country_weight reads whitespace-delimited format" {
	cat > "$TEST_TMPDIR/pcountry.conf" <<'EOF'
CN 20
RU 15
EOF
	run country_weight "CN" "$TEST_TMPDIR/pcountry.conf"
	assert_success
	assert_output "20"
}

@test "country_weight reads old CC=MULT format (backward compat)" {
	cat > "$TEST_TMPDIR/pcountry.conf" <<'EOF'
CN=20
RU=15
EOF
	run country_weight "CN" "$TEST_TMPDIR/pcountry.conf"
	assert_success
	assert_output "20"
}

@test "pressure-country.conf whitespace format loads into _cw_map" {
	bfd_require_bash42
	cat > "$INSTALL_PATH/pressure-country.conf" <<'EOF'
CN 20
RU 15
EOF
	# Load _cw_map using the same pattern as check() in bfd_core.sh
	declare -A _cw_map
	local _cw_file="$INSTALL_PATH/pressure-country.conf"
	local _cw_cc _cw_val
	while read -r _cw_cc _cw_val; do
		[[ "$_cw_cc" == \#* ]] && continue
		[ -z "$_cw_cc" ] && continue
		# dual-format: handle both CC=MULT (old) and CC MULT (new)
		if [[ "$_cw_cc" == *=* ]]; then
			_cw_val="${_cw_cc#*=}"
			_cw_cc="${_cw_cc%%=*}"
		fi
		[ -z "$_cw_val" ] && continue
		_cw_map[$_cw_cc]="$_cw_val"
	done < "$_cw_file"

	[ "${_cw_map[CN]}" = "20" ]
	[ "${_cw_map[RU]}" = "15" ]
}

# ============================================================
# Detection pipeline CDN integration (Phase 3)
# ============================================================

# Helper: set up minimal check() environment for CDN integration tests
_cdn_setup_check_env() {
	local rules_dir="$1"
	RULES_PATH="$rules_dir"
	GLOB_PRESSURE_TRIP="5"
	GLOB_TRIG="5"
	PRESSURE_HALF_LIFE="300"
	TRIG_WINDOW="300"
	PRESSURE_TRIP_GLOBAL="0"
	TRIG_GLOBAL="0"
	UTIME="1000"
	IGNORE_HOST_FILES="$TEST_TMPDIR/exclude.files"
	LO_HOSTS="$TEST_TMPDIR/lo_hosts"
	touch "$IGNORE_HOST_FILES" "$LO_HOSTS"
	BAN_COMMAND_TEMPLATE="/bin/true"
	BAN_COMMAND_V6_TEMPLATE=""
	DRY_RUN="0"
	BAN_TTL="0"
	BAN_DURATION="0"
	BAN_ESCALATE_AFTER="0"
	BAN_PERMANENT_AFTER="0"
	BAN_ESCALATE_WINDOW="86400"
	BAN_PERMANENT_WINDOW="86400"
	SKIP_ALERT=""
	EMAIL_ALERTS="0"
	SUBNET_TRIG="0"
}

# Helper: create a rule file with given MATCHED_HOSTS
_cdn_create_rule() {
	local rules_dir="$1" name="$2" hosts="$3" trip="${4:-2}"
	local logfile="$TEST_TMPDIR/test.log"
	echo "test line" > "$logfile"
	cat > "$rules_dir/$name" <<RULEEOF
TRIG="$trip"
PREREQ="/bin/sh"
LOG_FILE="$logfile"
LOG_TAG="$name"
MATCHED_HOSTS="$hosts"
RULEEOF
	chmod 644 "$rules_dir/$name"
	chown root "$rules_dir/$name"
}

@test "CDN_ENABLE=0 skips all CDN processing" {
	bfd_require_bash42
	local rules_dir="$TEST_TMPDIR/rules"
	mkdir -p "$rules_dir"
	# IP in CDN range, 3 events at trip=2 -> should ban normally
	_cdn_create_rule "$rules_dir" "testrule" "1.0.0.50 1.0.0.50 1.0.0.50"
	# Create cdn.dat with range covering 1.0.0.0/24 = 16777216..16777471
	# treatment=ignore should block the IP, but CDN_ENABLE=0 means it is skipped
	cat > "$INSTALL_PATH/cdn.dat" <<'EOF'
16777216 16777471 cloudflare ignore 10
EOF
	CDN_ENABLE="0"
	_cdn_setup_check_env "$rules_dir"
	run check
	assert_success
	# IP should be banned because CDN is disabled
	assert_output --partial "1 bans executed"
}

@test "missing cdn.dat is no-op when CDN_ENABLE=1" {
	bfd_require_bash42
	local rules_dir="$TEST_TMPDIR/rules"
	mkdir -p "$rules_dir"
	_cdn_create_rule "$rules_dir" "testrule" "1.0.0.50 1.0.0.50 1.0.0.50"
	# No cdn.dat file
	CDN_ENABLE="1"
	_cdn_setup_check_env "$rules_dir"
	run check
	assert_success
	# IP should be banned normally — missing cdn.dat is no-op
	assert_output --partial "1 bans executed"
}

@test "cdn ignore treatment skips IP in detection loop" {
	bfd_require_bash42
	local rules_dir="$TEST_TMPDIR/rules"
	mkdir -p "$rules_dir"
	# IP 1.0.0.50 -> int ~16777266, inside 1.0.0.0/24 range (16777216..16777471)
	_cdn_create_rule "$rules_dir" "testrule" "1.0.0.50 1.0.0.50 1.0.0.50"
	cat > "$INSTALL_PATH/cdn.dat" <<'EOF'
16777216 16777471 cloudflare ignore 10
EOF
	CDN_ENABLE="1"
	_cdn_setup_check_env "$rules_dir"
	run check
	assert_success
	# IP should NOT be banned — cdn ignore skips entirely
	assert_output --partial "0 bans executed"
	# attack.pool should not contain this IP (skipped before pool write)
	run grep "1.0.0.50" "$INSTALL_PATH/stats/attack.pool"
	[ "$status" -ne 0 ]
}

@test "cdn exclude treatment records event but skips ban" {
	bfd_require_bash42
	local rules_dir="$TEST_TMPDIR/rules"
	mkdir -p "$rules_dir"
	_cdn_create_rule "$rules_dir" "testrule" "1.0.0.50 1.0.0.50 1.0.0.50"
	cat > "$INSTALL_PATH/cdn.dat" <<'EOF'
16777216 16777471 cloudflare exclude 10
EOF
	CDN_ENABLE="1"
	_cdn_setup_check_env "$rules_dir"
	run check
	assert_success
	# IP should NOT be banned — cdn exclude skips ban
	assert_output --partial "0 bans executed"
	# attack.pool should contain the IP with ACTION=cdn-exclude
	grep -q "cdn-exclude" "$INSTALL_PATH/stats/attack.pool"
	grep -q "1.0.0.50" "$INSTALL_PATH/stats/attack.pool"
}

@test "cdn derate treatment reduces pressure multiplier" {
	bfd_require_bash42
	local rules_dir="$TEST_TMPDIR/rules"
	mkdir -p "$rules_dir"
	# 4 events at trip=5, weight=1 -> pressure=4.0 < 5 -> no ban normally
	# With derate mult=3 (0.3x), weight goes from 1 -> (1*3+5)/10 = 0 -> clamp to 1
	# So derate with mult=3 still has weight=1 (min clamp)
	# Instead: use trip=3, events=4 -> pressure=4.0 >= 3 -> ban
	# With derate mult=5 (0.5x), weight=1 -> (1*5+5)/10 = 1 -> still 1 (min clamp)
	# Need higher initial weight. Use PRESSURE_WEIGHT in rule.
	# Alternatively: 10 events at trip=5 -> pressure=10 >= 5 -> ban normally
	# With derate mult=3 -> scoring_weight = (1*3+5)/10 = 0 -> clamp to 1 -> still bans
	# The derate only changes scoring_weight. To test it meaningfully:
	# Set eff_weight=10, trip=5, 1 event -> pressure=10 >= 5 -> ban
	# With derate mult=3 -> scoring_weight = (10*3+5)/10 = 3 -> pressure=3 < 5 -> no ban
	_cdn_create_rule "$rules_dir" "testrule" "1.0.0.50" "5"
	cat >> "$rules_dir/testrule" <<'EOF'
PRESSURE_WEIGHT="10"
EOF
	cat > "$INSTALL_PATH/cdn.dat" <<'EOF'
16777216 16777471 cloudflare derate 3
EOF
	CDN_ENABLE="1"
	_cdn_setup_check_env "$rules_dir"
	run check
	assert_success
	# Without derate: weight=10, 1 event -> pressure=10 >= trip=5 -> ban
	# With derate mult=3: weight=10*(3/10)=3, 1 event -> pressure=3 < 5 -> no ban
	assert_output --partial "0 bans executed"
	# Pool should have an observed entry (sub-trip)
	grep -q "1.0.0.50" "$INSTALL_PATH/stats/attack.pool"
	grep -q "observed" "$INSTALL_PATH/stats/attack.pool"
}

@test "cdn treatment is per-provider independent" {
	bfd_require_bash42
	local rules_dir="$TEST_TMPDIR/rules"
	mkdir -p "$rules_dir"
	# Two IPs from different CDN ranges, different treatments
	# 1.0.0.50 (16777266) -> cloudflare ignore
	# 10.0.0.50 (167772210) -> fastly exclude
	# 192.168.1.50 (3232235826) -> no CDN match, should ban normally
	_cdn_create_rule "$rules_dir" "testrule" "1.0.0.50 1.0.0.50 1.0.0.50 10.0.0.50 10.0.0.50 10.0.0.50 192.168.1.50 192.168.1.50 192.168.1.50"
	cat > "$INSTALL_PATH/cdn.dat" <<'EOF'
16777216 16777471 cloudflare ignore 10
167772160 167772415 fastly exclude 10
EOF
	CDN_ENABLE="1"
	_cdn_setup_check_env "$rules_dir"
	run check
	assert_success
	# 1.0.0.50: cdn ignore -> skipped entirely (no ban, no pool)
	# 10.0.0.50: cdn exclude -> recorded as cdn-exclude, no ban
	# 192.168.1.50: normal -> should be banned
	assert_output --partial "1 bans executed"
	# Verify pool contents
	local pool="$INSTALL_PATH/stats/attack.pool"
	# 1.0.0.50 should NOT be in pool (ignore skips it)
	run grep "1.0.0.50" "$pool"
	[ "$status" -ne 0 ]
	# 10.0.0.50 should be in pool as cdn-exclude
	grep -q "10.0.0.50.*cdn-exclude" "$pool"
	# 192.168.1.50 should be in pool as ban (or ban-failed since DRY_RUN=0 with /bin/true)
	grep -q "192.168.1.50" "$pool"
}
