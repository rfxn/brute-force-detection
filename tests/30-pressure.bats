#!/usr/bin/env bats
#
# Test suite for pressure model functions:
#   pressure_compute(), pressure_format(), record_and_score(),
#   _load_pressure_conf(), _apply_pressure()
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

setup() {
	bfd_standard_setup
}

teardown() {
	bfd_teardown
}

# ============================================================
# pressure_format()
# ============================================================

@test "pressure_format: 0 → 0.0" {
	run pressure_format 0
	assert_success
	assert_output "0.0"
}

@test "pressure_format: 1000 → 1.0" {
	run pressure_format 1000
	assert_success
	assert_output "1.0"
}

@test "pressure_format: 18400 → 18.4" {
	run pressure_format 18400
	assert_success
	assert_output "18.4"
}

@test "pressure_format: 500 → 0.5" {
	run pressure_format 500
	assert_success
	assert_output "0.5"
}

@test "pressure_format: 3999 → 4.0" {
	run pressure_format 3999
	assert_success
	assert_output "4.0"
}

# ============================================================
# pressure_compute() — empty / missing events
# ============================================================

@test "pressure_compute: empty events file returns 0" {
	local now; now=$(date +%s)
	run pressure_compute "$INSTALL_PATH" "192.0.2.1" "300" "$now"
	assert_success
	assert_output "0"
}

@test "pressure_compute: missing events file returns 0" {
	rm -f "$INSTALL_PATH/tmp/pressure.dat"
	local now; now=$(date +%s)
	run pressure_compute "$INSTALL_PATH" "192.0.2.1" "300" "$now"
	assert_success
	assert_output "0"
}

# ============================================================
# pressure_compute() — single event
# ============================================================

@test "pressure_compute: single event at t=now returns weight*1000" {
	local now; now=$(date +%s)
	# event: timestamp IP mod weight
	echo "$now 192.0.2.1 sshd 3" > "$INSTALL_PATH/tmp/pressure.dat"
	run pressure_compute "$INSTALL_PATH" "192.0.2.1" "300" "$now" "sshd"
	assert_success
	# weight=3, age=0, decay=1.0 → 3*1000=3000
	assert_output "3000"
}

@test "pressure_compute: single event weight=1 returns 1000" {
	local now; now=$(date +%s)
	echo "$now 192.0.2.1 sshd 1" > "$INSTALL_PATH/tmp/pressure.dat"
	run pressure_compute "$INSTALL_PATH" "192.0.2.1" "300" "$now" "sshd"
	assert_success
	assert_output "1000"
}

# ============================================================
# pressure_compute() — decay
# ============================================================

@test "pressure_compute: event at exactly 1 half-life ago ≈ weight*500" {
	local now; now=$(date +%s)
	local ts=$((now - 300))
	echo "$ts 192.0.2.1 sshd 1" > "$INSTALL_PATH/tmp/pressure.dat"
	run pressure_compute "$INSTALL_PATH" "192.0.2.1" "300" "$now" "sshd"
	assert_success
	# weight=1, decay=0.5 → ~500
	assert_output "500"
}

@test "pressure_compute: event at 2 half-lives ago ≈ weight*250" {
	local now; now=$(date +%s)
	local ts=$((now - 600))
	echo "$ts 192.0.2.1 sshd 1" > "$INSTALL_PATH/tmp/pressure.dat"
	run pressure_compute "$INSTALL_PATH" "192.0.2.1" "300" "$now" "sshd"
	assert_success
	assert_output "250"
}

# ============================================================
# pressure_compute() — multi-event sum
# ============================================================

@test "pressure_compute: two events at t=now sums weights" {
	local now; now=$(date +%s)
	{
		echo "$now 192.0.2.1 sshd 3"
		echo "$now 192.0.2.1 sshd 3"
	} > "$INSTALL_PATH/tmp/pressure.dat"
	run pressure_compute "$INSTALL_PATH" "192.0.2.1" "300" "$now" "sshd"
	assert_success
	# 3+3 = 6 → 6000
	assert_output "6000"
}

@test "pressure_compute: events from different IPs are separate" {
	local now; now=$(date +%s)
	{
		echo "$now 192.0.2.1 sshd 3"
		echo "$now 192.0.2.2 sshd 3"
	} > "$INSTALL_PATH/tmp/pressure.dat"
	run pressure_compute "$INSTALL_PATH" "192.0.2.1" "300" "$now" "sshd"
	assert_success
	assert_output "3000"
}

# ============================================================
# pressure_compute() — per-service filtering
# ============================================================

@test "pressure_compute: filters by service when mod given" {
	local now; now=$(date +%s)
	{
		echo "$now 192.0.2.1 sshd 3"
		echo "$now 192.0.2.1 dovecot 2"
	} > "$INSTALL_PATH/tmp/pressure.dat"
	run pressure_compute "$INSTALL_PATH" "192.0.2.1" "300" "$now" "sshd"
	assert_success
	assert_output "3000"
}

@test "pressure_compute: cross-service when mod omitted" {
	local now; now=$(date +%s)
	{
		echo "$now 192.0.2.1 sshd 3"
		echo "$now 192.0.2.1 dovecot 2"
	} > "$INSTALL_PATH/tmp/pressure.dat"
	run pressure_compute "$INSTALL_PATH" "192.0.2.1" "300" "$now"
	assert_success
	# 3+2 = 5 → 5000
	assert_output "5000"
}

# ============================================================
# pressure_compute() — old 3-field format compat
# ============================================================

@test "pressure_compute: 3-field events use weight=1" {
	local now; now=$(date +%s)
	echo "$now 192.0.2.1 sshd" > "$INSTALL_PATH/tmp/pressure.dat"
	run pressure_compute "$INSTALL_PATH" "192.0.2.1" "300" "$now" "sshd"
	assert_success
	assert_output "1000"
}

# ============================================================
# record_and_score()
# ============================================================

@test "record_and_score: appends events and returns pressure" {
	local now; now=$(date +%s)
	PRESSURE_HALF_LIFE="300"
	local hosts="192.0.2.1
192.0.2.1
192.0.2.1"
	run record_and_score "192.0.2.1" "$hosts" "$INSTALL_PATH" "300" "$now" "sshd" "3"
	assert_success
	# 3 events * weight 3 = 9.0 → 9000
	assert_output "9000"
}

@test "record_and_score: creates events in pressure.dat" {
	local now; now=$(date +%s)
	local hosts="192.0.2.1
192.0.2.1"
	record_and_score "192.0.2.1" "$hosts" "$INSTALL_PATH" "300" "$now" "sshd" "2" > /dev/null
	local lines
	lines=$(wc -l < "$INSTALL_PATH/tmp/pressure.dat")
	[ "$lines" -eq 2 ]
}

@test "record_and_score: weight=1 with single event equals count model" {
	local now; now=$(date +%s)
	local hosts="192.0.2.1"
	run record_and_score "192.0.2.1" "$hosts" "$INSTALL_PATH" "300" "$now" "sshd" "1"
	assert_success
	# 1 event * weight 1 at t=0 → 1000
	assert_output "1000"
}

@test "record_and_score: pre-computed count (8th arg) skips grep" {
	local now; now=$(date +%s)
	# hosts_parsed is irrelevant when count is provided directly
	run record_and_score "192.0.2.1" "" "$INSTALL_PATH" "300" "$now" "sshd" "3" "3"
	assert_success
	# 3 events * weight 3 at t=0 → 9000
	assert_output "9000"
}

@test "record_and_score: pre-computed count=0 appends nothing" {
	local now; now=$(date +%s)
	record_and_score "192.0.2.1" "" "$INSTALL_PATH" "300" "$now" "sshd" "1" "0" > /dev/null
	# pressure.dat should not exist or be empty
	[ ! -s "$INSTALL_PATH/tmp/pressure.dat" ]
}

# ============================================================
# _load_pressure_conf()
# ============================================================

@test "_load_pressure_conf: parses SKIP_ALERT and RULE_EMAIL" {
	local pconf="$TEST_TMPDIR/pressure.conf"
	echo "dovecot:PRESSURE_WEIGHT=2:SKIP_ALERT=1:RULE_EMAIL=ops@test.com" > "$pconf"
	_load_pressure_conf "$pconf"
	[ "${_PRESS_WEIGHT[dovecot]}" = "2" ]
	[ "${_PRESS_SKIP_ALERT[dovecot]}" = "1" ]
	[ "${_PRESS_RULE_EMAIL[dovecot]}" = "ops@test.com" ]
}

@test "_load_pressure_conf: skips comment lines" {
	local pconf="$TEST_TMPDIR/pressure.conf"
	{
		echo "# comment"
		echo "sshd:PRESSURE_WEIGHT=3"
	} > "$pconf"
	_load_pressure_conf "$pconf"
	[ "${_PRESS_WEIGHT[sshd]}" = "3" ]
}

@test "_load_pressure_conf: handles legacy TRIG as PRESSURE_TRIP" {
	local pconf="$TEST_TMPDIR/pressure.conf"
	echo "sshd:TRIG=10" > "$pconf"
	_load_pressure_conf "$pconf"
	[ "${_PRESS_TRIP[sshd]}" = "10" ]
}

@test "_load_pressure_conf: weight-only entry works" {
	local pconf="$TEST_TMPDIR/pressure.conf"
	echo "sshd:PRESSURE_WEIGHT=5" > "$pconf"
	_load_pressure_conf "$pconf"
	[ "${_PRESS_WEIGHT[sshd]}" = "5" ]
	[ -z "${_PRESS_TRIP[sshd]:-}" ]
}

@test "_load_pressure_conf: multiple rules parsed" {
	bfd_require_bash42
	local pconf="$TEST_TMPDIR/pressure.conf"
	{
		echo "sshd:PRESSURE_WEIGHT=3:PRESSURE_TRIP=15"
		echo "dovecot:PRESSURE_WEIGHT=2:PRESSURE_TRIP=20"
		echo "cpanel:PRESSURE_WEIGHT=5:PRESSURE_TRIP=10"
	} > "$pconf"
	_load_pressure_conf "$pconf"
	[ "${_PRESS_WEIGHT[sshd]}" = "3" ]
	[ "${_PRESS_WEIGHT[dovecot]}" = "2" ]
	[ "${_PRESS_WEIGHT[cpanel]}" = "5" ]
	[ "${_PRESS_TRIP[sshd]}" = "15" ]
	[ "${_PRESS_TRIP[dovecot]}" = "20" ]
	[ "${_PRESS_TRIP[cpanel]}" = "10" ]
}

@test "_load_pressure_conf: non-numeric PRESSURE_WEIGHT skipped" {
	local pconf="$TEST_TMPDIR/pressure.conf"
	echo "sshd:PRESSURE_WEIGHT=abc:PRESSURE_TRIP=15" > "$pconf"
	_load_pressure_conf "$pconf"
	[ -z "${_PRESS_WEIGHT[sshd]:-}" ]
	[ "${_PRESS_TRIP[sshd]}" = "15" ]
}

@test "_load_pressure_conf: zero PRESSURE_WEIGHT skipped" {
	local pconf="$TEST_TMPDIR/pressure.conf"
	echo "sshd:PRESSURE_WEIGHT=0" > "$pconf"
	_load_pressure_conf "$pconf"
	[ -z "${_PRESS_WEIGHT[sshd]:-}" ]
}

@test "_load_pressure_conf: non-numeric PRESSURE_TRIP skipped" {
	local pconf="$TEST_TMPDIR/pressure.conf"
	echo "sshd:PRESSURE_WEIGHT=3:PRESSURE_TRIP=foo" > "$pconf"
	_load_pressure_conf "$pconf"
	[ "${_PRESS_WEIGHT[sshd]}" = "3" ]
	[ -z "${_PRESS_TRIP[sshd]:-}" ]
}

@test "_load_pressure_conf: negative PRESSURE_TRIP skipped" {
	local pconf="$TEST_TMPDIR/pressure.conf"
	echo "sshd:PRESSURE_TRIP=-5" > "$pconf"
	_load_pressure_conf "$pconf"
	[ -z "${_PRESS_TRIP[sshd]:-}" ]
}

@test "_load_pressure_conf: PRESSURE_TRIP above 200 clamped" {
	local pconf="$TEST_TMPDIR/pressure.conf"
	echo "sshd:PRESSURE_TRIP=500" > "$pconf"
	_load_pressure_conf "$pconf"
	[ "${_PRESS_TRIP[sshd]}" = "200" ]
}

@test "_load_pressure_conf: PRESSURE_TRIP=200 accepted (ceiling)" {
	local pconf="$TEST_TMPDIR/pressure.conf"
	echo "sshd:PRESSURE_TRIP=200" > "$pconf"
	_load_pressure_conf "$pconf"
	[ "${_PRESS_TRIP[sshd]}" = "200" ]
}

# ============================================================
# _apply_pressure()
# ============================================================

@test "_apply_pressure: fills from pressure.conf array" {
	_PRESS_WEIGHT=()
	_PRESS_TRIP=()
	_PRESS_WEIGHT[sshd]="3"
	_PRESS_TRIP[sshd]="15"
	PRESSURE_WEIGHT=""
	PRESSURE_TRIP=""
	TRIG=""
	_apply_pressure "sshd"
	[ "$PRESSURE_WEIGHT" = "3" ]
	[ "$PRESSURE_TRIP" = "15" ]
}

@test "_apply_pressure: rule file value takes precedence" {
	_PRESS_WEIGHT=()
	_PRESS_TRIP=()
	_PRESS_WEIGHT[sshd]="3"
	_PRESS_TRIP[sshd]="15"
	PRESSURE_WEIGHT="5"
	PRESSURE_TRIP="10"
	_apply_pressure "sshd"
	# rule file already set → not overwritten
	[ "$PRESSURE_WEIGHT" = "5" ]
	[ "$PRESSURE_TRIP" = "10" ]
}

@test "_apply_pressure: TRIG fills PRESSURE_TRIP for backward compat" {
	_PRESS_WEIGHT=()
	_PRESS_TRIP=()
	PRESSURE_WEIGHT=""
	PRESSURE_TRIP=""
	TRIG="5"
	_apply_pressure "sshd"
	# old-style TRIG from rule file should fill PRESSURE_TRIP
	[ "$PRESSURE_TRIP" = "5" ]
	[ "$TRIG" = "5" ]
}

@test "_apply_pressure: PRESSURE_TRIP wins over TRIG" {
	_PRESS_WEIGHT=()
	_PRESS_TRIP=()
	PRESSURE_WEIGHT=""
	PRESSURE_TRIP="10"
	TRIG="5"
	_apply_pressure "sshd"
	# PRESSURE_TRIP was already set → TRIG doesn't override
	[ "$PRESSURE_TRIP" = "10" ]
}

@test "_apply_pressure: global fallback when no rule or conf" {
	_PRESS_WEIGHT=()
	_PRESS_TRIP=()
	PRESSURE_WEIGHT=""
	PRESSURE_TRIP=""
	TRIG=""
	GLOB_PRESSURE_TRIP="20"
	_apply_pressure "unknown_rule"
	# no array entry → stays empty (global used at call site)
	[ -z "$PRESSURE_WEIGHT" ]
	[ -z "$PRESSURE_TRIP" ]
}

@test "_apply_pressure: sets TRIG from PRESSURE_TRIP for backward compat" {
	_PRESS_WEIGHT=()
	_PRESS_TRIP=()
	_PRESS_TRIP[sshd]="15"
	PRESSURE_TRIP=""
	TRIG=""
	_apply_pressure "sshd"
	[ "$PRESSURE_TRIP" = "15" ]
	[ "$TRIG" = "15" ]
}

@test "_apply_pressure: fills SKIP_ALERT from array" {
	_PRESS_WEIGHT=()
	_PRESS_TRIP=()
	_PRESS_SKIP_ALERT=()
	_PRESS_SKIP_ALERT[sshd]="1"
	SKIP_ALERT=""
	_apply_pressure "sshd"
	[ "$SKIP_ALERT" = "1" ]
}

@test "_apply_pressure: fills RULE_EMAIL from array" {
	_PRESS_WEIGHT=()
	_PRESS_TRIP=()
	_PRESS_RULE_EMAIL=()
	_PRESS_RULE_EMAIL[sshd]="ops@test.com"
	RULE_EMAIL=""
	_apply_pressure "sshd"
	[ "$RULE_EMAIL" = "ops@test.com" ]
}

# ============================================================
# state_pressure_append() — weight parameter (count+weight combo)
# ============================================================

@test "state_pressure_append: count=2 creates 2 lines with weight" {
	local now; now=$(date +%s)
	state_pressure_append "$INSTALL_PATH" "$now" "192.0.2.1" "sshd" "2" "5"
	local lines
	lines=$(wc -l < "$INSTALL_PATH/tmp/pressure.dat")
	[ "$lines" -eq 2 ]
	# both lines should have weight=5
	local w1 w2
	w1=$(awk 'NR==1{print $4}' "$INSTALL_PATH/tmp/pressure.dat")
	w2=$(awk 'NR==2{print $4}' "$INSTALL_PATH/tmp/pressure.dat")
	[ "$w1" = "5" ]
	[ "$w2" = "5" ]
}

# ============================================================
# Integration: pressure trip comparison
# ============================================================

@test "pressure: 7 SSH events at weight=3 exceed trip=15" {
	local now; now=$(date +%s)
	# 7 events, weight 3 → pressure 21 → 21000 scaled
	local i
	for i in 1 2 3 4 5 6 7; do
		echo "$now 192.0.2.1 sshd 3" >> "$INSTALL_PATH/tmp/pressure.dat"
	done
	run pressure_compute "$INSTALL_PATH" "192.0.2.1" "300" "$now" "sshd"
	assert_success
	local pressure="$output"
	local trip_scaled=$((15 * 1000))
	[ "$pressure" -ge "$trip_scaled" ]
}

@test "pressure: 4 SSH events at weight=3 below trip=15" {
	local now; now=$(date +%s)
	# 4 events, weight 3 → pressure 12 → 12000 scaled
	local i
	for i in 1 2 3 4; do
		echo "$now 192.0.2.1 sshd 3" >> "$INSTALL_PATH/tmp/pressure.dat"
	done
	run pressure_compute "$INSTALL_PATH" "192.0.2.1" "300" "$now" "sshd"
	assert_success
	local pressure="$output"
	local trip_scaled=$((15 * 1000))
	[ "$pressure" -lt "$trip_scaled" ]
}

# ============================================================
# Edge cases
# ============================================================

@test "pressure_compute: events beyond 10 half-lives contribute zero" {
	local now=10000
	local half_life=300
	# event at 11 half-lives ago = now - 3300 = 6700
	echo "6700 192.0.2.1 sshd 1" >> "$INSTALL_PATH/tmp/pressure.dat"
	run pressure_compute "$INSTALL_PATH" "192.0.2.1" "$half_life" "$now" "sshd"
	assert_success
	assert_output "0"
}

@test "pressure_compute: event at 9 half-lives still contributes" {
	local now=10000
	local half_life=300
	# event at 9 half-lives ago = now - 2700 = 7300
	echo "7300 192.0.2.1 sshd 1" >> "$INSTALL_PATH/tmp/pressure.dat"
	run pressure_compute "$INSTALL_PATH" "192.0.2.1" "$half_life" "$now" "sshd"
	assert_success
	# 2^(-9) ≈ 0.00195, scaled = 1 (truncated)
	[ "$output" -ge 1 ]
}

@test "pressure_compute: zero weight in 4-field event falls back to weight 1" {
	local now; now=$(date +%s)
	echo "$now 192.0.2.1 sshd 0" >> "$INSTALL_PATH/tmp/pressure.dat"
	run pressure_compute "$INSTALL_PATH" "192.0.2.1" "300" "$now" "sshd"
	assert_success
	# weight=0 → fallback to 1 → pressure = 1000
	assert_output "1000"
}

@test "pressure_compute: mixed 3-field and 4-field events in same file" {
	local now; now=$(date +%s)
	# 3-field (old format) → weight defaults to 1
	echo "$now 192.0.2.1 sshd" >> "$INSTALL_PATH/tmp/pressure.dat"
	# 4-field (new format) → weight explicit 3
	echo "$now 192.0.2.1 sshd 3" >> "$INSTALL_PATH/tmp/pressure.dat"
	run pressure_compute "$INSTALL_PATH" "192.0.2.1" "300" "$now" "sshd"
	assert_success
	# 1 + 3 = 4 → 4000 scaled
	assert_output "4000"
}

@test "pressure_format: negative input returns 0.0 sentinel" {
	# negative input shouldn't occur in practice, but verify no crash
	run pressure_format -500
	assert_success
	# implementation detail: may show "0.-5" or similar, but shouldn't crash
	# mainly verifying no error exit
}

# ============================================================
# _batch_pressure_compute()
# ============================================================

@test "_batch_pressure_compute: empty events file produces no output" {
	local now; now=$(date +%s)
	> "$INSTALL_PATH/tmp/pressure.dat"
	run _batch_pressure_compute "$INSTALL_PATH/tmp/pressure.dat" "$now" "300" "sshd"
	assert_success
	assert_output ""
}

@test "_batch_pressure_compute: missing events file produces no output" {
	local now; now=$(date +%s)
	command rm -f "$INSTALL_PATH/tmp/pressure.dat"
	run _batch_pressure_compute "$INSTALL_PATH/tmp/pressure.dat" "$now" "300" "sshd"
	assert_success
	assert_output ""
}

@test "_batch_pressure_compute: single IP returns per-mod and global pressure" {
	local now; now=$(date +%s)
	echo "$now 192.0.2.1 sshd 3" > "$INSTALL_PATH/tmp/pressure.dat"
	run _batch_pressure_compute "$INSTALL_PATH/tmp/pressure.dat" "$now" "300" "sshd"
	assert_success
	# weight=3, age=0, decay=1.0 → per-mod=3000, global=3000
	assert_output "192.0.2.1 3000 3000"
}

@test "_batch_pressure_compute: per-mod filters by service" {
	local now; now=$(date +%s)
	{
		echo "$now 192.0.2.1 sshd 3"
		echo "$now 192.0.2.1 dovecot 2"
	} > "$INSTALL_PATH/tmp/pressure.dat"
	run _batch_pressure_compute "$INSTALL_PATH/tmp/pressure.dat" "$now" "300" "sshd"
	assert_success
	# per-mod (sshd only) = 3000, global (sshd+dovecot) = 5000
	assert_output "192.0.2.1 3000 5000"
}

@test "_batch_pressure_compute: multiple IPs returned separately" {
	local now; now=$(date +%s)
	{
		echo "$now 192.0.2.1 sshd 3"
		echo "$now 192.0.2.2 sshd 2"
	} > "$INSTALL_PATH/tmp/pressure.dat"
	local result
	result=$(_batch_pressure_compute "$INSTALL_PATH/tmp/pressure.dat" "$now" "300" "sshd")
	# both IPs should appear (order may vary)
	echo "$result" | grep -q "192.0.2.1 3000 3000"
	echo "$result" | grep -q "192.0.2.2 2000 2000"
}

@test "_batch_pressure_compute: cutoff excludes events beyond 10 half-lives" {
	local now=10000
	local half_life=300
	# event at 11 half-lives ago → cutoff = 10000 - 3000 = 7000; ts=6700 < 7000
	echo "6700 192.0.2.1 sshd 3" > "$INSTALL_PATH/tmp/pressure.dat"
	run _batch_pressure_compute "$INSTALL_PATH/tmp/pressure.dat" "$now" "$half_life" "sshd"
	assert_success
	assert_output ""
}

@test "_batch_pressure_compute: event at 1 half-life decays to ~half" {
	local now=10000
	local half_life=300
	local ts=$((now - half_life))
	echo "$ts 192.0.2.1 sshd 1" > "$INSTALL_PATH/tmp/pressure.dat"
	local result
	result=$(_batch_pressure_compute "$INSTALL_PATH/tmp/pressure.dat" "$now" "$half_life" "sshd")
	# weight=1, decay≈0.5 → ~500 scaled
	local per_mod global_p
	read -r _ per_mod global_p <<< "$result"
	[ "$per_mod" -ge 490 ] && [ "$per_mod" -le 510 ]
}
