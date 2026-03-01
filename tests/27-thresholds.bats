#!/usr/bin/env bats
#
# Tests for thresholds.conf / pressure.conf parsing and application
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

setup() {
	bfd_require_bash42
	bfd_common_setup
	declare -gA _THRESH_TRIG _THRESH_SKIP_ALERT _THRESH_RULE_EMAIL
	declare -gA _PRESS_WEIGHT _PRESS_TRIP _PRESS_SKIP_ALERT _PRESS_RULE_EMAIL
	GLOB_PRESSURE_TRIP="15"
	GLOB_TRIG="15"
}

teardown() {
	bfd_teardown
}

# --- _load_thresholds ---

@test "_load_thresholds: parses TRIG values" {
	local conf="$TEST_TMPDIR/thresholds.conf"
	cat > "$conf" <<'EOF'
sshd:TRIG=5
dovecot:TRIG=10
named:TRIG=100
EOF
	chown root "$conf"
	chmod 640 "$conf"
	_load_thresholds "$conf"
	[ "${_THRESH_TRIG[sshd]}" = "5" ]
	[ "${_THRESH_TRIG[dovecot]}" = "10" ]
	[ "${_THRESH_TRIG[named]}" = "100" ]
}

@test "_load_thresholds: parses multi-field entries" {
	local conf="$TEST_TMPDIR/thresholds.conf"
	cat > "$conf" <<'EOF'
postfix:TRIG=20:SKIP_ALERT=1:RULE_EMAIL=sec@example.com
EOF
	chown root "$conf"
	chmod 640 "$conf"
	_load_thresholds "$conf"
	[ "${_THRESH_TRIG[postfix]}" = "20" ]
	[ "${_THRESH_SKIP_ALERT[postfix]}" = "1" ]
	[ "${_THRESH_RULE_EMAIL[postfix]}" = "sec@example.com" ]
}

@test "_load_thresholds: skips comments and blank lines" {
	local conf="$TEST_TMPDIR/thresholds.conf"
	cat > "$conf" <<'EOF'
# this is a comment
sshd:TRIG=5

# another comment
dovecot:TRIG=10
EOF
	chown root "$conf"
	chmod 640 "$conf"
	_load_thresholds "$conf"
	[ "${#_THRESH_TRIG[@]}" -eq 2 ]
	[ "${_THRESH_TRIG[sshd]}" = "5" ]
	[ "${_THRESH_TRIG[dovecot]}" = "10" ]
}

@test "_load_thresholds: ignores unknown keys" {
	local conf="$TEST_TMPDIR/thresholds.conf"
	cat > "$conf" <<'EOF'
sshd:TRIG=5:BADKEY=nope:SKIP_ALERT=1
EOF
	chown root "$conf"
	chmod 640 "$conf"
	_load_thresholds "$conf"
	[ "${_THRESH_TRIG[sshd]}" = "5" ]
	[ "${_THRESH_SKIP_ALERT[sshd]}" = "1" ]
	# BADKEY should not exist in any array
	[ -z "${_THRESH_TRIG[BADKEY]:-}" ]
}

@test "_load_thresholds: missing file returns 0 with empty arrays" {
	run _load_thresholds "/nonexistent/thresholds.conf"
	assert_success
	[ "${#_THRESH_TRIG[@]}" -eq 0 ]
}

@test "_load_thresholds: empty argument returns 0" {
	run _load_thresholds ""
	assert_success
}

@test "_load_thresholds: non-root-owned file is skipped" {
	local conf="$TEST_TMPDIR/thresholds.conf"
	echo "sshd:TRIG=5" > "$conf"
	# make it owned by a non-root user (uid 65534 = nobody)
	chown 65534 "$conf"
	chmod 640 "$conf"
	_load_thresholds "$conf"
	[ "${#_THRESH_TRIG[@]}" -eq 0 ]
}

@test "_load_thresholds: world-writable file is skipped" {
	local conf="$TEST_TMPDIR/thresholds.conf"
	echo "sshd:TRIG=5" > "$conf"
	chown root "$conf"
	chmod 646 "$conf"
	_load_thresholds "$conf"
	[ "${#_THRESH_TRIG[@]}" -eq 0 ]
}

# --- _apply_thresholds ---

@test "_apply_thresholds: rule TRIG wins over thresholds.conf" {
	_THRESH_TRIG=([sshd]="99")
	TRIG="5"
	_apply_thresholds "sshd"
	[ "$TRIG" = "5" ]
}

@test "_apply_thresholds: fills empty TRIG from thresholds.conf" {
	_THRESH_TRIG=([sshd]="7")
	TRIG=""
	_apply_thresholds "sshd"
	[ "$TRIG" = "7" ]
}

@test "_apply_thresholds: fills SKIP_ALERT from thresholds.conf" {
	_THRESH_SKIP_ALERT=([postfix]="1")
	SKIP_ALERT=""
	_apply_thresholds "postfix"
	[ "$SKIP_ALERT" = "1" ]
}

@test "_apply_thresholds: fills RULE_EMAIL from thresholds.conf" {
	_THRESH_RULE_EMAIL=([dovecot]="alerts@example.com")
	RULE_EMAIL=""
	_apply_thresholds "dovecot"
	[ "$RULE_EMAIL" = "alerts@example.com" ]
}

@test "_apply_thresholds: no-op for unlisted rule" {
	_THRESH_TRIG=([sshd]="5")
	TRIG=""
	SKIP_ALERT=""
	RULE_EMAIL=""
	_apply_thresholds "nginx-http-auth"
	[ -z "$TRIG" ]
	[ -z "$SKIP_ALERT" ]
	[ -z "$RULE_EMAIL" ]
}

@test "_apply_thresholds: does not overwrite non-empty SKIP_ALERT" {
	_THRESH_SKIP_ALERT=([sshd]="1")
	SKIP_ALERT="0"
	_apply_thresholds "sshd"
	[ "$SKIP_ALERT" = "0" ]
}

# --- precedence integration ---

@test "precedence: thresholds.conf fills TRIG, then conf.bfd fallback" {
	# rule left TRIG empty, thresholds.conf has value
	_THRESH_TRIG=([sshd]="8")
	_clear_rule_vars
	_apply_thresholds "sshd"
	[ "$TRIG" = "8" ]

	# rule left TRIG empty, thresholds.conf has no entry → still empty
	_clear_rule_vars
	_apply_thresholds "unlisted_rule"
	[ -z "$TRIG" ]
	# caller would then do: TRIG="${TRIG:-$GLOB_TRIG}"
	TRIG="${TRIG:-$GLOB_TRIG}"
	[ "$TRIG" = "15" ]
}

# --- _load_pressure_conf ---

@test "_load_pressure_conf: parses PRESSURE_TRIP values" {
	local conf="$TEST_TMPDIR/pressure.conf"
	cat > "$conf" <<'EOF'
sshd:PRESSURE_TRIP=5
dovecot:PRESSURE_TRIP=10
named:PRESSURE_TRIP=100
EOF
	chown root "$conf"
	chmod 640 "$conf"
	_load_pressure_conf "$conf"
	[ "${_PRESS_TRIP[sshd]}" = "5" ]
	[ "${_PRESS_TRIP[dovecot]}" = "10" ]
	[ "${_PRESS_TRIP[named]}" = "100" ]
}

@test "_load_pressure_conf: parses PRESSURE_WEIGHT values" {
	local conf="$TEST_TMPDIR/pressure.conf"
	cat > "$conf" <<'EOF'
sshd:PRESSURE_WEIGHT=2:PRESSURE_TRIP=10
dovecot:PRESSURE_WEIGHT=3:PRESSURE_TRIP=15
EOF
	chown root "$conf"
	chmod 640 "$conf"
	_load_pressure_conf "$conf"
	[ "${_PRESS_WEIGHT[sshd]}" = "2" ]
	[ "${_PRESS_WEIGHT[dovecot]}" = "3" ]
	[ "${_PRESS_TRIP[sshd]}" = "10" ]
	[ "${_PRESS_TRIP[dovecot]}" = "15" ]
}

@test "_load_pressure_conf: parses multi-field entries" {
	local conf="$TEST_TMPDIR/pressure.conf"
	cat > "$conf" <<'EOF'
postfix:PRESSURE_WEIGHT=2:PRESSURE_TRIP=20:SKIP_ALERT=1:RULE_EMAIL=sec@example.com
EOF
	chown root "$conf"
	chmod 640 "$conf"
	_load_pressure_conf "$conf"
	[ "${_PRESS_WEIGHT[postfix]}" = "2" ]
	[ "${_PRESS_TRIP[postfix]}" = "20" ]
	[ "${_PRESS_SKIP_ALERT[postfix]}" = "1" ]
	[ "${_PRESS_RULE_EMAIL[postfix]}" = "sec@example.com" ]
}

@test "_load_pressure_conf: ignores unknown keys" {
	local conf="$TEST_TMPDIR/pressure.conf"
	cat > "$conf" <<'EOF'
sshd:PRESSURE_TRIP=5:BADKEY=nope:SKIP_ALERT=1
EOF
	chown root "$conf"
	chmod 640 "$conf"
	_load_pressure_conf "$conf"
	[ "${_PRESS_TRIP[sshd]}" = "5" ]
	[ "${_PRESS_SKIP_ALERT[sshd]}" = "1" ]
	[ -z "${_PRESS_TRIP[BADKEY]:-}" ]
}

@test "_load_pressure_conf: missing file returns 0 with empty arrays" {
	run _load_pressure_conf "/nonexistent/pressure.conf"
	assert_success
	[ "${#_PRESS_TRIP[@]}" -eq 0 ]
}

@test "_load_pressure_conf: empty argument returns 0" {
	run _load_pressure_conf ""
	assert_success
}

@test "_load_pressure_conf: non-root-owned file is skipped" {
	local conf="$TEST_TMPDIR/pressure.conf"
	echo "sshd:PRESSURE_TRIP=5" > "$conf"
	chown 65534 "$conf"
	chmod 640 "$conf"
	_load_pressure_conf "$conf"
	[ "${#_PRESS_TRIP[@]}" -eq 0 ]
}

@test "_load_pressure_conf: world-writable file is skipped" {
	local conf="$TEST_TMPDIR/pressure.conf"
	echo "sshd:PRESSURE_TRIP=5" > "$conf"
	chown root "$conf"
	chmod 646 "$conf"
	_load_pressure_conf "$conf"
	[ "${#_PRESS_TRIP[@]}" -eq 0 ]
}

# --- _apply_pressure ---

@test "_apply_pressure: does not overwrite non-empty SKIP_ALERT" {
	_PRESS_SKIP_ALERT=([sshd]="1")
	SKIP_ALERT="0"
	PRESSURE_WEIGHT=""
	PRESSURE_TRIP=""
	_apply_pressure "sshd"
	[ "$SKIP_ALERT" = "0" ]
}

# --- pressure precedence integration ---

@test "precedence: pressure.conf fills PRESSURE_TRIP, then GLOB_PRESSURE_TRIP fallback" {
	# rule left PRESSURE_TRIP empty, pressure.conf has value
	_PRESS_TRIP=([sshd]="8")
	_clear_rule_vars
	_apply_pressure "sshd"
	[ "$PRESSURE_TRIP" = "8" ]

	# rule left PRESSURE_TRIP empty, pressure.conf has no entry → still empty
	_clear_rule_vars
	_apply_pressure "unlisted_rule"
	[ -z "$PRESSURE_TRIP" ]
	# caller would then do: PRESSURE_TRIP="${PRESSURE_TRIP:-$GLOB_PRESSURE_TRIP}"
	PRESSURE_TRIP="${PRESSURE_TRIP:-$GLOB_PRESSURE_TRIP}"
	[ "$PRESSURE_TRIP" = "15" ]
}
