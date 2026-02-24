#!/usr/bin/env bats
#
# Tests for thresholds.conf parsing and application
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

setup() {
	bfd_common_setup
	declare -gA _THRESH_TRIG _THRESH_SKIP_ALERT _THRESH_RULE_EMAIL
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
