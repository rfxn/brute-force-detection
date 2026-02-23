#!/usr/bin/env bats
#
# Test suite for importconf config migration
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

setup() {
	bfd_common_setup
	IMPORTCONF="$PROJECT_ROOT/importconf"
}

teardown() {
	bfd_teardown
}

# --- fresh install (no backup dir) ---

@test "importconf: exits cleanly when no backup dir exists" {
	# override INSTALL_PATH to a non-existent path
	local script
	script=$(mktemp "$TEST_TMPDIR/importconf.XXXXXX")
	sed 's|INSTALL_PATH=.*|INSTALL_PATH="'"$TEST_TMPDIR/bfd"'"|' "$IMPORTCONF" > "$script"
	chmod +x "$script"
	run bash "$script"
	assert_success
	assert_output ""
}

# --- upgrade with value preservation ---

@test "importconf: preserves simple user values (TRIG, EMAIL_ALERTS)" {
	# set up install path and backup
	local inst="$TEST_TMPDIR/bfd"
	mkdir -p "$inst" "$inst.bk.last" "$inst/tmp" "$inst/stats"

	# old config with user customizations
	cat > "$inst.bk.last/conf.bfd" <<'OLDEOF'
# Brute Force Detection 1.5-2 <bfd@rfxn.com>
TRIG="10"
EMAIL_ALERTS="1"
EMAIL_ADDRESS="admin@example.com"
BAN_COMMAND="/etc/apf/apf -d $ATTACK_HOST {bfd.$MOD}"
INSTALL_PATH="/usr/local/bfd"
OLDEOF

	# new config with defaults
	cat > "$inst/conf.bfd" <<'NEWEOF'
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
TRIG="15"
EMAIL_ALERTS="0"
EMAIL_ADDRESS="root"
BAN_COMMAND="/etc/apf/apf -d $ATTACK_HOST {bfd.$MOD}"
INSTALL_PATH="/usr/local/bfd"
NEWEOF

	local script
	script=$(mktemp "$TEST_TMPDIR/importconf.XXXXXX")
	sed 's|INSTALL_PATH=.*|INSTALL_PATH="'"$inst"'"|' "$IMPORTCONF" > "$script"
	chmod +x "$script"
	run bash "$script"
	assert_success

	# verify old values preserved
	run grep '^TRIG=' "$inst/conf.bfd"
	assert_output 'TRIG="10"'
	run grep '^EMAIL_ALERTS=' "$inst/conf.bfd"
	assert_output 'EMAIL_ALERTS="1"'
	run grep '^EMAIL_ADDRESS=' "$inst/conf.bfd"
	assert_output 'EMAIL_ADDRESS="admin@example.com"'
}

@test "importconf: preserves template variables (BAN_COMMAND with \$ATTACK_HOST)" {
	local inst="$TEST_TMPDIR/bfd"
	mkdir -p "$inst" "$inst.bk.last" "$inst/tmp" "$inst/stats"

	cat > "$inst.bk.last/conf.bfd" <<'OLDEOF'
# Brute Force Detection 1.5-2 <bfd@rfxn.com>
BAN_COMMAND="/sbin/iptables -I INPUT -s $ATTACK_HOST -j DROP"
INSTALL_PATH="/usr/local/bfd"
OLDEOF

	cat > "$inst/conf.bfd" <<'NEWEOF'
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
BAN_COMMAND="/etc/apf/apf -d $ATTACK_HOST {bfd.$MOD}"
INSTALL_PATH="/usr/local/bfd"
NEWEOF

	local script
	script=$(mktemp "$TEST_TMPDIR/importconf.XXXXXX")
	sed 's|INSTALL_PATH=.*|INSTALL_PATH="'"$inst"'"|' "$IMPORTCONF" > "$script"
	chmod +x "$script"
	run bash "$script"
	assert_success

	# $ATTACK_HOST must be preserved as literal text, not expanded
	run grep '^BAN_COMMAND=' "$inst/conf.bfd"
	assert_output 'BAN_COMMAND="/sbin/iptables -I INPUT -s $ATTACK_HOST -j DROP"'
}

@test "importconf: new variables get defaults (old config missing BAN_COMMAND_V6)" {
	local inst="$TEST_TMPDIR/bfd"
	mkdir -p "$inst" "$inst.bk.last" "$inst/tmp" "$inst/stats"

	# old config WITHOUT BAN_COMMAND_V6
	cat > "$inst.bk.last/conf.bfd" <<'OLDEOF'
# Brute Force Detection 1.5-2 <bfd@rfxn.com>
TRIG="10"
INSTALL_PATH="/usr/local/bfd"
OLDEOF

	# new config WITH BAN_COMMAND_V6
	cat > "$inst/conf.bfd" <<'NEWEOF'
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
TRIG="15"
BAN_COMMAND_V6=""
INSTALL_PATH="/usr/local/bfd"
NEWEOF

	local script
	script=$(mktemp "$TEST_TMPDIR/importconf.XXXXXX")
	sed 's|INSTALL_PATH=.*|INSTALL_PATH="'"$inst"'"|' "$IMPORTCONF" > "$script"
	chmod +x "$script"
	run bash "$script"
	assert_success

	# new variable should keep its default
	run grep '^BAN_COMMAND_V6=' "$inst/conf.bfd"
	assert_output 'BAN_COMMAND_V6=""'
	# old value should be preserved
	run grep '^TRIG=' "$inst/conf.bfd"
	assert_output 'TRIG="10"'
}

@test "importconf: removed variables dropped (old config has var not in new)" {
	local inst="$TEST_TMPDIR/bfd"
	mkdir -p "$inst" "$inst.bk.last" "$inst/tmp" "$inst/stats"

	cat > "$inst.bk.last/conf.bfd" <<'OLDEOF'
# Brute Force Detection 1.5-2 <bfd@rfxn.com>
TRIG="10"
OBSOLETE_VAR="something"
INSTALL_PATH="/usr/local/bfd"
OLDEOF

	cat > "$inst/conf.bfd" <<'NEWEOF'
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
TRIG="15"
INSTALL_PATH="/usr/local/bfd"
NEWEOF

	local script
	script=$(mktemp "$TEST_TMPDIR/importconf.XXXXXX")
	sed 's|INSTALL_PATH=.*|INSTALL_PATH="'"$inst"'"|' "$IMPORTCONF" > "$script"
	chmod +x "$script"
	run bash "$script"
	assert_success

	# removed variable should NOT appear
	run grep 'OBSOLETE_VAR' "$inst/conf.bfd"
	assert_failure
}

@test "importconf: comments and section headers from new config preserved" {
	local inst="$TEST_TMPDIR/bfd"
	mkdir -p "$inst" "$inst.bk.last" "$inst/tmp" "$inst/stats"

	cat > "$inst.bk.last/conf.bfd" <<'OLDEOF'
# Brute Force Detection 1.5-2 <bfd@rfxn.com>
TRIG="10"
OLDEOF

	cat > "$inst/conf.bfd" <<'NEWEOF'
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
# =============================================
# Detection Thresholds
# =============================================
# This is a new comment explaining TRIG
TRIG="15"

# commented example that should pass through
#BAN_COMMAND="/sbin/iptables -I INPUT -s $ATTACK_HOST -j DROP"
NEWEOF

	local script
	script=$(mktemp "$TEST_TMPDIR/importconf.XXXXXX")
	sed 's|INSTALL_PATH=.*|INSTALL_PATH="'"$inst"'"|' "$IMPORTCONF" > "$script"
	chmod +x "$script"
	run bash "$script"
	assert_success

	# new comments should be present
	run grep 'This is a new comment explaining TRIG' "$inst/conf.bfd"
	assert_success
	# section header should be present
	run grep 'Detection Thresholds' "$inst/conf.bfd"
	assert_success
	# commented example should pass through unchanged
	run grep '^#BAN_COMMAND=' "$inst/conf.bfd"
	assert_success
}

@test "importconf: version extraction works" {
	local inst="$TEST_TMPDIR/bfd"
	mkdir -p "$inst" "$inst.bk.last" "$inst/tmp" "$inst/stats"

	cat > "$inst.bk.last/conf.bfd" <<'OLDEOF'
# Brute Force Detection 1.5-2 <bfd@rfxn.com>
TRIG="10"
INSTALL_PATH="/usr/local/bfd"
OLDEOF

	cat > "$inst/conf.bfd" <<'NEWEOF'
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
TRIG="15"
INSTALL_PATH="/usr/local/bfd"
NEWEOF

	local script
	script=$(mktemp "$TEST_TMPDIR/importconf.XXXXXX")
	sed 's|INSTALL_PATH=.*|INSTALL_PATH="'"$inst"'"|' "$IMPORTCONF" > "$script"
	chmod +x "$script"
	run bash "$script"
	assert_success
	assert_output "  Imported config and state from BFD 1.5-2 to 2.0.1."
}

@test "importconf: pre-split conf.bfd variables migrate to internals.conf" {
	local inst="$TEST_TMPDIR/bfd"
	mkdir -p "$inst" "$inst.bk.last" "$inst/tmp" "$inst/stats"

	# old pre-split config has internal variables in conf.bfd
	cat > "$inst.bk.last/conf.bfd" <<'OLDEOF'
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
TRIG="10"
INSTALL_PATH="/usr/local/bfd"
RULES_PATH="/usr/local/bfd/rules"
TLOG_PATH="/usr/local/bfd/tlog"
LOCK_FILE="/usr/local/bfd/lock.utime"
LOCK_FILE_TIMEOUT="600"
OLDEOF

	# new conf.bfd (no internal variables)
	cat > "$inst/conf.bfd" <<'NEWEOF'
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
TRIG="15"
LOCK_FILE_TIMEOUT="300"
NEWEOF

	# new internals.conf
	cat > "$inst/internals.conf" <<'INTEOF'
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
RULES_PATH="$INSTALL_PATH/rules"
TLOG_PATH="$INSTALL_PATH/tlog"
LOCK_FILE="$INSTALL_PATH/lock.utime"
INTEOF

	local script
	script=$(mktemp "$TEST_TMPDIR/importconf.XXXXXX")
	sed 's|INSTALL_PATH=.*|INSTALL_PATH="'"$inst"'"|' "$IMPORTCONF" > "$script"
	chmod +x "$script"
	run bash "$script"
	assert_success

	# TRIG should migrate to conf.bfd
	run grep '^TRIG=' "$inst/conf.bfd"
	assert_output 'TRIG="10"'
	# LOCK_FILE_TIMEOUT should migrate to conf.bfd
	run grep '^LOCK_FILE_TIMEOUT=' "$inst/conf.bfd"
	assert_output 'LOCK_FILE_TIMEOUT="600"'
	# RULES_PATH should migrate to internals.conf
	run grep '^RULES_PATH=' "$inst/internals.conf"
	assert_output 'RULES_PATH="/usr/local/bfd/rules"'
	# LOCK_FILE should migrate to internals.conf
	run grep '^LOCK_FILE=' "$inst/internals.conf"
	assert_output 'LOCK_FILE="/usr/local/bfd/lock.utime"'
}

@test "importconf: post-split upgrade merges both old files" {
	local inst="$TEST_TMPDIR/bfd"
	mkdir -p "$inst" "$inst.bk.last" "$inst/tmp" "$inst/stats"

	# old post-split install has both files
	cat > "$inst.bk.last/conf.bfd" <<'OLDEOF'
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
TRIG="8"
OLDEOF
	cat > "$inst.bk.last/internals.conf" <<'OLDINTEOF'
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
RULES_PATH="/custom/rules"
OLDINTEOF

	# new conf.bfd
	cat > "$inst/conf.bfd" <<'NEWEOF'
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
TRIG="15"
NEWEOF

	# new internals.conf
	cat > "$inst/internals.conf" <<'INTEOF'
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
RULES_PATH="$INSTALL_PATH/rules"
INTEOF

	local script
	script=$(mktemp "$TEST_TMPDIR/importconf.XXXXXX")
	sed 's|INSTALL_PATH=.*|INSTALL_PATH="'"$inst"'"|' "$IMPORTCONF" > "$script"
	chmod +x "$script"
	run bash "$script"
	assert_success

	# conf.bfd value preserved
	run grep '^TRIG=' "$inst/conf.bfd"
	assert_output 'TRIG="8"'
	# internals.conf value preserved from old internals.conf
	run grep '^RULES_PATH=' "$inst/internals.conf"
	assert_output 'RULES_PATH="/custom/rules"'
}

@test "importconf: state files (bans.active, events.dat) copied on upgrade" {
	local inst="$TEST_TMPDIR/bfd"
	mkdir -p "$inst" "$inst.bk.last/tmp" "$inst.bk.last/stats" "$inst/tmp" "$inst/stats"

	cat > "$inst.bk.last/conf.bfd" <<'OLDEOF'
# Brute Force Detection 1.5-2 <bfd@rfxn.com>
INSTALL_PATH="/usr/local/bfd"
OLDEOF

	cat > "$inst/conf.bfd" <<'NEWEOF'
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
INSTALL_PATH="/usr/local/bfd"
NEWEOF

	# create state files in old backup
	echo "1.2.3.4 1700000000 0 sshd all" > "$inst.bk.last/tmp/bans.active"
	echo "1.2.3.4 1700000000 ban sshd all" > "$inst.bk.last/tmp/bans.history"
	echo "1.2.3.4 1700000000 sshd" > "$inst.bk.last/tmp/events.dat"
	echo "1.2.3.4;5;sshd" > "$inst.bk.last/stats/attack.pool"
	echo "10.0.0.1" > "$inst.bk.last/ignore.hosts"

	local script
	script=$(mktemp "$TEST_TMPDIR/importconf.XXXXXX")
	sed 's|INSTALL_PATH=.*|INSTALL_PATH="'"$inst"'"|' "$IMPORTCONF" > "$script"
	chmod +x "$script"
	run bash "$script"
	assert_success

	# verify state files were copied
	[ -f "$inst/tmp/bans.active" ]
	[ -f "$inst/tmp/bans.history" ]
	[ -f "$inst/tmp/events.dat" ]
	[ -f "$inst/stats/attack.pool" ]
	[ -f "$inst/ignore.hosts" ]

	# verify content
	run cat "$inst/tmp/bans.active"
	assert_output "1.2.3.4 1700000000 0 sshd all"
	run cat "$inst/ignore.hosts"
	assert_output "10.0.0.1"
}
