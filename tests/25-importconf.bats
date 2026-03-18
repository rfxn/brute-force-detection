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
	_PKG_LIB_SRC="$PROJECT_ROOT/files/internals/pkg_lib.sh"
}

teardown() {
	bfd_teardown
}

# _importconf_prep_inst: create internals dir and copy pkg_lib.sh into $inst
# Call after creating the $inst directory in each test.
_importconf_prep_inst() {
	local inst="$1"
	mkdir -p "$inst/internals"
	cp "$_PKG_LIB_SRC" "$inst/internals/pkg_lib.sh"
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
	_importconf_prep_inst "$inst"

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
	_importconf_prep_inst "$inst"

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
	_importconf_prep_inst "$inst"

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
	_importconf_prep_inst "$inst"

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
	_importconf_prep_inst "$inst"

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
	_importconf_prep_inst "$inst"

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
	assert_output --partial "Imported config and state from BFD 1.5-2 to 2.0.1."
}

@test "importconf: pre-split conf.bfd variables migrate to internals.conf" {
	local inst="$TEST_TMPDIR/bfd"
	mkdir -p "$inst" "$inst.bk.last" "$inst/tmp" "$inst/stats" "$inst/internals"
	_importconf_prep_inst "$inst"

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
NEWEOF

	# new internals.conf (LOCK_FILE_TIMEOUT moved here in 2.0.1)
	cat > "$inst/internals/internals.conf" <<'INTEOF'
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
RULES_PATH="$INSTALL_PATH/rules"
TLOG_PATH="$INSTALL_PATH/tlog"
LOCK_FILE="$INSTALL_PATH/lock.utime"
LOCK_FILE_TIMEOUT="${LOCK_FILE_TIMEOUT:-300}"
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
	# LOCK_FILE_TIMEOUT should migrate to internals/internals.conf
	run grep '^LOCK_FILE_TIMEOUT=' "$inst/internals/internals.conf"
	assert_output 'LOCK_FILE_TIMEOUT="600"'
	# RULES_PATH should migrate to internals/internals.conf
	run grep '^RULES_PATH=' "$inst/internals/internals.conf"
	assert_output 'RULES_PATH="/usr/local/bfd/rules"'
	# LOCK_FILE should migrate to internals/internals.conf
	run grep '^LOCK_FILE=' "$inst/internals/internals.conf"
	assert_output 'LOCK_FILE="/usr/local/bfd/lock.utime"'
}

@test "importconf: post-split upgrade merges both old files" {
	local inst="$TEST_TMPDIR/bfd"
	mkdir -p "$inst" "$inst.bk.last" "$inst/tmp" "$inst/stats" "$inst/internals"
	_importconf_prep_inst "$inst"

	# old post-split install has both files (flat layout)
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
	cat > "$inst/internals/internals.conf" <<'INTEOF'
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
	# internals/internals.conf value preserved from old internals.conf
	run grep '^RULES_PATH=' "$inst/internals/internals.conf"
	assert_output 'RULES_PATH="/custom/rules"'
}

@test "importconf: state files (bans.active, pressure.dat) copied on upgrade" {
	local inst="$TEST_TMPDIR/bfd"
	mkdir -p "$inst" "$inst.bk.last/tmp" "$inst.bk.last/stats" "$inst/tmp" "$inst/stats"
	_importconf_prep_inst "$inst"

	cat > "$inst.bk.last/conf.bfd" <<'OLDEOF'
# Brute Force Detection 1.5-2 <bfd@rfxn.com>
INSTALL_PATH="/usr/local/bfd"
OLDEOF

	cat > "$inst/conf.bfd" <<'NEWEOF'
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
INSTALL_PATH="/usr/local/bfd"
NEWEOF

	# create state files in old backup
	echo "192.0.2.4 1700000000 0 sshd all" > "$inst.bk.last/tmp/bans.active"
	echo "192.0.2.4 1700000000 ban sshd all" > "$inst.bk.last/tmp/bans.history"
	echo "192.0.2.4 1700000000 sshd" > "$inst.bk.last/tmp/pressure.dat"
	echo "192.0.2.4;5;sshd" > "$inst.bk.last/stats/attack.pool"
	echo "192.0.2.1" > "$inst.bk.last/ignore.hosts"

	local script
	script=$(mktemp "$TEST_TMPDIR/importconf.XXXXXX")
	sed 's|INSTALL_PATH=.*|INSTALL_PATH="'"$inst"'"|' "$IMPORTCONF" > "$script"
	chmod +x "$script"
	run bash "$script"
	assert_success

	# verify state files were copied
	[ -f "$inst/tmp/bans.active" ]
	[ -f "$inst/tmp/bans.history" ]
	[ -f "$inst/tmp/pressure.dat" ]
	[ -f "$inst/stats/attack.pool" ]
	[ -f "$inst/ignore.hosts" ]

	# verify content
	run cat "$inst/tmp/bans.active"
	assert_output "192.0.2.4 1700000000 0 sshd all"
	run cat "$inst/ignore.hosts"
	assert_output "192.0.2.1"
}

@test "importconf: events.dat in backup migrated to pressure.dat" {
	local inst="$TEST_TMPDIR/bfd"
	mkdir -p "$inst" "$inst.bk.last/tmp" "$inst/tmp"
	_importconf_prep_inst "$inst"

	cat > "$inst.bk.last/conf.bfd" <<'OLDEOF'
# Brute Force Detection 1.5-2 <bfd@rfxn.com>
INSTALL_PATH="/usr/local/bfd"
OLDEOF

	cat > "$inst/conf.bfd" <<'NEWEOF'
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
INSTALL_PATH="/usr/local/bfd"
NEWEOF

	# old backup has events.dat (pre-rename), no pressure.dat
	echo "1700000000 192.0.2.4 sshd 3" > "$inst.bk.last/tmp/events.dat"

	local script
	script=$(mktemp "$TEST_TMPDIR/importconf.XXXXXX")
	sed 's|INSTALL_PATH=.*|INSTALL_PATH="'"$inst"'"|' "$IMPORTCONF" > "$script"
	chmod +x "$script"
	run bash "$script"
	assert_success

	# events.dat should be migrated to pressure.dat
	[ -f "$inst/tmp/pressure.dat" ]
	run cat "$inst/tmp/pressure.dat"
	assert_output "1700000000 192.0.2.4 sshd 3"
}

# --- pressure.conf / thresholds.conf migration ---

@test "importconf: pre-thresholds upgrade migrates old rule TRIG to pressure.conf" {
	local inst="$TEST_TMPDIR/bfd"
	mkdir -p "$inst" "$inst.bk.last/rules" "$inst/tmp" "$inst/stats"
	_importconf_prep_inst "$inst"

	cat > "$inst.bk.last/conf.bfd" <<'OLDEOF'
# Brute Force Detection 1.5-2 <bfd@rfxn.com>
TRIG="15"
INSTALL_PATH="/usr/local/bfd"
OLDEOF

	cat > "$inst/conf.bfd" <<'NEWEOF'
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
PRESSURE_TRIP="15"
INSTALL_PATH="/usr/local/bfd"
NEWEOF

	# old rules with uncommented TRIG (pre-thresholds format)
	cat > "$inst.bk.last/rules/sshd" <<'EOF'
TRIG="3"
REQ="/usr/sbin/sshd"
EOF
	cat > "$inst.bk.last/rules/dovecot" <<'EOF'
TRIG="20"
REQ="/usr/sbin/dovecot"
EOF

	# new pressure.conf with defaults
	cat > "$inst/pressure.conf" <<'EOF'
sshd:PRESSURE_TRIP=5
dovecot:PRESSURE_TRIP=10
EOF

	local script
	script=$(mktemp "$TEST_TMPDIR/importconf.XXXXXX")
	sed 's|INSTALL_PATH=.*|INSTALL_PATH="'"$inst"'"|' "$IMPORTCONF" > "$script"
	chmod +x "$script"
	run bash "$script"
	assert_success
	assert_output --partial "Migrated 2 per-rule thresholds"

	# verify pressure.conf was updated with old TRIG values as PRESSURE_TRIP
	run grep '^sshd:' "$inst/pressure.conf"
	assert_output --partial "PRESSURE_TRIP=3"
	run grep '^dovecot:' "$inst/pressure.conf"
	assert_output --partial "PRESSURE_TRIP=20"
}

@test "importconf: post-pressure upgrade preserves existing pressure.conf" {
	local inst="$TEST_TMPDIR/bfd"
	mkdir -p "$inst" "$inst.bk.last" "$inst/tmp" "$inst/stats"
	_importconf_prep_inst "$inst"

	cat > "$inst.bk.last/conf.bfd" <<'OLDEOF'
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
PRESSURE_TRIP="15"
INSTALL_PATH="/usr/local/bfd"
OLDEOF

	cat > "$inst/conf.bfd" <<'NEWEOF'
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
PRESSURE_TRIP="15"
INSTALL_PATH="/usr/local/bfd"
NEWEOF

	# old install had pressure.conf with user customizations
	cat > "$inst.bk.last/pressure.conf" <<'EOF'
sshd:PRESSURE_TRIP=3
dovecot:PRESSURE_TRIP=25:SKIP_ALERT=1
EOF

	# new pressure.conf with defaults
	cat > "$inst/pressure.conf" <<'EOF'
sshd:PRESSURE_TRIP=5
dovecot:PRESSURE_TRIP=10
EOF

	local script
	script=$(mktemp "$TEST_TMPDIR/importconf.XXXXXX")
	sed 's|INSTALL_PATH=.*|INSTALL_PATH="'"$inst"'"|' "$IMPORTCONF" > "$script"
	chmod +x "$script"
	run bash "$script"
	assert_success
	assert_output --partial "Preserved pressure.conf"

	# verify old pressure.conf was copied over new one
	run grep '^sshd:' "$inst/pressure.conf"
	assert_output "sshd:PRESSURE_TRIP=3"
	run grep '^dovecot:' "$inst/pressure.conf"
	assert_output "dovecot:PRESSURE_TRIP=25:SKIP_ALERT=1"
}

@test "importconf: thresholds.conf migrated to pressure.conf on upgrade" {
	local inst="$TEST_TMPDIR/bfd"
	mkdir -p "$inst" "$inst.bk.last" "$inst/tmp" "$inst/stats"
	_importconf_prep_inst "$inst"

	cat > "$inst.bk.last/conf.bfd" <<'OLDEOF'
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
TRIG="15"
INSTALL_PATH="/usr/local/bfd"
OLDEOF

	cat > "$inst/conf.bfd" <<'NEWEOF'
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
PRESSURE_TRIP="15"
INSTALL_PATH="/usr/local/bfd"
NEWEOF

	# old install had thresholds.conf (no pressure.conf)
	cat > "$inst.bk.last/thresholds.conf" <<'EOF'
sshd:TRIG=3
dovecot:TRIG=25:SKIP_ALERT=1
EOF

	# new pressure.conf with defaults
	cat > "$inst/pressure.conf" <<'EOF'
sshd:PRESSURE_TRIP=5
dovecot:PRESSURE_TRIP=10
EOF

	local script
	script=$(mktemp "$TEST_TMPDIR/importconf.XXXXXX")
	sed 's|INSTALL_PATH=.*|INSTALL_PATH="'"$inst"'"|' "$IMPORTCONF" > "$script"
	chmod +x "$script"
	run bash "$script"
	assert_success
	assert_output --partial "Migrated 2 per-rule thresholds from thresholds.conf to pressure.conf"

	# verify thresholds.conf TRIG values were translated to PRESSURE_TRIP in pressure.conf
	run grep '^sshd:' "$inst/pressure.conf"
	assert_output --partial "PRESSURE_TRIP=3"
	run grep '^dovecot:' "$inst/pressure.conf"
	assert_output --partial "PRESSURE_TRIP=25"
	assert_output --partial "SKIP_ALERT=1"
}

@test "importconf: TRIG migrated to PRESSURE_TRIP in conf.bfd" {
	local inst="$TEST_TMPDIR/bfd"
	mkdir -p "$inst" "$inst.bk.last" "$inst/tmp" "$inst/stats"
	_importconf_prep_inst "$inst"

	# old config with legacy TRIG variable
	cat > "$inst.bk.last/conf.bfd" <<'OLDEOF'
# Brute Force Detection 1.5-2 <bfd@rfxn.com>
TRIG="10"
INSTALL_PATH="/usr/local/bfd"
OLDEOF

	# new config with PRESSURE_TRIP
	cat > "$inst/conf.bfd" <<'NEWEOF'
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
PRESSURE_TRIP="15"
INSTALL_PATH="/usr/local/bfd"
NEWEOF

	local script
	script=$(mktemp "$TEST_TMPDIR/importconf.XXXXXX")
	sed 's|INSTALL_PATH=.*|INSTALL_PATH="'"$inst"'"|' "$IMPORTCONF" > "$script"
	chmod +x "$script"
	run bash "$script"
	assert_success
	assert_output --partial "Migrated legacy config"

	# verify PRESSURE_TRIP got the old TRIG value
	run grep '^PRESSURE_TRIP=' "$inst/conf.bfd"
	assert_output 'PRESSURE_TRIP="10"'
}

@test "importconf: TRIG=500 clamped to 200 during migration" {
	local inst="$TEST_TMPDIR/bfd"
	mkdir -p "$inst" "$inst.bk.last" "$inst/tmp" "$inst/stats"
	_importconf_prep_inst "$inst"

	cat > "$inst.bk.last/conf.bfd" <<'OLDEOF'
# Brute Force Detection 1.5-2 <bfd@rfxn.com>
TRIG="500"
INSTALL_PATH="/usr/local/bfd"
OLDEOF

	cat > "$inst/conf.bfd" <<'NEWEOF'
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
PRESSURE_TRIP="20"
INSTALL_PATH="/usr/local/bfd"
NEWEOF

	local script
	script=$(mktemp "$TEST_TMPDIR/importconf.XXXXXX")
	sed 's|INSTALL_PATH=.*|INSTALL_PATH="'"$inst"'"|' "$IMPORTCONF" > "$script"
	chmod +x "$script"
	run bash "$script"
	assert_success
	assert_output --partial "WARNING"
	assert_output --partial "clamped to 200"

	run grep '^PRESSURE_TRIP=' "$inst/conf.bfd"
	assert_output 'PRESSURE_TRIP="200"'
}

@test "importconf: inherited PRESSURE_TRIP=500 clamped to 200 post-merge" {
	local inst="$TEST_TMPDIR/bfd"
	mkdir -p "$inst" "$inst.bk.last" "$inst/tmp" "$inst/stats"
	_importconf_prep_inst "$inst"

	# old config already has PRESSURE_TRIP=500 (from prior bad migration)
	cat > "$inst.bk.last/conf.bfd" <<'OLDEOF'
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
PRESSURE_TRIP="500"
INSTALL_PATH="/usr/local/bfd"
OLDEOF

	cat > "$inst/conf.bfd" <<'NEWEOF'
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
PRESSURE_TRIP="20"
INSTALL_PATH="/usr/local/bfd"
NEWEOF

	local script
	script=$(mktemp "$TEST_TMPDIR/importconf.XXXXXX")
	sed 's|INSTALL_PATH=.*|INSTALL_PATH="'"$inst"'"|' "$IMPORTCONF" > "$script"
	chmod +x "$script"
	run bash "$script"
	assert_success
	assert_output --partial "WARNING"
	assert_output --partial "clamped to 200"

	run grep '^PRESSURE_TRIP=' "$inst/conf.bfd"
	assert_output 'PRESSURE_TRIP="200"'
}

@test "importconf: BAN_DURATION migrated to BAN_TTL in conf.bfd" {
	local inst="$TEST_TMPDIR/bfd"
	mkdir -p "$inst" "$inst.bk.last" "$inst/tmp" "$inst/stats"
	_importconf_prep_inst "$inst"

	cat > "$inst.bk.last/conf.bfd" <<'OLDEOF'
# Brute Force Detection 1.5-2 <bfd@rfxn.com>
BAN_DURATION="300"
INSTALL_PATH="/usr/local/bfd"
OLDEOF

	cat > "$inst/conf.bfd" <<'NEWEOF'
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
BAN_TTL="600"
INSTALL_PATH="/usr/local/bfd"
NEWEOF

	local script
	script=$(mktemp "$TEST_TMPDIR/importconf.XXXXXX")
	sed 's|INSTALL_PATH=.*|INSTALL_PATH="'"$inst"'"|' "$IMPORTCONF" > "$script"
	chmod +x "$script"
	run bash "$script"
	assert_success
	assert_output --partial "Migrated legacy config"

	# old BAN_DURATION=300 should replace new BAN_TTL=600
	run grep '^BAN_TTL=' "$inst/conf.bfd"
	assert_output 'BAN_TTL="300"'
}

@test "importconf: TRIG_WINDOW migrated to PRESSURE_HALF_LIFE in conf.bfd" {
	local inst="$TEST_TMPDIR/bfd"
	mkdir -p "$inst" "$inst.bk.last" "$inst/tmp" "$inst/stats"
	_importconf_prep_inst "$inst"

	cat > "$inst.bk.last/conf.bfd" <<'OLDEOF'
# Brute Force Detection 1.5-2 <bfd@rfxn.com>
TRIG_WINDOW="600"
INSTALL_PATH="/usr/local/bfd"
OLDEOF

	cat > "$inst/conf.bfd" <<'NEWEOF'
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
PRESSURE_HALF_LIFE="300"
INSTALL_PATH="/usr/local/bfd"
NEWEOF

	local script
	script=$(mktemp "$TEST_TMPDIR/importconf.XXXXXX")
	sed 's|INSTALL_PATH=.*|INSTALL_PATH="'"$inst"'"|' "$IMPORTCONF" > "$script"
	chmod +x "$script"
	run bash "$script"
	assert_success
	assert_output --partial "Migrated legacy config"

	run grep '^PRESSURE_HALF_LIFE=' "$inst/conf.bfd"
	assert_output 'PRESSURE_HALF_LIFE="600"'
}

@test "importconf: BAN_PERMANENT_AFTER migrated to BAN_ESCALATE_AFTER" {
	local inst="$TEST_TMPDIR/bfd"
	mkdir -p "$inst" "$inst.bk.last" "$inst/tmp" "$inst/stats"
	_importconf_prep_inst "$inst"

	cat > "$inst.bk.last/conf.bfd" <<'OLDEOF'
# Brute Force Detection 1.5-2 <bfd@rfxn.com>
BAN_PERMANENT_AFTER="3"
INSTALL_PATH="/usr/local/bfd"
OLDEOF

	cat > "$inst/conf.bfd" <<'NEWEOF'
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
BAN_ESCALATE_AFTER="5"
INSTALL_PATH="/usr/local/bfd"
NEWEOF

	local script
	script=$(mktemp "$TEST_TMPDIR/importconf.XXXXXX")
	sed 's|INSTALL_PATH=.*|INSTALL_PATH="'"$inst"'"|' "$IMPORTCONF" > "$script"
	chmod +x "$script"
	run bash "$script"
	assert_success
	assert_output --partial "Migrated legacy config"

	run grep '^BAN_ESCALATE_AFTER=' "$inst/conf.bfd"
	assert_output 'BAN_ESCALATE_AFTER="3"'
}

# --- tlog byte-offset state preservation (F-006) ---

@test "importconf: tlog byte-offset files preserved on upgrade" {
	local inst="$TEST_TMPDIR/bfd"
	mkdir -p "$inst" "$inst.bk.last/tmp" "$inst/tmp" "$inst/stats"
	_importconf_prep_inst "$inst"

	cat > "$inst.bk.last/conf.bfd" <<'OLDEOF'
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
INSTALL_PATH="/usr/local/bfd"
OLDEOF

	cat > "$inst/conf.bfd" <<'NEWEOF'
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
INSTALL_PATH="/usr/local/bfd"
NEWEOF

	# create tlog byte-offset state files (bare names, no extension)
	echo "12345" > "$inst.bk.last/tmp/sshd"
	echo "67890" > "$inst.bk.last/tmp/dovecot"
	echo "11111" > "$inst.bk.last/tmp/postfix"

	local script
	script=$(mktemp "$TEST_TMPDIR/importconf.XXXXXX")
	sed 's|INSTALL_PATH=.*|INSTALL_PATH="'"$inst"'"|' "$IMPORTCONF" > "$script"
	chmod +x "$script"
	run bash "$script"
	assert_success

	# verify byte-offset files were copied
	[ -f "$inst/tmp/sshd" ]
	[ -f "$inst/tmp/dovecot" ]
	[ -f "$inst/tmp/postfix" ]
	run cat "$inst/tmp/sshd"
	assert_output "12345"
	run cat "$inst/tmp/dovecot"
	assert_output "67890"
}

@test "importconf: tlog loop skips dotfiles and extension files" {
	local inst="$TEST_TMPDIR/bfd"
	mkdir -p "$inst" "$inst.bk.last/tmp" "$inst/tmp" "$inst/stats"
	_importconf_prep_inst "$inst"

	cat > "$inst.bk.last/conf.bfd" <<'OLDEOF'
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
INSTALL_PATH="/usr/local/bfd"
OLDEOF

	cat > "$inst/conf.bfd" <<'NEWEOF'
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
INSTALL_PATH="/usr/local/bfd"
NEWEOF

	# create files that should NOT be copied by tlog loop
	echo "skip" > "$inst.bk.last/tmp/.hidden"
	echo "skip" > "$inst.bk.last/tmp/foo.cursor"
	echo "skip" > "$inst.bk.last/tmp/bar.jts"
	echo "skip" > "$inst.bk.last/tmp/bans.active"
	echo "skip" > "$inst.bk.last/tmp/pressure.dat"
	# also create one that SHOULD be copied
	echo "keep" > "$inst.bk.last/tmp/sshd"

	local script
	script=$(mktemp "$TEST_TMPDIR/importconf.XXXXXX")
	sed 's|INSTALL_PATH=.*|INSTALL_PATH="'"$inst"'"|' "$IMPORTCONF" > "$script"
	chmod +x "$script"
	run bash "$script"
	assert_success

	# bare-name file should be copied
	[ -f "$inst/tmp/sshd" ]
	# dotfiles should NOT be copied by tlog loop (may or may not exist from other cp's)
	[ ! -f "$inst/tmp/.hidden" ]
}

# --- alert.bfd preservation (F-007) ---

@test "importconf: custom alert template preserved on upgrade" {
	local inst="$TEST_TMPDIR/bfd"
	mkdir -p "$inst" "$inst.bk.last" "$inst/tmp" "$inst/stats"
	_importconf_prep_inst "$inst"

	cat > "$inst.bk.last/conf.bfd" <<'OLDEOF'
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
INSTALL_PATH="/usr/local/bfd"
OLDEOF

	cat > "$inst/conf.bfd" <<'NEWEOF'
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
INSTALL_PATH="/usr/local/bfd"
NEWEOF

	# create custom alert template in old install
	echo "CUSTOM ALERT TEMPLATE" > "$inst.bk.last/alert.bfd"
	# create default alert template in new install (install.sh would have placed this)
	echo "DEFAULT ALERT TEMPLATE" > "$inst/alert.bfd"

	local script
	script=$(mktemp "$TEST_TMPDIR/importconf.XXXXXX")
	sed 's|INSTALL_PATH=.*|INSTALL_PATH="'"$inst"'"|' "$IMPORTCONF" > "$script"
	chmod +x "$script"
	run bash "$script"
	assert_success

	# verify custom template was preserved over default
	run cat "$inst/alert.bfd"
	assert_output "CUSTOM ALERT TEMPLATE"
}

# --- custom rules preservation (F-005) ---

@test "importconf: custom rule files restored on upgrade" {
	local inst="$TEST_TMPDIR/bfd"
	mkdir -p "$inst" "$inst.bk.last/rules" "$inst/rules" "$inst/tmp" "$inst/stats"
	_importconf_prep_inst "$inst"

	cat > "$inst.bk.last/conf.bfd" <<'OLDEOF'
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
INSTALL_PATH="/usr/local/bfd"
OLDEOF

	cat > "$inst/conf.bfd" <<'NEWEOF'
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
INSTALL_PATH="/usr/local/bfd"
NEWEOF

	# shipped rules in both old and new
	echo "NEW SSHD CONTENT" > "$inst/rules/sshd"
	echo "NEW DOVECOT CONTENT" > "$inst/rules/dovecot"
	echo "OLD SSHD CONTENT" > "$inst.bk.last/rules/sshd"
	echo "OLD DOVECOT CONTENT" > "$inst.bk.last/rules/dovecot"
	# custom rule only in old backup
	echo "CUSTOM APP RULE" > "$inst.bk.last/rules/custom_app"

	local script
	script=$(mktemp "$TEST_TMPDIR/importconf.XXXXXX")
	sed 's|INSTALL_PATH=.*|INSTALL_PATH="'"$inst"'"|' "$IMPORTCONF" > "$script"
	chmod +x "$script"
	run bash "$script"
	assert_success
	assert_output --partial "Restored 1 custom rule(s)"

	# custom rule restored
	[ -f "$inst/rules/custom_app" ]
	run cat "$inst/rules/custom_app"
	assert_output "CUSTOM APP RULE"
	# permissions should be 640
	run stat -c '%a' "$inst/rules/custom_app"
	assert_output "640"
	# shipped rules NOT overwritten (new version kept)
	run cat "$inst/rules/sshd"
	assert_output "NEW SSHD CONTENT"
}

@test "importconf: shipped rules not overwritten by backup versions" {
	local inst="$TEST_TMPDIR/bfd"
	mkdir -p "$inst" "$inst.bk.last/rules" "$inst/rules" "$inst/tmp" "$inst/stats"
	_importconf_prep_inst "$inst"

	cat > "$inst.bk.last/conf.bfd" <<'OLDEOF'
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
INSTALL_PATH="/usr/local/bfd"
OLDEOF

	cat > "$inst/conf.bfd" <<'NEWEOF'
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
INSTALL_PATH="/usr/local/bfd"
NEWEOF

	echo "NEW SSHD CONTENT" > "$inst/rules/sshd"
	echo "OLD SSHD CONTENT" > "$inst.bk.last/rules/sshd"

	local script
	script=$(mktemp "$TEST_TMPDIR/importconf.XXXXXX")
	sed 's|INSTALL_PATH=.*|INSTALL_PATH="'"$inst"'"|' "$IMPORTCONF" > "$script"
	chmod +x "$script"
	run bash "$script"
	assert_success

	# shipped rule keeps new version
	run cat "$inst/rules/sshd"
	assert_output "NEW SSHD CONTENT"
}

@test "importconf: no custom rules produces no restoration output" {
	local inst="$TEST_TMPDIR/bfd"
	mkdir -p "$inst" "$inst.bk.last/rules" "$inst/rules" "$inst/tmp" "$inst/stats"
	_importconf_prep_inst "$inst"

	cat > "$inst.bk.last/conf.bfd" <<'OLDEOF'
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
INSTALL_PATH="/usr/local/bfd"
OLDEOF

	cat > "$inst/conf.bfd" <<'NEWEOF'
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
INSTALL_PATH="/usr/local/bfd"
NEWEOF

	# only shipped rules in both
	echo "sshd content" > "$inst/rules/sshd"
	echo "sshd content" > "$inst.bk.last/rules/sshd"

	local script
	script=$(mktemp "$TEST_TMPDIR/importconf.XXXXXX")
	sed 's|INSTALL_PATH=.*|INSTALL_PATH="'"$inst"'"|' "$IMPORTCONF" > "$script"
	chmod +x "$script"
	run bash "$script"
	assert_success
	refute_output --partial "custom rule"
}

@test "importconf: exclude.files preserved on upgrade" {
	local inst="$TEST_TMPDIR/bfd"
	mkdir -p "$inst" "$inst.bk.last" "$inst/tmp" "$inst/stats"
	_importconf_prep_inst "$inst"

	cat > "$inst.bk.last/conf.bfd" <<'OLDEOF'
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
INSTALL_PATH="/usr/local/bfd"
OLDEOF

	cat > "$inst/conf.bfd" <<'NEWEOF'
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
INSTALL_PATH="/usr/local/bfd"
NEWEOF

	# user's custom exclude.files in backup
	printf '/var/log/custom.log\n/var/log/other.log\n' > "$inst.bk.last/exclude.files"
	# default exclude.files in new install
	printf '/var/log/default.log\n' > "$inst/exclude.files"

	local script
	script=$(mktemp "$TEST_TMPDIR/importconf.XXXXXX")
	sed 's|INSTALL_PATH=.*|INSTALL_PATH="'"$inst"'"|' "$IMPORTCONF" > "$script"
	chmod +x "$script"
	run bash "$script"
	assert_success

	# user's exclude.files should be preserved
	run cat "$inst/exclude.files"
	assert_line --index 0 "/var/log/custom.log"
	assert_line --index 1 "/var/log/other.log"
	# default content should be gone (overwritten by user's version)
	refute_output --partial "/var/log/default.log"
}

@test "importconf: missing alert.bfd in backup keeps new default" {
	local inst="$TEST_TMPDIR/bfd"
	mkdir -p "$inst" "$inst.bk.last" "$inst/tmp" "$inst/stats"
	_importconf_prep_inst "$inst"

	cat > "$inst.bk.last/conf.bfd" <<'OLDEOF'
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
INSTALL_PATH="/usr/local/bfd"
OLDEOF

	cat > "$inst/conf.bfd" <<'NEWEOF'
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
INSTALL_PATH="/usr/local/bfd"
NEWEOF

	# no alert.bfd in backup, but new default exists
	echo "DEFAULT ALERT TEMPLATE" > "$inst/alert.bfd"

	local script
	script=$(mktemp "$TEST_TMPDIR/importconf.XXXXXX")
	sed 's|INSTALL_PATH=.*|INSTALL_PATH="'"$inst"'"|' "$IMPORTCONF" > "$script"
	chmod +x "$script"
	run bash "$script"
	assert_success

	# default template should be unchanged
	run cat "$inst/alert.bfd"
	assert_output "DEFAULT ALERT TEMPLATE"
}

# --- pressure-country.conf preservation (F-046) ---

@test "importconf: pressure-country.conf preserved on upgrade (F-046)" {
	local inst="$TEST_TMPDIR/bfd"
	mkdir -p "$inst" "$inst.bk.last" "$inst/tmp" "$inst/stats"
	_importconf_prep_inst "$inst"

	cat > "$inst.bk.last/conf.bfd" <<'OLDEOF'
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
INSTALL_PATH="/usr/local/bfd"
OLDEOF

	cat > "$inst/conf.bfd" <<'NEWEOF'
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
INSTALL_PATH="/usr/local/bfd"
NEWEOF

	# user-customized country multipliers in old install
	printf 'CN 20\nRU 15\n' > "$inst.bk.last/pressure-country.conf"
	# new default in fresh install
	printf '# country multiplier config\n' > "$inst/pressure-country.conf"

	local script
	script=$(mktemp "$TEST_TMPDIR/importconf.XXXXXX")
	sed 's|INSTALL_PATH=.*|INSTALL_PATH="'"$inst"'"|' "$IMPORTCONF" > "$script"
	chmod +x "$script"
	run bash "$script"
	assert_success
	assert_output --partial "Preserved pressure-country.conf"

	# verify user customizations were preserved
	run cat "$inst/pressure-country.conf"
	assert_line --index 0 "CN 20"
	assert_line --index 1 "RU 15"
}

@test "importconf: missing pressure-country.conf in backup keeps new default (F-046)" {
	local inst="$TEST_TMPDIR/bfd"
	mkdir -p "$inst" "$inst.bk.last" "$inst/tmp" "$inst/stats"
	_importconf_prep_inst "$inst"

	cat > "$inst.bk.last/conf.bfd" <<'OLDEOF'
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
INSTALL_PATH="/usr/local/bfd"
OLDEOF

	cat > "$inst/conf.bfd" <<'NEWEOF'
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
INSTALL_PATH="/usr/local/bfd"
NEWEOF

	# no pressure-country.conf in backup; new default exists
	printf '# default country config\n' > "$inst/pressure-country.conf"

	local script
	script=$(mktemp "$TEST_TMPDIR/importconf.XXXXXX")
	sed 's|INSTALL_PATH=.*|INSTALL_PATH="'"$inst"'"|' "$IMPORTCONF" > "$script"
	chmod +x "$script"
	run bash "$script"
	assert_success
	refute_output --partial "Preserved pressure-country.conf"

	# default should be unchanged
	run cat "$inst/pressure-country.conf"
	assert_output "# default country config"
}

# --- modsec -> mod_sec rename handling ---

@test "importconf: modsec entries in pressure.conf renamed to mod_sec" {
	local inst="$TEST_TMPDIR/bfd"
	mkdir -p "$inst" "$inst.bk.last" "$inst/tmp" "$inst/stats"
	_importconf_prep_inst "$inst"

	cat > "$inst.bk.last/conf.bfd" <<'OLDEOF'
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
INSTALL_PATH="/usr/local/bfd"
OLDEOF

	cat > "$inst/conf.bfd" <<'NEWEOF'
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
INSTALL_PATH="/usr/local/bfd"
NEWEOF

	# old pressure.conf with modsec entries
	cat > "$inst.bk.last/pressure.conf" <<'EOF'
sshd:PRESSURE_WEIGHT=3:PRESSURE_TRIP=10
modsec:PRESSURE_WEIGHT=3:PRESSURE_TRIP=5
dovecot:PRESSURE_WEIGHT=2
EOF

	# new pressure.conf with defaults
	cat > "$inst/pressure.conf" <<'EOF'
sshd:PRESSURE_TRIP=5
mod_sec:PRESSURE_TRIP=10
EOF

	local script
	script=$(mktemp "$TEST_TMPDIR/importconf.XXXXXX")
	sed 's|INSTALL_PATH=.*|INSTALL_PATH="'"$inst"'"|' "$IMPORTCONF" > "$script"
	chmod +x "$script"
	run bash "$script"
	assert_success

	# modsec should be renamed to mod_sec in preserved pressure.conf
	run grep '^mod_sec:' "$inst/pressure.conf"
	assert_output "mod_sec:PRESSURE_WEIGHT=3:PRESSURE_TRIP=5"
	# old modsec: prefix should not remain
	run grep '^modsec:' "$inst/pressure.conf"
	assert_failure
}

@test "importconf: old modsec rule file blocked by _REMOVED_RULES" {
	local inst="$TEST_TMPDIR/bfd"
	mkdir -p "$inst" "$inst.bk.last/rules" "$inst/rules" "$inst/tmp" "$inst/stats"
	_importconf_prep_inst "$inst"

	cat > "$inst.bk.last/conf.bfd" <<'OLDEOF'
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
INSTALL_PATH="/usr/local/bfd"
OLDEOF

	cat > "$inst/conf.bfd" <<'NEWEOF'
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
INSTALL_PATH="/usr/local/bfd"
NEWEOF

	# shipped rules in new install
	echo "NEW SSHD" > "$inst/rules/sshd"
	echo "NEW MOD_SEC" > "$inst/rules/mod_sec"

	# old backup has both shipped and renamed rules
	echo "OLD SSHD" > "$inst.bk.last/rules/sshd"
	echo "OLD MODSEC" > "$inst.bk.last/rules/modsec"
	# also a genuinely custom rule
	echo "CUSTOM RULE" > "$inst.bk.last/rules/my_custom"

	local script
	script=$(mktemp "$TEST_TMPDIR/importconf.XXXXXX")
	sed 's|INSTALL_PATH=.*|INSTALL_PATH="'"$inst"'"|' "$IMPORTCONF" > "$script"
	chmod +x "$script"
	run bash "$script"
	assert_success

	# modsec should NOT be restored (it's in _REMOVED_RULES)
	[ ! -f "$inst/rules/modsec" ]
	# custom rule should be restored
	[ -f "$inst/rules/my_custom" ]
	run cat "$inst/rules/my_custom"
	assert_output "CUSTOM RULE"
	# shipped rules should keep new version
	run cat "$inst/rules/sshd"
	assert_output "NEW SSHD"
}

# --- legacy migration message (F-047) ---

@test "importconf: legacy migration message recommends bfd -c (F-047)" {
	local inst="$TEST_TMPDIR/bfd"
	mkdir -p "$inst" "$inst.bk.last" "$inst/tmp" "$inst/stats"
	_importconf_prep_inst "$inst"

	cat > "$inst.bk.last/conf.bfd" <<'OLDEOF'
# Brute Force Detection 1.5-2 <bfd@rfxn.com>
TRIG="10"
INSTALL_PATH="/usr/local/bfd"
OLDEOF

	cat > "$inst/conf.bfd" <<'NEWEOF'
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
PRESSURE_TRIP="15"
INSTALL_PATH="/usr/local/bfd"
NEWEOF

	local script
	script=$(mktemp "$TEST_TMPDIR/importconf.XXXXXX")
	sed 's|INSTALL_PATH=.*|INSTALL_PATH="'"$inst"'"|' "$IMPORTCONF" > "$script"
	chmod +x "$script"
	run bash "$script"
	assert_success
	assert_output --partial "bfd -c"
	refute_output --partial "equivalent behavior"
}
