#!/usr/bin/env bats
#
# Test suite for watch mode daemon lifecycle (C-003)
#
# Tier 1: Unit tests — cleanup_watch() and reload_watch() extracted from
#          files/bfd and tested in isolation with bfd.lib.sh functions.
# Tier 2: Integration tests — actual bfd --watch process lifecycle.
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

# _load_watch_functions: extract cleanup_watch/reload_watch from files/bfd
# into the current shell scope. Both functions depend only on bfd.lib.sh
# (already sourced via bfd_common_setup) and config variables.
_load_watch_functions() {
	local bfd_file="$PROJECT_ROOT/files/bfd"
	eval "$(awk '/^config_init\(\) \{/,/^\}/' "$bfd_file")"
	eval "$(awk '/^cleanup_watch\(\) \{/,/^\}/' "$bfd_file")"
	eval "$(awk '/^reload_watch\(\) \{/,/^\}/' "$bfd_file")"
}

# _setup_watch_env: create a minimal BFD install directory suitable for
# reload_watch() — needs conf.bfd and internals.conf with root ownership
# and safe permissions (for stat checks inside reload_watch).
_setup_watch_env() {
	INSTALL_PATH="$TEST_TMPDIR/bfd"
	mkdir -p "$INSTALL_PATH/tmp" "$INSTALL_PATH/rules" "$INSTALL_PATH/stats"
	state_init "$INSTALL_PATH"

	CNF="$INSTALL_PATH/conf.bfd"
	INTCNF="$INSTALL_PATH/internals.conf"

	cat > "$CNF" <<CNFEOF
#!/bin/bash
PRESSURE_TRIP="20"
PRESSURE_HALF_LIFE="300"
PRESSURE_TRIP_GLOBAL="0"
BAN_TTL="600"
BAN_ESCALATE_AFTER="5"
BAN_ESCALATE_WINDOW="86400"
BAN_ESCALATION="none"
BAN_ESCALATION_CAP="86400"
EMAIL_ALERTS="0"
EMAIL_ADDRESS="root"
EMAIL_SUBJECT="BFD Alert"
EMAIL_LOGLINES="50"
FIREWALL="custom"
BAN_COMMAND="/bin/true"
UNBAN_COMMAND="/bin/true"
WATCH_INTERVAL="10"
SUBNET_TRIG="0"
SUBNET_MASK="24"
SUBNET_MASK_V6="48"
OUTPUT_SYSLOG="0"
BFD_LOG_PATH="$BFD_LOG_PATH"
AUTH_LOG_PATH="/dev/null"
KERNEL_LOG_PATH="/dev/null"
MAIL_LOG_PATH="/dev/null"
LOG_FORMAT="classic"
LOG_LEVEL="1"
SCAN_MAX_LINES="50000"
SCAN_TIMEOUT="120"
CNFEOF
	chown root "$CNF"
	chmod 640 "$CNF"

	cat > "$INTCNF" <<INTEOF
#!/bin/bash
RULES_PATH="$INSTALL_PATH/rules"
TLOG_PATH="$INSTALL_PATH/tlog"
TLOG_BASERUN="$INSTALL_PATH/tmp"
EMAIL_TEMPLATE="$INSTALL_PATH/alert.bfd"
IGNORE_HOST_FILES="$INSTALL_PATH/exclude.files"
LOCK_FILE="$INSTALL_PATH/lock.utime"
LOCK_FILE_TIMEOUT="300"
OUTPUT_SYSLOG_FILE="/dev/null"
BAN_RETRY_COUNT="0"
LOG_SOURCE="auto"
INTEOF
	chown root "$INTCNF"
	chmod 640 "$INTCNF"

	# set globals needed before config_init runs (cleanup_watch tests,
	# reload_watch local IP refresh, initial LOCK_FILE for cleanup tests)
	LOCK_FILE="$INSTALL_PATH/lock.utime"
	KERNEL_LOG_PATH="/dev/null"
	IP_BIN=""
	LO_HOSTS="$INSTALL_PATH/ignore.hosts.local"
	touch "$LO_HOSTS"
	touch "$INSTALL_PATH/exclude.files"

	# run config_init for initial setup (sets all derived vars, pressure arrays, etc.)
	config_init
}

setup() {
	bfd_require_bash42
	bfd_common_setup
	_load_watch_functions
	_setup_watch_env
}

teardown() {
	# kill any lingering watch process
	if [ -n "${_WATCH_PID:-}" ]; then
		kill -TERM "$_WATCH_PID" 2>/dev/null
		wait "$_WATCH_PID" 2>/dev/null || true
	fi
	bfd_teardown
}

# ============================================================
# Tier 1: Unit tests — cleanup_watch()
# ============================================================

@test "cleanup_watch: removes lock directory" {
	mkdir -p "$LOCK_FILE.lk"
	echo "$$" > "$LOCK_FILE.lk/pid"
	echo "1700000000" > "$LOCK_FILE"
	cleanup_watch
	[ ! -d "$LOCK_FILE.lk" ]
}

@test "cleanup_watch: removes lock timestamp file" {
	mkdir -p "$LOCK_FILE.lk"
	echo "1700000000" > "$LOCK_FILE"
	cleanup_watch
	[ ! -f "$LOCK_FILE" ]
}

@test "cleanup_watch: logs shutdown message" {
	mkdir -p "$LOCK_FILE.lk"
	echo "1700000000" > "$LOCK_FILE"
	cleanup_watch
	run grep "watch mode shutting down" "$BFD_LOG_PATH"
	assert_success
}

# ============================================================
# Tier 1: Unit tests — reload_watch()
# ============================================================

@test "reload_watch: re-sources conf.bfd — changed PRESSURE_TRIP takes effect" {
	# initial value
	PRESSURE_TRIP="20"
	# change config file
	sed -i 's/PRESSURE_TRIP="20"/PRESSURE_TRIP="42"/' "$CNF"
	reload_watch
	[ "$PRESSURE_TRIP" = "42" ]
}

@test "reload_watch: re-sources internals.conf — changed variable takes effect" {
	LOCK_FILE_TIMEOUT="300"
	sed -i 's/LOCK_FILE_TIMEOUT="300"/LOCK_FILE_TIMEOUT="600"/' "$INTCNF"
	reload_watch
	[ "$LOCK_FILE_TIMEOUT" = "600" ]
}

@test "reload_watch: rejects unsafe conf.bfd (wrong perms)" {
	local old_trip="$PRESSURE_TRIP"
	chmod 666 "$CNF"
	run reload_watch
	assert_failure
	# old value should be preserved (config not re-sourced)
	[ "$PRESSURE_TRIP" = "$old_trip" ]
}

@test "reload_watch: clears pressure arrays when pressure.conf deleted (F-063)" {
	# create pressure.conf with an entry
	local pconf="$INSTALL_PATH/pressure.conf"
	echo "sshd:PRESSURE_WEIGHT=5" > "$pconf"
	chown root "$pconf"
	chmod 640 "$pconf"

	# initial load fills arrays
	reload_watch
	[ "${_PRESS_WEIGHT[sshd]}" = "5" ]

	# delete pressure.conf and reload
	rm -f "$pconf"
	reload_watch

	# arrays should be empty (no stale data)
	[ -z "${_PRESS_WEIGHT[sshd]+x}" ]
}

@test "reload_watch: re-derives fallback variables (F-030)" {
	# unset variables that should get fallback values
	unset RULES_PATH
	unset TLOG_PATH
	unset EMAIL_TEMPLATE
	# also remove from internals.conf so sourcing doesn't set them
	cat > "$INTCNF" <<'INTEOF'
#!/bin/bash
LOCK_FILE_TIMEOUT="300"
INTEOF
	chown root "$INTCNF"
	chmod 640 "$INTCNF"

	reload_watch

	# fallback values should be derived from INSTALL_PATH
	[ "$RULES_PATH" = "$INSTALL_PATH/rules" ]
	[ "$TLOG_PATH" = "$INSTALL_PATH/tlog" ]
	[ "$EMAIL_TEMPLATE" = "$INSTALL_PATH/alert.bfd" ]
}

@test "reload_watch: refreshes firewall backend" {
	_FW_BACKEND="custom"
	reload_watch
	# fw_resolve_backend runs, but with FIREWALL="custom" it stays custom
	[ "$_FW_BACKEND" = "custom" ]
}

@test "reload_watch: logs reload complete message" {
	reload_watch
	run grep "watch mode reload complete" "$BFD_LOG_PATH"
	assert_success
}

@test "reload_watch: ELOG_FORMAT re-derived from LOG_FORMAT (F-002)" {
	# change LOG_FORMAT in conf.bfd
	sed -i 's/LOG_FORMAT="classic"/LOG_FORMAT="json"/' "$CNF"
	reload_watch
	[ "$ELOG_FORMAT" = "json" ]
}

@test "reload_watch: ELOG_LEVEL re-derived from LOG_LEVEL (F-002)" {
	sed -i 's/LOG_LEVEL="1"/LOG_LEVEL="3"/' "$CNF"
	reload_watch
	[ "$ELOG_LEVEL" = "3" ]
}

@test "reload_watch: ELOG_SYSLOG_FILE re-derived from OUTPUT_SYSLOG (F-002)" {
	# enable syslog output
	sed -i 's/OUTPUT_SYSLOG="0"/OUTPUT_SYSLOG="1"/' "$CNF"
	reload_watch
	[ -n "$ELOG_SYSLOG_FILE" ]
}

@test "reload_watch: unsets BAN_ESCALATION on config change (F-010)" {
	# initial value from conf.bfd
	[ "$BAN_ESCALATION" = "none" ]
	# change to linear
	sed -i 's/BAN_ESCALATION="none"/BAN_ESCALATION="linear"/' "$CNF"
	reload_watch
	[ "$BAN_ESCALATION" = "linear" ]
}

@test "reload_watch: unsets EMAIL_ALERTS on config change (F-010)" {
	[ "$EMAIL_ALERTS" = "0" ]
	sed -i 's/EMAIL_ALERTS="0"/EMAIL_ALERTS="1"/' "$CNF"
	reload_watch
	[ "$EMAIL_ALERTS" = "1" ]
}

@test "reload_watch: re-registers journal filters (F-057)" {
	reload_watch
	# _bfd_journal_register_all registers 23 mappings
	[ "${#_TLOG_JOURNAL_NAMES[@]}" -ge 23 ]
}

@test "reload_watch: config validation failure returns non-zero (F-014)" {
	# set PRESSURE_TRIP to invalid value
	sed -i 's/PRESSURE_TRIP="20"/PRESSURE_TRIP="abc"/' "$CNF"
	run reload_watch
	assert_failure
}

@test "reload_watch: syntax error in conf.bfd aborts before unset" {
	local old_trip="$PRESSURE_TRIP"
	# introduce syntax error
	echo 'if [' >> "$CNF"
	run reload_watch
	assert_failure
	# old value should be preserved (unset never ran)
	[ "$PRESSURE_TRIP" = "$old_trip" ]
}

# ============================================================
# Tier 2: Integration tests — bfd --watch process lifecycle
# ============================================================

# _start_watch: launch bfd --watch in background with test config
_start_watch() {
	# create a minimal working install
	local inst="$TEST_TMPDIR/watch-inst"
	mkdir -p "$inst/tmp" "$inst/rules" "$inst/stats"
	cp "$PROJECT_ROOT/files/bfd" "$inst/bfd"
	cp "$PROJECT_ROOT/files/bfd.lib.sh" "$inst/bfd.lib.sh"
	chown root "$inst/bfd.lib.sh"
	chmod 640 "$inst/bfd.lib.sh"
	cp "$PROJECT_ROOT/files/tlog" "$inst/tlog"
	chmod 750 "$inst/tlog"
	cp "$PROJECT_ROOT/files/tlog_lib.sh" "$inst/tlog_lib.sh"
	chmod 750 "$inst/tlog_lib.sh"
	cp "$PROJECT_ROOT/files/elog_lib.sh" "$inst/elog_lib.sh"
	chmod 750 "$inst/elog_lib.sh"
	touch "$inst/exclude.files"
	touch "$inst/alert.bfd"

	cat > "$inst/conf.bfd" <<CNFEOF
#!/bin/bash
PRESSURE_TRIP="20"
PRESSURE_HALF_LIFE="300"
PRESSURE_TRIP_GLOBAL="0"
BAN_TTL="600"
BAN_ESCALATE_AFTER="5"
BAN_ESCALATE_WINDOW="86400"
BAN_ESCALATION="none"
BAN_ESCALATION_CAP="86400"
EMAIL_ALERTS="0"
EMAIL_ADDRESS="root"
EMAIL_SUBJECT="BFD Alert"
EMAIL_LOGLINES="50"
FIREWALL="custom"
BAN_COMMAND="/bin/true"
UNBAN_COMMAND="/bin/true"
WATCH_INTERVAL="1"
SUBNET_TRIG="0"
SUBNET_MASK="24"
SUBNET_MASK_V6="48"
OUTPUT_SYSLOG="0"
BFD_LOG_PATH="$inst/tmp/bfd.log"
AUTH_LOG_PATH="/dev/null"
KERNEL_LOG_PATH="/dev/null"
MAIL_LOG_PATH="/dev/null"
LOG_FORMAT="classic"
LOG_LEVEL="1"
SCAN_MAX_LINES="50000"
SCAN_TIMEOUT="120"
CNFEOF
	chown root "$inst/conf.bfd"
	chmod 640 "$inst/conf.bfd"

	cat > "$inst/internals.conf" <<INTEOF
#!/bin/bash
RULES_PATH="$inst/rules"
TLOG_PATH="$inst/tlog"
TLOG_BASERUN="$inst/tmp"
EMAIL_TEMPLATE="$inst/alert.bfd"
IGNORE_HOST_FILES="$inst/exclude.files"
LOCK_FILE="$inst/lock.utime"
LOCK_FILE_TIMEOUT="300"
OUTPUT_SYSLOG_FILE="/dev/null"
BAN_RETRY_COUNT="0"
LOG_SOURCE="file"
INTEOF
	chown root "$inst/internals.conf"
	chmod 640 "$inst/internals.conf"

	touch "$inst/tmp/bfd.log"

	# patch INSTALL_PATH in the copied bfd script
	sed -i "s|^INSTALL_PATH=.*|INSTALL_PATH=\"$inst\"|" "$inst/bfd"

	_WATCH_INST="$inst"
	bash "$inst/bfd" --watch &
	_WATCH_PID=$!

	# wait for lock file to appear (up to 5s)
	local _tries=0
	while [ ! -d "$inst/lock.utime.lk" ] && [ "$_tries" -lt 10 ]; do
		sleep 0.5
		_tries=$((_tries + 1))
	done
}

@test "watch: starts and creates lock file" {
	_start_watch
	[ -d "$_WATCH_INST/lock.utime.lk" ]
	[ -f "$_WATCH_INST/lock.utime" ]
}

@test "watch: creates PID file in lock directory" {
	_start_watch
	[ -f "$_WATCH_INST/lock.utime.lk/pid" ]
	local pid
	pid=$(cat "$_WATCH_INST/lock.utime.lk/pid")
	[ "$pid" = "$_WATCH_PID" ]
}

@test "watch: logs start message" {
	_start_watch
	# give it a moment to write
	sleep 1
	run grep "watch mode started" "$_WATCH_INST/tmp/bfd.log"
	assert_success
}

@test "watch: SIGTERM causes graceful shutdown" {
	_start_watch
	sleep 1
	kill -TERM "$_WATCH_PID"
	wait "$_WATCH_PID" 2>/dev/null || true
	_WATCH_PID=""

	# lock should be cleaned up
	[ ! -d "$_WATCH_INST/lock.utime.lk" ]
	[ ! -f "$_WATCH_INST/lock.utime" ]

	# shutdown message should be logged
	run grep "watch mode shutting down" "$_WATCH_INST/tmp/bfd.log"
	assert_success
}

@test "watch: SIGHUP causes config reload" {
	_start_watch
	sleep 1
	kill -HUP "$_WATCH_PID"
	sleep 2

	run grep "watch mode reload complete" "$_WATCH_INST/tmp/bfd.log"
	assert_success
}
