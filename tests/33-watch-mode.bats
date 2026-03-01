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

	cat > "$CNF" <<'CNFEOF'
#!/bin/bash
PRESSURE_TRIP="20"
PRESSURE_HALF_LIFE="300"
PRESSURE_TRIP_GLOBAL="0"
BAN_TTL="600"
BAN_ESCALATE_AFTER="5"
BAN_ESCALATE_WINDOW="86400"
EMAIL_ALERTS="0"
EMAIL_ADDRESS="root"
FIREWALL="custom"
BAN_COMMAND="/bin/true"
UNBAN_COMMAND="/bin/true"
WATCH_INTERVAL="10"
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

	# set globals needed by reload_watch
	LOCK_FILE="$INSTALL_PATH/lock.utime"
	TLOG_BASERUN="$INSTALL_PATH/tmp"
	BAN_COMMAND_TEMPLATE="/bin/true"
	UNBAN_COMMAND_TEMPLATE="/bin/true"
	BAN_COMMAND_V6_TEMPLATE=""
	UNBAN_COMMAND_V6_TEMPLATE=""
	_FW_BACKEND="custom"
	BAN_RETRY_COUNT="0"
	TLOG_PATH="$INSTALL_PATH/tlog"
	RULES_PATH="$INSTALL_PATH/rules"
	KERNEL_LOG_PATH="/dev/null"
	IP_BIN=""
	LO_HOSTS="$INSTALL_PATH/ignore.hosts.local"
	touch "$LO_HOSTS"
	touch "$INSTALL_PATH/exclude.files"
	declare -gA _PRESS_WEIGHT _PRESS_TRIP _PRESS_SKIP_ALERT _PRESS_RULE_EMAIL
	declare -gA _THRESH_TRIG _THRESH_SKIP_ALERT _THRESH_RULE_EMAIL
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

	cat > "$inst/conf.bfd" <<'CNFEOF'
#!/bin/bash
PRESSURE_TRIP="20"
PRESSURE_HALF_LIFE="300"
PRESSURE_TRIP_GLOBAL="0"
BAN_TTL="600"
BAN_ESCALATE_AFTER="5"
BAN_ESCALATE_WINDOW="86400"
EMAIL_ALERTS="0"
EMAIL_ADDRESS="root"
FIREWALL="custom"
BAN_COMMAND="/bin/true"
UNBAN_COMMAND="/bin/true"
WATCH_INTERVAL="1"
OUTPUT_SYSLOG="0"
BFD_LOG_PATH="__LOGPATH__"
CNFEOF
	sed -i "s|__LOGPATH__|$inst/tmp/bfd.log|" "$inst/conf.bfd"
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
