#!/usr/bin/env bats
#
# Test suite for bfd-watch.init SysVinit init script
# and get_state() PID liveness lock behavior
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

setup() {
	bfd_common_setup
	INSTALL_PATH="$TEST_TMPDIR/bfd"
	mkdir -p "$INSTALL_PATH"
	LOCK_FILE="$INSTALL_PATH/lock.utime"
	LOCK_FILE_TIMEOUT="300"
}

teardown() {
	bfd_teardown
}

# --- bfd-watch.init structural tests ---

@test "bfd-watch.init: syntax check passes" {
	run bash -n "$PROJECT_ROOT/bfd-watch.init"
	assert_success
}

@test "bfd-watch.init: LSB init header present" {
	run grep '### BEGIN INIT INFO' "$PROJECT_ROOT/bfd-watch.init"
	assert_success
	run grep '### END INIT INFO' "$PROJECT_ROOT/bfd-watch.init"
	assert_success
}

@test "bfd-watch.init: chkconfig header present" {
	run grep '# chkconfig:' "$PROJECT_ROOT/bfd-watch.init"
	assert_success
}

@test "bfd-watch.init: Provides bfd-watch" {
	run grep '# Provides:.*bfd-watch' "$PROJECT_ROOT/bfd-watch.init"
	assert_success
}

@test "bfd-watch.init: case dispatcher has required actions" {
	for action in start stop restart reload status condrestart try-restart; do
		run grep -E "(^|[|[:space:]])$action([|)])" "$PROJECT_ROOT/bfd-watch.init"
		assert_success
	done
}

@test "bfd-watch.init: BFD_BIN variable points to expected path" {
	run grep '^BFD_BIN="/usr/local/sbin/bfd"' "$PROJECT_ROOT/bfd-watch.init"
	assert_success
}

@test "bfd-watch.init: PIDFILE uses /var/run/" {
	run grep '^PIDFILE="/var/run/' "$PROJECT_ROOT/bfd-watch.init"
	assert_success
}

@test "bfd-watch.init: sources RHEL or Debian init functions" {
	run grep '/etc/init.d/functions' "$PROJECT_ROOT/bfd-watch.init"
	assert_success
	run grep '/lib/lsb/init-functions' "$PROJECT_ROOT/bfd-watch.init"
	assert_success
}

@test "bfd-watch.init: INITSTYLE bare fallback exists" {
	run grep 'INITSTYLE="bare"' "$PROJECT_ROOT/bfd-watch.init"
	assert_success
}

@test "bfd-watch.init: graceful stop sends SIGTERM before SIGKILL" {
	# verify the stop function sends SIGTERM first, then escalates
	run grep 'kill "$_pid"' "$PROJECT_ROOT/bfd-watch.init"
	assert_success
	run grep 'kill -9' "$PROJECT_ROOT/bfd-watch.init"
	assert_success
}

@test "bfd-watch.init: reload sends SIGHUP" {
	run grep 'kill -HUP' "$PROJECT_ROOT/bfd-watch.init"
	assert_success
}

@test "bfd-watch.init: uses --watch flag" {
	run grep -- '--watch' "$PROJECT_ROOT/bfd-watch.init"
	assert_success
}

@test "bfd-watch.init: copyright header present" {
	run grep 'Copyright.*R-fx Networks' "$PROJECT_ROOT/bfd-watch.init"
	assert_success
}

# --- get_state() PID liveness lock tests ---
# These test the lock behavior by directly simulating lock state
# and running the get_state() function extracted from files/bfd

# Helper: define get_state() in test context with minimal dependencies
_define_get_state() {
	# get_state() is defined in files/bfd; we reproduce it here
	# to test in isolation (files/bfd has top-level init that can't run)
	get_state() {
		if ! mkdir "$LOCK_FILE.lk" 2>/dev/null; then
			if [ -f "$LOCK_FILE" ]; then
				OVAL=$(cat "$LOCK_FILE")
				DIFF=$((UTIME - OVAL))
				if [ "$DIFF" -gt "$LOCK_FILE_TIMEOUT" ]; then
					eout "cleared stale lock (${DIFF}s old, pid=$(cat "$LOCK_FILE.lk/pid" 2>/dev/null || echo unknown))."
					rm -rf "$LOCK_FILE.lk"
					mkdir "$LOCK_FILE.lk" 2>/dev/null || {
						eout "unable to acquire lock after stale cleanup, aborting."
						exit "$EXIT_LOCK_ERROR"
					}
				else
					local _lock_pid
					_lock_pid=$(cat "$LOCK_FILE.lk/pid" 2>/dev/null)
					if [ -n "$_lock_pid" ] && ! kill -0 "$_lock_pid" 2>/dev/null; then
						eout "cleared dead lock (pid=$_lock_pid exited, lock ${DIFF}s old)."
						rm -rf "$LOCK_FILE.lk"
						mkdir "$LOCK_FILE.lk" 2>/dev/null || {
							eout "unable to acquire lock after dead-pid cleanup, aborting."
							exit "$EXIT_LOCK_ERROR"
						}
					else
						eout "locked subsystem, already running ? ($LOCK_FILE is $DIFF seconds old), aborting."
						exit "$EXIT_LOCK_ERROR"
					fi
				fi
			else
				eout "lock directory exists but no timestamp file, aborting."
				exit "$EXIT_LOCK_ERROR"
			fi
		fi
		echo "$$" > "$LOCK_FILE.lk/pid"
		echo "$UTIME" > "$LOCK_FILE"
	}
}

@test "get_state: acquires lock on clean state" {
	_define_get_state
	UTIME=$(date +"%s")
	get_state
	[ -d "$LOCK_FILE.lk" ]
	[ -f "$LOCK_FILE.lk/pid" ]
	[ -f "$LOCK_FILE" ]
}

@test "get_state: clears lock when holder PID is dead" {
	_define_get_state
	UTIME=$(date +"%s")

	# simulate a lock held by a dead process
	mkdir "$LOCK_FILE.lk"
	echo "99999999" > "$LOCK_FILE.lk/pid"  # almost certainly not running
	echo "$UTIME" > "$LOCK_FILE"            # fresh timestamp

	# get_state should detect dead PID and re-acquire
	run get_state
	assert_success
	assert_output --partial "cleared dead lock"
}

@test "get_state: blocks when holder PID is alive" {
	_define_get_state
	UTIME=$(date +"%s")

	# simulate a lock held by a living process (PID 1 is always alive)
	mkdir "$LOCK_FILE.lk"
	echo "1" > "$LOCK_FILE.lk/pid"
	echo "$UTIME" > "$LOCK_FILE"

	# get_state should refuse (exit 2 = EXIT_LOCK_ERROR)
	run get_state
	assert_failure "$EXIT_LOCK_ERROR"
	assert_output --partial "locked subsystem, already running"
}

@test "get_state: clears stale lock by timestamp regardless of PID" {
	_define_get_state
	UTIME=$(date +"%s")

	# simulate a stale lock (timestamp > LOCK_FILE_TIMEOUT ago)
	mkdir "$LOCK_FILE.lk"
	echo "1" > "$LOCK_FILE.lk/pid"  # PID 1 is alive
	local old_time=$((UTIME - LOCK_FILE_TIMEOUT - 100))
	echo "$old_time" > "$LOCK_FILE"

	# get_state should clear by staleness
	run get_state
	assert_success
	assert_output --partial "cleared stale lock"
}

@test "get_state: handles missing PID file gracefully" {
	_define_get_state
	UTIME=$(date +"%s")

	# simulate lock dir without PID file but with fresh timestamp
	mkdir "$LOCK_FILE.lk"
	echo "$UTIME" > "$LOCK_FILE"
	# no pid file — _lock_pid will be empty
	# empty PID means the kill -0 check won't match, falls through to "already running"

	run get_state
	assert_failure "$EXIT_LOCK_ERROR"
	assert_output --partial "locked subsystem, already running"
}

@test "get_state: handles lock dir without timestamp file" {
	_define_get_state
	UTIME=$(date +"%s")

	# simulate lock dir without timestamp file
	mkdir "$LOCK_FILE.lk"

	run get_state
	assert_failure "$EXIT_LOCK_ERROR"
	assert_output --partial "lock directory exists but no timestamp file"
}

@test "get_state: dead PID lock recovery writes new PID" {
	_define_get_state
	UTIME=$(date +"%s")

	# simulate dead lock
	mkdir "$LOCK_FILE.lk"
	echo "99999999" > "$LOCK_FILE.lk/pid"
	echo "$UTIME" > "$LOCK_FILE"

	get_state
	# after recovery, PID file should contain current process PID
	local new_pid
	new_pid=$(cat "$LOCK_FILE.lk/pid")
	[ "$new_pid" = "$$" ]
}
