#!/usr/bin/env bats
#
# Test suite for systemd journal reader — tlog_journal_filter(), tlog_journal_read(),
# tlog_read() journal dispatch, and validate_rule() journal awareness
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

setup() {
	TEST_TMPDIR=$(mktemp -d)
	export BASERUN="$TEST_TMPDIR/tracking"
	mkdir -p "$BASERUN"

	# eout dependencies
	BFD_LOG_PATH="$TEST_TMPDIR/bfd.log"
	touch "$BFD_LOG_PATH"
	OUTPUT_SYSLOG="0"
	OUTPUT_SYSLOG_FILE="/dev/null"

	# create mock journalctl
	MOCK_BIN="$TEST_TMPDIR/bin"
	mkdir -p "$MOCK_BIN"
	# empty bin dir for "no journalctl" tests
	EMPTY_BIN="$TEST_TMPDIR/empty_bin"
	mkdir -p "$EMPTY_BIN"
	SAVED_PATH="$PATH"
	export PATH="$MOCK_BIN:$PATH"
	_create_mock_journalctl
}

teardown() {
	rm -rf "$TEST_TMPDIR"
}

# Helper: create a mock journalctl that outputs syslog-format lines
_create_mock_journalctl() {
	cat > "$MOCK_BIN/journalctl" <<'MOCK'
#!/bin/bash
# Mock journalctl for testing
# Understands: --after-cursor, --since, -n 0, --show-cursor, --output, --no-pager, -q
CURSOR_OUTPUT=""
LINES_OUTPUT=""
SHOW_CURSOR=0
NULL_RUN=0
for arg in "$@"; do
	case "$arg" in
		--show-cursor) SHOW_CURSOR=1 ;;
		-n) : ;;
		0) if [ "${prev_arg:-}" = "-n" ]; then NULL_RUN=1; fi ;;
		--after-cursor=INVALID_CURSOR)
			# simulate invalid cursor error
			echo "Failed to seek to cursor" >&2
			exit 1
			;;
		--after-cursor=*)
			# subsequent run — output new lines
			LINES_OUTPUT="subsequent"
			;;
		--since=*)
			# timestamp-based fallback
			LINES_OUTPUT="timestamp_fallback"
			;;
	esac
	prev_arg="$arg"
done

if [ "$NULL_RUN" = "1" ]; then
	# first run — output only cursor
	if [ "$SHOW_CURSOR" = "1" ]; then
		echo "-- cursor: s=abc123;i=1;b=def456"
	fi
	exit 0
fi

if [ "$LINES_OUTPUT" = "subsequent" ]; then
	echo "Feb 20 10:15:01 server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2"
	echo "Feb 20 10:15:02 server sshd[12346]: Invalid user admin from 10.0.0.5 port 22 ssh2"
	if [ "$SHOW_CURSOR" = "1" ]; then
		echo "-- cursor: s=abc123;i=3;b=def456"
	fi
	exit 0
fi

if [ "$LINES_OUTPUT" = "timestamp_fallback" ]; then
	echo "Feb 20 10:20:01 server sshd[12347]: Failed password for user1 from 172.16.0.1 port 22 ssh2"
	if [ "$SHOW_CURSOR" = "1" ]; then
		echo "-- cursor: s=abc123;i=5;b=def456"
	fi
	exit 0
fi

# default: output some lines
echo "Feb 20 10:00:01 server sshd[12340]: Failed password for root from 192.168.1.50 port 22 ssh2"
if [ "$SHOW_CURSOR" = "1" ]; then
	echo "-- cursor: s=abc123;i=2;b=def456"
fi
exit 0
MOCK
	chmod +x "$MOCK_BIN/journalctl"
}

# --- tlog_journal_filter() tests ---

@test "tlog_journal_filter: sshd maps to SYSLOG_IDENTIFIER=sshd" {
	run tlog_journal_filter "sshd"
	assert_success
	assert_output "SYSLOG_IDENTIFIER=sshd"
}

@test "tlog_journal_filter: dovecot maps correctly" {
	run tlog_journal_filter "dovecot"
	assert_success
	assert_output "SYSLOG_IDENTIFIER=dovecot"
}

@test "tlog_journal_filter: courier maps to couriertcpd" {
	run tlog_journal_filter "courier"
	assert_success
	assert_output "SYSLOG_IDENTIFIER=couriertcpd"
}

@test "tlog_journal_filter: sendmail maps to sm-mta" {
	run tlog_journal_filter "sendmail"
	assert_success
	assert_output "SYSLOG_IDENTIFIER=sm-mta"
}

@test "tlog_journal_filter: rh_imapd maps to imapd" {
	run tlog_journal_filter "rh_imapd"
	assert_success
	assert_output "SYSLOG_IDENTIFIER=imapd"
}

@test "tlog_journal_filter: unknown identifier returns failure" {
	run tlog_journal_filter "apache-auth"
	assert_failure
}

@test "tlog_journal_filter: httpd returns failure (no mapping)" {
	run tlog_journal_filter "httpd"
	assert_failure
}

# --- tlog_journal_read() tests ---

@test "tlog_journal_read: first run outputs nothing and creates cursor file" {
	run tlog_journal_read "sshd" "$BASERUN"
	assert_success
	assert_output ""
	[ -f "$BASERUN/sshd.cursor" ]
	[ -f "$BASERUN/sshd.jts" ]
}

@test "tlog_journal_read: second run outputs new lines" {
	# first run — creates cursor
	tlog_journal_read "sshd" "$BASERUN" >/dev/null
	# second run — should output lines from --after-cursor
	run tlog_journal_read "sshd" "$BASERUN"
	assert_success
	assert_output --partial "Failed password for root from 192.168.1.100"
	assert_output --partial "Invalid user admin from 10.0.0.5"
}

@test "tlog_journal_read: cursor file updated on subsequent reads" {
	tlog_journal_read "sshd" "$BASERUN" >/dev/null
	local first_cursor
	first_cursor=$(cat "$BASERUN/sshd.cursor")
	# second run updates cursor
	tlog_journal_read "sshd" "$BASERUN" >/dev/null
	local second_cursor
	second_cursor=$(cat "$BASERUN/sshd.cursor")
	[ -n "$second_cursor" ]
	# cursor changed to new value
	[ "$second_cursor" = "s=abc123;i=3;b=def456" ]
}

@test "tlog_journal_read: timestamp file created and updated" {
	tlog_journal_read "sshd" "$BASERUN" >/dev/null
	[ -f "$BASERUN/sshd.jts" ]
	local ts
	ts=$(cat "$BASERUN/sshd.jts")
	local int_pattern='^[0-9]+$'
	[[ "$ts" =~ $int_pattern ]]
}

@test "tlog_journal_read: invalid cursor falls back to timestamp" {
	# set up invalid cursor and valid timestamp
	echo "INVALID_CURSOR" > "$BASERUN/sshd.cursor"
	echo "1700000000" > "$BASERUN/sshd.jts"
	run tlog_journal_read "sshd" "$BASERUN"
	assert_success
	assert_output --partial "Failed password for user1 from 172.16.0.1"
}

@test "tlog_journal_read: missing journalctl returns error" {
	# run in subshell with restricted PATH to hide journalctl
	run bash -c "
		source '${PROJECT_ROOT}/files/bfd.lib.sh'
		export PATH='$EMPTY_BIN'
		export BASERUN='$BASERUN'
		tlog_journal_read 'sshd' '$BASERUN'
	"
	assert_failure
}

@test "tlog_journal_read: non-journal-capable tlog_name returns error" {
	run tlog_journal_read "apache-auth" "$BASERUN"
	assert_failure
}

@test "tlog_journal_read: missing baserun returns error" {
	run tlog_journal_read "sshd" "$TEST_TMPDIR/nonexistent"
	assert_failure
}

# --- tlog_read() journal dispatch tests ---

@test "tlog_read: file exists uses file mode (no journal)" {
	echo "log line" > "$TEST_TMPDIR/test.log"
	LOG_SOURCE="auto"
	run tlog_read "$TEST_TMPDIR/test.log" "sshd" "$BASERUN"
	assert_success
	# first run outputs nothing (file mode init)
	assert_output ""
	# should have created byte-offset file, not cursor file
	[ -f "$BASERUN/sshd" ]
	[ ! -f "$BASERUN/sshd.cursor" ]
}

@test "tlog_read: file missing + journalctl + mapping uses journal mode" {
	LOG_SOURCE="auto"
	run tlog_read "/nonexistent/auth.log" "sshd" "$BASERUN"
	assert_success
	# journal first run — outputs nothing, creates cursor
	assert_output ""
	[ -f "$BASERUN/sshd.cursor" ]
}

@test "tlog_read: file missing + no journalctl returns error" {
	run bash -c "
		source '${PROJECT_ROOT}/files/bfd.lib.sh'
		export PATH='$EMPTY_BIN'
		export LOG_SOURCE='auto'
		tlog_read '/nonexistent/auth.log' 'sshd' '$BASERUN'
	"
	assert_failure
}

@test "tlog_read: file missing + no mapping returns error" {
	LOG_SOURCE="auto"
	run tlog_read "/nonexistent/error.log" "apache-auth" "$BASERUN"
	assert_failure
}

@test "tlog_read: LOG_SOURCE=file never attempts journal" {
	LOG_SOURCE="file"
	run tlog_read "/nonexistent/auth.log" "sshd" "$BASERUN"
	assert_failure
	[ ! -f "$BASERUN/sshd.cursor" ]
}

@test "tlog_read: LOG_SOURCE=journal + journal-capable uses journal even if file exists" {
	echo "log line" > "$TEST_TMPDIR/test.log"
	LOG_SOURCE="journal"
	run tlog_read "$TEST_TMPDIR/test.log" "sshd" "$BASERUN"
	assert_success
	# should have used journal mode
	[ -f "$BASERUN/sshd.cursor" ]
	[ ! -f "$BASERUN/sshd" ]
}

# --- validate_rule() journal awareness tests ---

@test "validate_rule: LP missing + journal available + mapping passes" {
	LP="/nonexistent/auth.log"
	TLOG_TF="sshd"
	ARG_VAL="10.0.0.1"
	LOG_SOURCE="auto"
	run validate_rule "sshd"
	assert_success
}

@test "validate_rule: LP missing + no journalctl fails" {
	run bash -c "
		source '${PROJECT_ROOT}/files/bfd.lib.sh'
		export PATH='$EMPTY_BIN'
		export BFD_LOG_PATH='$BFD_LOG_PATH'
		export OUTPUT_SYSLOG='0'
		export OUTPUT_SYSLOG_FILE='/dev/null'
		LP='/nonexistent/auth.log'
		TLOG_TF='sshd'
		ARG_VAL='10.0.0.1'
		LOG_SOURCE='auto'
		validate_rule 'sshd'
	"
	assert_failure
	assert_output --partial "does not exist"
}

@test "validate_rule: LP missing + LOG_SOURCE=file fails" {
	LP="/nonexistent/auth.log"
	TLOG_TF="sshd"
	ARG_VAL="10.0.0.1"
	LOG_SOURCE="file"
	run validate_rule "sshd"
	assert_failure
	assert_output --partial "does not exist"
}

@test "validate_rule: LP missing + no mapping fails" {
	LP="/nonexistent/error.log"
	TLOG_TF="apache-auth"
	ARG_VAL="10.0.0.1"
	LOG_SOURCE="auto"
	run validate_rule "apache-auth"
	assert_failure
	assert_output --partial "does not exist"
}

# --- validate_config() LOG_SOURCE validation ---

@test "validate_config: LOG_SOURCE=auto passes" {
	LOG_SOURCE="auto"
	TRIG="15"; TRIG_WINDOW="300"; TRIG_GLOBAL="0"
	BAN_DURATION="0"; BAN_PERMANENT_AFTER="0"; BAN_PERMANENT_WINDOW="86400"
	EMAIL_ALERTS="0"; LOCK_FILE_TIMEOUT="300"
	INSTALL_PATH="$TEST_TMPDIR"
	BAN_COMMAND_TEMPLATE="/bin/true"
	run validate_config
	assert_success
}

@test "validate_config: LOG_SOURCE=invalid fails" {
	LOG_SOURCE="invalid"
	TRIG="15"; TRIG_WINDOW="300"; TRIG_GLOBAL="0"
	BAN_DURATION="0"; BAN_PERMANENT_AFTER="0"; BAN_PERMANENT_WINDOW="86400"
	EMAIL_ALERTS="0"; LOCK_FILE_TIMEOUT="300"
	INSTALL_PATH="$TEST_TMPDIR"
	BAN_COMMAND_TEMPLATE="/bin/true"
	run validate_config
	assert_failure
	assert_output --partial "LOG_SOURCE must be auto, file, or journal"
}
