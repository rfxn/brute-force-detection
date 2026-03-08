#!/bin/bash
#
# BFD custom BATS assertions
# Loaded by bfd-common.bash; available to all test files
#

# assert_banned HOST — assert host has an active ban entry
assert_banned() {
	local host="$1"
	local bans_file="${INSTALL_PATH}/tmp/bans.active"
	if ! awk -v ip="$host" '$3 == ip {found=1; exit} END {exit !found}' "$bans_file" 2>/dev/null; then
		echo "expected '$host' to be in bans.active" >&2
		echo "contents:" >&2
		cat "$bans_file" >&2 2>/dev/null || echo "(empty or missing)" >&2
		return 1
	fi
}

# refute_banned HOST — assert host does NOT have an active ban
refute_banned() {
	local host="$1"
	local bans_file="${INSTALL_PATH}/tmp/bans.active"
	if awk -v ip="$host" '$3 == ip {found=1; exit} END {exit !found}' "$bans_file" 2>/dev/null; then
		echo "expected '$host' NOT to be in bans.active" >&2
		echo "contents:" >&2
		cat "$bans_file" >&2
		return 1
	fi
}

# assert_ban_count N — assert bans.active has exactly N entries
assert_ban_count() {
	local expected="$1"
	local bans_file="${INSTALL_PATH}/tmp/bans.active"
	local actual
	actual=$(wc -l < "$bans_file" 2>/dev/null) || actual=0
	if [ "$actual" -ne "$expected" ]; then
		echo "expected $expected active bans, got $actual" >&2
		return 1
	fi
}

# assert_event_count N — assert pressure.dat has exactly N lines
assert_event_count() {
	local expected="$1"
	local events_file="${INSTALL_PATH}/tmp/pressure.dat"
	local actual
	actual=$(wc -l < "$events_file" 2>/dev/null) || actual=0
	if [ "$actual" -ne "$expected" ]; then
		echo "expected $expected events, got $actual" >&2
		return 1
	fi
}

# assert_history_count N — assert bans.history has exactly N entries
assert_history_count() {
	local expected="$1"
	local hist_file="${INSTALL_PATH}/tmp/bans.history"
	local actual
	actual=$(wc -l < "$hist_file" 2>/dev/null) || actual=0
	if [ "$actual" -ne "$expected" ]; then
		echo "expected $expected history entries, got $actual" >&2
		return 1
	fi
}

# assert_pool_count N — assert attack.pool has exactly N lines
assert_pool_count() {
	local expected="$1"
	local pool_file="${INSTALL_PATH}/stats/attack.pool"
	local actual
	actual=$(wc -l < "$pool_file" 2>/dev/null) || actual=0
	if [ "$actual" -ne "$expected" ]; then
		echo "expected $expected pool entries, got $actual" >&2
		return 1
	fi
}
