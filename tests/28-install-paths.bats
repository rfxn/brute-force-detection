#!/usr/bin/env bats
#
# Test suite for install.sh path replacement logic (INSPATH and BINPATH sed)
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

setup() {
	bfd_common_setup
	SEDDIR="$TEST_TMPDIR/sedtest"
	mkdir -p "$SEDDIR"
}

teardown() {
	bfd_teardown
}

# --- INSPATH source files contain default path ---

@test "install-paths: files/bfd contains literal /usr/local/bfd" {
	run grep -c '/usr/local/bfd' "$PROJECT_ROOT/files/bfd"
	assert_success
	[ "$output" -ge 1 ]
}

@test "install-paths: files/tlog contains literal /usr/local/bfd" {
	run grep -c '/usr/local/bfd' "$PROJECT_ROOT/files/tlog"
	assert_success
	[ "$output" -ge 1 ]
}

@test "install-paths: files/exclude.files contains literal /usr/local/bfd" {
	run grep -c '/usr/local/bfd' "$PROJECT_ROOT/files/exclude.files"
	assert_success
	[ "$output" -ge 1 ]
}

@test "install-paths: cron.daily contains literal /usr/local/bfd" {
	run grep -c '/usr/local/bfd' "$PROJECT_ROOT/cron.daily"
	assert_success
	[ "$output" -ge 1 ]
}

# --- BINPATH source files contain default path ---

@test "install-paths: cron contains literal /usr/local/sbin/bfd" {
	run grep -c '/usr/local/sbin/bfd' "$PROJECT_ROOT/cron"
	assert_success
	[ "$output" -ge 1 ]
}

@test "install-paths: bfd-watch.service contains literal /usr/local/sbin/bfd" {
	run grep -c '/usr/local/sbin/bfd' "$PROJECT_ROOT/bfd-watch.service"
	assert_success
	[ "$output" -ge 1 ]
}

@test "install-paths: bfd.service contains literal /usr/local/sbin/bfd" {
	run grep -c '/usr/local/sbin/bfd' "$PROJECT_ROOT/bfd.service"
	assert_success
	[ "$output" -ge 1 ]
}

@test "install-paths: bfd-watch.init contains literal /usr/local/sbin/bfd" {
	run grep -c '/usr/local/sbin/bfd' "$PROJECT_ROOT/bfd-watch.init"
	assert_success
	[ "$output" -ge 1 ]
}

# --- INSPATH sed replaces correctly ---

@test "install-paths: INSPATH sed replaces /usr/local/bfd with custom path" {
	local custom="/opt/custom/bfd"
	cp "$PROJECT_ROOT/files/bfd" "$SEDDIR/bfd"
	cp "$PROJECT_ROOT/files/tlog" "$SEDDIR/tlog"
	cp "$PROJECT_ROOT/files/exclude.files" "$SEDDIR/exclude.files"
	cp "$PROJECT_ROOT/cron.daily" "$SEDDIR/cron.daily"
	sed -i "s|/usr/local/bfd|$custom|g" \
		"$SEDDIR/bfd" "$SEDDIR/tlog" "$SEDDIR/exclude.files" "$SEDDIR/cron.daily"
	# verify custom path present in each file
	grep -q "$custom" "$SEDDIR/bfd"
	grep -q "$custom" "$SEDDIR/tlog"
	grep -q "$custom" "$SEDDIR/exclude.files"
	grep -q "$custom" "$SEDDIR/cron.daily"
}

@test "install-paths: INSPATH sed leaves no stray defaults" {
	local custom="/opt/custom/bfd"
	cp "$PROJECT_ROOT/files/bfd" "$SEDDIR/bfd"
	cp "$PROJECT_ROOT/files/tlog" "$SEDDIR/tlog"
	cp "$PROJECT_ROOT/files/exclude.files" "$SEDDIR/exclude.files"
	cp "$PROJECT_ROOT/cron.daily" "$SEDDIR/cron.daily"
	sed -i "s|/usr/local/bfd|$custom|g" \
		"$SEDDIR/bfd" "$SEDDIR/tlog" "$SEDDIR/exclude.files" "$SEDDIR/cron.daily"
	# no stray defaults should remain
	run grep -r '/usr/local/bfd' "$SEDDIR/"
	assert_failure
}

# --- BINPATH sed replaces correctly ---

@test "install-paths: BINPATH sed replaces /usr/local/sbin/bfd with custom path" {
	local custom="/opt/bin/bfd"
	cp "$PROJECT_ROOT/cron" "$SEDDIR/cron"
	cp "$PROJECT_ROOT/bfd-watch.service" "$SEDDIR/bfd-watch.service"
	cp "$PROJECT_ROOT/bfd.service" "$SEDDIR/bfd.service"
	cp "$PROJECT_ROOT/bfd-watch.init" "$SEDDIR/bfd-watch.init"
	sed -i "s|/usr/local/sbin/bfd|$custom|g" \
		"$SEDDIR/cron" "$SEDDIR/bfd-watch.service" \
		"$SEDDIR/bfd.service" "$SEDDIR/bfd-watch.init"
	grep -q "$custom" "$SEDDIR/cron"
	grep -q "$custom" "$SEDDIR/bfd-watch.service"
	grep -q "$custom" "$SEDDIR/bfd.service"
	grep -q "$custom" "$SEDDIR/bfd-watch.init"
}

@test "install-paths: BINPATH sed leaves no stray defaults" {
	local custom="/opt/bin/bfd"
	cp "$PROJECT_ROOT/cron" "$SEDDIR/cron"
	cp "$PROJECT_ROOT/bfd-watch.service" "$SEDDIR/bfd-watch.service"
	cp "$PROJECT_ROOT/bfd.service" "$SEDDIR/bfd.service"
	cp "$PROJECT_ROOT/bfd-watch.init" "$SEDDIR/bfd-watch.init"
	sed -i "s|/usr/local/sbin/bfd|$custom|g" \
		"$SEDDIR/cron" "$SEDDIR/bfd-watch.service" \
		"$SEDDIR/bfd.service" "$SEDDIR/bfd-watch.init"
	run grep -r '/usr/local/sbin/bfd' "$SEDDIR/"
	assert_failure
}

# --- Combined replacement ---

@test "install-paths: combined INSPATH+BINPATH replacement updates all paths" {
	local cinst="/opt/mybfd"
	local cbin="/opt/sbin/mybfd"
	cp "$PROJECT_ROOT/files/bfd" "$SEDDIR/bfd"
	cp "$PROJECT_ROOT/files/tlog" "$SEDDIR/tlog"
	cp "$PROJECT_ROOT/files/exclude.files" "$SEDDIR/exclude.files"
	cp "$PROJECT_ROOT/cron.daily" "$SEDDIR/cron.daily"
	cp "$PROJECT_ROOT/cron" "$SEDDIR/cron"
	cp "$PROJECT_ROOT/bfd-watch.service" "$SEDDIR/bfd-watch.service"
	cp "$PROJECT_ROOT/bfd.service" "$SEDDIR/bfd.service"
	cp "$PROJECT_ROOT/bfd-watch.init" "$SEDDIR/bfd-watch.init"
	# INSPATH sed
	sed -i "s|/usr/local/bfd|$cinst|g" \
		"$SEDDIR/bfd" "$SEDDIR/tlog" "$SEDDIR/exclude.files" "$SEDDIR/cron.daily"
	# BINPATH sed
	sed -i "s|/usr/local/sbin/bfd|$cbin|g" \
		"$SEDDIR/cron" "$SEDDIR/bfd-watch.service" \
		"$SEDDIR/bfd.service" "$SEDDIR/bfd-watch.init"
	# verify no defaults remain
	run grep -r '/usr/local/bfd' "$SEDDIR/"
	assert_failure
	run grep -r '/usr/local/sbin/bfd' "$SEDDIR/"
	assert_failure
}

# --- Replacement preserves shell validity ---

@test "install-paths: INSPATH sed preserves bash -n validity" {
	local custom="/opt/custom/bfd"
	cp "$PROJECT_ROOT/files/bfd" "$SEDDIR/bfd"
	cp "$PROJECT_ROOT/files/tlog" "$SEDDIR/tlog"
	cp "$PROJECT_ROOT/cron.daily" "$SEDDIR/cron.daily"
	sed -i "s|/usr/local/bfd|$custom|g" \
		"$SEDDIR/bfd" "$SEDDIR/tlog" "$SEDDIR/cron.daily"
	run bash -n "$SEDDIR/bfd"
	assert_success
	run bash -n "$SEDDIR/tlog"
	assert_success
	run bash -n "$SEDDIR/cron.daily"
	assert_success
}

# --- exclude.files paths updated ---

@test "install-paths: exclude.files ignore.hosts paths updated by INSPATH sed" {
	local custom="/opt/custom/bfd"
	cp "$PROJECT_ROOT/files/exclude.files" "$SEDDIR/exclude.files"
	sed -i "s|/usr/local/bfd|$custom|g" "$SEDDIR/exclude.files"
	grep -q "$custom/ignore.hosts$" "$SEDDIR/exclude.files"
	grep -q "$custom/ignore.hosts.local$" "$SEDDIR/exclude.files"
}

# --- Default paths are no-op ---

@test "install-paths: default INSPATH is conditional no-op in install.sh" {
	# install.sh wraps the sed in: if [ "$INSPATH" != "/usr/local/bfd" ]
	# verify the guard exists in install.sh
	run grep -c 'INSPATH.*!=.*/usr/local/bfd' "$PROJECT_ROOT/install.sh"
	assert_success
	[ "$output" -ge 1 ]
}

# --- Man page ---

@test "install-paths: bfd.1 man page exists in source tree" {
	[ -f "$PROJECT_ROOT/bfd.1" ]
}

@test "install-paths: bfd.1 contains /usr/local/bfd default paths" {
	run grep -c '/usr/local/bfd' "$PROJECT_ROOT/bfd.1"
	assert_success
	[ "$output" -ge 1 ]
}

@test "install-paths: install.sh has man page install section" {
	run grep -c 'man1/bfd.1' "$PROJECT_ROOT/install.sh"
	assert_success
	[ "$output" -ge 1 ]
}

@test "install-paths: uninstall.sh removes man page" {
	run grep -c 'man1/bfd.1' "$PROJECT_ROOT/uninstall.sh"
	assert_success
	[ "$output" -ge 1 ]
}

# --- Bash tab completion ---

@test "install-paths: bfd.bash-completion exists in source tree" {
	[ -f "$PROJECT_ROOT/bfd.bash-completion" ]
}

@test "install-paths: bfd.bash-completion contains /usr/local/bfd default paths" {
	run grep -c '/usr/local/bfd' "$PROJECT_ROOT/bfd.bash-completion"
	assert_success
	[ "$output" -ge 1 ]
}

@test "install-paths: bfd.bash-completion has valid bash syntax" {
	run bash -n "$PROJECT_ROOT/bfd.bash-completion"
	assert_success
}

@test "install-paths: install.sh has bash completion section" {
	run grep -c 'bash_completion.d' "$PROJECT_ROOT/install.sh"
	assert_success
	[ "$output" -ge 1 ]
}
