#!/bin/bash
#
# BFD Package Install Verification Tests
# Run inside Docker containers after package installation.
#
# Usage: test-pkg-install.sh [rpm|deb]
#
set -euo pipefail

PASS=0
FAIL=0
PKG_TYPE="${1:-auto}"

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

check_file() {
	local path="$1" desc="$2"
	if [ -f "$path" ] || [ -d "$path" ]; then
		pass "$desc ($path)"
	else
		fail "$desc ($path missing)"
	fi
}

check_link() {
	local link="$1" target="$2" desc="$3"
	if [ -L "$link" ]; then
		local actual
		actual=$(readlink "$link")
		if [ "$actual" = "$target" ]; then
			pass "$desc ($link -> $target)"
		else
			fail "$desc ($link -> $actual, expected $target)"
		fi
	else
		fail "$desc ($link is not a symlink)"
	fi
}

check_perms() {
	local path="$1" expected="$2" desc="$3"
	if [ -e "$path" ]; then
		local actual
		actual=$(stat -c '%a' "$path")
		if [ "$actual" = "$expected" ]; then
			pass "$desc (perms $actual)"
		else
			fail "$desc (perms $actual, expected $expected)"
		fi
	else
		fail "$desc ($path missing)"
	fi
}

# Auto-detect package type
if [ "$PKG_TYPE" = "auto" ]; then
	if command -v rpm >/dev/null 2>&1 && rpm -q bfd >/dev/null 2>&1; then
		PKG_TYPE="rpm"
	elif command -v dpkg >/dev/null 2>&1 && dpkg -s bfd >/dev/null 2>&1; then
		PKG_TYPE="deb"
	else
		echo "ERROR: Cannot detect installed package type"
		exit 1
	fi
fi

echo "=== BFD Package Verification ($PKG_TYPE) ==="
echo ""

# --- Test 1: FHS paths exist ---
echo "--- Test 1: FHS file layout ---"
check_file /usr/sbin/bfd "Executable"
check_file /usr/lib/bfd/bfd.lib.sh "Library: bfd.lib.sh"
check_file /usr/lib/bfd/tlog "Library: tlog"
check_file /usr/lib/bfd/alert_lib.sh "Library: alert_lib.sh"
check_file /usr/lib/bfd/alert "Library: alert directory"
check_file /usr/lib/bfd/update-ipcountry.sh "Library: update-ipcountry.sh"
check_file /usr/lib/bfd/importconf "Library: importconf"
check_file /etc/bfd/conf.bfd "Config: conf.bfd"
check_file /etc/bfd/internals.conf "Config: internals.conf"
check_file /etc/bfd/pressure.conf "Config: pressure.conf"
check_file /etc/bfd/pressure-country.conf "Config: pressure-country.conf"
check_file /etc/bfd/exclude.files "Config: exclude.files"
check_file /etc/bfd/ignore.hosts "Config: ignore.hosts"
check_file /usr/share/bfd/ipcountry.dat "Data: ipcountry.dat"
check_file /usr/share/bfd/rules "Data: rules directory"
check_file /var/lib/bfd/tmp "State: tmp directory"
check_file /var/lib/bfd/stats "State: stats directory"
check_file /etc/cron.d/bfd "Cron: bfd"
check_file /etc/cron.daily/bfd "Cron: daily"
check_file /etc/logrotate.d/bfd "Logrotate: bfd"
echo ""

# --- Test 2: Symlink farm ---
echo "--- Test 2: Symlink farm ---"
check_link /usr/local/bfd/bfd.lib.sh /usr/lib/bfd/bfd.lib.sh "Symlink: bfd.lib.sh"
check_link /usr/local/bfd/tlog /usr/lib/bfd/tlog "Symlink: tlog"
check_link /usr/local/bfd/alert_lib.sh /usr/lib/bfd/alert_lib.sh "Symlink: alert_lib.sh"
check_link /usr/local/bfd/alert /usr/lib/bfd/alert "Symlink: alert"
check_link /usr/local/bfd/update-ipcountry.sh /usr/lib/bfd/update-ipcountry.sh "Symlink: update-ipcountry.sh"
check_link /usr/local/bfd/importconf /usr/lib/bfd/importconf "Symlink: importconf"
check_link /usr/local/bfd/conf.bfd /etc/bfd/conf.bfd "Symlink: conf.bfd"
check_link /usr/local/bfd/internals.conf /etc/bfd/internals.conf "Symlink: internals.conf"
check_link /usr/local/bfd/pressure.conf /etc/bfd/pressure.conf "Symlink: pressure.conf"
check_link /usr/local/bfd/pressure-country.conf /etc/bfd/pressure-country.conf "Symlink: pressure-country.conf"
check_link /usr/local/bfd/exclude.files /etc/bfd/exclude.files "Symlink: exclude.files"
check_link /usr/local/bfd/ignore.hosts /etc/bfd/ignore.hosts "Symlink: ignore.hosts"
check_link /usr/local/bfd/ipcountry.dat /usr/share/bfd/ipcountry.dat "Symlink: ipcountry.dat"
check_link /usr/local/bfd/rules /usr/share/bfd/rules "Symlink: rules"
check_link /usr/local/bfd/tmp /var/lib/bfd/tmp "Symlink: tmp"
check_link /usr/local/bfd/stats /var/lib/bfd/stats "Symlink: stats"
check_link /usr/local/sbin/bfd /usr/sbin/bfd "Symlink: /usr/local/sbin/bfd"
echo ""

# --- Test 3: internals.conf FHS paths ---
echo "--- Test 3: internals.conf FHS paths ---"
if grep -q '/usr/share/bfd/rules' /etc/bfd/internals.conf; then
	pass "RULES_PATH uses FHS path"
else
	fail "RULES_PATH still uses \$INSTALL_PATH"
fi
if grep -q '/usr/lib/bfd/tlog' /etc/bfd/internals.conf; then
	pass "TLOG_PATH uses FHS path"
else
	fail "TLOG_PATH still uses \$INSTALL_PATH"
fi
if grep -q '/var/lib/bfd/tmp' /etc/bfd/internals.conf; then
	pass "TLOG_BASERUN uses FHS path"
else
	fail "TLOG_BASERUN still uses \$INSTALL_PATH"
fi
if grep -q '/usr/lib/bfd/alert"' /etc/bfd/internals.conf; then
	pass "ALERT_TEMPLATE_DIR uses FHS path"
else
	fail "ALERT_TEMPLATE_DIR still uses \$INSTALL_PATH"
fi
if grep -q '/etc/bfd/exclude.files' /etc/bfd/internals.conf; then
	pass "IGNORE_HOST_FILES uses FHS path"
else
	fail "IGNORE_HOST_FILES still uses \$INSTALL_PATH"
fi
if grep -q '/var/lib/bfd/lock.utime' /etc/bfd/internals.conf; then
	pass "LOCK_FILE uses FHS path"
else
	fail "LOCK_FILE still uses \$INSTALL_PATH"
fi
if grep -q '/etc/bfd/pressure.conf' /etc/bfd/internals.conf; then
	pass "PRESSURE_CONF uses FHS path"
else
	fail "PRESSURE_CONF still uses \$INSTALL_PATH"
fi
echo ""

# --- Test 4: Lock coordination ---
echo "--- Test 4: Lock file coordination ---"
cron_lock=$(grep 'INSTALL_PATH=' /etc/cron.daily/bfd | head -1)
if echo "$cron_lock" | grep -q '/var/lib/bfd'; then
	pass "cron.daily INSTALL_PATH defaults to /var/lib/bfd"
else
	fail "cron.daily INSTALL_PATH does not default to /var/lib/bfd: $cron_lock"
fi
echo ""

# --- Test 5: Cron binary path ---
echo "--- Test 5: Cron binary path ---"
if grep -q '/usr/sbin/bfd' /etc/cron.d/bfd; then
	pass "Cron uses /usr/sbin/bfd"
else
	fail "Cron does not use /usr/sbin/bfd"
fi
echo ""

# --- Test 6: Permissions ---
echo "--- Test 6: File permissions ---"
check_perms /usr/sbin/bfd 755 "Executable perms"
check_perms /etc/bfd/conf.bfd 640 "Config perms"
check_perms /var/lib/bfd/tmp 750 "State dir perms"
check_perms /var/lib/bfd/stats 750 "Stats dir perms"
echo ""

# --- Test 7: Rule files ---
echo "--- Test 7: Rule files ---"
rule_count=$(find /usr/share/bfd/rules/ -maxdepth 1 -type f 2>/dev/null | wc -l)
if [ "$rule_count" -ge 40 ]; then
	pass "Rule files present ($rule_count rules)"
else
	fail "Expected >= 40 rules, found $rule_count"
fi
echo ""

# --- Test 7b: Alert template files ---
echo "--- Test 7b: Alert templates ---"
tpl_count=$(find /usr/lib/bfd/alert/ -maxdepth 1 -name '*.tpl' -type f 2>/dev/null | wc -l)
if [ "$tpl_count" -eq 8 ]; then
	pass "Alert template files present ($tpl_count templates)"
else
	fail "Expected 8 alert templates, found $tpl_count"
fi
echo ""

# --- Test 7c: Alert custom.d directory ---
echo "--- Test 7c: Alert custom.d directory ---"
check_file /usr/lib/bfd/alert/custom.d "Custom template override directory"
echo ""

# --- Test 8: exclude.files references ---
echo "--- Test 8: exclude.files FHS paths ---"
if grep -q '/etc/bfd/ignore.hosts' /etc/bfd/exclude.files; then
	pass "exclude.files references /etc/bfd/ignore.hosts"
else
	fail "exclude.files still references /usr/local/bfd/ignore.hosts"
fi
echo ""

# --- Test 9: Systemd units ---
echo "--- Test 9: Systemd units ---"
if [ "$PKG_TYPE" = "rpm" ]; then
	_sysdir="/usr/lib/systemd/system"
else
	_sysdir="/lib/systemd/system"
fi
check_file "$_sysdir/bfd.service" "Systemd: bfd.service"
check_file "$_sysdir/bfd.timer" "Systemd: bfd.timer"
check_file "$_sysdir/bfd-watch.service" "Systemd: bfd-watch.service"
if grep -q '/usr/sbin/bfd' "$_sysdir/bfd.service"; then
	pass "bfd.service uses /usr/sbin/bfd"
else
	fail "bfd.service does not use /usr/sbin/bfd"
fi
if grep -q '/usr/sbin/bfd' "$_sysdir/bfd-watch.service"; then
	pass "bfd-watch.service uses /usr/sbin/bfd"
else
	fail "bfd-watch.service does not use /usr/sbin/bfd"
fi
echo ""

# --- Test 9b: SysVinit init script (DEB) ---
if [ "$PKG_TYPE" = "deb" ]; then
	echo "--- Test 9b: SysVinit init script ---"
	check_file /etc/init.d/bfd-watch "Init script: bfd-watch"
	check_perms /etc/init.d/bfd-watch 755 "Init script perms"
	if grep -q '/usr/sbin/bfd' /etc/init.d/bfd-watch; then
		pass "Init script uses /usr/sbin/bfd"
	else
		fail "Init script does not use /usr/sbin/bfd"
	fi
	echo ""
fi

# --- Test 10: bfd --version via symlink farm ---
echo "--- Test 10: bfd execution ---"
ver_out=$(/usr/local/sbin/bfd --version 2>&1 || true)
if echo "$ver_out" | grep -q '2\.0\.1'; then
	pass "bfd --version via /usr/local/sbin/bfd works"
else
	fail "bfd --version output: $ver_out"
fi
ver_out2=$(/usr/sbin/bfd --version 2>&1 || true)
if echo "$ver_out2" | grep -q '2\.0\.1'; then
	pass "bfd --version via /usr/sbin/bfd works"
else
	fail "bfd --version via /usr/sbin/bfd output: $ver_out2"
fi
echo ""

# --- Summary ---
echo "=== Results: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
	exit 1
fi
exit 0
