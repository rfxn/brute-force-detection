#!/usr/bin/env bats
#
# Tests for Tier 2 rules: sogo, freeswitch, ejabberd, drupal, jellyfin, powerdns
# Validates pattern matching via test_rule / test_pattern against synthetic logs
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

# create/remove mock PREREQ binaries at file level to avoid race with
# BATS --jobs parallel test-gathering phase (per-test teardown rm races
# with the next test's setup touch on shared /usr paths)
setup_file() {
	mkdir -p /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /opt/jellyfin
	touch /usr/sbin/sogod
	touch /usr/bin/freeswitch
	touch /usr/sbin/ejabberdctl
	touch /usr/sbin/pdns_server
	touch /usr/bin/jellyfin
	# placeholder log so the jellyfin rule's existence gate passes; the
	# actual fixture content is supplied per-test via _TLOG_PASSTHROUGH
	# (test_rule's 3rd arg). A shared path here would race in --jobs mode.
	mkdir -p /var/log/jellyfin
	touch /var/log/jellyfin/log_20260101.log
}

teardown_file() {
	rm -f /usr/sbin/sogod /usr/bin/freeswitch /usr/sbin/ejabberdctl \
		/usr/sbin/pdns_server /usr/bin/jellyfin
	rm -rf /var/log/jellyfin
}

setup() {
	bfd_standard_setup
	GLOB_PRESSURE_TRIP="15"
	PRESSURE_TRIP=""
	RULES_PATH="$INSTALL_PATH/rules"
	mkdir -p "$RULES_PATH"
	LOG_SOURCE="file"

	# drupal rule uses KERNEL_LOG_PATH as PREREQ — set and create mock
	KERNEL_LOG_PATH="$TEST_TMPDIR/syslog"
	touch "$KERNEL_LOG_PATH"

	# copy rule files from project source
	cp "$PROJECT_ROOT/files/rules/sogo" "$RULES_PATH/"
	cp "$PROJECT_ROOT/files/rules/freeswitch" "$RULES_PATH/"
	cp "$PROJECT_ROOT/files/rules/ejabberd" "$RULES_PATH/"
	cp "$PROJECT_ROOT/files/rules/drupal" "$RULES_PATH/"
	cp "$PROJECT_ROOT/files/rules/jellyfin" "$RULES_PATH/"
	cp "$PROJECT_ROOT/files/rules/powerdns" "$RULES_PATH/"
	chown root "$RULES_PATH/sogo" "$RULES_PATH/freeswitch" \
		"$RULES_PATH/ejabberd" "$RULES_PATH/drupal" \
		"$RULES_PATH/jellyfin" "$RULES_PATH/powerdns"
	chmod 644 "$RULES_PATH/sogo" "$RULES_PATH/freeswitch" \
		"$RULES_PATH/ejabberd" "$RULES_PATH/drupal" \
		"$RULES_PATH/jellyfin" "$RULES_PATH/powerdns"
}

teardown() {
	bfd_teardown
}

# --- sogo ---

@test "sogo: login failure extracts IP" {
	local log="$TEST_TMPDIR/sogo.log"
	echo "Mar  8 10:01:01 server sogod[1234]: Login from '203.0.113.10' as 'admin' in domain 'example.com' might not have worked" > "$log"
	run test_rule "$INSTALL_PATH" "sogo" "$log"
	assert_success
	assert_output --partial "203.0.113.10"
	assert_output --partial "1 matches"
}

@test "sogo: multiple failures aggregate correctly" {
	local log="$TEST_TMPDIR/sogo.log"
	cat > "$log" <<'EOF'
Mar  8 10:01:01 server sogod[1234]: Login from '203.0.113.10' as 'admin' in domain 'example.com' might not have worked
Mar  8 10:01:02 server sogod[1234]: Login from '198.51.100.5' as 'user1' in domain 'example.com' might not have worked
Mar  8 10:01:03 server sogod[1234]: Login from '203.0.113.10' as 'test' in domain 'example.com' might not have worked
EOF
	run test_rule "$INSTALL_PATH" "sogo" "$log"
	assert_success
	assert_output --partial "3 matches, 2 unique IPs"
}

@test "sogo: successful login not matched" {
	local log="$TEST_TMPDIR/sogo.log"
	echo "Mar  8 10:01:01 server sogod[1234]: Login from '203.0.113.10' as 'admin' in domain 'example.com' was successful" > "$log"
	run test_rule "$INSTALL_PATH" "sogo" "$log"
	assert_success
	assert_output --partial "0 matches"
}

# --- freeswitch ---

@test "freeswitch: SIP auth failure extracts IP" {
	local log="$TEST_TMPDIR/freeswitch.log"
	echo '2026-03-08 10:01:01.123456 [WARNING] sofia_reg.c:2999 SIP auth failure (REGISTER) on sofia profile internal for [1001@example.com] from ip 203.0.113.20' > "$log"
	run test_rule "$INSTALL_PATH" "freeswitch" "$log"
	assert_success
	assert_output --partial "203.0.113.20"
	assert_output --partial "1 matches"
}

@test "freeswitch: unknown user extracts IP" {
	local log="$TEST_TMPDIR/freeswitch.log"
	echo "2026-03-08 10:01:01.123456 [WARNING] sofia_reg.c:3050 Can't find user [1001@example.com] from ip 198.51.100.15" > "$log"
	run test_rule "$INSTALL_PATH" "freeswitch" "$log"
	assert_success
	assert_output --partial "198.51.100.15"
	assert_output --partial "1 matches"
}

@test "freeswitch: multiple failures aggregate correctly" {
	local log="$TEST_TMPDIR/freeswitch.log"
	cat > "$log" <<'EOF'
2026-03-08 10:01:01.123456 [WARNING] sofia_reg.c:2999 SIP auth failure (REGISTER) on sofia profile internal for [1001@example.com] from ip 203.0.113.20
2026-03-08 10:01:02.123456 [WARNING] sofia_reg.c:3050 Can't find user [1001@example.com] from ip 203.0.113.20
2026-03-08 10:01:03.123456 [WARNING] sofia_reg.c:2999 SIP auth failure (INVITE) on sofia profile external for [1002@example.com] from ip 198.51.100.15
EOF
	run test_rule "$INSTALL_PATH" "freeswitch" "$log"
	assert_success
	assert_output --partial "3 matches, 2 unique IPs"
}

@test "freeswitch: auth challenge not matched" {
	local log="$TEST_TMPDIR/freeswitch.log"
	echo '2026-03-08 10:01:01.123456 [DEBUG] sofia_reg.c:2900 SIP auth challenge (REGISTER) on sofia profile internal for [1001@example.com] from ip 203.0.113.20' > "$log"
	run test_rule "$INSTALL_PATH" "freeswitch" "$log"
	assert_success
	assert_output --partial "0 matches"
}

# --- ejabberd ---

@test "ejabberd: c2s auth failure extracts IP" {
	local log="$TEST_TMPDIR/ejabberd.log"
	echo '2026-03-08 10:01:01.123 [warning] Failed c2s PLAIN authentication user@example.com from 203.0.113.30' > "$log"
	run test_rule "$INSTALL_PATH" "ejabberd" "$log"
	assert_success
	assert_output --partial "203.0.113.30"
	assert_output --partial "1 matches"
}

@test "ejabberd: SCRAM-SHA-256 auth failure extracts IP" {
	local log="$TEST_TMPDIR/ejabberd.log"
	echo '2026-03-08 10:01:01.123 [warning] Failed c2s SCRAM-SHA-256 authentication admin@example.com from 198.51.100.25' > "$log"
	run test_rule "$INSTALL_PATH" "ejabberd" "$log"
	assert_success
	assert_output --partial "198.51.100.25"
	assert_output --partial "1 matches"
}

@test "ejabberd: IPv4-mapped IPv6 address extracted as IPv4" {
	local log="$TEST_TMPDIR/ejabberd.log"
	echo '2026-03-08 10:01:01.123 [warning] Failed c2s PLAIN authentication user@example.com from ::ffff:192.0.2.50' > "$log"
	run test_rule "$INSTALL_PATH" "ejabberd" "$log"
	assert_success
	assert_output --partial "192.0.2.50"
	assert_output --partial "1 matches"
}

@test "ejabberd: multiple failures aggregate correctly" {
	local log="$TEST_TMPDIR/ejabberd.log"
	cat > "$log" <<'EOF'
2026-03-08 10:01:01.123 [warning] Failed c2s PLAIN authentication user@example.com from 203.0.113.30
2026-03-08 10:01:02.456 [warning] Failed c2s SCRAM-SHA-1 authentication admin@example.com from 198.51.100.25
2026-03-08 10:01:03.789 [warning] Failed c2s SCRAM-SHA-256 authentication test@example.com from 203.0.113.30
EOF
	run test_rule "$INSTALL_PATH" "ejabberd" "$log"
	assert_success
	assert_output --partial "3 matches, 2 unique IPs"
}

@test "ejabberd: successful auth not matched" {
	local log="$TEST_TMPDIR/ejabberd.log"
	echo '2026-03-08 10:01:01.123 [info] Accepted c2s PLAIN authentication user@example.com from 203.0.113.30' > "$log"
	run test_rule "$INSTALL_PATH" "ejabberd" "$log"
	assert_success
	assert_output --partial "0 matches"
}

# --- drupal ---

@test "drupal: login attempt failed extracts IP" {
	local log="$TEST_TMPDIR/syslog"
	echo 'Mar  8 10:01:01 server drupal: https://example.com/|1709899261|user|203.0.113.40|https://example.com/user/login||0||Login attempt failed for admin.' > "$log"
	run test_rule "$INSTALL_PATH" "drupal" "$log"
	assert_success
	assert_output --partial "203.0.113.40"
	assert_output --partial "1 matches"
}

@test "drupal: blocked submission extracts IP" {
	local log="$TEST_TMPDIR/syslog"
	echo 'Mar  8 10:01:01 server drupal: https://example.com/|1709899261|honeypot|198.51.100.35|https://example.com/user/login||0||Blocked submission of user_login_form.' > "$log"
	run test_rule "$INSTALL_PATH" "drupal" "$log"
	assert_success
	assert_output --partial "198.51.100.35"
	assert_output --partial "1 matches"
}

@test "drupal: multiple failures aggregate correctly" {
	local log="$TEST_TMPDIR/syslog"
	cat > "$log" <<'EOF'
Mar  8 10:01:01 server drupal: https://example.com/|1709899261|user|203.0.113.40|https://example.com/user/login||0||Login attempt failed for admin.
Mar  8 10:01:02 server drupal: https://example.com/|1709899262|user|203.0.113.40|https://example.com/user/login||0||Login attempt failed for editor.
Mar  8 10:01:03 server drupal: https://example.com/|1709899263|honeypot|198.51.100.35|https://example.com/user/login||0||Blocked submission of user_login_form.
EOF
	run test_rule "$INSTALL_PATH" "drupal" "$log"
	assert_success
	assert_output --partial "3 matches, 2 unique IPs"
}

@test "drupal: normal page view not matched" {
	local log="$TEST_TMPDIR/syslog"
	echo 'Mar  8 10:01:01 server drupal: https://example.com/|1709899261|access|203.0.113.40|https://example.com/node/1||0||Node 1 viewed.' > "$log"
	run test_rule "$INSTALL_PATH" "drupal" "$log"
	assert_success
	assert_output --partial "0 matches"
}

# --- jellyfin ---

@test "jellyfin: auth denied extracts IP" {
	# per-test fixture under TEST_TMPDIR avoids races with sibling jellyfin
	# tests under bats --jobs (rule's existence gate is satisfied by the
	# placeholder file created in setup_file)
	local log="$TEST_TMPDIR/jellyfin.log"
	echo '[2026-03-08 10:01:01.123 +00:00] [INF] Authentication request for "admin" has been denied (IP: "203.0.113.50").' > "$log"
	run test_rule "$INSTALL_PATH" "jellyfin" "$log"
	assert_success
	assert_output --partial "203.0.113.50"
	assert_output --partial "1 matches"
}

@test "jellyfin: multiple failures aggregate correctly" {
	local log="$TEST_TMPDIR/jellyfin.log"
	cat > "$log" <<'EOF'
[2026-03-08 10:01:01.123 +00:00] [INF] Authentication request for "admin" has been denied (IP: "203.0.113.50").
[2026-03-08 10:01:02.456 +00:00] [INF] Authentication request for "user1" has been denied (IP: "198.51.100.45").
[2026-03-08 10:01:03.789 +00:00] [INF] Authentication request for "admin" has been denied (IP: "203.0.113.50").
EOF
	run test_rule "$INSTALL_PATH" "jellyfin" "$log"
	assert_success
	assert_output --partial "3 matches, 2 unique IPs"
}

@test "jellyfin: successful auth not matched" {
	local log="$TEST_TMPDIR/jellyfin.log"
	echo '[2026-03-08 10:01:01.123 +00:00] [INF] Authentication request for "admin" has succeeded (IP: "203.0.113.50").' > "$log"
	run test_rule "$INSTALL_PATH" "jellyfin" "$log"
	assert_success
	assert_output --partial "0 matches"
}

# --- powerdns ---

@test "powerdns: AXFR denied extracts IP" {
	local log="$TEST_TMPDIR/syslog"
	echo 'Mar  8 10:01:01 server pdns_server[1234]: AXFR of domain example.com denied: client IP 203.0.113.60 has no permission' > "$log"
	run test_rule "$INSTALL_PATH" "powerdns" "$log"
	assert_success
	assert_output --partial "203.0.113.60"
	assert_output --partial "1 matches"
}

@test "powerdns: unauthorized NOTIFY extracts IP" {
	local log="$TEST_TMPDIR/syslog"
	echo 'Mar  8 10:01:01 server pdns_server[1234]: Received NOTIFY for domain example.com from 198.51.100.55 for which we are not authoritative' > "$log"
	run test_rule "$INSTALL_PATH" "powerdns" "$log"
	assert_success
	assert_output --partial "198.51.100.55"
	assert_output --partial "1 matches"
}

@test "powerdns: multiple failures aggregate correctly" {
	local log="$TEST_TMPDIR/syslog"
	cat > "$log" <<'EOF'
Mar  8 10:01:01 server pdns_server[1234]: AXFR of domain example.com denied: client IP 203.0.113.60 has no permission
Mar  8 10:01:02 server pdns_server[1234]: Received NOTIFY for domain example.com from 198.51.100.55 for which we are not authoritative
Mar  8 10:01:03 server pdns_server[1234]: AXFR of domain test.com denied: client IP 203.0.113.60 has no permission
EOF
	run test_rule "$INSTALL_PATH" "powerdns" "$log"
	assert_success
	assert_output --partial "3 matches, 2 unique IPs"
}

@test "powerdns: normal query not matched" {
	local log="$TEST_TMPDIR/syslog"
	echo 'Mar  8 10:01:01 server pdns_server[1234]: Query for example.com from 203.0.113.60 answered with NOERROR' > "$log"
	run test_rule "$INSTALL_PATH" "powerdns" "$log"
	assert_success
	assert_output --partial "0 matches"
}

# --- cross-rule: pattern isolation via test_pattern ---

@test "test_pattern: sogo login failure pattern" {
	local log="$TEST_TMPDIR/sogo.log"
	echo "Login from '192.0.2.99' as 'admin' in domain 'example.com' might not have worked" > "$log"
	run test_pattern "Login from '<HOST>.* might not have worked" "$log"
	assert_success
	assert_output --partial "Matches:  1"
	assert_output --partial "192.0.2.99"
}

@test "test_pattern: freeswitch auth failure pattern" {
	local log="$TEST_TMPDIR/fs.log"
	echo 'SIP auth failure (REGISTER) on sofia profile internal for [1001@example.com] from ip 192.0.2.88' > "$log"
	run test_pattern "SIP auth failure.* from ip <HOST>" "$log"
	assert_success
	assert_output --partial "Matches:  1"
	assert_output --partial "192.0.2.88"
}

@test "test_pattern: ejabberd c2s failure pattern" {
	local log="$TEST_TMPDIR/ejab.log"
	echo 'Failed c2s SCRAM-SHA-256 authentication user@example.com from 192.0.2.77' > "$log"
	run test_pattern "Failed c2s .* authentication .* from <HOST>" "$log"
	assert_success
	assert_output --partial "Matches:  1"
	assert_output --partial "192.0.2.77"
}

@test "test_pattern: drupal login failure pattern" {
	local log="$TEST_TMPDIR/drupal.log"
	echo 'drupal: https://example.com/|1709899261|user|192.0.2.66|https://example.com/user/login||0||Login attempt failed for admin.' > "$log"
	run test_pattern "drupal.*[|]<HOST>[|].*Login attempt failed" "$log"
	assert_success
	assert_output --partial "Matches:  1"
	assert_output --partial "192.0.2.66"
}

@test "test_pattern: jellyfin auth denied pattern" {
	local log="$TEST_TMPDIR/jelly.log"
	echo 'Authentication request for "admin" has been denied (IP: "192.0.2.55").' > "$log"
	run test_pattern 'Authentication request for .* has been denied.*IP: "<HOST>"' "$log"
	assert_success
	assert_output --partial "Matches:  1"
	assert_output --partial "192.0.2.55"
}

@test "test_pattern: powerdns AXFR denied pattern" {
	local log="$TEST_TMPDIR/pdns.log"
	echo 'AXFR of domain example.com denied: client IP 192.0.2.44 has no permission' > "$log"
	run test_pattern "AXFR of domain .* denied: client IP <HOST>" "$log"
	assert_success
	assert_output --partial "Matches:  1"
	assert_output --partial "192.0.2.44"
}

@test "test_pattern: powerdns NOTIFY pattern" {
	local log="$TEST_TMPDIR/pdns.log"
	echo 'Received NOTIFY for domain example.com from 192.0.2.33 for which we are not authoritative' > "$log"
	run test_pattern "Received NOTIFY .* from <HOST>.* not authoritative" "$log"
	assert_success
	assert_output --partial "Matches:  1"
	assert_output --partial "192.0.2.33"
}
