#!/usr/bin/env bats
#
# Tests for Tier 1 rules: vaultwarden, guacamole, haproxy, squid
# Validates pattern matching via test_rule / test_pattern against synthetic logs
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

setup() {
	bfd_standard_setup
	GLOB_PRESSURE_TRIP="15"
	PRESSURE_TRIP=""
	RULES_PATH="$INSTALL_PATH/rules"
	mkdir -p "$RULES_PATH"
	LOG_SOURCE="file"

	# create mock PREREQ binaries so rule if-guards pass
	mkdir -p /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin
	touch /usr/bin/vaultwarden
	touch /usr/sbin/guacd
	touch /usr/sbin/haproxy
	touch /usr/sbin/squid

	# copy rule files from project source
	cp "$PROJECT_ROOT/files/rules/vaultwarden" "$RULES_PATH/"
	cp "$PROJECT_ROOT/files/rules/guacamole" "$RULES_PATH/"
	cp "$PROJECT_ROOT/files/rules/haproxy" "$RULES_PATH/"
	cp "$PROJECT_ROOT/files/rules/squid" "$RULES_PATH/"
	chown root "$RULES_PATH/vaultwarden" "$RULES_PATH/guacamole" \
		"$RULES_PATH/haproxy" "$RULES_PATH/squid"
	chmod 644 "$RULES_PATH/vaultwarden" "$RULES_PATH/guacamole" \
		"$RULES_PATH/haproxy" "$RULES_PATH/squid"
}

teardown() {
	# clean up mock PREREQ binaries
	rm -f /usr/bin/vaultwarden /usr/sbin/guacd /usr/sbin/haproxy /usr/sbin/squid
	bfd_teardown
}

# --- vaultwarden ---

@test "vaultwarden: password failure extracts IP" {
	local log="$TEST_TMPDIR/vaultwarden.log"
	echo '[2026-03-08 10:01:01] Username or password is incorrect. Try again. IP: 203.0.113.10. Username: admin.' > "$log"
	run test_rule "$INSTALL_PATH" "vaultwarden" "$log"
	assert_success
	assert_output --partial "203.0.113.10"
	assert_output --partial "1 matches"
}

@test "vaultwarden: invalid admin token extracts IP" {
	local log="$TEST_TMPDIR/vaultwarden.log"
	echo '[2026-03-08 10:01:01] Invalid admin token. IP: 198.51.100.5. Navigate to the admin page.' > "$log"
	run test_rule "$INSTALL_PATH" "vaultwarden" "$log"
	assert_success
	assert_output --partial "198.51.100.5"
	assert_output --partial "1 matches"
}

@test "vaultwarden: invalid TOTP code extracts IP" {
	local log="$TEST_TMPDIR/vaultwarden.log"
	echo '[2026-03-08 10:01:01] Invalid TOTP code for user admin. IP: 192.0.2.30.' > "$log"
	run test_rule "$INSTALL_PATH" "vaultwarden" "$log"
	assert_success
	assert_output --partial "192.0.2.30"
	assert_output --partial "1 matches"
}

@test "vaultwarden: multiple failures aggregate correctly" {
	local log="$TEST_TMPDIR/vaultwarden.log"
	cat > "$log" <<'EOF'
[2026-03-08 10:01:01] Username or password is incorrect. Try again. IP: 203.0.113.10. Username: admin.
[2026-03-08 10:01:02] Username or password is incorrect. Try again. IP: 203.0.113.10. Username: user1.
[2026-03-08 10:01:03] Invalid admin token. IP: 198.51.100.5. Navigate to the admin page.
[2026-03-08 10:01:04] Invalid TOTP code for user admin. IP: 203.0.113.10.
EOF
	run test_rule "$INSTALL_PATH" "vaultwarden" "$log"
	assert_success
	assert_output --partial "4 matches, 2 unique IPs"
}

@test "vaultwarden: non-matching line yields zero" {
	local log="$TEST_TMPDIR/vaultwarden.log"
	echo '[2026-03-08 10:01:01] User admin logged in successfully. IP: 203.0.113.10.' > "$log"
	run test_rule "$INSTALL_PATH" "vaultwarden" "$log"
	assert_success
	assert_output --partial "0 matches"
}

# --- guacamole ---

@test "guacamole: auth failure extracts IP" {
	local log="$TEST_TMPDIR/catalina.out"
	echo '08-Mar-2026 10:01:01.123 INFO Authentication attempt from 203.0.113.20 for user admin failed.' > "$log"
	run test_rule "$INSTALL_PATH" "guacamole" "$log"
	assert_success
	assert_output --partial "203.0.113.20"
	assert_output --partial "1 matches"
}

@test "guacamole: multiple IPs extracted" {
	local log="$TEST_TMPDIR/catalina.out"
	cat > "$log" <<'EOF'
08-Mar-2026 10:01:01.123 INFO Authentication attempt from 203.0.113.20 for user admin failed.
08-Mar-2026 10:01:02.456 INFO Authentication attempt from 198.51.100.15 for user root failed.
08-Mar-2026 10:01:03.789 INFO Authentication attempt from 203.0.113.20 for user test failed.
EOF
	run test_rule "$INSTALL_PATH" "guacamole" "$log"
	assert_success
	assert_output --partial "3 matches, 2 unique IPs"
}

@test "guacamole: non-matching line yields zero" {
	local log="$TEST_TMPDIR/catalina.out"
	echo '08-Mar-2026 10:01:01.123 INFO Connection from 203.0.113.20 established.' > "$log"
	run test_rule "$INSTALL_PATH" "guacamole" "$log"
	assert_success
	assert_output --partial "0 matches"
}

# --- haproxy ---

@test "haproxy: HTTP 401 extracts IP from log format" {
	local log="$TEST_TMPDIR/haproxy.log"
	echo 'Mar  8 10:01:01 server haproxy[1234]: 203.0.113.50:43210 [08/Mar/2026:10:01:01.000] frontend backend/server 0/0/0/5/5 401 512 - - ---- 1/1/0/0/0 0/0 "GET /admin HTTP/1.1"' > "$log"
	run test_rule "$INSTALL_PATH" "haproxy" "$log"
	assert_success
	assert_output --partial "203.0.113.50"
	assert_output --partial "1 matches"
}

@test "haproxy: multiple 401s from different IPs" {
	local log="$TEST_TMPDIR/haproxy.log"
	cat > "$log" <<'EOF'
Mar  8 10:01:01 server haproxy[1234]: 203.0.113.50:43210 [08/Mar/2026:10:01:01.000] fe be/srv 0/0/0/5/5 401 512 - - ---- 1/1/0/0/0 0/0 "GET /admin HTTP/1.1"
Mar  8 10:01:02 server haproxy[1234]: 198.51.100.25:43211 [08/Mar/2026:10:01:02.000] fe be/srv 0/0/0/5/5 401 512 - - ---- 1/1/0/0/0 0/0 "GET /admin HTTP/1.1"
Mar  8 10:01:03 server haproxy[1234]: 203.0.113.50:43212 [08/Mar/2026:10:01:03.000] fe be/srv 0/0/0/5/5 401 512 - - ---- 1/1/0/0/0 0/0 "GET /admin HTTP/1.1"
EOF
	run test_rule "$INSTALL_PATH" "haproxy" "$log"
	assert_success
	assert_output --partial "3 matches, 2 unique IPs"
}

@test "haproxy: HTTP 200 not matched" {
	local log="$TEST_TMPDIR/haproxy.log"
	echo 'Mar  8 10:01:01 server haproxy[1234]: 203.0.113.50:43210 [08/Mar/2026:10:01:01.000] fe be/srv 0/0/0/5/5 200 512 - - ---- 1/1/0/0/0 0/0 "GET / HTTP/1.1"' > "$log"
	run test_rule "$INSTALL_PATH" "haproxy" "$log"
	assert_success
	assert_output --partial "0 matches"
}

@test "haproxy: HTTP 403 not matched (only 401)" {
	local log="$TEST_TMPDIR/haproxy.log"
	echo 'Mar  8 10:01:01 server haproxy[1234]: 203.0.113.50:43210 [08/Mar/2026:10:01:01.000] fe be/srv 0/0/0/5/5 403 512 - - ---- 1/1/0/0/0 0/0 "GET /admin HTTP/1.1"' > "$log"
	run test_rule "$INSTALL_PATH" "haproxy" "$log"
	assert_success
	assert_output --partial "0 matches"
}

# --- squid ---

@test "squid: TCP_DENIED/407 extracts IP" {
	local log="$TEST_TMPDIR/access.log"
	echo '1709899261.123    150 203.0.113.70 TCP_DENIED/407 3900 GET http://example.com/ - HIER_NONE/- text/html' > "$log"
	run test_rule "$INSTALL_PATH" "squid" "$log"
	assert_success
	assert_output --partial "203.0.113.70"
	assert_output --partial "1 matches"
}

@test "squid: TCP_DENIED/403 extracts IP" {
	local log="$TEST_TMPDIR/access.log"
	echo '1709899261.123    150 198.51.100.40 TCP_DENIED/403 3900 GET http://blocked.example.com/ - HIER_NONE/- text/html' > "$log"
	run test_rule "$INSTALL_PATH" "squid" "$log"
	assert_success
	assert_output --partial "198.51.100.40"
	assert_output --partial "1 matches"
}

@test "squid: multiple denials aggregate correctly" {
	local log="$TEST_TMPDIR/access.log"
	cat > "$log" <<'EOF'
1709899261.123    150 203.0.113.70 TCP_DENIED/407 3900 GET http://example.com/ - HIER_NONE/- text/html
1709899262.456    150 203.0.113.70 TCP_DENIED/407 3900 GET http://example.com/page - HIER_NONE/- text/html
1709899263.789    150 198.51.100.40 TCP_DENIED/403 3900 GET http://blocked.example.com/ - HIER_NONE/- text/html
EOF
	run test_rule "$INSTALL_PATH" "squid" "$log"
	assert_success
	assert_output --partial "3 matches, 2 unique IPs"
}

@test "squid: TCP_MISS/200 not matched" {
	local log="$TEST_TMPDIR/access.log"
	echo '1709899261.123    150 203.0.113.70 TCP_MISS/200 3900 GET http://example.com/ - HIER_DIRECT/example.com text/html' > "$log"
	run test_rule "$INSTALL_PATH" "squid" "$log"
	assert_success
	assert_output --partial "0 matches"
}

@test "squid: TCP_DENIED/404 not matched (only 407 and 403)" {
	local log="$TEST_TMPDIR/access.log"
	echo '1709899261.123    150 203.0.113.70 TCP_DENIED/404 3900 GET http://example.com/nopage - HIER_NONE/- text/html' > "$log"
	run test_rule "$INSTALL_PATH" "squid" "$log"
	assert_success
	assert_output --partial "0 matches"
}

# --- cross-rule: pattern isolation via test_pattern ---

@test "test_pattern: vaultwarden password pattern" {
	local log="$TEST_TMPDIR/vw.log"
	echo '[2026-03-08 10:01:01] Username or password is incorrect. Try again. IP: 192.0.2.99. Username: test.' > "$log"
	run test_pattern "Username or password is incorrect.* IP: <HOST>" "$log"
	assert_success
	assert_output --partial "Matches:  1"
	assert_output --partial "192.0.2.99"
}

@test "test_pattern: guacamole auth pattern" {
	local log="$TEST_TMPDIR/guac.log"
	echo '08-Mar-2026 10:01:01.123 INFO Authentication attempt from 192.0.2.88 for user test failed.' > "$log"
	run test_pattern "Authentication attempt from <HOST>.* failed" "$log"
	assert_success
	assert_output --partial "Matches:  1"
	assert_output --partial "192.0.2.88"
}

@test "test_pattern: haproxy 401 pattern" {
	local log="$TEST_TMPDIR/hap.log"
	echo '192.0.2.77:43210 [08/Mar/2026:10:01:01.000] fe be/srv 0/0/0/5/5 401 512' > "$log"
	run test_pattern "<HOST>:[0-9]+.* 401 [0-9]" "$log"
	assert_success
	assert_output --partial "Matches:  1"
	assert_output --partial "192.0.2.77"
}

@test "test_pattern: squid 407 pattern" {
	local log="$TEST_TMPDIR/sq.log"
	echo '1709899261.123    150 192.0.2.66 TCP_DENIED/407 3900 GET http://example.com/' > "$log"
	run test_pattern "<HOST> TCP_DENIED/407 " "$log"
	assert_success
	assert_output --partial "Matches:  1"
	assert_output --partial "192.0.2.66"
}

@test "test_pattern: squid 403 pattern" {
	local log="$TEST_TMPDIR/sq.log"
	echo '1709899261.123    150 192.0.2.55 TCP_DENIED/403 3900 GET http://blocked.example.com/' > "$log"
	run test_pattern "<HOST> TCP_DENIED/403 " "$log"
	assert_success
	assert_output --partial "Matches:  1"
	assert_output --partial "192.0.2.55"
}
