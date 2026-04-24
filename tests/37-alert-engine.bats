#!/usr/bin/env bats
#
# Test suite for alert_lib.sh — template engine, content helpers, rendering
# Delivery and messaging tests split to 37a-alert-delivery.bats
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

setup() {
	bfd_common_setup
	INSTALL_PATH="$TEST_TMPDIR/bfd"
	mkdir -p "$INSTALL_PATH"
	DATA_PATH="$INSTALL_PATH/data"
	mkdir -p "$DATA_PATH"
}

teardown() {
	bfd_teardown
}

# ===================================================================
# Source guard & version
# ===================================================================

@test "alert_lib: reputation link arrays are populated" {
	[ "${#_REPLINK_KEYS[@]}" -eq 5 ]
	[ "${#_REPLINK_LABELS[@]}" -eq 5 ]
	[ "${#_REPLINK_URLS[@]}" -eq 5 ]
}

@test "alert_lib: regional indicator byte array has 26 entries" {
	[ "${#_RI_BYTES[@]}" -eq 26 ]
}

# ===================================================================
# _alert_tpl_render — template engine
# ===================================================================

@test "_alert_tpl_render: replaces single variable" {
	local tpl="$TEST_TMPDIR/test.tpl"
	echo "Hello {{NAME}}" > "$tpl"
	export NAME="World"
	run _alert_tpl_render "$tpl"
	assert_success
	assert_output "Hello World"
}

@test "_alert_tpl_render: replaces multiple variables on same line" {
	local tpl="$TEST_TMPDIR/test.tpl"
	echo "{{HOST}} via {{SERVICE}} on {{PORTS}}" > "$tpl"
	export HOST="192.0.2.1"
	export SERVICE="sshd"
	export PORTS="22"
	run _alert_tpl_render "$tpl"
	assert_success
	assert_output "192.0.2.1 via sshd on 22"
}

@test "_alert_tpl_render: replaces variables across multiple lines" {
	local tpl="$TEST_TMPDIR/test.tpl"
	cat > "$tpl" <<'EOF'
Host: {{HOST}}
Service: {{SERVICE}}
EOF
	export HOST="203.0.113.5"
	export SERVICE="dovecot"
	run _alert_tpl_render "$tpl"
	assert_success
	assert_line --index 0 "Host: 203.0.113.5"
	assert_line --index 1 "Service: dovecot"
}

@test "_alert_tpl_render: unknown variables become empty" {
	local tpl="$TEST_TMPDIR/test.tpl"
	echo "Value: [{{NONEXISTENT_VAR_XYZ}}]" > "$tpl"
	unset NONEXISTENT_VAR_XYZ 2>/dev/null || true
	run _alert_tpl_render "$tpl"
	assert_success
	assert_output "Value: []"
}

@test "_alert_tpl_render: preserves lines without variables" {
	local tpl="$TEST_TMPDIR/test.tpl"
	echo "No variables here, just plain text." > "$tpl"
	run _alert_tpl_render "$tpl"
	assert_success
	assert_output "No variables here, just plain text."
}

@test "_alert_tpl_render: preserves HTML tags" {
	local tpl="$TEST_TMPDIR/test.tpl"
	echo '<td style="color:red;">{{VALUE}}</td>' > "$tpl"
	export VALUE="test"
	run _alert_tpl_render "$tpl"
	assert_success
	assert_output '<td style="color:red;">test</td>'
}

@test "_alert_tpl_render: returns 1 for missing file" {
	run _alert_tpl_render "$TEST_TMPDIR/does_not_exist.tpl"
	assert_failure
}

@test "_alert_tpl_render: handles empty template" {
	local tpl="$TEST_TMPDIR/empty.tpl"
	: > "$tpl"
	run _alert_tpl_render "$tpl"
	assert_success
	assert_output ""
}

@test "_alert_tpl_render: variable with underscores and digits" {
	local tpl="$TEST_TMPDIR/test.tpl"
	echo "{{SUMMARY_TOTAL_BANS}} bans, {{ENTRY_NUM}} of {{ENTRY_TOTAL}}" > "$tpl"
	export SUMMARY_TOTAL_BANS="7"
	export ENTRY_NUM="3"
	export ENTRY_TOTAL="5"
	run _alert_tpl_render "$tpl"
	assert_success
	assert_output "7 bans, 3 of 5"
}

@test "_alert_tpl_render: does not expand shell variables" {
	local tpl="$TEST_TMPDIR/test.tpl"
	echo 'No expansion: $HOME $(whoami) `id`' > "$tpl"
	run _alert_tpl_render "$tpl"
	assert_success
	# must be preserved literally, no expansion
	assert_output 'No expansion: $HOME $(whoami) `id`'
}

@test "_alert_tpl_render: braces that are not template tokens pass through" {
	local tpl="$TEST_TMPDIR/test.tpl"
	echo '{{lowercase}} {SINGLE} {{ SPACES }} {{123NUM}}' > "$tpl"
	run _alert_tpl_render "$tpl"
	assert_success
	# none of these match {{[A-Z_][A-Z0-9_]*}} so they pass through literally
	assert_output '{{lowercase}} {SINGLE} {{ SPACES }} {{123NUM}}'
}

# ===================================================================
# _alert_html_escape
# ===================================================================

@test "_alert_html_escape: escapes all HTML entities and passes through safe strings" {
	# ampersand
	run _alert_html_escape "foo & bar"
	assert_success
	assert_output "foo &amp; bar"

	# less-than and greater-than
	run _alert_html_escape "<script>alert('xss')</script>"
	assert_success
	assert_output "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;"

	# double quotes
	run _alert_html_escape 'value="test"'
	assert_success
	assert_output 'value=&quot;test&quot;'

	# single quotes
	run _alert_html_escape "it's a test"
	assert_success
	assert_output "it&#39;s a test"

	# multiple special chars together
	run _alert_html_escape '<b>"A & B"</b>'
	assert_success
	assert_output '&lt;b&gt;&quot;A &amp; B&quot;&lt;/b&gt;'

	# empty string
	run _alert_html_escape ""
	assert_success
	assert_output ""

	# IP address passes through
	run _alert_html_escape "192.0.2.1"
	assert_success
	assert_output "192.0.2.1"
}

# ===================================================================
# _alert_sanitize_logs
# ===================================================================

@test "_alert_sanitize_logs: extracts matching lines" {
	local logfile="$TEST_TMPDIR/auth.log"
	cat > "$logfile" <<'EOF'
Jan  1 00:00:01 host sshd: Failed password for user from 192.0.2.1
Jan  1 00:00:02 host sshd: Accepted password for admin from 10.0.0.1
Jan  1 00:00:03 host sshd: Failed password for root from 192.0.2.1
EOF
	run _alert_sanitize_logs "$logfile" "192.0.2.1" 50
	assert_success
	assert_line --index 0 --partial "192.0.2.1"
	assert_line --index 1 --partial "192.0.2.1"
	# line for 10.0.0.1 should not appear
	refute_output --partial "10.0.0.1"
}

@test "_alert_sanitize_logs: redacts password values" {
	local logfile="$TEST_TMPDIR/auth.log"
	echo 'Jan  1 00:00:01 host app: password=secret123 from 192.0.2.1' > "$logfile"
	run _alert_sanitize_logs "$logfile" "192.0.2.1" 50
	assert_success
	assert_output --partial "password=<REDACTED>"
	refute_output --partial "secret123"
}

@test "_alert_sanitize_logs: redacts authorization headers" {
	local logfile="$TEST_TMPDIR/auth.log"
	echo 'Jan  1 00:00:01 host app: Authorization: Bearer abc123 from 192.0.2.1' > "$logfile"
	run _alert_sanitize_logs "$logfile" "192.0.2.1" 50
	assert_success
	assert_output --partial "Authorization: <REDACTED>"
	refute_output --partial "abc123"
}

@test "_alert_sanitize_logs: limits to loglines count" {
	local logfile="$TEST_TMPDIR/auth.log"
	local i
	for i in $(seq 1 20); do
		echo "Jan  1 00:00:$i host sshd: Failed from 192.0.2.1 attempt $i" >> "$logfile"
	done
	run _alert_sanitize_logs "$logfile" "192.0.2.1" 5
	assert_success
	# should have exactly 5 lines
	local count
	count=$(echo "$output" | wc -l)
	[ "$count" -eq 5 ]
}

@test "_alert_sanitize_logs: returns 1 for missing file" {
	run _alert_sanitize_logs "/nonexistent/file" "192.0.2.1" 50
	assert_failure
}

@test "_alert_sanitize_logs: returns 1 for empty host match" {
	local logfile="$TEST_TMPDIR/auth.log"
	echo "Jan  1 00:00:01 host sshd: something else entirely" > "$logfile"
	run _alert_sanitize_logs "$logfile" "192.0.2.99" 50
	assert_failure
}

@test "_alert_sanitize_logs: returns 1 for empty log_file param" {
	run _alert_sanitize_logs "" "192.0.2.1" 50
	assert_failure
}

@test "_alert_sanitize_logs: patterns param filters to matching patterns only" {
	local logfile="$TEST_TMPDIR/auth.log"
	cat > "$logfile" <<'EOF'
Jan  1 00:00:01 host sshd: Failed password for user from 192.0.2.1
Jan  1 00:00:02 host sshd: Accepted password for admin from 192.0.2.1
Jan  1 00:00:03 host sshd: Invalid user test from 192.0.2.1
Jan  1 00:00:04 host sshd: Disconnected from 192.0.2.1
EOF
	local patterns
	patterns=$(printf '%s\n' \
		"sshd.*Failed password for .* from <HOST>" \
		"sshd.*Invalid user .* from <HOST>")
	run _alert_sanitize_logs "$logfile" "192.0.2.1" 50 "$patterns"
	assert_success
	assert_line --index 0 --partial "Failed password"
	assert_line --index 1 --partial "Invalid user"
	refute_output --partial "Accepted password"
	refute_output --partial "Disconnected"
}

@test "_alert_sanitize_logs: patterns param escapes IPv4 dots" {
	local logfile="$TEST_TMPDIR/auth.log"
	cat > "$logfile" <<'EOF'
Jan  1 00:00:01 host sshd: Failed password for user from 192.0.2.1
Jan  1 00:00:02 host sshd: Failed password for user from 192X0X2X1
EOF
	local patterns="sshd.*Failed password for .* from <HOST>"
	run _alert_sanitize_logs "$logfile" "192.0.2.1" 50 "$patterns"
	assert_success
	# dot-escaped IP should not match 192X0X2X1
	local count
	count=$(echo "$output" | wc -l)
	[ "$count" -eq 1 ]
	assert_output --partial "192.0.2.1"
}

@test "_alert_sanitize_logs: empty patterns falls back to IP grep" {
	local logfile="$TEST_TMPDIR/auth.log"
	cat > "$logfile" <<'EOF'
Jan  1 00:00:01 host sshd: Failed password for user from 192.0.2.1
Jan  1 00:00:02 host sshd: Accepted password for admin from 192.0.2.1
EOF
	run _alert_sanitize_logs "$logfile" "192.0.2.1" 50 ""
	assert_success
	# both lines match with blanket grep (backward compat)
	local count
	count=$(echo "$output" | wc -l)
	[ "$count" -eq 2 ]
}

@test "_alert_sanitize_logs: patterns with redaction still works" {
	local logfile="$TEST_TMPDIR/auth.log"
	echo 'Jan  1 00:00:01 host sshd: Failed password=secret from 192.0.2.1' > "$logfile"
	local patterns="sshd.*Failed password.* from <HOST>"
	run _alert_sanitize_logs "$logfile" "192.0.2.1" 50 "$patterns"
	assert_success
	assert_output --partial "password=<REDACTED>"
	refute_output --partial "secret"
}

# ===================================================================
# _alert_country_flag
# ===================================================================

@test "_alert_country_flag: input validation for valid CCs, lowercase, empty, and invalid inputs" {
	# US produces non-empty output
	run _alert_country_flag "US"
	assert_success
	[ -n "$output" ]

	# lowercase input works
	run _alert_country_flag "cn"
	assert_success
	[ -n "$output" ]

	# empty input returns empty
	run _alert_country_flag ""
	assert_success
	assert_output ""

	# single char returns empty
	run _alert_country_flag "X"
	assert_success
	assert_output ""

	# three chars returns empty
	run _alert_country_flag "USA"
	assert_success
	assert_output ""

	# numeric input returns empty
	run _alert_country_flag "12"
	assert_success
	assert_output ""
}

@test "_alert_country_flag: same CC always produces same output" {
	local out1 out2
	out1=$(_alert_country_flag "DE")
	out2=$(_alert_country_flag "DE")
	[ "$out1" = "$out2" ]
}

@test "_alert_country_flag: different CCs produce different output" {
	local out1 out2
	out1=$(_alert_country_flag "US")
	out2=$(_alert_country_flag "CN")
	[ "$out1" != "$out2" ]
}

# ===================================================================
# _alert_build_reputation_links
# ===================================================================

@test "_alert_build_reputation_links: single key" {
	_alert_build_reputation_links "192.0.2.1" "abuseipdb"
	[ -n "$REPUTATION_LINKS_TEXT" ]
	[ -n "$REPUTATION_LINKS_HTML" ]
	[[ "$REPUTATION_LINKS_TEXT" == *"AbuseIPDB"* ]]
	[[ "$REPUTATION_LINKS_TEXT" == *"192.0.2.1"* ]]
	[[ "$REPUTATION_LINKS_HTML" == *"abuseipdb.com"* ]]
	[[ "$REPUTATION_LINKS_HTML" == *"192.0.2.1"* ]]
}

@test "_alert_build_reputation_links: multiple keys" {
	_alert_build_reputation_links "198.51.100.5" "abuseipdb,ipinfo,shodan"
	[[ "$REPUTATION_LINKS_TEXT" == *"AbuseIPDB"* ]]
	[[ "$REPUTATION_LINKS_TEXT" == *"IPinfo"* ]]
	[[ "$REPUTATION_LINKS_TEXT" == *"Shodan"* ]]
	# HTML should have middot separators
	[[ "$REPUTATION_LINKS_HTML" == *"middot"* ]]
}

@test "_alert_build_reputation_links: all five keys" {
	_alert_build_reputation_links "203.0.113.1" "abuseipdb,shodan,virustotal,ipinfo,greynoise"
	[[ "$REPUTATION_LINKS_TEXT" == *"AbuseIPDB"* ]]
	[[ "$REPUTATION_LINKS_TEXT" == *"Shodan"* ]]
	[[ "$REPUTATION_LINKS_TEXT" == *"VirusTotal"* ]]
	[[ "$REPUTATION_LINKS_TEXT" == *"IPinfo"* ]]
	[[ "$REPUTATION_LINKS_TEXT" == *"GreyNoise"* ]]
}

@test "_alert_build_reputation_links: IPv6 address" {
	_alert_build_reputation_links "2001:db8::1" "abuseipdb"
	[[ "$REPUTATION_LINKS_TEXT" == *"2001:db8::1"* ]]
	[[ "$REPUTATION_LINKS_HTML" == *"2001:db8::1"* ]]
}

@test "_alert_build_reputation_links: unknown key is silently skipped" {
	_alert_build_reputation_links "192.0.2.1" "abuseipdb,bogus_key,ipinfo"
	# should have abuseipdb and ipinfo but not bogus_key
	[[ "$REPUTATION_LINKS_TEXT" == *"AbuseIPDB"* ]]
	[[ "$REPUTATION_LINKS_TEXT" == *"IPinfo"* ]]
	[[ "$REPUTATION_LINKS_TEXT" != *"bogus_key"* ]]
}

@test "_alert_build_reputation_links: returns 1 for empty config" {
	run _alert_build_reputation_links "192.0.2.1" ""
	assert_failure
}

@test "_alert_build_reputation_links: returns 1 for empty ip" {
	run _alert_build_reputation_links "" "abuseipdb"
	assert_failure
}

@test "_alert_build_reputation_links: returns 1 for all unknown keys" {
	run _alert_build_reputation_links "192.0.2.1" "fake1,fake2"
	assert_failure
}

@test "_alert_build_reputation_links: handles spaces around commas" {
	_alert_build_reputation_links "192.0.2.1" "abuseipdb , ipinfo"
	[[ "$REPUTATION_LINKS_TEXT" == *"AbuseIPDB"* ]]
	[[ "$REPUTATION_LINKS_TEXT" == *"IPinfo"* ]]
}

@test "_alert_build_reputation_links: HTML contains href attributes" {
	_alert_build_reputation_links "192.0.2.1" "abuseipdb"
	[[ "$REPUTATION_LINKS_HTML" == *'href='* ]]
	[[ "$REPUTATION_LINKS_HTML" == *'</a>'* ]]
}

# ===================================================================
# _alert_pressure_bar
# ===================================================================

@test "_alert_pressure_bar: produces correct visualization for all percentages" {
	run _alert_pressure_bar 0
	assert_success
	assert_output "[                    ] 0%"

	run _alert_pressure_bar 50
	assert_success
	assert_output "[==========          ] 50%"

	run _alert_pressure_bar 100
	assert_success
	assert_output "[====================] 100%"

	run _alert_pressure_bar 150
	assert_success
	assert_output "[====================] 150%"

	run _alert_pressure_bar 25
	assert_success
	assert_output "[=====               ] 25%"

	# 1 * 20 / 100 = 0
	run _alert_pressure_bar 1
	assert_success
	assert_output "[                    ] 1%"

	run _alert_pressure_bar 5
	assert_success
	assert_output "[=                   ] 5%"
}

# ===================================================================
# _alert_pressure_color
# ===================================================================

@test "_alert_pressure_color: correct color tier for all pressure percentages" {
	# green tier: 0-69%
	run _alert_pressure_color 0
	assert_success
	assert_output "#16a34a"

	run _alert_pressure_color 30
	assert_success
	assert_output "#16a34a"

	run _alert_pressure_color 69
	assert_success
	assert_output "#16a34a"

	# amber tier: 70-99%
	run _alert_pressure_color 70
	assert_success
	assert_output "#d97706"

	run _alert_pressure_color 99
	assert_success
	assert_output "#d97706"

	# red tier: 100%+
	run _alert_pressure_color 100
	assert_success
	assert_output "#dc2626"

	run _alert_pressure_color 200
	assert_success
	assert_output "#dc2626"
}

# ===================================================================
# _alert_ban_type_color
# ===================================================================

@test "_alert_ban_type_color: correct color for escalate, permanent, temporary, and escalate-override" {
	# escalate is amber
	run _alert_ban_type_color "escalate" "0"
	assert_success
	assert_output "#d97706"

	# permanent (expiry=0) is red
	run _alert_ban_type_color "ban" "0"
	assert_success
	assert_output "#dc2626"

	# temporary is teal
	run _alert_ban_type_color "ban" "1709553600"
	assert_success
	assert_output "#0891b2"

	# escalate overrides expiry check — even with non-zero expiry, amber
	run _alert_ban_type_color "escalate" "1709553600"
	assert_success
	assert_output "#d97706"
}

# ===================================================================
# Template partials — file existence and structure
# ===================================================================

@test "template partials: all 8 files exist, contain tokens, and text has no HTML" {
	local tpl_dir="${PROJECT_ROOT}/files/alert"
	local expected=(
		text.header.tpl text.entry.tpl text.summary.tpl text.footer.tpl
		html.header.tpl html.entry.tpl html.summary.tpl html.footer.tpl
	)
	local f
	# all 8 files exist
	for f in "${expected[@]}"; do
		[ -f "$tpl_dir/$f" ]
	done
	# text templates contain {{VAR}} tokens
	for f in text.header.tpl text.entry.tpl text.summary.tpl text.footer.tpl; do
		grep -qE '\{\{[A-Z_][A-Z0-9_]*\}\}' "$tpl_dir/$f"
	done
	# HTML templates contain {{VAR}} tokens
	for f in html.header.tpl html.entry.tpl html.summary.tpl html.footer.tpl; do
		grep -qE '\{\{[A-Z_][A-Z0-9_]*\}\}' "$tpl_dir/$f"
	done
	# text templates have no HTML tags
	for f in text.header.tpl text.entry.tpl text.summary.tpl text.footer.tpl; do
		! grep -qE '<[a-z]+[> ]' "$tpl_dir/$f"
	done
}

@test "template partials: HTML header opens html/body/table" {
	local tpl="${PROJECT_ROOT}/files/alert/html.header.tpl"
	grep -q '<html' "$tpl"
	grep -q '<body' "$tpl"
	grep -q '<table' "$tpl"
}

@test "template partials: HTML footer closes html/body/table" {
	local tpl="${PROJECT_ROOT}/files/alert/html.footer.tpl"
	grep -q '</html>' "$tpl"
	grep -q '</body>' "$tpl"
	grep -q '</table>' "$tpl"
}

@test "template partials: HTML entry is self-contained" {
	local tpl="${PROJECT_ROOT}/files/alert/html.entry.tpl"
	# count opening and closing table tags — must balance
	local opens closes
	opens=$(grep -c '<table' "$tpl")
	closes=$(grep -c '</table>' "$tpl")
	[ "$opens" -eq "$closes" ]
	[ "$opens" -gt 0 ]
}

@test "template partials: HTML summary is self-contained" {
	local tpl="${PROJECT_ROOT}/files/alert/html.summary.tpl"
	local opens closes
	opens=$(grep -c '<table' "$tpl")
	closes=$(grep -c '</table>' "$tpl")
	[ "$opens" -eq "$closes" ]
	[ "$opens" -gt 0 ]
}

# ===================================================================
# Template partials — rendering tests
# ===================================================================

@test "template render: text.header.tpl smoke test" {
	export HOSTNAME="web01.example.com"
	export TIMESTAMP="2026-03-04 14:22:31"
	export TIME_ZONE="-0600"
	export ALERT_COUNT="3"
	run _alert_tpl_render "${PROJECT_ROOT}/files/alert/text.header.tpl"
	assert_success
	assert_output --partial "[BFD] web01.example.com"
	assert_output --partial "2026-03-04 14:22:31 -0600"
	assert_output --partial "3 host(s) banned"
}

@test "template render: text.entry.tpl smoke test" {
	export TIMESTAMP="2026-03-04 14:22:31"
	export HOST_LINE="192.0.2.1  IPv4  US  United States"
	export SERVICE_LINE="sshd  port 22"
	export ACTION_LINE="apf · temporary 10m · expires 2026-03-04 14:32:31"
	export WHY_LINE_1="7 failed logins this scan"
	export WHY_LINE_2="pressure 85  (trip 100 · weight 10 · half-life 30m)"
	export ENTRY_SEPARATOR="──── ban 1 of 3 ────"
	export HISTORY_LINE="  history:   2 prior bans"
	export ESCALATION_LINE=""
	export REPUTATION_SECTION_TEXT=""
	export SOURCE_LOGS_SECTION_TEXT=""
	run _alert_tpl_render "${PROJECT_ROOT}/files/alert/text.entry.tpl"
	assert_success
	assert_output --partial "ban 1 of 3"
	assert_output --partial "192.0.2.1  IPv4  US  United States"
	assert_output --partial "sshd  port 22"
	assert_output --partial "apf · temporary 10m"
	assert_output --partial "7 failed logins this scan"
	assert_output --partial "pressure 85"
	assert_output --partial "trip 100"
	assert_output --partial "weight 10"
	assert_output --partial "half-life 30m"
	assert_output --partial "history:"
	assert_output --partial "2 prior bans"
}

@test "template render: text.summary.tpl smoke test" {
	export SUMMARY_TOTAL_BANS="5"
	export SUMMARY_UNIQUE_IPS="3"
	export SUMMARY_SERVICES="sshd, dovecot"
	export SUMMARY_COUNTRIES="US, CN, RU"
	export SUMMARY_TEMPORARY="3"
	export SUMMARY_ESCALATED="1"
	export SUMMARY_PERMANENT="1"
	export SUMMARY_REPEAT_OFFENDERS="2"
	export SUMMARY_REPEAT_PCT="40"
	run _alert_tpl_render "${PROJECT_ROOT}/files/alert/text.summary.tpl"
	assert_success
	assert_output --partial "summary"
	assert_output --partial "5 bans (3 unique IPs)"
	assert_output --partial "sshd, dovecot"
	assert_output --partial "3 temporary · 1 escalated · 1 permanent"
	assert_output --partial "2 of 5 (40%)"
}

@test "template render: text.footer.tpl smoke test" {
	export BFD_VERSION="2.0.1"
	run _alert_tpl_render "${PROJECT_ROOT}/files/alert/text.footer.tpl"
	assert_success
	assert_output --partial "bfd 2.0.1"
	assert_output --partial "rfxn.com/projects/brute-force-detection"
}

@test "template render: html.header.tpl contains banner and timestamp" {
	export HOSTNAME="mail01.example.com"
	export TIMESTAMP="2026-03-04 15:00:00"
	export TIME_ZONE="+0000"
	export ALERT_COUNT="1"
	run _alert_tpl_render "${PROJECT_ROOT}/files/alert/html.header.tpl"
	assert_success
	assert_output --partial "BFD Alert"
	assert_output --partial "mail01.example.com"
	assert_output --partial "1 banned"
	assert_output --partial "#0891b2"
}

@test "template render: html.entry.tpl contains pressure detail and severity rows" {
	export HOST="198.51.100.5"
	export HOST_VERSION="IPv4"
	export COUNTRY_CODE="CN"
	export COUNTRY_DISPLAY="China (CN)"
	export COUNTRY_FLAG=""
	export SERVICE="dovecot"
	export PORTS="110,143"
	export PRESSURE="120"
	export PRESSURE_TRIP="100"
	export PRESSURE_PCT="120"
	export PRESSURE_PCT_CLAMPED="100"
	export PRESSURE_COLOR="#dc2626"
	export WEIGHT="15"
	export FAIL_COUNT="14"
	export FAIL_COUNT_DISPLAY="14"
	export PRESSURE_CONTRIB="210"
	export HALF_LIFE_FMT="1h"
	export BAN_TYPE="escalated"
	export BAN_TYPE_COLOR="#d97706"
	export BAN_DURATION_DETAIL=""
	export BAN_COMMAND="/sbin/iptables -I INPUT -s 198.51.100.5 -j DROP"
	export ENTRY_NUM="2"
	export ENTRY_TOTAL="2"
	export HISTORY_ROW_HTML=""
	export ESCALATION_ROW_HTML=""
	export REPUTATION_SECTION_HTML=""
	export SOURCE_LOGS_SECTION_HTML=""
	run _alert_tpl_render "${PROJECT_ROOT}/files/alert/html.entry.tpl"
	assert_success
	assert_output --partial "198.51.100.5"
	assert_output --partial "#d97706"
	assert_output --partial "dovecot"
	assert_output --partial "14 failed logins"
	assert_output --partial "+210 this scan"
	assert_output --partial "accumulated pressure"
	assert_output --partial "weight 15"
	assert_output --partial "trips at 100"
}

@test "template render: html.footer.tpl closes structure and shows version" {
	export BFD_VERSION="2.0.1"
	export HOSTNAME="test01"
	run _alert_tpl_render "${PROJECT_ROOT}/files/alert/html.footer.tpl"
	assert_success
	assert_output --partial "</html>"
	assert_output --partial "</body>"
	assert_output --partial "2.0.1"
	assert_output --partial "rfxn.com/projects/brute-force-detection"
}

# ===================================================================
# Template partials — conditional variable behavior
# ===================================================================

@test "template render: empty HISTORY_LINE produces no label text" {
	export HOST="192.0.2.1" HOST_VERSION="IPv4" COUNTRY_CODE="US"
	export COUNTRY_DISPLAY="United States (US)"
	export SERVICE="sshd" PORTS="22" PRESSURE="50" PRESSURE_TRIP="100"
	export PRESSURE_BAR="[==========          ] 50%"
	export WEIGHT="10" HALF_LIFE_FMT="30m"
	export BAN_TYPE="temporary" BAN_DURATION_DETAIL="" BAN_COMMAND="iptables -I"
	export ENTRY_NUM="1" ENTRY_TOTAL="1"
	export HISTORY_LINE="" ESCALATION_LINE=""
	export REPUTATION_SECTION_TEXT="" SOURCE_LOGS_SECTION_TEXT=""
	run _alert_tpl_render "${PROJECT_ROOT}/files/alert/text.entry.tpl"
	assert_success
	refute_output --partial "History:"
	refute_output --partial "Escalation:"
}

@test "template render: populated HISTORY_LINE appears in output" {
	export HOST="192.0.2.1" HOST_VERSION="IPv4" COUNTRY_CODE=""
	export COUNTRY_DISPLAY="--"
	export SERVICE="sshd" PORTS="22" PRESSURE="100" PRESSURE_TRIP="100"
	export PRESSURE_BAR="[====================] 100%"
	export WEIGHT="10" HALF_LIFE_FMT="30m"
	export BAN_TYPE="temporary" BAN_DURATION_DETAIL="" BAN_COMMAND="iptables -I"
	export ENTRY_NUM="1" ENTRY_TOTAL="1"
	export HISTORY_LINE="  History:     3 prior bans (last: 2026-03-01)"
	export ESCALATION_LINE="  Escalation:  linear, step 2 of 5"
	export REPUTATION_SECTION_TEXT="" SOURCE_LOGS_SECTION_TEXT=""
	run _alert_tpl_render "${PROJECT_ROOT}/files/alert/text.entry.tpl"
	assert_success
	assert_output --partial "History:     3 prior bans"
	assert_output --partial "Escalation:  linear, step 2 of 5"
}

@test "template render: multi-line SOURCE_LOGS_SECTION_TEXT renders correctly" {
	export HOST="203.0.113.1" HOST_VERSION="IPv4" COUNTRY_CODE="RU"
	export COUNTRY_DISPLAY="Russia (RU)"
	export SERVICE="sshd" PORTS="22" PRESSURE="90" PRESSURE_TRIP="100"
	export PRESSURE_BAR="[==================  ] 90%"
	export WEIGHT="10" HALF_LIFE_FMT="30m"
	export BAN_TYPE="temporary" BAN_DURATION_DETAIL="" BAN_COMMAND="iptables -I"
	export ENTRY_NUM="1" ENTRY_TOTAL="1"
	export HISTORY_LINE="" ESCALATION_LINE=""
	export REPUTATION_SECTION_TEXT=""
	# multi-line variable — must appear on its own template line
	local logs
	logs="  Source logs:
    Jan  1 00:00:01 host sshd: Failed password from 203.0.113.1
    Jan  1 00:00:02 host sshd: Failed password from 203.0.113.1"
	export SOURCE_LOGS_SECTION_TEXT="$logs"
	run _alert_tpl_render "${PROJECT_ROOT}/files/alert/text.entry.tpl"
	assert_success
	assert_output --partial "Source logs:"
	assert_output --partial "Failed password from 203.0.113.1"
}

@test "template render: empty HTML conditional rows leave no artifacts" {
	export HOST="192.0.2.1" HOST_VERSION="IPv4" COUNTRY_CODE=""
	export COUNTRY_DISPLAY="--"
	export COUNTRY_FLAG="" SERVICE="sshd" PORTS="22"
	export PRESSURE="50" PRESSURE_TRIP="100" PRESSURE_PCT="50"
	export PRESSURE_PCT_CLAMPED="50" PRESSURE_COLOR="#16a34a"
	export WEIGHT="10" HALF_LIFE_FMT="30m"
	export BAN_TYPE="temporary" BAN_TYPE_COLOR="#0891b2"
	export BAN_DURATION_DETAIL="" BAN_COMMAND="iptables -I"
	export ENTRY_NUM="1" ENTRY_TOTAL="1"
	export HISTORY_ROW_HTML="" ESCALATION_ROW_HTML=""
	export REPUTATION_SECTION_HTML="" SOURCE_LOGS_SECTION_HTML=""
	run _alert_tpl_render "${PROJECT_ROOT}/files/alert/html.entry.tpl"
	assert_success
	# Should not contain History or Escalation labels
	refute_output --partial "History"
	refute_output --partial "Escalation"
}

# ===================================================================
# _alert_set_global_vars
# ===================================================================

@test "_alert_set_global_vars: sets globals, timestamp formats, timezone, and version fallback" {
	# Call with V set — verify all global variables
	V="2.0.1"
	_alert_set_global_vars 3
	[ -n "$HOSTNAME" ]
	[ -n "$TIMESTAMP" ]
	[[ "$TIMESTAMP" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}\ [0-9]{2}:[0-9]{2}:[0-9]{2}$ ]]
	[ "$ALERT_COUNT" = "3" ]
	[ "$BFD_VERSION" = "2.0.1" ]

	# TIMESTAMP_ISO has ISO 8601 format
	[[ "$TIMESTAMP_ISO" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2} ]]

	# TIME_ZONE is exported
	[ -n "$TIME_ZONE" ]

	# BFD_VERSION falls back to ALERT_LIB_VERSION when V unset
	unset V 2>/dev/null || true
	unset BFD_VERSION 2>/dev/null || true
	_alert_set_global_vars 0
	[ "$BFD_VERSION" = "$ALERT_LIB_VERSION" ]
}

# ===================================================================
# _alert_set_entry_vars
# ===================================================================

@test "_alert_set_entry_vars: parses basic pipe-delimited line" {
	# set up required globals
	BAN_COMMAND_TEMPLATE="echo ban \$ATTACK_HOST"
	_FW_BACKEND="custom"
	BAN_ESCALATE_AFTER="0"
	BAN_ESCALATION="none"
	EMAIL_REPUTATION_LINKS=""
	UTIME="1000"
	local line="192.0.2.1|sshd|22|15000|0|ban|0|/dev/null|root|10|300|3|5"
	_alert_set_entry_vars "$line" 1 1
	[ "$HOST" = "192.0.2.1" ]
	[ "$HOST_VERSION" = "IPv4" ]
	[ "$SERVICE" = "sshd" ]
	[ "$PORTS" = "port 22" ]
	[ "$BAN_TYPE" = "Permanent" ]
	[ "$ENTRY_NUM" = "1" ]
	[ "$ENTRY_TOTAL" = "1" ]
	[ "$WEIGHT" = "3" ]
}

@test "_alert_set_entry_vars: IPv6 sets HOST_VERSION correctly" {
	BAN_COMMAND_TEMPLATE="echo ban \$ATTACK_HOST"
	_FW_BACKEND="custom"
	BAN_ESCALATE_AFTER="0"
	BAN_ESCALATION="none"
	EMAIL_REPUTATION_LINKS=""
	local line="2001:db8::1|sshd|22|5000|0|ban|0||root|10|300|1|5"
	_alert_set_entry_vars "$line" 1 1
	[ "$HOST_VERSION" = "IPv6" ]
	[ "$HOST" = "2001:db8::1" ]
}

@test "_alert_set_entry_vars: ports=all becomes 'all ports'" {
	BAN_COMMAND_TEMPLATE="echo ban \$ATTACK_HOST"
	_FW_BACKEND="custom"
	BAN_ESCALATE_AFTER="0"
	BAN_ESCALATION="none"
	EMAIL_REPUTATION_LINKS=""
	local line="192.0.2.1|sshd|all|5000|0|ban|0||root|10|300|1|5"
	_alert_set_entry_vars "$line" 1 1
	[ "$PORTS" = "all ports" ]
}

@test "_alert_set_entry_vars: pressure percentage computed correctly" {
	BAN_COMMAND_TEMPLATE="echo ban \$ATTACK_HOST"
	_FW_BACKEND="custom"
	BAN_ESCALATE_AFTER="0"
	BAN_ESCALATION="none"
	EMAIL_REPUTATION_LINKS=""
	# 15000 scaled / (10 * 1000) = 150%
	local line="192.0.2.1|sshd|22|15000|0|ban|0||root|10|300|1|5"
	_alert_set_entry_vars "$line" 1 1
	[ "$PRESSURE_PCT" = "150" ]
	[ "$PRESSURE_PCT_CLAMPED" = "100" ]
}

@test "_alert_set_entry_vars: escalated ban type" {
	BAN_COMMAND_TEMPLATE="echo ban \$ATTACK_HOST"
	_FW_BACKEND="custom"
	BAN_ESCALATE_AFTER="5"
	BAN_ESCALATION="linear"
	EMAIL_REPUTATION_LINKS=""
	local line="192.0.2.1|sshd|22|15000|0|escalate|5||root|10|300|1|5"
	_alert_set_entry_vars "$line" 1 1
	[ "$BAN_TYPE" = "Permanent (escalated)" ]
	[ "$BAN_TYPE_COLOR" = "#d97706" ]
	[[ "$ESCALATION_LINE" == *"permanent after 5 offenses"* ]]
	[[ "$ESCALATION_ROW_HTML" == *"Permanent after 5 offenses"* ]]
}

@test "_alert_set_entry_vars: temporary ban with expiry" {
	BAN_COMMAND_TEMPLATE="echo ban \$ATTACK_HOST"
	_FW_BACKEND="custom"
	BAN_ESCALATE_AFTER="0"
	BAN_ESCALATION="none"
	EMAIL_REPUTATION_LINKS=""
	# expiry far in the future
	local future_expiry=$(($(date +%s) + 600))
	local line="192.0.2.1|sshd|22|15000|${future_expiry}|ban|0||root|10|300|1|5"
	_alert_set_entry_vars "$line" 1 1
	[ "$BAN_TYPE" = "Temporary" ]
	[[ "$BAN_DURATION_DETAIL" == *"expires"* ]]
	[ "$BAN_TYPE_COLOR" = "#0891b2" ]
}

@test "_alert_set_entry_vars: history line when escalation configured" {
	BAN_COMMAND_TEMPLATE="echo ban \$ATTACK_HOST"
	_FW_BACKEND="custom"
	BAN_ESCALATE_AFTER="5"
	BAN_ESCALATE_WINDOW="86400"
	BAN_ESCALATION="linear"
	EMAIL_REPUTATION_LINKS=""
	local line="192.0.2.1|sshd|22|15000|0|ban|3||root|10|300|1|5"
	_alert_set_entry_vars "$line" 1 2
	[[ "$HISTORY_LINE" == *"3 previous ban(s)"* ]]
	[[ "$HISTORY_LINE" == *"permanent at 5"* ]]
	[[ "$HISTORY_ROW_HTML" == *"3 previous ban(s)"* ]]
}

@test "_alert_set_entry_vars: no history when recent=0" {
	BAN_COMMAND_TEMPLATE="echo ban \$ATTACK_HOST"
	_FW_BACKEND="custom"
	BAN_ESCALATE_AFTER="5"
	BAN_ESCALATION="linear"
	EMAIL_REPUTATION_LINKS=""
	local line="192.0.2.1|sshd|22|15000|0|ban|0||root|10|300|1|5"
	_alert_set_entry_vars "$line" 1 1
	[ -z "$HISTORY_LINE" ]
	[ -z "$HISTORY_ROW_HTML" ]
}

@test "_alert_set_entry_vars: ban command with fw_backend" {
	BAN_COMMAND_TEMPLATE=""
	_FW_BACKEND="iptables"
	BAN_ESCALATE_AFTER="0"
	BAN_ESCALATION="none"
	EMAIL_REPUTATION_LINKS=""
	local line="192.0.2.1|sshd|22|5000|0|ban|0||root|10|300|1|5"
	_alert_set_entry_vars "$line" 1 1
	[[ "$BAN_COMMAND" == *"fw_ban 192.0.2.1"* ]]
	[[ "$BAN_COMMAND" == *"iptables"* ]]
}

@test "_alert_set_entry_vars: reputation links when configured" {
	BAN_COMMAND_TEMPLATE="echo ban \$ATTACK_HOST"
	_FW_BACKEND="custom"
	BAN_ESCALATE_AFTER="0"
	BAN_ESCALATION="none"
	EMAIL_REPUTATION_LINKS="abuseipdb,ipinfo"
	local line="192.0.2.1|sshd|22|5000|0|ban|0||root|10|300|1|5"
	_alert_set_entry_vars "$line" 1 1
	[[ "$REPUTATION_SECTION_TEXT" == *"lookup:"* ]]
	[[ "$REPUTATION_SECTION_TEXT" == *"AbuseIPDB"* ]]
	[[ "$REPUTATION_SECTION_HTML" == *"Reputation"* ]]
}

@test "_alert_set_entry_vars: no reputation when not configured" {
	BAN_COMMAND_TEMPLATE="echo ban \$ATTACK_HOST"
	_FW_BACKEND="custom"
	BAN_ESCALATE_AFTER="0"
	BAN_ESCALATION="none"
	EMAIL_REPUTATION_LINKS=""
	local line="192.0.2.1|sshd|22|5000|0|ban|0||root|10|300|1|5"
	_alert_set_entry_vars "$line" 1 1
	[ -z "$REPUTATION_SECTION_TEXT" ]
	[ -z "$REPUTATION_SECTION_HTML" ]
}

@test "_alert_set_entry_vars: source logs with journal fallback" {
	BAN_COMMAND_TEMPLATE="echo ban \$ATTACK_HOST"
	_FW_BACKEND="custom"
	BAN_ESCALATE_AFTER="0"
	BAN_ESCALATION="none"
	EMAIL_REPUTATION_LINKS=""
	# empty log path = journal
	local line="192.0.2.1|sshd|22|5000|0|ban|0||root|10|300|1|5"
	_alert_set_entry_vars "$line" 1 1
	[[ "$SOURCE_LOGS_SECTION_TEXT" == *"systemd journal"* ]]
	[[ "$SOURCE_LOGS_SECTION_HTML" == *"systemd journal"* ]]
}

@test "_alert_set_entry_vars: source logs from file" {
	BAN_COMMAND_TEMPLATE="echo ban \$ATTACK_HOST"
	_FW_BACKEND="custom"
	BAN_ESCALATE_AFTER="0"
	BAN_ESCALATION="none"
	EMAIL_REPUTATION_LINKS=""
	local logfile="$TEST_TMPDIR/auth.log"
	echo "Jan  1 00:00:01 host sshd: Failed password from 192.0.2.1" > "$logfile"
	local line="192.0.2.1|sshd|22|5000|0|ban|0|${logfile}|root|10|300|1|5"
	_alert_set_entry_vars "$line" 1 1
	[[ "$SOURCE_LOGS_SECTION_TEXT" == *"logs from"* ]]
	[[ "$SOURCE_LOGS_SECTION_TEXT" == *"Failed password"* ]]
	[[ "$SOURCE_LOGS_SECTION_HTML" == *"Failed password"* ]]
}

@test "_alert_set_entry_vars: country code defaults to -- and COUNTRY_DISPLAY to --" {
	BAN_COMMAND_TEMPLATE="echo ban \$ATTACK_HOST"
	_FW_BACKEND="custom"
	BAN_ESCALATE_AFTER="0"
	BAN_ESCALATION="none"
	EMAIL_REPUTATION_LINKS=""
	# no ipcountry.dat available
	local _old_ip="${INSTALL_PATH:-}"
	local _old_dp="${DATA_PATH:-}"
	INSTALL_PATH="$TEST_TMPDIR/nonexistent"
	DATA_PATH="$TEST_TMPDIR/nonexistent/data"
	local line="192.0.2.1|sshd|22|5000|0|ban|0||root|10|300|1|5"
	_alert_set_entry_vars "$line" 1 1
	[ "$COUNTRY_CODE" = "--" ]
	[ "$COUNTRY_DISPLAY" = "--" ]
	INSTALL_PATH="$_old_ip"
	DATA_PATH="$_old_dp"
}

@test "_alert_set_entry_vars: COUNTRY_DISPLAY includes full name when geoip_lib loaded" {
	declare -f geoip_cc_name >/dev/null 2>&1 || skip "geoip_lib not loaded"
	BAN_COMMAND_TEMPLATE="echo ban \$ATTACK_HOST"
	_FW_BACKEND="custom"
	BAN_ESCALATE_AFTER="0"
	BAN_ESCALATION="none"
	EMAIL_REPUTATION_LINKS=""
	# create ipcountry.dat with CN mapping for 192.0.2.128
	mkdir -p "$DATA_PATH"
	cat > "$DATA_PATH/ipcountry.dat" <<'EOF'
3221226112 3221226239 CN
EOF
	local line="192.0.2.128|sshd|22|5000|0|ban|0||root|10|300|1|5"
	_alert_set_entry_vars "$line" 1 1
	[ "$COUNTRY_CODE" = "CN" ]
	[ "$COUNTRY_DISPLAY" = "China (CN)" ]
}

@test "_alert_set_entry_vars: FAIL_COUNT from 13th field" {
	BAN_COMMAND_TEMPLATE="echo ban \$ATTACK_HOST"
	_FW_BACKEND="custom"
	BAN_ESCALATE_AFTER="0"
	BAN_ESCALATION="none"
	EMAIL_REPUTATION_LINKS=""
	local line="192.0.2.1|sshd|22|15000|0|ban|0|/dev/null|root|10|300|3|7"
	_alert_set_entry_vars "$line" 1 1
	[ "$FAIL_COUNT" = "7" ]
}

@test "_alert_set_entry_vars: FAIL_COUNT fallback for 12-field line" {
	BAN_COMMAND_TEMPLATE="echo ban \$ATTACK_HOST"
	_FW_BACKEND="custom"
	BAN_ESCALATE_AFTER="0"
	BAN_ESCALATION="none"
	EMAIL_REPUTATION_LINKS=""
	# 12-field line (no 13th field) — should compute ceil(15000 / (3*1000)) = 5
	local line="192.0.2.1|sshd|22|15000|0|ban|0|/dev/null|root|10|300|3"
	_alert_set_entry_vars "$line" 1 1
	[ "$FAIL_COUNT" = "5" ]
}

@test "_alert_set_entry_vars: FAIL_COUNT fallback rounds up" {
	BAN_COMMAND_TEMPLATE="echo ban \$ATTACK_HOST"
	_FW_BACKEND="custom"
	BAN_ESCALATE_AFTER="0"
	BAN_ESCALATION="none"
	EMAIL_REPUTATION_LINKS=""
	# 12-field line — ceil(21400 / (3*1000)) = ceil(7.13) = 8
	local line="192.0.2.1|sshd|22|21400|0|ban|0|/dev/null|root|10|300|3"
	_alert_set_entry_vars "$line" 1 1
	[ "$FAIL_COUNT" = "8" ]
}

# ===================================================================
# _alert_compute_summary
# ===================================================================

@test "_alert_compute_summary: basic single entry" {
	local af="$TEST_TMPDIR/alerts"
	echo "192.0.2.1|sshd|22|5000|0|ban|0||root|10|300|1|5" > "$af"
	_alert_compute_summary "$af"
	[ "$SUMMARY_TOTAL_BANS" = "1" ]
	[ "$SUMMARY_UNIQUE_IPS" = "1" ]
	[ "$SUMMARY_PERMANENT" = "1" ]
	[ "$SUMMARY_TEMPORARY" = "0" ]
	[ "$SUMMARY_ESCALATED" = "0" ]
	[ "$SUMMARY_REPEAT_OFFENDERS" = "0" ]
	[ "$SUMMARY_REPEAT_PCT" = "0" ]
}

@test "_alert_compute_summary: multiple entries with mixed types" {
	local af="$TEST_TMPDIR/alerts"
	cat > "$af" <<'EOF'
192.0.2.1|sshd|22|5000|0|ban|0||root|10|300|1|5
198.51.100.5|dovecot|143|8000|1709553600|ban|2||root|10|300|1|5
203.0.113.10|sshd|22|12000|0|escalate|5||root|10|300|1|5
192.0.2.1|postfix|25|6000|1709553600|ban|0||root|10|300|1|5
EOF
	_alert_compute_summary "$af"
	[ "$SUMMARY_TOTAL_BANS" = "4" ]
	[ "$SUMMARY_UNIQUE_IPS" = "3" ]
	[ "$SUMMARY_PERMANENT" = "1" ]
	[ "$SUMMARY_TEMPORARY" = "2" ]
	[ "$SUMMARY_ESCALATED" = "1" ]
	[ "$SUMMARY_REPEAT_OFFENDERS" = "2" ]
	[ "$SUMMARY_REPEAT_PCT" = "50" ]
	[[ "$SUMMARY_SERVICES" == *"sshd"* ]]
	[[ "$SUMMARY_SERVICES" == *"dovecot"* ]]
}

@test "_alert_compute_summary: returns 1 for empty file" {
	local af="$TEST_TMPDIR/alerts_empty"
	: > "$af"
	run _alert_compute_summary "$af"
	assert_failure
}

@test "_alert_compute_summary: returns 1 for missing file" {
	run _alert_compute_summary "$TEST_TMPDIR/nonexistent_alerts"
	assert_failure
}

# ===================================================================
# _alert_render_text
# ===================================================================

@test "_alert_render_text: renders single entry email (format C)" {
	V="2.0.1"
	BAN_COMMAND_TEMPLATE="echo ban \$ATTACK_HOST"
	_FW_BACKEND="custom"
	BAN_ESCALATE_AFTER="0"
	BAN_ESCALATION="none"
	EMAIL_REPUTATION_LINKS=""
	local af="$TEST_TMPDIR/alerts"
	echo "192.0.2.1|sshd|22|15000|0|ban|0||root|10|300|3|5" > "$af"
	run _alert_render_text "$af" "${PROJECT_ROOT}/files/alert"
	assert_success
	# header
	assert_output --partial "[BFD]"
	assert_output --partial "1 host(s) banned"
	# entry: no "ban N of N" when entry_total == 1
	refute_output --partial "ban 1 of 1"
	assert_output --partial "192.0.2.1"
	assert_output --partial "sshd"
	# lowercase format-C labels
	assert_output --partial "  host:"
	assert_output --partial "  rule:"
	assert_output --partial "  action:"
	assert_output --partial "  why:"
	# footer
	assert_output --partial "bfd 2.0.1"
	assert_output --partial "rfxn.com/projects/brute-force-detection"
	# pressure math still exposed
	assert_output --partial "5 failed logins this scan"
	assert_output --partial "trip"
	assert_output --partial "weight 3"
	# no summary for single entry
	refute_output --partial "summary"
}

@test "_alert_render_text: renders multi-entry with summary (format C)" {
	V="2.0.1"
	BAN_COMMAND_TEMPLATE="echo ban \$ATTACK_HOST"
	_FW_BACKEND="custom"
	BAN_ESCALATE_AFTER="0"
	BAN_ESCALATION="none"
	EMAIL_REPUTATION_LINKS=""
	local af="$TEST_TMPDIR/alerts"
	cat > "$af" <<'EOF'
192.0.2.1|sshd|22|15000|0|ban|0||root|10|300|1|5
198.51.100.5|dovecot|143|8000|0|ban|0||root|10|300|1|5
EOF
	run _alert_render_text "$af" "${PROJECT_ROOT}/files/alert"
	assert_success
	assert_output --partial "2 host(s) banned"
	assert_output --partial "ban 1 of 2"
	assert_output --partial "ban 2 of 2"
	assert_output --partial "summary"
	assert_output --partial "total:"
}

@test "_alert_render_text: returns 1 for empty alerts" {
	local af="$TEST_TMPDIR/alerts_empty"
	: > "$af"
	run _alert_render_text "$af" "${PROJECT_ROOT}/files/alert"
	assert_failure
}

# ===================================================================
# _alert_render_html
# ===================================================================

@test "_alert_render_html: renders single entry HTML" {
	V="2.0.1"
	BAN_COMMAND_TEMPLATE="echo ban \$ATTACK_HOST"
	_FW_BACKEND="custom"
	BAN_ESCALATE_AFTER="0"
	BAN_ESCALATION="none"
	EMAIL_REPUTATION_LINKS=""
	local af="$TEST_TMPDIR/alerts"
	echo "192.0.2.1|sshd|22|15000|0|ban|0||root|10|300|3|5" > "$af"
	run _alert_render_html "$af" "${PROJECT_ROOT}/files/alert"
	assert_success
	assert_output --partial "<!DOCTYPE html>"
	assert_output --partial "BFD Alert"
	assert_output --partial "192.0.2.1"
	assert_output --partial "</html>"
	# no summary for single
	refute_output --partial "Summary"
}

@test "_alert_render_html: multi-entry includes summary card" {
	V="2.0.1"
	BAN_COMMAND_TEMPLATE="echo ban \$ATTACK_HOST"
	_FW_BACKEND="custom"
	BAN_ESCALATE_AFTER="0"
	BAN_ESCALATION="none"
	EMAIL_REPUTATION_LINKS=""
	local af="$TEST_TMPDIR/alerts"
	cat > "$af" <<'EOF'
192.0.2.1|sshd|22|15000|0|ban|0||root|10|300|1|5
198.51.100.5|dovecot|143|8000|0|ban|0||root|10|300|1|5
EOF
	run _alert_render_html "$af" "${PROJECT_ROOT}/files/alert"
	assert_success
	assert_output --partial "Summary"
	assert_output --partial "<!DOCTYPE html>"
	assert_output --partial "</html>"
}

@test "_alert_render_html: pressure formula chain and severity color" {
	V="2.0.1"
	BAN_COMMAND_TEMPLATE="echo ban \$ATTACK_HOST"
	_FW_BACKEND="custom"
	BAN_ESCALATE_AFTER="0"
	BAN_ESCALATION="none"
	EMAIL_REPUTATION_LINKS=""
	local af="$TEST_TMPDIR/alerts"
	echo "192.0.2.1|sshd|22|15000|0|ban|0||root|10|300|1|5" > "$af"
	run _alert_render_html "$af" "${PROJECT_ROOT}/files/alert"
	assert_success
	# severity color from ban type (permanent: expiry=0)
	assert_output --partial "background-color:#dc2626"
	# A-1 formula chain: 5 failed logins = +5
	assert_output --partial "failed logins"
	assert_output --partial "accumulated pressure"
}

# ===================================================================
# _alert_build_mime
# ===================================================================

@test "_alert_build_mime: produces valid MIME structure" {
	local text_body="Plain text content here"
	local html_body="<html><body>HTML content</body></html>"
	run _alert_build_mime "$text_body" "$html_body"
	assert_success
	assert_output --partial "MIME-Version: 1.0"
	assert_output --partial "Content-Type: multipart/alternative"
	assert_output --partial "Content-Type: text/plain; charset=UTF-8"
	assert_output --partial "Content-Type: text/html; charset=UTF-8"
	assert_output --partial "Plain text content here"
	# HTML part is base64-encoded (RFC 5321 line length compliance)
	assert_output --partial "Content-Transfer-Encoding: base64"
}

@test "_alert_build_mime: boundary is present and closes" {
	local text_body="text"
	local html_body="<html>html</html>"
	local result
	result=$(_alert_build_mime "$text_body" "$html_body")
	# extract boundary from Content-Type header
	local boundary
	boundary=$(echo "$result" | grep 'boundary=' | sed 's/.*boundary="\(.*\)"/\1/')
	[ -n "$boundary" ]
	# opening boundaries
	local opens
	opens=$(echo "$result" | grep -c "^--${boundary}$" || true)
	[ "$opens" -eq 2 ]
	# closing boundary
	echo "$result" | grep -q "^--${boundary}--$"
}

