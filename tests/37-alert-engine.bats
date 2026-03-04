#!/usr/bin/env bats
#
# Test suite for alert_lib.sh — template engine, content helpers, formatting
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

setup() {
	bfd_common_setup
	INSTALL_PATH="$TEST_TMPDIR/bfd"
	mkdir -p "$INSTALL_PATH"
}

teardown() {
	bfd_teardown
}

# ===================================================================
# Source guard & version
# ===================================================================

@test "alert_lib: ALERT_LIB_VERSION is set" {
	[ -n "$ALERT_LIB_VERSION" ]
	[[ "$ALERT_LIB_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
}

@test "alert_lib: reputation link arrays are populated" {
	[ "${#_REPLINK_KEYS[@]}" -eq 5 ]
	[ "${#_REPLINK_LABELS[@]}" -eq 5 ]
	[ "${#_REPLINK_URLS[@]}" -eq 5 ]
}

@test "alert_lib: regional indicator byte array has 26 entries" {
	[ "${#_RI_BYTES[@]}" -eq 26 ]
}

# ===================================================================
# _tpl_render — template engine
# ===================================================================

@test "_tpl_render: replaces single variable" {
	local tpl="$TEST_TMPDIR/test.tpl"
	echo "Hello {{NAME}}" > "$tpl"
	export NAME="World"
	run _tpl_render "$tpl"
	assert_success
	assert_output "Hello World"
}

@test "_tpl_render: replaces multiple variables on same line" {
	local tpl="$TEST_TMPDIR/test.tpl"
	echo "{{HOST}} via {{SERVICE}} on {{PORTS}}" > "$tpl"
	export HOST="192.0.2.1"
	export SERVICE="sshd"
	export PORTS="22"
	run _tpl_render "$tpl"
	assert_success
	assert_output "192.0.2.1 via sshd on 22"
}

@test "_tpl_render: replaces variables across multiple lines" {
	local tpl="$TEST_TMPDIR/test.tpl"
	cat > "$tpl" <<'EOF'
Host: {{HOST}}
Service: {{SERVICE}}
EOF
	export HOST="203.0.113.5"
	export SERVICE="dovecot"
	run _tpl_render "$tpl"
	assert_success
	assert_line --index 0 "Host: 203.0.113.5"
	assert_line --index 1 "Service: dovecot"
}

@test "_tpl_render: unknown variables become empty" {
	local tpl="$TEST_TMPDIR/test.tpl"
	echo "Value: [{{NONEXISTENT_VAR_XYZ}}]" > "$tpl"
	unset NONEXISTENT_VAR_XYZ 2>/dev/null || true
	run _tpl_render "$tpl"
	assert_success
	assert_output "Value: []"
}

@test "_tpl_render: preserves lines without variables" {
	local tpl="$TEST_TMPDIR/test.tpl"
	echo "No variables here, just plain text." > "$tpl"
	run _tpl_render "$tpl"
	assert_success
	assert_output "No variables here, just plain text."
}

@test "_tpl_render: preserves HTML tags" {
	local tpl="$TEST_TMPDIR/test.tpl"
	echo '<td style="color:red;">{{VALUE}}</td>' > "$tpl"
	export VALUE="test"
	run _tpl_render "$tpl"
	assert_success
	assert_output '<td style="color:red;">test</td>'
}

@test "_tpl_render: returns 1 for missing file" {
	run _tpl_render "$TEST_TMPDIR/does_not_exist.tpl"
	assert_failure
}

@test "_tpl_render: handles empty template" {
	local tpl="$TEST_TMPDIR/empty.tpl"
	: > "$tpl"
	run _tpl_render "$tpl"
	assert_success
	assert_output ""
}

@test "_tpl_render: variable with underscores and digits" {
	local tpl="$TEST_TMPDIR/test.tpl"
	echo "{{SUMMARY_TOTAL_BANS}} bans, {{ENTRY_NUM}} of {{ENTRY_TOTAL}}" > "$tpl"
	export SUMMARY_TOTAL_BANS="7"
	export ENTRY_NUM="3"
	export ENTRY_TOTAL="5"
	run _tpl_render "$tpl"
	assert_success
	assert_output "7 bans, 3 of 5"
}

@test "_tpl_render: does not expand shell variables" {
	local tpl="$TEST_TMPDIR/test.tpl"
	echo 'No expansion: $HOME $(whoami) `id`' > "$tpl"
	run _tpl_render "$tpl"
	assert_success
	# must be preserved literally, no expansion
	assert_output 'No expansion: $HOME $(whoami) `id`'
}

@test "_tpl_render: braces that are not template tokens pass through" {
	local tpl="$TEST_TMPDIR/test.tpl"
	echo '{{lowercase}} {SINGLE} {{ SPACES }} {{123NUM}}' > "$tpl"
	run _tpl_render "$tpl"
	assert_success
	# none of these match {{[A-Z_][A-Z0-9_]*}} so they pass through literally
	assert_output '{{lowercase}} {SINGLE} {{ SPACES }} {{123NUM}}'
}

# ===================================================================
# _html_escape
# ===================================================================

@test "_html_escape: escapes ampersand" {
	run _html_escape "foo & bar"
	assert_success
	assert_output "foo &amp; bar"
}

@test "_html_escape: escapes less-than and greater-than" {
	run _html_escape "<script>alert('xss')</script>"
	assert_success
	assert_output "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;"
}

@test "_html_escape: escapes double quotes" {
	run _html_escape 'value="test"'
	assert_success
	assert_output 'value=&quot;test&quot;'
}

@test "_html_escape: escapes single quotes" {
	run _html_escape "it's a test"
	assert_success
	assert_output "it&#39;s a test"
}

@test "_html_escape: handles multiple special chars together" {
	run _html_escape '<b>"A & B"</b>'
	assert_success
	assert_output '&lt;b&gt;&quot;A &amp; B&quot;&lt;/b&gt;'
}

@test "_html_escape: empty string" {
	run _html_escape ""
	assert_success
	assert_output ""
}

@test "_html_escape: plain text passes through" {
	run _html_escape "hello world 123"
	assert_success
	assert_output "hello world 123"
}

@test "_html_escape: IP address passes through" {
	run _html_escape "192.0.2.1"
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

# ===================================================================
# _alert_country_flag
# ===================================================================

@test "_alert_country_flag: US produces non-empty output" {
	run _alert_country_flag "US"
	assert_success
	# should produce 8 bytes (two 4-byte UTF-8 codepoints)
	local len=${#output}
	# byte length check: depends on locale but the string should be non-empty
	[ -n "$output" ]
}

@test "_alert_country_flag: lowercase input works" {
	run _alert_country_flag "cn"
	assert_success
	[ -n "$output" ]
}

@test "_alert_country_flag: empty input returns empty" {
	run _alert_country_flag ""
	assert_success
	assert_output ""
}

@test "_alert_country_flag: single char returns empty" {
	run _alert_country_flag "X"
	assert_success
	assert_output ""
}

@test "_alert_country_flag: three chars returns empty" {
	run _alert_country_flag "USA"
	assert_success
	assert_output ""
}

@test "_alert_country_flag: numeric input returns empty" {
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

@test "_alert_pressure_bar: 0% produces empty bar" {
	run _alert_pressure_bar 0
	assert_success
	assert_output "[                    ] 0%"
}

@test "_alert_pressure_bar: 50% fills half" {
	run _alert_pressure_bar 50
	assert_success
	assert_output "[==========          ] 50%"
}

@test "_alert_pressure_bar: 100% fills fully" {
	run _alert_pressure_bar 100
	assert_success
	assert_output "[====================] 100%"
}

@test "_alert_pressure_bar: 150% caps at full but shows actual pct" {
	run _alert_pressure_bar 150
	assert_success
	assert_output "[====================] 150%"
}

@test "_alert_pressure_bar: 25% fills 5 chars" {
	run _alert_pressure_bar 25
	assert_success
	assert_output "[=====               ] 25%"
}

@test "_alert_pressure_bar: 1% fills 0 chars" {
	run _alert_pressure_bar 1
	assert_success
	# 1 * 20 / 100 = 0
	assert_output "[                    ] 1%"
}

@test "_alert_pressure_bar: 5% fills 1 char" {
	run _alert_pressure_bar 5
	assert_success
	assert_output "[=                   ] 5%"
}

# ===================================================================
# _alert_pressure_color
# ===================================================================

@test "_alert_pressure_color: low pressure is green" {
	run _alert_pressure_color 30
	assert_success
	assert_output "#4caf50"
}

@test "_alert_pressure_color: 0% is green" {
	run _alert_pressure_color 0
	assert_success
	assert_output "#4caf50"
}

@test "_alert_pressure_color: 69% is green" {
	run _alert_pressure_color 69
	assert_success
	assert_output "#4caf50"
}

@test "_alert_pressure_color: 70% is orange" {
	run _alert_pressure_color 70
	assert_success
	assert_output "#ff9800"
}

@test "_alert_pressure_color: 99% is orange" {
	run _alert_pressure_color 99
	assert_success
	assert_output "#ff9800"
}

@test "_alert_pressure_color: 100% is red" {
	run _alert_pressure_color 100
	assert_success
	assert_output "#d32f2f"
}

@test "_alert_pressure_color: 200% is red" {
	run _alert_pressure_color 200
	assert_success
	assert_output "#d32f2f"
}

# ===================================================================
# _alert_ban_type_color
# ===================================================================

@test "_alert_ban_type_color: escalate is orange" {
	run _alert_ban_type_color "escalate" "0"
	assert_success
	assert_output "#f57c00"
}

@test "_alert_ban_type_color: permanent (expiry=0) is red" {
	run _alert_ban_type_color "ban" "0"
	assert_success
	assert_output "#d32f2f"
}

@test "_alert_ban_type_color: temporary is amber" {
	run _alert_ban_type_color "ban" "1709553600"
	assert_success
	assert_output "#f9a825"
}

@test "_alert_ban_type_color: escalate overrides expiry check" {
	# even with non-zero expiry, escalate action should be orange
	run _alert_ban_type_color "escalate" "1709553600"
	assert_success
	assert_output "#f57c00"
}
