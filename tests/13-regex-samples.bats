#!/usr/bin/env bats
#
# Regex pattern validation for BFD rules.
#
# Coverage strategy:
#   - Data-driven tests read tests/regex_samples.txt (132 samples covering all
#     rules, positive + negative cases, IPv4 + IPv6, IGNOREREGEX).
#   - Inline tests below cover patterns/IPs NOT in regex_samples.txt —
#     removing them would lose coverage.
#

load 'helpers/bfd-common'

setup() {
	bfd_common_setup
	IGNOREREGEX=""
}

teardown() {
	bfd_teardown
}

# ============================================================
# INLINE TESTS — patterns or IPs not covered by regex_samples.txt
# ============================================================

# DenyUsers old-style pattern (negative test — expects no match)
# regex_samples.txt uses the "sshd.*User .* from <HOST> not allowed" pattern;
# this tests the legacy "DenyUsers.*" anchor which intentionally does NOT match.
@test "regex: sshd - DenyUsers (legacy pattern, negative)" {
	local result
	result=$(echo "Feb 22 10:15:07 myhost sshd[12345]: User root from 198.51.100.1 not allowed because listed in DenyUsers" | \
		extract_hosts "DenyUsers.*User .* from <HOST>")
	[ -z "$result" ]
}

# AH01617 with real-world IP (76.181.65.196, non-RFC-5737 — tests that
# extract_hosts handles non-documentation IPs)
@test "regex: apache-auth - AH01617 password mismatch (real IP)" {
	local result
	result=$(echo '[Tue Sep 08 13:34:46.224312 2015] [auth_basic:error] [pid 2043:tid 140302748706560] [client 76.181.65.196:53340] AH01617: user mfoley: authentication failure for "/admin/": Password Mismatch' | \
		extract_hosts "\[client <HOST>.*AH0161[78]")
	[ "$result" = "76.181.65.196" ]
}

# webmin Non-existent login with real-world IP (86.0.6.217)
@test "regex: webmin - Non-existent login (real IP)" {
	local result
	result=$(echo "Mar 15 09:22:11 myhost webmin[15673]: Non-existent login as toto from 86.0.6.217" | \
		extract_hosts "webmin.*Non-existent login as .* from <HOST>")
	[ "$result" = "86.0.6.217" ]
}

# http_401 pattern with trailing space after 401 — the regex_samples.txt
# pattern is '<HOST> -.*" 401' (no trailing space); these test the more
# specific variant '<HOST> -.*" 401 ' (with trailing space)
@test "regex: http_401 - Apache combined 401 (trailing-space pattern)" {
	local result
	result=$(echo '203.0.113.100 - - [22/Feb/2024:10:15:03 +0000] "GET /admin HTTP/1.1" 401 381 "-" "curl/7.68.0"' | \
		extract_hosts '<HOST> -.*" 401 ')
	[ "$result" = "203.0.113.100" ]
}

@test "regex: http_401 - POST 401 with referer (trailing-space pattern)" {
	local result
	result=$(echo '192.0.2.5 - admin [22/Feb/2024:10:15:05 +0000] "POST /wp-login.php HTTP/1.1" 401 4521 "https://example.com/" "Mozilla/5.0"' | \
		extract_hosts '<HOST> -.*" 401 ')
	[ "$result" = "192.0.2.5" ]
}

# pam_generic second test case (login, not su) — regex_samples.txt covers
# the su variant with 203.0.113.50; this tests the login variant with 192.0.2.5
@test "regex: pam_generic - login auth failure (alt IP)" {
	local result
	result=$(echo "Feb 22 10:15:05 myhost login: pam_unix(login:auth): authentication failure; logname= uid=0 euid=0 tty=tty1 ruser= rhost=192.0.2.5 user=root" | \
		extract_hosts "pam_unix.*authentication failure.*rhost=<HOST>")
	[ "$result" = "192.0.2.5" ]
}

# postgresql no pg_hba.conf entry with "no encryption" suffix — tests
# the same pattern but with a different log line variant
@test "regex: postgresql - no pg_hba.conf entry (no encryption suffix)" {
	local result
	result=$(echo '2026-02-22 10:15:07.789 UTC [12347] FATAL:  no pg_hba.conf entry for host "198.51.100.1", user "postgres", database "production", no encryption' | \
		extract_hosts 'no pg_hba.conf entry for host "<HOST>"')
	[ "$result" = "198.51.100.1" ]
}

# IPv6 with non-RFC-5737 address (2607:f8b0:4004:800::200e, a Google address)
# — regex_samples.txt covers sshd Invalid user with 2001:db8:: prefixes only
@test "regex: sshd - Invalid user (IPv6 real address)" {
	local result
	result=$(echo "Feb 22 10:15:05 myhost sshd[12345]: Invalid user admin from 2607:f8b0:4004:800::200e port 54321 ssh2" | \
		extract_hosts "sshd.*Invalid user .* from <HOST>")
	[ "$result" = "2607:f8b0:4004:800::200e" ]
}

# ============================================================
# DATA-DRIVEN TESTS — reads tests/regex_samples.txt
# ============================================================

@test "regex_samples.txt: all positive matches" {
	local samples_file="$BATS_TEST_DIRNAME/regex_samples.txt"
	[ -f "$samples_file" ] || skip "regex_samples.txt not found"

	local failures=0 total=0
	local rule="" pattern="" expect="" note="" igr="" logline=""
	local fail_details=""
	while IFS= read -r line; do
		case "$line" in
			"# RULE: "*)        rule="${line#\# RULE: }" ;;
			"# PATTERN: "*)     pattern="${line#\# PATTERN: }" ;;
			"# EXPECT: "*)      expect="${line#\# EXPECT: }" ;;
			"# IGNOREREGEX: "*) igr="${line#\# IGNOREREGEX: }" ;;
			"# NOTE: "*)        note="${line#\# NOTE: }" ;;
			"#"*|"")            continue ;;
			*)
				logline="$line"
				[ -z "$expect" ] && continue
				# skip negative tests — handled in separate test
				if [ "$expect" = "NONE" ]; then
					rule="" pattern="" expect="" note="" igr=""
					continue
				fi
				total=$((total + 1))
				IGNOREREGEX="$igr"
				local result
				result=$(echo "$logline" | extract_hosts "$pattern")
				if [ "$result" != "$expect" ]; then
					failures=$((failures + 1))
					fail_details="${fail_details}  FAIL: rule=$rule pattern='$pattern' expect='$expect' got='$result'"$'\n'
				fi
				IGNOREREGEX=""
				rule="" pattern="" expect="" note="" igr=""
				;;
		esac
	done < "$samples_file"
	if [ "$failures" -gt 0 ]; then
		echo "Tested $total samples, $failures failures:"
		echo "$fail_details"
	fi
	[ "$failures" -eq 0 ]
}

@test "regex_samples.txt: all negative matches" {
	local samples_file="$BATS_TEST_DIRNAME/regex_samples.txt"
	[ -f "$samples_file" ] || skip "regex_samples.txt not found"

	local failures=0 total=0
	local rule="" pattern="" expect="" note="" igr="" logline=""
	local fail_details=""
	while IFS= read -r line; do
		case "$line" in
			"# RULE: "*)        rule="${line#\# RULE: }" ;;
			"# PATTERN: "*)     pattern="${line#\# PATTERN: }" ;;
			"# EXPECT: "*)      expect="${line#\# EXPECT: }" ;;
			"# IGNOREREGEX: "*) igr="${line#\# IGNOREREGEX: }" ;;
			"# NOTE: "*)        note="${line#\# NOTE: }" ;;
			"#"*|"")            continue ;;
			*)
				logline="$line"
				[ -z "$expect" ] && continue
				# skip positive tests — handled in separate test
				if [ "$expect" != "NONE" ]; then
					rule="" pattern="" expect="" note="" igr=""
					continue
				fi
				total=$((total + 1))
				IGNOREREGEX="$igr"
				local result
				result=$(echo "$logline" | extract_hosts "$pattern")
				if [ -n "$result" ]; then
					failures=$((failures + 1))
					fail_details="${fail_details}  FAIL: rule=$rule pattern='$pattern' expected NONE got='$result'"$'\n'
				fi
				IGNOREREGEX=""
				rule="" pattern="" expect="" note="" igr=""
				;;
		esac
	done < "$samples_file"
	if [ "$failures" -gt 0 ]; then
		echo "Tested $total negative samples, $failures failures:"
		echo "$fail_details"
	fi
	[ "$failures" -eq 0 ]
}

@test "regex_samples.txt: all IPs are RFC 5737 compliant" {
	local samples_file="$BATS_TEST_DIRNAME/regex_samples.txt"
	[ -f "$samples_file" ] || skip "regex_samples.txt not found"

	# Extract all IPv4 addresses from log lines (non-comment lines)
	local bad_ips
	bad_ips=$(grep -v '^#' "$samples_file" | grep -v '^$' | \
		grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort -u | \
		grep -Ev '^(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)' || true)
	if [ -n "$bad_ips" ]; then
		echo "Non-RFC-5737 IPv4 addresses found in log lines:"
		echo "$bad_ips"
	fi
	[ -z "$bad_ips" ]
}
