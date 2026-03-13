#!/bin/bash
#
# BFD performance benchmark helpers
# Sourced by 45-perf-benchmark.bats via load directive
#
# Provides:
#   generate_sshd_log       — pseudo sshd auth failure log lines
#   generate_mod_sec_log    — pseudo ModSecurity denial log lines
#   generate_postfix_log    — pseudo postfix SASL failure log lines
#   generate_dovecot_log    — pseudo dovecot imap-login failure log lines
#   timer_start             — capture start time in nanoseconds (if available)
#   timer_elapsed_ms        — compute elapsed milliseconds since timer_start
#   kpi_report              — emit TAP diagnostic KPI line
#   perf_timeout_check      — check elapsed time against 30s ceiling, fail if exceeded
#   generate_pressure_dat   — create synthetic pressure.dat entries
#   generate_ipcountry_dat  — create synthetic ipcountry.dat entries
#
# Log generators accept an optional target_len (4th arg). When >0, each line
# is padded with domain-appropriate content to reach the target character count.
# This simulates real-world log line lengths (e.g., mod_sec 800 chars with
# OWASP CRS metadata vs 120-char synthetic).  Omit or pass 0 for original
# compact output.
#

# --- Timing helpers ---

# _perf_has_ns: detect whether date supports %N (nanoseconds)
# GNU date does; BusyBox and some BSD date do not.
_perf_has_ns=""
_perf_ns_check() {
	local test_ns
	test_ns=$(date +%s%N 2>/dev/null)
	if [ ${#test_ns} -gt 12 ]; then
		_perf_has_ns=1
	else
		_perf_has_ns=0
	fi
}
_perf_ns_check

# timer_start: set _PERF_T0 to current time
# Stores nanoseconds if available, seconds otherwise
timer_start() {
	if [ "$_perf_has_ns" = "1" ]; then
		_PERF_T0=$(date +%s%N)
	else
		_PERF_T0=$(date +%s)
	fi
}

# timer_elapsed_ms: output elapsed milliseconds since timer_start
# If nanosecond support is absent, resolution is 1000ms
timer_elapsed_ms() {
	local now elapsed_ms
	if [ "$_perf_has_ns" = "1" ]; then
		now=$(date +%s%N)
		elapsed_ms=$(( (now - _PERF_T0) / 1000000 ))
	else
		now=$(date +%s)
		elapsed_ms=$(( (now - _PERF_T0) * 1000 ))
	fi
	echo "$elapsed_ms"
}

# kpi_report NAME VALUE UNIT
# Emits a TAP diagnostic line: # KPI: NAME -- VALUE UNIT
kpi_report() {
	local name="$1" value="$2" unit="$3"
	echo "# KPI: ${name} -- ${value} ${unit}" >&3
}

# perf_timeout_check STAGE START_EPOCH TIMEOUT_SEC
# Checks if current epoch exceeds start + timeout. If so, fail with diagnostic.
perf_timeout_check() {
	local stage="$1" start_epoch="$2" timeout_sec="$3"
	local now
	now=$(date +%s)
	local elapsed=$(( now - start_epoch ))
	if [ "$elapsed" -ge "$timeout_sec" ]; then
		echo "# TIMEOUT: exceeded ${timeout_sec}s at stage: ${stage} (elapsed: ${elapsed}s)" >&3
		echo "benchmark group exceeded ${timeout_sec}s timeout at stage: ${stage}" >&2
		return 1
	fi
}

# --- Log generators (awk-based for speed) ---
# Each takes: line_count unique_ip_count match_ratio (0-100) [target_len]
# Output: syslog-format lines to stdout
# All use awk to avoid shell loop overhead at 10K+ lines
#
# target_len (optional, default 0): when >0, lines are padded with
# domain-appropriate content to reach this character length.  Padding is
# appended AFTER the regex match point so it does not interfere with
# extract_hosts pattern matching.  When 0 or omitted, output is identical
# to the original compact format (backward compatible with P1 tests).

# generate_sshd_log LINE_COUNT UNIQUE_IP_COUNT MATCH_RATIO [TARGET_LEN]
# Real-world sshd lines: ~150 chars (synthetic ~110).
# Padding: key fingerprint + session metadata.
generate_sshd_log() {
	awk -v lines="$1" -v uips="$2" -v ratio="$3" -v tlen="${4:-0}" 'BEGIN {
		# padding appended after "port NNN ssh2"
		mpad = ": RSA SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8 ED25519 SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU"
		npad = ": RSA SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8 ED25519 SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU"
		thresh = int(lines * ratio / 100)
		for (i = 0; i < lines; i++) {
			idx = i % uips
			o2 = int(idx / 65536) % 256
			o3 = int(idx / 256) % 256
			o4 = idx % 256
			if (o4 == 0) o4 = 1
			ip = "10." o2 "." o3 "." o4
			pid = 10000 + i
			if (i < thresh) {
				base = "Mar 13 10:15:03 testhost sshd[" pid "]: Failed password for root from " ip " port 22 ssh2"
				if (tlen > 0 && length(base) < tlen) {
					need = tlen - length(base)
					print base substr(mpad, 1, need)
				} else print base
			} else {
				base = "Mar 13 10:15:03 testhost sshd[" pid "]: Accepted publickey for user from " ip " port 22 ssh2"
				if (tlen > 0 && length(base) < tlen) {
					need = tlen - length(base)
					print base substr(npad, 1, need)
				} else print base
			}
		}
	}' /dev/null
}

# generate_mod_sec_log LINE_COUNT UNIQUE_IP_COUNT MATCH_RATIO [TARGET_LEN]
# Real-world mod_sec lines: ~800 chars (synthetic ~120).
# Padding: OWASP CRS metadata fields ([file], [id], [msg], [data],
# [severity], [ver], [tag]...) — the bulk of real ModSecurity output.
generate_mod_sec_log() {
	awk -v lines="$1" -v uips="$2" -v ratio="$3" -v tlen="${4:-0}" 'BEGIN {
		# match padding: OWASP CRS rule metadata (placed after match point)
		mpad = ". Matched \"Operator Rx with parameter (?:(?:[\"\\\\]\\s*?(?:;|(?:--|#))\\s)|(?:[^\\w]UNION(?:\\s|/\\*.*?\\*/)))\" against \"REQUEST_URI\""
		mpad = mpad " [file \"/etc/modsecurity/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf\"]"
		mpad = mpad " [line \"1080\"] [id \"942440\"] [rev \"\"]"
		mpad = mpad " [msg \"SQL Comment Sequence Detected\"]"
		mpad = mpad " [data \"Matched Data: union select found within REQUEST_URI: /index.php?id=1 union select 1,2,3--\"]"
		mpad = mpad " [severity \"CRITICAL\"] [ver \"OWASP_CRS/3.3.2\"]"
		mpad = mpad " [maturity \"0\"] [accuracy \"0\"]"
		mpad = mpad " [tag \"application-multi\"] [tag \"language-multi\"]"
		mpad = mpad " [tag \"platform-multi\"] [tag \"attack-sqli\"]"
		mpad = mpad " [tag \"paranoia-level/1\"] [tag \"OWASP_CRS\"]"
		mpad = mpad " [tag \"capec/1000/152/248/66\"] [tag \"PCI/6.5.2\"]"
		mpad = mpad " [hostname \"app.example.com\"] [uri \"/wp-login.php\"]"
		mpad = mpad " [unique_id \"ZDFsdf23sdDFG789abcXYZ012345\"]"
		# non-match padding: Apache trace context
		npad = " [header parser] [core:trace4] mod_authz_core.c(835): Require all granted: granted"
		npad = npad ", referer: https://app.example.com/dashboard/admin/settings/security"
		npad = npad " [pid 12345:tid 140234567890123] mod_headers.c(903): AH01502: Setting header"
		npad = npad " X-Content-Type-Options: nosniff [hostname \"app.example.com\"]"
		npad = npad " [uri \"/api/v2/health\"] [unique_id \"YWJjZGVmZ2hpamtsbW5vcHFy\"]"
		thresh = int(lines * ratio / 100)
		for (i = 0; i < lines; i++) {
			idx = i % uips
			o2 = int(idx / 65536) % 256
			o3 = int(idx / 256) % 256
			o4 = idx % 256
			if (o4 == 0) o4 = 1
			ip = "10." o2 "." o3 "." o4
			pid = 10000 + i
			if (i < thresh) {
				base = "[Thu Mar 13 10:15:03." i " 2026] [error] [pid " pid "] [client " ip ":54321] ModSecurity: Access denied with code 403 (phase 2)"
				if (tlen > 0 && length(base) < tlen) {
					need = tlen - length(base)
					print base substr(mpad, 1, need)
				} else print base
			} else {
				base = "[Thu Mar 13 10:15:03." i " 2026] [notice] [pid " pid "] [client " ip ":54321] AH01626: authorization result"
				if (tlen > 0 && length(base) < tlen) {
					need = tlen - length(base)
					print base substr(npad, 1, need)
				} else print base
			}
		}
	}' /dev/null
}

# generate_postfix_log LINE_COUNT UNIQUE_IP_COUNT MATCH_RATIO [TARGET_LEN]
# Real-world postfix lines: ~250 chars (synthetic ~120).
# Padding: TLS cipher details + SASL mechanism + queue ID.
generate_postfix_log() {
	awk -v lines="$1" -v uips="$2" -v ratio="$3" -v tlen="${4:-0}" 'BEGIN {
		# match padding: extended SASL detail (placed after "authentication failure")
		mpad = ", sasl_method=LOGIN, sasl_username=admin@mail.example.com"
		mpad = mpad " (TLS: TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits) key-exchange X25519 server-signature RSA-PSS (2048 bits))"
		# non-match padding: EHLO + TLS negotiation detail
		npad = ", ehlo=mail.sender-domain.example.com"
		npad = npad " (TLS: TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits) key-exchange X25519 server-signature RSA-PSS (2048 bits))"
		npad = npad " queue_id=4Y8KzR6Lptz3vGN"
		thresh = int(lines * ratio / 100)
		for (i = 0; i < lines; i++) {
			idx = i % uips
			o2 = int(idx / 65536) % 256
			o3 = int(idx / 256) % 256
			o4 = idx % 256
			if (o4 == 0) o4 = 1
			ip = "10." o2 "." o3 "." o4
			pid = 10000 + i
			if (i < thresh) {
				base = "Mar 13 10:15:03 testhost postfix/smtpd[" pid "]: warning: unknown[" ip "]: SASL PLAIN authentication failed: authentication failure"
				if (tlen > 0 && length(base) < tlen) {
					need = tlen - length(base)
					print base substr(mpad, 1, need)
				} else print base
			} else {
				base = "Mar 13 10:15:03 testhost postfix/smtpd[" pid "]: connect from unknown[" ip "]"
				if (tlen > 0 && length(base) < tlen) {
					need = tlen - length(base)
					print base substr(npad, 1, need)
				} else print base
			}
		}
	}' /dev/null
}

# generate_dovecot_log LINE_COUNT UNIQUE_IP_COUNT MATCH_RATIO [TARGET_LEN]
# Real-world dovecot lines: ~250 chars (synthetic ~130).
# Padding: TLS version, session ID, secured detail, client cert info.
generate_dovecot_log() {
	awk -v lines="$1" -v uips="$2" -v ratio="$3" -v tlen="${4:-0}" 'BEGIN {
		# match padding: TLS + session detail (placed after "lip=...")
		mpad = ", TLS: TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits), session=<abc123def456ghi789jkl0+mno1>"
		mpad = mpad ", client_id=thunderbird/115.6.0, local_port=993, orig_client=proxy"
		# non-match padding: same structure for successful login
		npad = ", TLS: TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits), session=<abc123def456ghi789jkl0+mno1>"
		npad = npad ", client_id=thunderbird/115.6.0, local_port=993, orig_client=proxy"
		thresh = int(lines * ratio / 100)
		for (i = 0; i < lines; i++) {
			idx = i % uips
			o2 = int(idx / 65536) % 256
			o3 = int(idx / 256) % 256
			o4 = idx % 256
			if (o4 == 0) o4 = 1
			ip = "10." o2 "." o3 "." o4
			pid = 10000 + i
			if (i < thresh) {
				base = "Mar 13 10:15:03 testhost dovecot: imap-login: Disconnected (auth failed, 1 attempts): user=<admin>, method=PLAIN, rip=" ip ", lip=10.0.0.1"
				if (tlen > 0 && length(base) < tlen) {
					need = tlen - length(base)
					print base substr(mpad, 1, need)
				} else print base
			} else {
				base = "Mar 13 10:15:03 testhost dovecot: imap-login: Login: user=<admin>, method=PLAIN, rip=" ip ", lip=10.0.0.1"
				if (tlen > 0 && length(base) < tlen) {
					need = tlen - length(base)
					print base substr(npad, 1, need)
				} else print base
			}
		}
	}' /dev/null
}

# --- State generators (awk-based for speed) ---

# generate_pressure_dat OUTPUT_FILE ENTRY_COUNT NOW
# Creates synthetic pressure.dat entries with deterministic IPs and timestamps
generate_pressure_dat() {
	local output_file="$1" entry_count="$2" now="$3"
	awk -v entries="$entry_count" -v now="$now" 'BEGIN {
		split("sshd,dovecot,postfix,mod_sec", mods, ",")
		for (i = 0; i < entries; i++) {
			idx = i % 500
			o2 = int(idx / 65536) % 256
			o3 = int(idx / 256) % 256
			o4 = idx % 256
			if (o4 == 0) o4 = 1
			ip = "10." o2 "." o3 "." o4
			ts = now - (i % 300)
			mod = mods[(i % 4) + 1]
			w = (i % 5) + 1
			print ts, ip, mod, 1, w
		}
	}' /dev/null > "$output_file"
}

# generate_ipcountry_dat OUTPUT_FILE IP_COUNT
# Creates synthetic ipcountry.dat with ranges covering 10.x.x.x IPs
# Format: START_INT END_INT CC
generate_ipcountry_dat() {
	local output_file="$1" ip_count="$2"
	awk -v count="$ip_count" 'BEGIN {
		base = 167772160
		split("US,CN,RU,DE,BR,IN,FR,GB,JP,KR", ccs, ",")
		for (i = 0; i < count; i++) {
			v = base + i
			print v, v, ccs[(i % 10) + 1]
		}
	}' /dev/null > "$output_file"
}
