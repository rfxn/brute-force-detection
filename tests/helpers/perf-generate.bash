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
# Each takes: line_count unique_ip_count match_ratio (0-100)
# Output: syslog-format lines to stdout
# All use awk to avoid shell loop overhead at 10K+ lines

# generate_sshd_log LINE_COUNT UNIQUE_IP_COUNT MATCH_RATIO
generate_sshd_log() {
	awk -v lines="$1" -v uips="$2" -v ratio="$3" 'BEGIN {
		thresh = int(lines * ratio / 100)
		for (i = 0; i < lines; i++) {
			idx = i % uips
			o2 = int(idx / 65536) % 256
			o3 = int(idx / 256) % 256
			o4 = idx % 256
			if (o4 == 0) o4 = 1
			ip = "10." o2 "." o3 "." o4
			pid = 10000 + i
			if (i < thresh)
				print "Mar 13 10:15:03 testhost sshd[" pid "]: Failed password for root from " ip " port 22 ssh2"
			else
				print "Mar 13 10:15:03 testhost sshd[" pid "]: Accepted publickey for user from " ip " port 22 ssh2"
		}
	}' /dev/null
}

# generate_mod_sec_log LINE_COUNT UNIQUE_IP_COUNT MATCH_RATIO
generate_mod_sec_log() {
	awk -v lines="$1" -v uips="$2" -v ratio="$3" 'BEGIN {
		thresh = int(lines * ratio / 100)
		for (i = 0; i < lines; i++) {
			idx = i % uips
			o2 = int(idx / 65536) % 256
			o3 = int(idx / 256) % 256
			o4 = idx % 256
			if (o4 == 0) o4 = 1
			ip = "10." o2 "." o3 "." o4
			pid = 10000 + i
			if (i < thresh)
				print "[Thu Mar 13 10:15:03." i " 2026] [error] [pid " pid "] [client " ip ":54321] ModSecurity: Access denied with code 403 (phase 2)"
			else
				print "[Thu Mar 13 10:15:03." i " 2026] [notice] [pid " pid "] [client " ip ":54321] AH01626: authorization result"
		}
	}' /dev/null
}

# generate_postfix_log LINE_COUNT UNIQUE_IP_COUNT MATCH_RATIO
generate_postfix_log() {
	awk -v lines="$1" -v uips="$2" -v ratio="$3" 'BEGIN {
		thresh = int(lines * ratio / 100)
		for (i = 0; i < lines; i++) {
			idx = i % uips
			o2 = int(idx / 65536) % 256
			o3 = int(idx / 256) % 256
			o4 = idx % 256
			if (o4 == 0) o4 = 1
			ip = "10." o2 "." o3 "." o4
			pid = 10000 + i
			if (i < thresh)
				print "Mar 13 10:15:03 testhost postfix/smtpd[" pid "]: warning: unknown[" ip "]: SASL PLAIN authentication failed: authentication failure"
			else
				print "Mar 13 10:15:03 testhost postfix/smtpd[" pid "]: connect from unknown[" ip "]"
		}
	}' /dev/null
}

# generate_dovecot_log LINE_COUNT UNIQUE_IP_COUNT MATCH_RATIO
generate_dovecot_log() {
	awk -v lines="$1" -v uips="$2" -v ratio="$3" 'BEGIN {
		thresh = int(lines * ratio / 100)
		for (i = 0; i < lines; i++) {
			idx = i % uips
			o2 = int(idx / 65536) % 256
			o3 = int(idx / 256) % 256
			o4 = idx % 256
			if (o4 == 0) o4 = 1
			ip = "10." o2 "." o3 "." o4
			pid = 10000 + i
			if (i < thresh)
				print "Mar 13 10:15:03 testhost dovecot: imap-login: Disconnected (auth failed, 1 attempts): user=<admin>, method=PLAIN, rip=" ip ", lip=10.0.0.1"
			else
				print "Mar 13 10:15:03 testhost dovecot: imap-login: Login: user=<admin>, method=PLAIN, rip=" ip ", lip=10.0.0.1"
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
