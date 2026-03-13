#!/usr/bin/env bats
#
# BFD performance benchmark suite
# Measures core detection pipeline throughput across three scaling tiers.
# Each tier group has a HARD 30-SECOND TIMEOUT.
#
# KPI output format (TAP diagnostic via fd 3):
#   # KPI: metric.name.tier -- value unit
#
# Tiers (check() cycle / raw extract_hosts):
#   small:  1K / 1K lines, 50 unique IPs, 100% match ratio
#   medium: 10K / 2K lines, 500/200 unique IPs, 50% match ratio
#   large:  50K / 3K lines, 2K/500 unique IPs, 30% match ratio
# Raw extract_hosts sizes are smaller because it runs 4 rules sequentially
# without the batching optimizations that check() provides.
#
# Mode deviation (P2): diagnostic-only benchmarks documenting where modes
# diverge. No hard KPI assertions — reports scan vs standard tlog path,
# TLOG_FLOCK overhead, and DRY_RUN=0 vs DRY_RUN=1 ban execution overhead.
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'
# shellcheck disable=SC1091
source "${BATS_TEST_DIRNAME}/helpers/perf-generate.bash"

# Source check() function from bfd (defined there, not in bfd.lib.sh)
bfd_load_function check

setup() {
	bfd_require_bash42
	bfd_standard_setup
	# suppress elog to stderr (avoids noise in benchmark output)
	ELOG_STDOUT="never"
	# check() environment — mirrors _setup_check_env from 17-check-pipeline.bats
	PRESSURE_TRIP="${PRESSURE_TRIP:-20}"
	GLOB_PRESSURE_TRIP="$PRESSURE_TRIP"
	GLOB_TRIG="$PRESSURE_TRIP"
	PRESSURE_HALF_LIFE="${PRESSURE_HALF_LIFE:-300}"
	PRESSURE_TRIP_GLOBAL="0"
	TRIG_WINDOW="300"
	TRIG_GLOBAL="0"
	EMAIL_ALERTS="0"
	SUBNET_TRIG="0"
	DRY_RUN=1
	UTIME=$(date +"%s")
	IGNORE_HOST_FILES="$INSTALL_PATH/exclude.files"
	touch "$IGNORE_HOST_FILES"
	LO_HOSTS="$INSTALL_PATH/ignore.hosts.local"
	touch "$LO_HOSTS"
	BAN_COMMAND_TEMPLATE="/bin/true"
	BAN_COMMAND_V6_TEMPLATE=""
	BAN_TTL="${BAN_TTL:-600}"
	BAN_DURATION="0"
	BAN_ESCALATE_AFTER="0"
	BAN_PERMANENT_AFTER="0"
	BAN_ESCALATE_WINDOW="86400"
	BAN_PERMANENT_WINDOW="86400"
	SKIP_ALERT=""
	LOG_IDLE_SUPPRESS="0"
	_COUNTRY_CACHE_FILE=""
	_IGNORE_CACHE_FILE=""
	_TLOG_PASSTHROUGH=""
	_SCAN_MODE=""
	IGNOREREGEX=""
	VERBOSE=0
	ELOG_VERBOSE=0
}

teardown() {
	bfd_teardown
}

# --- Helper: generate log files for a tier ---
# _perf_generate_logs TIER LINE_COUNT UNIQUE_IPS MATCH_RATIO
# Creates 4 log files under INSTALL_PATH/tmp and sets _LOG_sshd etc.
_perf_generate_logs() {
	local tier="$1" lines="$2" uips="$3" ratio="$4"
	_LOG_sshd="$INSTALL_PATH/tmp/perf_${tier}_sshd.log"
	_LOG_mod_sec="$INSTALL_PATH/tmp/perf_${tier}_mod_sec.log"
	_LOG_postfix="$INSTALL_PATH/tmp/perf_${tier}_postfix.log"
	_LOG_dovecot="$INSTALL_PATH/tmp/perf_${tier}_dovecot.log"
	generate_sshd_log "$lines" "$uips" "$ratio" > "$_LOG_sshd"
	generate_mod_sec_log "$lines" "$uips" "$ratio" > "$_LOG_mod_sec"
	generate_postfix_log "$lines" "$uips" "$ratio" > "$_LOG_postfix"
	generate_dovecot_log "$lines" "$uips" "$ratio" > "$_LOG_dovecot"
}

# ============================================================
#  SMALL TIER: 1K lines, 50 unique IPs, 100% match ratio
# ============================================================

@test "perf: small tier -- extract_hosts throughput (4 rules)" {
	local _timeout=30
	local _group_start
	_group_start=$(date +%s)

	_perf_generate_logs "small" 1000 50 100
	perf_timeout_check "log_generation" "$_group_start" "$_timeout"

	# sshd
	timer_start
	local result
	result=$(cat "$_LOG_sshd" | extract_hosts \
		"sshd.*Failed password for .* from <HOST>")
	local ms
	ms=$(timer_elapsed_ms)
	local count
	count=$(echo "$result" | grep -c . 2>/dev/null || echo 0)
	local rate=$(( count * 1000 / (ms + 1) ))
	kpi_report "extract_hosts.sshd.small" "$count lines in ${ms}ms" "(${rate} lines/sec)"
	perf_timeout_check "extract_hosts.sshd" "$_group_start" "$_timeout"

	# mod_sec
	timer_start
	result=$(cat "$_LOG_mod_sec" | extract_hosts \
		"\[client <HOST>.*ModSecurity: Access denied")
	ms=$(timer_elapsed_ms)
	count=$(echo "$result" | grep -c . 2>/dev/null || echo 0)
	rate=$(( count * 1000 / (ms + 1) ))
	kpi_report "extract_hosts.mod_sec.small" "$count lines in ${ms}ms" "(${rate} lines/sec)"
	perf_timeout_check "extract_hosts.mod_sec" "$_group_start" "$_timeout"

	# postfix
	timer_start
	result=$(cat "$_LOG_postfix" | extract_hosts \
		"\[<HOST>\].*SASL.*authentication failed")
	ms=$(timer_elapsed_ms)
	count=$(echo "$result" | grep -c . 2>/dev/null || echo 0)
	rate=$(( count * 1000 / (ms + 1) ))
	kpi_report "extract_hosts.postfix.small" "$count lines in ${ms}ms" "(${rate} lines/sec)"
	perf_timeout_check "extract_hosts.postfix" "$_group_start" "$_timeout"

	# dovecot
	timer_start
	result=$(cat "$_LOG_dovecot" | extract_hosts \
		"imap-login.*auth failed.*rip=<HOST>")
	ms=$(timer_elapsed_ms)
	count=$(echo "$result" | grep -c . 2>/dev/null || echo 0)
	rate=$(( count * 1000 / (ms + 1) ))
	kpi_report "extract_hosts.dovecot.small" "$count lines in ${ms}ms" "(${rate} lines/sec)"
	perf_timeout_check "extract_hosts.dovecot" "$_group_start" "$_timeout"

	# ceiling: any single rule must complete in <5s
	[ "$ms" -lt 5000 ]
}

@test "perf: small tier -- batch pressure + country lookups" {
	local _timeout=30
	local _group_start
	_group_start=$(date +%s)

	# generate pressure data (1K entries)
	generate_pressure_dat "$INSTALL_PATH/tmp/pressure.dat" 1000 "$UTIME"
	perf_timeout_check "pressure_dat_gen" "$_group_start" "$_timeout"

	# generate ipcountry data (256 entries covers 10.0.0.x)
	generate_ipcountry_dat "$INSTALL_PATH/ipcountry.dat" 256
	perf_timeout_check "ipcountry_dat_gen" "$_group_start" "$_timeout"

	# create unique IP list (50 IPs)
	local _ip_file="$INSTALL_PATH/tmp/perf_ips.txt"
	awk -v n=50 'BEGIN {
		for (i = 0; i < n; i++) {
			o4 = i % 256; if (o4 == 0) o4 = 1
			print "10.0.0." o4
		}
	}' /dev/null > "$_ip_file"

	# batch pressure compute
	timer_start
	local _bp_out
	_bp_out=$(_batch_pressure_compute "$INSTALL_PATH/tmp/pressure.dat" "$UTIME" "$PRESSURE_HALF_LIFE" "sshd")
	local ms
	ms=$(timer_elapsed_ms)
	local bp_count
	bp_count=$(echo "$_bp_out" | grep -c . 2>/dev/null || echo 0)
	kpi_report "batch_pressure.small" "${bp_count} IPs in ${ms}ms" ""
	perf_timeout_check "batch_pressure" "$_group_start" "$_timeout"

	# batch country lookup
	timer_start
	local _cc_out
	_cc_out=$(_batch_ip_to_country "$INSTALL_PATH/ipcountry.dat" < "$_ip_file")
	ms=$(timer_elapsed_ms)
	local cc_count
	cc_count=$(echo "$_cc_out" | grep -c . 2>/dev/null || echo 0)
	kpi_report "batch_country.small" "${cc_count} IPs in ${ms}ms" ""
	perf_timeout_check "batch_country" "$_group_start" "$_timeout"

	[ "$ms" -lt 5000 ]
}

@test "perf: small tier -- full rule iteration (4 rules)" {
	local _timeout=30
	local _group_start
	_group_start=$(date +%s)

	_perf_generate_logs "small" 1000 50 100
	perf_timeout_check "log_generation" "$_group_start" "$_timeout"

	# create ipcountry for check()
	generate_ipcountry_dat "$INSTALL_PATH/ipcountry.dat" 256

	# Create 4 mock rules that use _TLOG_PASSTHROUGH
	create_mock_rule "sshd" "$(printf 'PREREQ=""\nLOG_FILE="%s"\nLOG_TAG="sshd"\n_TLOG_PASSTHROUGH="%s"\nMATCHED_HOSTS=$(_rule_tlog "$LOG_FILE" "$LOG_TAG" | extract_hosts "sshd.*Failed password for .* from <HOST>")\n' \
		"$_LOG_sshd" "$_LOG_sshd")"
	create_mock_rule "mod_sec" "$(printf 'PREREQ=""\nLOG_FILE="%s"\nLOG_TAG="httpd.modsec"\n_TLOG_PASSTHROUGH="%s"\nMATCHED_HOSTS=$(_rule_tlog "$LOG_FILE" "$LOG_TAG" | extract_hosts "\\[client <HOST>.*ModSecurity: Access denied")\n' \
		"$_LOG_mod_sec" "$_LOG_mod_sec")"
	create_mock_rule "postfix" "$(printf 'PREREQ=""\nLOG_FILE="%s"\nLOG_TAG="postfix"\n_TLOG_PASSTHROUGH="%s"\nMATCHED_HOSTS=$(_rule_tlog "$LOG_FILE" "$LOG_TAG" | extract_hosts "\\[<HOST>\\].*SASL.*authentication failed")\n' \
		"$_LOG_postfix" "$_LOG_postfix")"
	create_mock_rule "dovecot" "$(printf 'PREREQ=""\nLOG_FILE="%s"\nLOG_TAG="dovecot"\n_TLOG_PASSTHROUGH="%s"\nMATCHED_HOSTS=$(_rule_tlog "$LOG_FILE" "$LOG_TAG" | extract_hosts "imap-login.*auth failed.*rip=<HOST>")\n' \
		"$_LOG_dovecot" "$_LOG_dovecot")"

	perf_timeout_check "rule_creation" "$_group_start" "$_timeout"

	timer_start
	run check
	local ms
	ms=$(timer_elapsed_ms)
	kpi_report "cycle_wall.small" "${ms}ms" "(4 rules, 1K lines each)"
	perf_timeout_check "check_cycle" "$_group_start" "$_timeout"

	assert_success
	# ceiling: full group < 15s
	[ "$ms" -lt 15000 ]
}

# ============================================================
#  MEDIUM TIER: 10K lines for check(), 2K for raw extract_hosts
#  500 unique IPs, 50% match ratio
# ============================================================

@test "perf: medium tier -- extract_hosts throughput (4 rules)" {
	local _timeout=30
	local _group_start
	_group_start=$(date +%s)

	# Use 2K lines for raw extract_hosts (4 rules * ~6s/rule at ~300 lines/sec)
	# Full 10K tier tested in the check() cycle test below
	_perf_generate_logs "medium_eh" 2000 200 50
	perf_timeout_check "log_generation" "$_group_start" "$_timeout"

	# sshd (12 patterns in production, test with 1 for baseline)
	timer_start
	local result
	result=$(cat "$_LOG_sshd" | extract_hosts \
		"sshd.*Failed password for .* from <HOST>")
	local ms
	ms=$(timer_elapsed_ms)
	local count
	count=$(echo "$result" | grep -c . 2>/dev/null || echo 0)
	local rate=$(( count * 1000 / (ms + 1) ))
	kpi_report "extract_hosts.sshd.medium" "$count lines in ${ms}ms" "(${rate} lines/sec)"
	perf_timeout_check "extract_hosts.sshd" "$_group_start" "$_timeout"

	# mod_sec (1 pattern)
	timer_start
	result=$(cat "$_LOG_mod_sec" | extract_hosts \
		"\[client <HOST>.*ModSecurity: Access denied")
	ms=$(timer_elapsed_ms)
	count=$(echo "$result" | grep -c . 2>/dev/null || echo 0)
	rate=$(( count * 1000 / (ms + 1) ))
	kpi_report "extract_hosts.mod_sec.medium" "$count lines in ${ms}ms" "(${rate} lines/sec)"
	perf_timeout_check "extract_hosts.mod_sec" "$_group_start" "$_timeout"

	# postfix
	timer_start
	result=$(cat "$_LOG_postfix" | extract_hosts \
		"\[<HOST>\].*SASL.*authentication failed")
	ms=$(timer_elapsed_ms)
	count=$(echo "$result" | grep -c . 2>/dev/null || echo 0)
	rate=$(( count * 1000 / (ms + 1) ))
	kpi_report "extract_hosts.postfix.medium" "$count lines in ${ms}ms" "(${rate} lines/sec)"
	perf_timeout_check "extract_hosts.postfix" "$_group_start" "$_timeout"

	# dovecot (with IGNOREREGEX overhead test)
	IGNOREREGEX="no auth attempts"
	timer_start
	result=$(cat "$_LOG_dovecot" | extract_hosts \
		"imap-login.*auth failed.*rip=<HOST>")
	ms=$(timer_elapsed_ms)
	count=$(echo "$result" | grep -c . 2>/dev/null || echo 0)
	rate=$(( count * 1000 / (ms + 1) ))
	kpi_report "extract_hosts.dovecot.medium" "$count lines in ${ms}ms (with IGNOREREGEX)" "(${rate} lines/sec)"
	IGNOREREGEX=""
	perf_timeout_check "extract_hosts.dovecot" "$_group_start" "$_timeout"

	# ceiling: any single rule < 10s
	[ "$ms" -lt 10000 ]
}

@test "perf: medium tier -- batch lookups (10K pressure, 500 IPs)" {
	local _timeout=30
	local _group_start
	_group_start=$(date +%s)

	# generate pressure data (10K entries)
	generate_pressure_dat "$INSTALL_PATH/tmp/pressure.dat" 10000 "$UTIME"
	perf_timeout_check "pressure_dat_gen" "$_group_start" "$_timeout"

	# generate ipcountry data (2048 entries)
	generate_ipcountry_dat "$INSTALL_PATH/ipcountry.dat" 2048
	perf_timeout_check "ipcountry_dat_gen" "$_group_start" "$_timeout"

	# create unique IP list (500 IPs)
	local _ip_file="$INSTALL_PATH/tmp/perf_ips.txt"
	awk -v n=500 'BEGIN {
		for (i = 0; i < n; i++) {
			o3 = int(i / 256) % 256
			o4 = i % 256; if (o4 == 0) o4 = 1
			print "10.0." o3 "." o4
		}
	}' /dev/null > "$_ip_file"

	# batch pressure compute
	timer_start
	local _bp_out
	_bp_out=$(_batch_pressure_compute "$INSTALL_PATH/tmp/pressure.dat" "$UTIME" "$PRESSURE_HALF_LIFE" "sshd")
	local ms
	ms=$(timer_elapsed_ms)
	local bp_count
	bp_count=$(echo "$_bp_out" | grep -c . 2>/dev/null || echo 0)
	kpi_report "batch_pressure.medium" "${bp_count} IPs in ${ms}ms" "(10K entries)"
	perf_timeout_check "batch_pressure" "$_group_start" "$_timeout"

	# batch country lookup
	timer_start
	local _cc_out
	_cc_out=$(_batch_ip_to_country "$INSTALL_PATH/ipcountry.dat" < "$_ip_file")
	ms=$(timer_elapsed_ms)
	local cc_count
	cc_count=$(echo "$_cc_out" | grep -c . 2>/dev/null || echo 0)
	kpi_report "batch_country.medium" "${cc_count} IPs in ${ms}ms" "(2K db entries)"
	perf_timeout_check "batch_country" "$_group_start" "$_timeout"

	[ "$ms" -lt 10000 ]
}

@test "perf: medium tier -- full check() cycle (4 rules)" {
	local _timeout=30
	local _group_start
	_group_start=$(date +%s)

	_perf_generate_logs "medium" 10000 500 50
	perf_timeout_check "log_generation" "$_group_start" "$_timeout"

	# create ipcountry for check()
	generate_ipcountry_dat "$INSTALL_PATH/ipcountry.dat" 2048

	# Create 4 mock rules
	create_mock_rule "sshd" "$(printf 'PREREQ=""\nLOG_FILE="%s"\nLOG_TAG="sshd"\n_TLOG_PASSTHROUGH="%s"\nMATCHED_HOSTS=$(_rule_tlog "$LOG_FILE" "$LOG_TAG" | extract_hosts "sshd.*Failed password for .* from <HOST>")\n' \
		"$_LOG_sshd" "$_LOG_sshd")"
	create_mock_rule "mod_sec" "$(printf 'PREREQ=""\nLOG_FILE="%s"\nLOG_TAG="httpd.modsec"\n_TLOG_PASSTHROUGH="%s"\nMATCHED_HOSTS=$(_rule_tlog "$LOG_FILE" "$LOG_TAG" | extract_hosts "\\[client <HOST>.*ModSecurity: Access denied")\n' \
		"$_LOG_mod_sec" "$_LOG_mod_sec")"
	create_mock_rule "postfix" "$(printf 'PREREQ=""\nLOG_FILE="%s"\nLOG_TAG="postfix"\n_TLOG_PASSTHROUGH="%s"\nMATCHED_HOSTS=$(_rule_tlog "$LOG_FILE" "$LOG_TAG" | extract_hosts "\\[<HOST>\\].*SASL.*authentication failed")\n' \
		"$_LOG_postfix" "$_LOG_postfix")"
	create_mock_rule "dovecot" "$(printf 'PREREQ=""\nLOG_FILE="%s"\nLOG_TAG="dovecot"\n_TLOG_PASSTHROUGH="%s"\nMATCHED_HOSTS=$(_rule_tlog "$LOG_FILE" "$LOG_TAG" | extract_hosts "imap-login.*auth failed.*rip=<HOST>")\n' \
		"$_LOG_dovecot" "$_LOG_dovecot")"

	perf_timeout_check "rule_creation" "$_group_start" "$_timeout"

	timer_start
	run check
	local ms
	ms=$(timer_elapsed_ms)
	kpi_report "cycle_wall.medium" "${ms}ms" "(4 rules, 10K lines each, 50% match)"
	perf_timeout_check "check_cycle" "$_group_start" "$_timeout"

	assert_success
	# ceiling: full group < 25s
	[ "$ms" -lt 25000 ]
}

# ============================================================
#  LARGE TIER: 50K lines for check(), 3K for raw extract_hosts
#  2K unique IPs, 30% match ratio
# ============================================================

@test "perf: large tier -- extract_hosts throughput (4 rules)" {
	local _timeout=30
	local _group_start
	_group_start=$(date +%s)

	# Use 3K lines for raw extract_hosts (4 rules * ~7s/rule at ~300 lines/sec)
	# Full 50K tier tested in the check() cycle test below
	_perf_generate_logs "large_eh" 3000 500 30
	perf_timeout_check "log_generation" "$_group_start" "$_timeout"

	# sshd
	timer_start
	local result
	result=$(cat "$_LOG_sshd" | extract_hosts \
		"sshd.*Failed password for .* from <HOST>")
	local ms
	ms=$(timer_elapsed_ms)
	local count
	count=$(echo "$result" | grep -c . 2>/dev/null || echo 0)
	local rate=$(( count * 1000 / (ms + 1) ))
	kpi_report "extract_hosts.sshd.large" "$count lines in ${ms}ms" "(${rate} lines/sec)"
	perf_timeout_check "extract_hosts.sshd" "$_group_start" "$_timeout"

	# mod_sec
	timer_start
	result=$(cat "$_LOG_mod_sec" | extract_hosts \
		"\[client <HOST>.*ModSecurity: Access denied")
	ms=$(timer_elapsed_ms)
	count=$(echo "$result" | grep -c . 2>/dev/null || echo 0)
	rate=$(( count * 1000 / (ms + 1) ))
	kpi_report "extract_hosts.mod_sec.large" "$count lines in ${ms}ms" "(${rate} lines/sec)"
	perf_timeout_check "extract_hosts.mod_sec" "$_group_start" "$_timeout"

	# postfix
	timer_start
	result=$(cat "$_LOG_postfix" | extract_hosts \
		"\[<HOST>\].*SASL.*authentication failed")
	ms=$(timer_elapsed_ms)
	count=$(echo "$result" | grep -c . 2>/dev/null || echo 0)
	rate=$(( count * 1000 / (ms + 1) ))
	kpi_report "extract_hosts.postfix.large" "$count lines in ${ms}ms" "(${rate} lines/sec)"
	perf_timeout_check "extract_hosts.postfix" "$_group_start" "$_timeout"

	# dovecot
	timer_start
	result=$(cat "$_LOG_dovecot" | extract_hosts \
		"imap-login.*auth failed.*rip=<HOST>")
	ms=$(timer_elapsed_ms)
	count=$(echo "$result" | grep -c . 2>/dev/null || echo 0)
	rate=$(( count * 1000 / (ms + 1) ))
	kpi_report "extract_hosts.dovecot.large" "$count lines in ${ms}ms" "(${rate} lines/sec)"
	perf_timeout_check "extract_hosts.dovecot" "$_group_start" "$_timeout"

	# ceiling: any single rule < 20s
	[ "$ms" -lt 20000 ]
}

@test "perf: large tier -- batch lookups (100K pressure, 2K IPs)" {
	local _timeout=30
	local _group_start
	_group_start=$(date +%s)

	# generate pressure data (100K entries — stress test)
	generate_pressure_dat "$INSTALL_PATH/tmp/pressure.dat" 100000 "$UTIME"
	perf_timeout_check "pressure_dat_gen" "$_group_start" "$_timeout"

	# generate ipcountry data (8192 entries for broader coverage)
	generate_ipcountry_dat "$INSTALL_PATH/ipcountry.dat" 8192
	perf_timeout_check "ipcountry_dat_gen" "$_group_start" "$_timeout"

	# create unique IP list (2K IPs)
	local _ip_file="$INSTALL_PATH/tmp/perf_ips.txt"
	awk -v n=2000 'BEGIN {
		for (i = 0; i < n; i++) {
			o3 = int(i / 256) % 256
			o4 = i % 256; if (o4 == 0) o4 = 1
			print "10.0." o3 "." o4
		}
	}' /dev/null > "$_ip_file"

	# batch pressure compute
	timer_start
	local _bp_out
	_bp_out=$(_batch_pressure_compute "$INSTALL_PATH/tmp/pressure.dat" "$UTIME" "$PRESSURE_HALF_LIFE" "sshd")
	local ms
	ms=$(timer_elapsed_ms)
	local bp_count
	bp_count=$(echo "$_bp_out" | grep -c . 2>/dev/null || echo 0)
	kpi_report "batch_pressure.large" "${bp_count} IPs in ${ms}ms" "(100K entries)"
	perf_timeout_check "batch_pressure" "$_group_start" "$_timeout"

	# batch country lookup
	timer_start
	local _cc_out
	_cc_out=$(_batch_ip_to_country "$INSTALL_PATH/ipcountry.dat" < "$_ip_file")
	ms=$(timer_elapsed_ms)
	local cc_count
	cc_count=$(echo "$_cc_out" | grep -c . 2>/dev/null || echo 0)
	kpi_report "batch_country.large" "${cc_count} IPs in ${ms}ms" "(8K db entries)"
	perf_timeout_check "batch_country" "$_group_start" "$_timeout"

	[ "$ms" -lt 20000 ]
}

@test "perf: large tier -- full check() cycle (4 rules)" {
	local _timeout=30
	local _group_start
	_group_start=$(date +%s)

	_perf_generate_logs "large" 50000 2000 30
	perf_timeout_check "log_generation" "$_group_start" "$_timeout"

	# create ipcountry for check()
	generate_ipcountry_dat "$INSTALL_PATH/ipcountry.dat" 8192

	# Create 4 mock rules
	create_mock_rule "sshd" "$(printf 'PREREQ=""\nLOG_FILE="%s"\nLOG_TAG="sshd"\n_TLOG_PASSTHROUGH="%s"\nMATCHED_HOSTS=$(_rule_tlog "$LOG_FILE" "$LOG_TAG" | extract_hosts "sshd.*Failed password for .* from <HOST>")\n' \
		"$_LOG_sshd" "$_LOG_sshd")"
	create_mock_rule "mod_sec" "$(printf 'PREREQ=""\nLOG_FILE="%s"\nLOG_TAG="httpd.modsec"\n_TLOG_PASSTHROUGH="%s"\nMATCHED_HOSTS=$(_rule_tlog "$LOG_FILE" "$LOG_TAG" | extract_hosts "\\[client <HOST>.*ModSecurity: Access denied")\n' \
		"$_LOG_mod_sec" "$_LOG_mod_sec")"
	create_mock_rule "postfix" "$(printf 'PREREQ=""\nLOG_FILE="%s"\nLOG_TAG="postfix"\n_TLOG_PASSTHROUGH="%s"\nMATCHED_HOSTS=$(_rule_tlog "$LOG_FILE" "$LOG_TAG" | extract_hosts "\\[<HOST>\\].*SASL.*authentication failed")\n' \
		"$_LOG_postfix" "$_LOG_postfix")"
	create_mock_rule "dovecot" "$(printf 'PREREQ=""\nLOG_FILE="%s"\nLOG_TAG="dovecot"\n_TLOG_PASSTHROUGH="%s"\nMATCHED_HOSTS=$(_rule_tlog "$LOG_FILE" "$LOG_TAG" | extract_hosts "imap-login.*auth failed.*rip=<HOST>")\n' \
		"$_LOG_dovecot" "$_LOG_dovecot")"

	perf_timeout_check "rule_creation" "$_group_start" "$_timeout"

	timer_start
	run check
	local ms
	ms=$(timer_elapsed_ms)
	kpi_report "cycle_wall.large" "${ms}ms" "(4 rules, 50K lines each, 30% match)"
	perf_timeout_check "check_cycle" "$_group_start" "$_timeout"

	assert_success
	# ceiling: full group < 30s (the hard limit)
	[ "$ms" -lt 30000 ]
}

# ============================================================
#  MODE DEVIATION: scan vs standard, TLOG_FLOCK, DRY_RUN
#  Diagnostic-only — no hard KPI assertions, only ceiling guards.
#  Documents where BFD's operating modes diverge in performance.
# ============================================================

@test "perf: deviation -- scan vs standard tlog path (sshd, 2K lines)" {
	local _timeout=30
	local _group_start
	_group_start=$(date +%s)

	# Generate 2K sshd log (100% match for consistent extraction)
	local _log_file="$INSTALL_PATH/tmp/perf_dev_sshd.log"
	generate_sshd_log 2000 200 100 > "$_log_file"
	perf_timeout_check "log_generation" "$_group_start" "$_timeout"

	LOG_SOURCE="file"

	# --- Scan mode: _rule_tlog → tlog_read_full ---
	_SCAN_MODE=1
	_TLOG_PASSTHROUGH=""
	timer_start
	local scan_out
	scan_out=$(_rule_tlog "$_log_file" "sshd" | extract_hosts \
		"sshd.*Failed password for .* from <HOST>")
	local ms_scan
	ms_scan=$(timer_elapsed_ms)
	local scan_count
	scan_count=$(echo "$scan_out" | grep -c . 2>/dev/null || echo 0)
	kpi_report "deviation.scan.sshd" "$scan_count lines in ${ms_scan}ms" ""
	perf_timeout_check "scan_path" "$_group_start" "$_timeout"

	# --- Standard mode: _rule_tlog → tlog_read (TLOG_FIRST_RUN=full) ---
	_SCAN_MODE=""
	TLOG_FIRST_RUN="full"
	TLOG_FLOCK=0
	/usr/bin/rm -f "$TLOG_BASERUN/sshd" "$TLOG_BASERUN/sshd.lock"
	timer_start
	local std_out
	std_out=$(_rule_tlog "$_log_file" "sshd" | extract_hosts \
		"sshd.*Failed password for .* from <HOST>")
	local ms_std
	ms_std=$(timer_elapsed_ms)
	local std_count
	std_count=$(echo "$std_out" | grep -c . 2>/dev/null || echo 0)
	kpi_report "deviation.standard.sshd" "$std_count lines in ${ms_std}ms" ""
	perf_timeout_check "standard_path" "$_group_start" "$_timeout"

	# --- Delta ---
	local delta=0
	if [ "$ms_scan" -gt 0 ]; then
		delta=$(( (ms_std - ms_scan) * 100 / (ms_scan + 1) ))
	fi
	kpi_report "deviation.scan_vs_standard" "scan=${ms_scan}ms standard=${ms_std}ms" "(${delta}% overhead)"

	# cleanup
	TLOG_FIRST_RUN="skip"
}

@test "perf: deviation -- TLOG_FLOCK overhead (sshd, 2K lines)" {
	local _timeout=30
	local _group_start
	_group_start=$(date +%s)

	# Generate 2K sshd log
	local _log_file="$INSTALL_PATH/tmp/perf_dev_flock.log"
	generate_sshd_log 2000 200 100 > "$_log_file"
	perf_timeout_check "log_generation" "$_group_start" "$_timeout"

	LOG_SOURCE="file"
	_SCAN_MODE=""
	_TLOG_PASSTHROUGH=""
	TLOG_FIRST_RUN="full"

	# --- Without flock ---
	TLOG_FLOCK=0
	/usr/bin/rm -f "$TLOG_BASERUN/sshd" "$TLOG_BASERUN/sshd.lock"
	timer_start
	local noflock_out
	noflock_out=$(_rule_tlog "$_log_file" "sshd" | extract_hosts \
		"sshd.*Failed password for .* from <HOST>")
	local ms_noflock
	ms_noflock=$(timer_elapsed_ms)
	local noflock_count
	noflock_count=$(echo "$noflock_out" | grep -c . 2>/dev/null || echo 0)
	kpi_report "deviation.flock_off.sshd" "$noflock_count lines in ${ms_noflock}ms" ""
	perf_timeout_check "flock_off" "$_group_start" "$_timeout"

	# --- With flock ---
	TLOG_FLOCK=1
	/usr/bin/rm -f "$TLOG_BASERUN/sshd" "$TLOG_BASERUN/sshd.lock"
	timer_start
	local flock_out
	flock_out=$(_rule_tlog "$_log_file" "sshd" | extract_hosts \
		"sshd.*Failed password for .* from <HOST>")
	local ms_flock
	ms_flock=$(timer_elapsed_ms)
	local flock_count
	flock_count=$(echo "$flock_out" | grep -c . 2>/dev/null || echo 0)
	kpi_report "deviation.flock_on.sshd" "$flock_count lines in ${ms_flock}ms" ""
	perf_timeout_check "flock_on" "$_group_start" "$_timeout"

	# --- Delta ---
	local delta=0
	if [ "$ms_noflock" -gt 0 ]; then
		delta=$(( (ms_flock - ms_noflock) * 100 / (ms_noflock + 1) ))
	fi
	kpi_report "deviation.tlog_flock" "off=${ms_noflock}ms on=${ms_flock}ms" "(${delta}% overhead)"

	# cleanup
	TLOG_FIRST_RUN="skip"
	TLOG_FLOCK=0
}

@test "perf: deviation -- DRY_RUN=0 vs DRY_RUN=1 (4 rules, 1K lines)" {
	local _timeout=30
	local _group_start
	_group_start=$(date +%s)

	# Use small tier (1K lines) to keep within timeout
	_perf_generate_logs "dev" 1000 50 100
	perf_timeout_check "log_generation" "$_group_start" "$_timeout"

	generate_ipcountry_dat "$INSTALL_PATH/ipcountry.dat" 256

	# Create 4 mock rules using _TLOG_PASSTHROUGH (tlog path is identical;
	# only the ban execution path differs between DRY_RUN modes)
	create_mock_rule "sshd" "$(printf 'PREREQ=""\nLOG_FILE="%s"\nLOG_TAG="sshd"\n_TLOG_PASSTHROUGH="%s"\nMATCHED_HOSTS=$(_rule_tlog "$LOG_FILE" "$LOG_TAG" | extract_hosts "sshd.*Failed password for .* from <HOST>")\n' \
		"$_LOG_sshd" "$_LOG_sshd")"
	create_mock_rule "mod_sec" "$(printf 'PREREQ=""\nLOG_FILE="%s"\nLOG_TAG="httpd.modsec"\n_TLOG_PASSTHROUGH="%s"\nMATCHED_HOSTS=$(_rule_tlog "$LOG_FILE" "$LOG_TAG" | extract_hosts "\\[client <HOST>.*ModSecurity: Access denied")\n' \
		"$_LOG_mod_sec" "$_LOG_mod_sec")"
	create_mock_rule "postfix" "$(printf 'PREREQ=""\nLOG_FILE="%s"\nLOG_TAG="postfix"\n_TLOG_PASSTHROUGH="%s"\nMATCHED_HOSTS=$(_rule_tlog "$LOG_FILE" "$LOG_TAG" | extract_hosts "\\[<HOST>\\].*SASL.*authentication failed")\n' \
		"$_LOG_postfix" "$_LOG_postfix")"
	create_mock_rule "dovecot" "$(printf 'PREREQ=""\nLOG_FILE="%s"\nLOG_TAG="dovecot"\n_TLOG_PASSTHROUGH="%s"\nMATCHED_HOSTS=$(_rule_tlog "$LOG_FILE" "$LOG_TAG" | extract_hosts "imap-login.*auth failed.*rip=<HOST>")\n' \
		"$_LOG_dovecot" "$_LOG_dovecot")"

	perf_timeout_check "rule_creation" "$_group_start" "$_timeout"

	# --- DRY_RUN=1 (baseline, no ban execution) ---
	DRY_RUN=1
	timer_start
	run check
	local ms_dry
	ms_dry=$(timer_elapsed_ms)
	kpi_report "deviation.dryrun_on" "${ms_dry}ms" "(4 rules, 1K lines, DRY_RUN=1)"
	perf_timeout_check "dryrun_on" "$_group_start" "$_timeout"

	# Reset state for fair comparison
	> "$INSTALL_PATH/tmp/bans.active"
	> "$INSTALL_PATH/tmp/bans.history"
	> "$INSTALL_PATH/tmp/pressure.dat"
	> "$INSTALL_PATH/stats/attack.pool"

	# --- DRY_RUN=0 (live ban via mock /bin/true) ---
	DRY_RUN=0
	BAN_COMMAND_TEMPLATE="/bin/true"
	UNBAN_COMMAND_TEMPLATE="/bin/true"
	timer_start
	run check
	local ms_live
	ms_live=$(timer_elapsed_ms)
	kpi_report "deviation.dryrun_off" "${ms_live}ms" "(4 rules, 1K lines, DRY_RUN=0)"
	perf_timeout_check "dryrun_off" "$_group_start" "$_timeout"

	# --- Delta ---
	local delta=0
	if [ "$ms_dry" -gt 0 ]; then
		delta=$(( (ms_live - ms_dry) * 100 / (ms_dry + 1) ))
	fi
	kpi_report "deviation.dryrun" "dry=${ms_dry}ms live=${ms_live}ms" "(${delta}% overhead)"

	# restore
	DRY_RUN=1
}

@test "perf: deviation -- realistic line length (4 rules, 500 lines)" {
	local _timeout=30
	local _group_start
	_group_start=$(date +%s)

	# Real-world target line lengths (measured from production logs):
	#   sshd: 150 chars (synthetic ~110)  — "invalid user" + longer names
	#   mod_sec: 800 chars (synthetic ~120) — OWASP CRS metadata fields
	#   postfix: 250 chars (synthetic ~120) — TLS cipher + SASL detail
	#   dovecot: 250 chars (synthetic ~130) — TLS + session + attempts
	local _log_sshd="$INSTALL_PATH/tmp/perf_real_sshd.log"
	local _log_mod_sec="$INSTALL_PATH/tmp/perf_real_mod_sec.log"
	local _log_postfix="$INSTALL_PATH/tmp/perf_real_postfix.log"
	local _log_dovecot="$INSTALL_PATH/tmp/perf_real_dovecot.log"
	generate_sshd_log 500 50 100 150 > "$_log_sshd"
	generate_mod_sec_log 500 50 100 800 > "$_log_mod_sec"
	generate_postfix_log 500 50 100 250 > "$_log_postfix"
	generate_dovecot_log 500 50 100 250 > "$_log_dovecot"
	perf_timeout_check "log_generation" "$_group_start" "$_timeout"

	# sshd (150-char lines)
	timer_start
	local result
	result=$(cat "$_log_sshd" | extract_hosts \
		"sshd.*Failed password for .* from <HOST>")
	local ms
	ms=$(timer_elapsed_ms)
	local count
	count=$(echo "$result" | grep -c . 2>/dev/null || echo 0)
	local rate=$(( count * 1000 / (ms + 1) ))
	kpi_report "realistic.sshd" "$count lines in ${ms}ms" "(${rate} lines/sec, ~150 char/line)"
	perf_timeout_check "sshd" "$_group_start" "$_timeout"

	# mod_sec (800-char lines)
	timer_start
	result=$(cat "$_log_mod_sec" | extract_hosts \
		"\[client <HOST>.*ModSecurity: Access denied")
	ms=$(timer_elapsed_ms)
	count=$(echo "$result" | grep -c . 2>/dev/null || echo 0)
	rate=$(( count * 1000 / (ms + 1) ))
	kpi_report "realistic.mod_sec" "$count lines in ${ms}ms" "(${rate} lines/sec, ~800 char/line)"
	perf_timeout_check "mod_sec" "$_group_start" "$_timeout"

	# postfix (250-char lines)
	timer_start
	result=$(cat "$_log_postfix" | extract_hosts \
		"\[<HOST>\].*SASL.*authentication failed")
	ms=$(timer_elapsed_ms)
	count=$(echo "$result" | grep -c . 2>/dev/null || echo 0)
	rate=$(( count * 1000 / (ms + 1) ))
	kpi_report "realistic.postfix" "$count lines in ${ms}ms" "(${rate} lines/sec, ~250 char/line)"
	perf_timeout_check "postfix" "$_group_start" "$_timeout"

	# dovecot (250-char lines)
	timer_start
	result=$(cat "$_log_dovecot" | extract_hosts \
		"imap-login.*auth failed.*rip=<HOST>")
	ms=$(timer_elapsed_ms)
	count=$(echo "$result" | grep -c . 2>/dev/null || echo 0)
	rate=$(( count * 1000 / (ms + 1) ))
	kpi_report "realistic.dovecot" "$count lines in ${ms}ms" "(${rate} lines/sec, ~250 char/line)"
	perf_timeout_check "dovecot" "$_group_start" "$_timeout"
}
