#!/usr/bin/env bats
#
# Test suite for CIDR alert enrichment — _alert_set_entry_vars with sidecar
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

setup() {
	bfd_standard_setup
	BAN_COMMAND_TEMPLATE="echo ban \$ATTACK_HOST"
	_FW_BACKEND="custom"
	BAN_ESCALATE_AFTER="0"
	BAN_ESCALATION="none"
	EMAIL_REPUTATION_LINKS=""
	SUBNET_ALERT_TOP_N="5"
}

teardown() {
	bfd_teardown
}

# helper: create a sidecar file for a given subnet
_create_sidecar() {
	local subnet="$1" unique="$2" failures="$3" pressure="$4"
	shift 4
	local san_subnet
	san_subnet=$(printf '%s' "$subnet" | tr ':' '-' | tr '/' '_')
	local sidecar="$INSTALL_PATH/tmp/.cidr_detail_${san_subnet}"
	echo "HEADER $subnet $unique $failures $pressure" > "$sidecar"
	# remaining args are "ip mod fail_count pressure_scaled" lines
	while [ $# -gt 0 ]; do
		echo "$1" >> "$sidecar"
		shift
	done
}

# ============================================================
# FAIL_COUNT_DISPLAY
# ============================================================

@test "CIDR alert: FAIL_COUNT_DISPLAY shows 'N across M IPs'" {
	_create_sidecar "192.0.2.0/24" 3 47 47000 \
		"192.0.2.12 sshd 20 20000" \
		"192.0.2.88 sshd 15 15000" \
		"192.0.2.201 sshd 12 12000"

	local line="192.0.2.0/24|sshd|all|47000|0|ban|0|(multiple)|root|5|300|1|47"
	_alert_set_entry_vars "$line" 1 1
	[ "$FAIL_COUNT_DISPLAY" = "47 across 3 IPs" ]
	[ "$FAIL_COUNT" = "47" ]
	[ "$SUBNET_IP_COUNT" = "3" ]
}

@test "non-CIDR alert: FAIL_COUNT_DISPLAY equals FAIL_COUNT" {
	local line="192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|root|10|300|1|5"
	_alert_set_entry_vars "$line" 1 1
	[ "$FAIL_COUNT_DISPLAY" = "5" ]
	[ "$SUBNET_IP_COUNT" = "" ]
}

# ============================================================
# Contributing hosts table
# ============================================================

@test "CIDR alert: SOURCE_LOGS_SECTION_TEXT contains contributing hosts" {
	_create_sidecar "192.0.2.0/24" 3 47 47000 \
		"192.0.2.12 mod_sec 14 14000" \
		"192.0.2.88 sshd 9 9000" \
		"192.0.2.201 sshd 8 8000"

	local line="192.0.2.0/24|sshd|all|47000|0|ban|0|(multiple)|root|5|300|1|47"
	_alert_set_entry_vars "$line" 1 1
	[[ "$SOURCE_LOGS_SECTION_TEXT" == *"Contributing hosts"* ]]
	[[ "$SOURCE_LOGS_SECTION_TEXT" == *"192.0.2.12"* ]]
	[[ "$SOURCE_LOGS_SECTION_TEXT" == *"192.0.2.88"* ]]
	[[ "$SOURCE_LOGS_SECTION_TEXT" == *"192.0.2.201"* ]]
}

@test "CIDR alert: SOURCE_LOGS_SECTION_HTML contains styled table" {
	_create_sidecar "192.0.2.0/24" 2 10 10000 \
		"192.0.2.1 sshd 6 6000" \
		"192.0.2.2 sshd 4 4000"

	local line="192.0.2.0/24|sshd|all|10000|0|ban|0|(multiple)|root|5|300|1|10"
	_alert_set_entry_vars "$line" 1 1
	[[ "$SOURCE_LOGS_SECTION_HTML" == *"<table"* ]] || [[ "$SOURCE_LOGS_SECTION_HTML" == *"<div"* ]]
	[[ "$SOURCE_LOGS_SECTION_HTML" == *"192.0.2.1"* ]]
}

@test "CIDR alert: SUBNET_HOSTS_SECTION is JSON-escaped for messaging" {
	_create_sidecar "192.0.2.0/24" 2 10 10000 \
		"192.0.2.1 sshd 6 6000" \
		"192.0.2.2 sshd 4 4000"

	local line="192.0.2.0/24|sshd|all|10000|0|ban|0|(multiple)|root|5|300|1|10"
	_alert_set_entry_vars "$line" 1 1
	[[ "$SUBNET_HOSTS_SECTION" == *"192.0.2.1"* ]]
	[ -n "$SUBNET_HOSTS_SECTION" ]
	# JSON-escaped: literal newlines converted to \n sequences
	[[ "$SUBNET_HOSTS_SECTION" != *$'\n'* ]]
}

@test "CIDR alert: SUBNET_HOSTS_SECTION_TG is Telegram-escaped" {
	_create_sidecar "192.0.2.0/24" 2 10 10000 \
		"192.0.2.1 sshd 6 6000" \
		"192.0.2.2 sshd 4 4000"

	local line="192.0.2.0/24|sshd|all|10000|0|ban|0|(multiple)|root|5|300|1|10"
	_alert_set_entry_vars "$line" 1 1
	[[ "$SUBNET_HOSTS_SECTION_TG" == *"192\.0\.2\.1"* ]]
	[ -n "$SUBNET_HOSTS_SECTION_TG" ]
}

@test "non-CIDR alert: SUBNET_HOSTS_SECTION is empty" {
	local line="192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|root|10|300|1|5"
	_alert_set_entry_vars "$line" 1 1
	[ "$SUBNET_HOSTS_SECTION" = "" ]
	[ "$SUBNET_HOSTS_SECTION_TG" = "" ]
}

# ============================================================
# Sidecar fallback
# ============================================================

@test "CIDR alert: missing sidecar falls back to static message" {
	# no sidecar created — simulate race/cleanup
	local line="192.0.2.0/24|sshd|all|47000|0|ban|0|(multiple)|root|5|300|1|47"
	_alert_set_entry_vars "$line" 1 1
	# FAIL_COUNT_DISPLAY still works from field 13 alone, but no IP count
	[ "$FAIL_COUNT_DISPLAY" = "47" ]
	[[ "$SOURCE_LOGS_SECTION_TEXT" == *"not available"* ]]
	[ "$SUBNET_HOSTS_SECTION" = "" ]
	[ "$SUBNET_HOSTS_SECTION_TG" = "" ]
}

@test "CIDR alert: sidecar with OVERFLOW shows overflow line" {
	_create_sidecar "10.0.0.0/24" 6 47 47000 \
		"10.0.0.1 sshd 14 14000" \
		"10.0.0.2 sshd 9 9000" \
		"OVERFLOW 4"

	local line="10.0.0.0/24|sshd|all|47000|0|ban|0|(multiple)|root|5|300|1|47"
	_alert_set_entry_vars "$line" 1 1
	[[ "$SOURCE_LOGS_SECTION_TEXT" == *"4 more"* ]]
	[ "$SUBNET_IP_COUNT" = "6" ]
}

@test "CIDR alert: sidecar cleaned up after reading" {
	_create_sidecar "192.0.2.0/24" 2 10 10000 \
		"192.0.2.1 sshd 6 6000" \
		"192.0.2.2 sshd 4 4000"

	local line="192.0.2.0/24|sshd|all|10000|0|ban|0|(multiple)|root|5|300|1|10"
	_alert_set_entry_vars "$line" 1 1
	[ ! -f "$INSTALL_PATH/tmp/.cidr_detail_192.0.2.0_24" ]
}

# ============================================================
# End-to-end integration
# ============================================================

@test "E2E: CIDR ban produces enriched alert with correct template vars" {
	local now=1000000
	local events_file="$INSTALL_PATH/tmp/pressure.dat"
	local alerts_file="$TEST_TMPDIR/alerts"
	touch "$alerts_file"

	# 4 IPs in same /24 with varying weights
	echo "$now 10.0.0.1 sshd 3" >> "$events_file"
	echo "$now 10.0.0.1 sshd 3" >> "$events_file"
	echo "$now 10.0.0.2 sshd 2" >> "$events_file"
	echo "$now 10.0.0.3 sshd 1" >> "$events_file"
	echo "$now 10.0.0.4 sshd 1" >> "$events_file"

	SUBNET_TRIG="3"
	SUBNET_MASK="24"
	SUBNET_MASK_V6="48"
	TRIG_WINDOW="300"
	EMAIL_ALERTS="1"
	EMAIL_ADDRESS="admin@example.com"
	SUBNET_ALERT_TOP_N="3"
	BAN_DURATION="600"

	# run check_distributed to generate alert line + sidecar
	check_distributed "$INSTALL_PATH" "$TRIG_WINDOW" "$now" "$alerts_file" >/dev/null

	# verify alert line exists
	[ -s "$alerts_file" ]

	# read the alert line and render template vars
	local line
	line=$(head -1 "$alerts_file")
	_alert_set_entry_vars "$line" 1 1

	# total_failures = 2+1+1+1 = 5
	[ "$FAIL_COUNT" = "5" ]
	# FAIL_COUNT_DISPLAY includes IP count
	[ "$FAIL_COUNT_DISPLAY" = "5 across 4 IPs" ]
	# total_pressure_raw = 3+3+2+1+1 = 10, field 4 = 10000 -> PRESSURE = "10.0"
	[ "$PRESSURE" = "10.0" ]
	# contributing hosts table populated
	[[ "$SOURCE_LOGS_SECTION_TEXT" == *"Contributing hosts"* ]]
	[[ "$SOURCE_LOGS_SECTION_TEXT" == *"10.0.0.1"* ]]
	# SUBNET_HOSTS_SECTION populated for messaging (JSON-escaped)
	[[ "$SUBNET_HOSTS_SECTION" == *"10.0.0.1"* ]]
	# Telegram variant also populated
	[[ "$SUBNET_HOSTS_SECTION_TG" == *"10\.0\.0\.1"* ]]
	# sidecar cleaned up
	[ ! -f "$INSTALL_PATH/tmp/.cidr_detail_10.0.0.0_24" ]

	# TOP_N=3 with 4 IPs — overflow present
	# (OVERFLOW is in the text but was consumed when sidecar was read)
	[[ "$SOURCE_LOGS_SECTION_TEXT" == *"1 more"* ]]
}

@test "E2E: SUBNET_TRIG=1 single-IP subnet triggers enriched alert" {
	local now=1000000
	local events_file="$INSTALL_PATH/tmp/pressure.dat"
	local alerts_file="$TEST_TMPDIR/alerts"
	touch "$alerts_file"

	# single IP, 3 events at weight 2
	echo "$now 10.0.0.5 sshd 2" >> "$events_file"
	echo "$now 10.0.0.5 sshd 2" >> "$events_file"
	echo "$now 10.0.0.5 sshd 2" >> "$events_file"

	SUBNET_TRIG="1"
	SUBNET_MASK="24"
	SUBNET_MASK_V6="48"
	TRIG_WINDOW="300"
	EMAIL_ALERTS="1"
	EMAIL_ADDRESS="admin@example.com"
	SUBNET_ALERT_TOP_N="5"
	BAN_DURATION="600"

	check_distributed "$INSTALL_PATH" "$TRIG_WINDOW" "$now" "$alerts_file" >/dev/null
	[ -s "$alerts_file" ]

	local line
	line=$(head -1 "$alerts_file")
	_alert_set_entry_vars "$line" 1 1

	# total_failures = 3 (3 events), total_pressure_raw = 6 (3*2)
	[ "$FAIL_COUNT" = "3" ]
	[ "$FAIL_COUNT_DISPLAY" = "3 across 1 IPs" ]
	[ "$SUBNET_IP_COUNT" = "1" ]
	[ "$PRESSURE" = "6.0" ]
	# contributing hosts table has the single IP
	[[ "$SOURCE_LOGS_SECTION_TEXT" == *"10.0.0.5"* ]]
	# no overflow with 1 IP and TOP_N=5
	[[ "$SOURCE_LOGS_SECTION_TEXT" != *"more"* ]]
}

@test "E2E: single-IP alert unaffected by CIDR enrichment" {
	# verify non-CIDR path is clean
	BAN_COMMAND_TEMPLATE="echo ban \$ATTACK_HOST"
	_FW_BACKEND="custom"
	local line="192.0.2.1|sshd|22|18400|0|ban|0|/dev/null|root|10|300|3|6"
	_alert_set_entry_vars "$line" 1 1
	[ "$FAIL_COUNT" = "6" ]
	[ "$FAIL_COUNT_DISPLAY" = "6" ]
	[ "$SUBNET_IP_COUNT" = "" ]
	[ "$SUBNET_HOSTS_SECTION" = "" ]
	[ "$SUBNET_HOSTS_SECTION_TG" = "" ]
	[ "$PRESSURE" = "18.4" ]
	[ "$PRESSURE_CONTRIB" = "18" ]
}
