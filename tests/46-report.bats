#!/usr/bin/env bats
#
# Tests for periodic threat report functions
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

setup() {
	bfd_standard_setup
	UTIME=$(date +"%s")
	# Load report functions
	# shellcheck disable=SC1091
	source "$PROJECT_ROOT/files/internals/bfd_report.sh"
}

teardown() {
	bfd_teardown
}

# --- _report_init ---

@test "report_init: daily sets correct window vars" {
	_report_init "daily"
	[ "$_RPT_LABEL" = "Daily" ]
	[ "$_RPT_WINDOW" = "24h" ]
	[ "$_RPT_CUTOFF" -gt 0 ]
	[ "$_RPT_PREV_CUTOFF" -gt 0 ]
	[ "$_RPT_PREV_CUTOFF" -lt "$_RPT_CUTOFF" ]
}

@test "report_init: weekly sets 7d window" {
	_report_init "weekly"
	[ "$_RPT_LABEL" = "Weekly" ]
	[ "$_RPT_WINDOW" = "7d" ]
}

@test "report_init: monthly sets 30d window" {
	_report_init "monthly"
	[ "$_RPT_LABEL" = "Monthly" ]
	[ "$_RPT_WINDOW" = "30d" ]
}

@test "report_init: invalid interval returns error" {
	run _report_init "hourly"
	assert_failure
	assert_output --partial "invalid report interval"
}

# --- _report_trend_awk ---

@test "trend_awk: computes current and prior window totals" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	local now
	now=$(date +%s)
	# 3 events in current window (last 24h)
	echo "$((now - 100)) 192.0.2.1 sshd 1 CN ban 600 22 15000 service" >> "$pool"
	echo "$((now - 200)) 192.0.2.2 sshd 1 RU ban 600 22 15000 service" >> "$pool"
	echo "$((now - 300)) 192.0.2.1 dovecot 1 CN ban 600 143 15000 service" >> "$pool"
	# 1 event in prior window (24h-48h ago)
	echo "$((now - 90000)) 192.0.2.3 sshd 1 BR ban 600 22 15000 service" >> "$pool"
	# 1 event outside both windows (>48h ago)
	echo "$((now - 200000)) 192.0.2.4 sshd 1 US ban 600 22 15000 service" >> "$pool"

	local cutoff=$((now - 86400))
	local prev_cutoff=$((now - 172800))
	run _report_trend_awk "$pool" "$cutoff" "$prev_cutoff"
	assert_success
	# Current: 3 events, 2 unique IPs; Prior: 1 event, 1 unique IP
	assert_output "3|2|1|1"
}

@test "trend_awk: empty pool returns zeros" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	touch "$pool"
	local now
	now=$(date +%s)
	run _report_trend_awk "$pool" "$((now - 86400))" "$((now - 172800))"
	assert_success
	assert_output "0|0|0|0"
}

@test "trend_awk: all events in prior window" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	local now
	now=$(date +%s)
	echo "$((now - 90000)) 192.0.2.1 sshd 1 CN ban 600 22 15000 service" >> "$pool"
	echo "$((now - 95000)) 192.0.2.2 sshd 1 RU ban 600 22 15000 service" >> "$pool"
	local cutoff=$((now - 86400))
	local prev_cutoff=$((now - 172800))
	run _report_trend_awk "$pool" "$cutoff" "$prev_cutoff"
	assert_success
	assert_output "0|0|2|2"
}

# --- _report_data ---

@test "report_data: exports REPORT_* vars from populated pool" {
	bfd_require_bash42
	local pool="$INSTALL_PATH/stats/attack.pool"
	APOOL_LIST="$pool"
	local now
	now=$(date +%s)
	echo "$((now - 100)) 192.0.2.1 sshd 1 CN ban 600 22 15000 service" >> "$pool"
	echo "$((now - 200)) 192.0.2.2 sshd 1 RU observed 0 22 10000 service" >> "$pool"
	echo "$((now - 300)) 192.0.2.3 dovecot 1 BR ban 600 143 20000 service" >> "$pool"

	_report_init "daily"
	_report_data "$pool"

	[ -n "$REPORT_UNIQUE_IPS" ]
	[ "$REPORT_UNIQUE_IPS" -ge 1 ]
	[ -n "$REPORT_TOTAL_EVENTS" ]
	[ "$REPORT_TOTAL_EVENTS" -ge 1 ]
	[ -n "$REPORT_TREND_LABEL" ]
	[ -n "$REPORT_TOP_IPS_TEXT" ]
	[ -n "$REPORT_SERVICES_TEXT" ]
}

@test "report_data: empty pool sets zero counts" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	APOOL_LIST="$pool"
	touch "$pool"
	_report_init "daily"
	_report_data "$pool"
	[ "$REPORT_UNIQUE_IPS" = "0" ]
	[ "$REPORT_TOTAL_EVENTS" = "0" ]
}

@test "report_data: trend label computed correctly" {
	bfd_require_bash42
	local pool="$INSTALL_PATH/stats/attack.pool"
	APOOL_LIST="$pool"
	local now
	now=$(date +%s)
	# 5 current events
	local i
	for i in 1 2 3 4 5; do
		echo "$((now - i * 100)) 192.0.2.$i sshd 1 CN ban 600 22 15000 service" >> "$pool"
	done
	# 2 prior events
	echo "$((now - 90000)) 192.0.2.10 sshd 1 RU ban 600 22 15000 service" >> "$pool"
	echo "$((now - 91000)) 192.0.2.11 sshd 1 BR ban 600 22 15000 service" >> "$pool"

	_report_init "daily"
	_report_data "$pool"
	[ "$REPORT_TREND_DIRECTION" = "up" ]
	[ -n "$REPORT_TREND_PCT" ]
}

# --- report() orchestrator ---

@test "report: daily with populated pool produces text output" {
	bfd_require_bash42
	local pool="$INSTALL_PATH/stats/attack.pool"
	APOOL_LIST="$pool"
	ALERT_TEMPLATE_DIR="$PROJECT_ROOT/files/alert"
	EMAIL_ALERTS="0"
	REPORT_ENABLED="1"
	V="2.0.1"
	local now
	now=$(date +%s)
	echo "$((now - 100)) 192.0.2.1 sshd 1 CN ban 600 22 15000 service" >> "$pool"
	echo "$((now - 200)) 192.0.2.2 sshd 1 RU observed 0 22 10000 service" >> "$pool"

	run report "daily"
	assert_success
	assert_output --partial "Daily Threat Report"
	assert_output --partial "Threat Summary"
	assert_output --partial "Unique IPs"
	assert_output --partial "Trend"
}

@test "report: empty pool produces no-activity message" {
	local pool="$INSTALL_PATH/stats/attack.pool"
	APOOL_LIST="$pool"
	ALERT_TEMPLATE_DIR="$PROJECT_ROOT/files/alert"
	EMAIL_ALERTS="0"
	V="2.0.1"
	touch "$pool"

	run report "daily"
	assert_success
	assert_output --partial "No threat activity"
}

@test "report: invalid interval returns error" {
	run report "biweekly"
	assert_failure
	assert_output --partial "invalid report interval"
}

@test "report: weekly interval produces output" {
	bfd_require_bash42
	local pool="$INSTALL_PATH/stats/attack.pool"
	APOOL_LIST="$pool"
	ALERT_TEMPLATE_DIR="$PROJECT_ROOT/files/alert"
	EMAIL_ALERTS="0"
	V="2.0.1"
	local now
	now=$(date +%s)
	echo "$((now - 100)) 192.0.2.1 sshd 1 CN ban 600 22 15000 service" >> "$pool"

	run report "weekly"
	assert_success
	assert_output --partial "Weekly Threat Report"
}

@test "report: monthly interval produces output" {
	bfd_require_bash42
	local pool="$INSTALL_PATH/stats/attack.pool"
	APOOL_LIST="$pool"
	ALERT_TEMPLATE_DIR="$PROJECT_ROOT/files/alert"
	EMAIL_ALERTS="0"
	V="2.0.1"
	local now
	now=$(date +%s)
	echo "$((now - 100)) 192.0.2.1 sshd 1 CN ban 600 22 15000 service" >> "$pool"

	run report "monthly"
	assert_success
	assert_output --partial "Monthly Threat Report"
}
