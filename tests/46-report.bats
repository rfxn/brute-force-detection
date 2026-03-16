#!/usr/bin/env bats
#
# Tests for periodic threat report functions
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

# Load apool/ban-status functions from files/bfd (not in bfd.lib.sh)
bfd_load_function _apool_summary_awk
bfd_load_function _apool_awk
bfd_load_function _apool_service_dual_awk
bfd_load_function _batch_ban_status_init
bfd_load_function _batch_ban_status_lookup
bfd_load_function _batch_ban_status_cleanup

setup() {
	bfd_standard_setup
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
	# Ban breakdown stats
	[ -n "$REPORT_TOTAL_BANS" ]
	[ -n "$REPORT_TEMP_BANS" ]
	[ -n "$REPORT_PERM_BANS" ]
	[ -n "$REPORT_ESCALATIONS" ]
	[ -n "$REPORT_TOP_COUNTRIES" ]
}

@test "report_data: ban breakdown counts correct" {
	bfd_require_bash42
	local pool="$INSTALL_PATH/stats/attack.pool"
	APOOL_LIST="$pool"
	local now
	now=$(date +%s)
	# 2 temporary bans (DURATION>0, ACTION=ban)
	echo "$((now - 100)) 192.0.2.1 sshd 1 CN ban 600 22 15000 service" >> "$pool"
	echo "$((now - 200)) 192.0.2.2 sshd 1 RU ban 600 22 15000 service" >> "$pool"
	# 1 permanent ban (DURATION=0, ACTION=ban)
	echo "$((now - 300)) 192.0.2.3 dovecot 1 BR ban 0 143 20000 service" >> "$pool"
	# 1 escalation (ACTION=escalate)
	echo "$((now - 400)) 192.0.2.1 sshd 1 CN escalate 0 22 25000 service" >> "$pool"
	# 1 observed (not a ban)
	echo "$((now - 500)) 192.0.2.4 postfix 1 US observed 0 25 5000 service" >> "$pool"
	# 1 ban-failed
	echo "$((now - 600)) 192.0.2.5 sshd 1 IN ban-failed 0 22 15000 service" >> "$pool"

	_report_init "daily"
	_report_data "$pool"

	[ "$REPORT_TOTAL_BANS" = "4" ]
	[ "$REPORT_TEMP_BANS" = "2" ]
	[ "$REPORT_ESCALATIONS" = "1" ]
	[ "$REPORT_PERM_BANS" = "2" ]
	[ "$REPORT_BAN_FAILED" = "1" ]
}

@test "report_data: repeat offenders counts only ban actions" {
	bfd_require_bash42
	local pool="$INSTALL_PATH/stats/attack.pool"
	APOOL_LIST="$pool"
	local now
	now=$(date +%s)
	# IP banned twice (repeat offender)
	echo "$((now - 100)) 192.0.2.1 sshd 1 CN ban 600 22 15000 service" >> "$pool"
	echo "$((now - 200)) 192.0.2.1 sshd 1 CN ban 600 22 15000 service" >> "$pool"
	# IP with observed + ban (NOT repeat — only 1 ban)
	echo "$((now - 300)) 192.0.2.2 sshd 1 RU observed 0 22 10000 service" >> "$pool"
	echo "$((now - 400)) 192.0.2.2 sshd 1 RU ban 600 22 15000 service" >> "$pool"
	# IP with only observed (not counted at all)
	echo "$((now - 500)) 192.0.2.3 sshd 1 BR observed 0 22 5000 service" >> "$pool"

	_report_init "daily"
	_report_data "$pool"

	# Only 192.0.2.1 is a repeat offender (2 bans)
	[ "$REPORT_REPEAT_OFFENDERS" = "1" ]
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
