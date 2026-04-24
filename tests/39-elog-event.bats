#!/usr/bin/env bats
#
# Test suite for elog_event() structured event integration
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

setup() {
	bfd_common_setup
	# Ensure audit_file module is enabled (elog_init not called in unit tests)
	elog_output_enable "audit_file" 2>/dev/null || true
}

teardown() {
	bfd_teardown
}

# --- Basic dispatch ---

@test "elog_event: block_added writes to ELOG_AUDIT_FILE" {
	: > "$ELOG_AUDIT_FILE"
	elog_event "block_added" "warn" "{sshd} banned 192.0.2.1 via iptables" \
		"ip=192.0.2.1" "mod=sshd" "backend=iptables" "ports=all"
	[ "$(wc -l < "$ELOG_AUDIT_FILE")" -eq 1 ]
	grep -q '"type":"block_added"' "$ELOG_AUDIT_FILE"
}

@test "elog_event: does NOT write to ELOG_LOG_FILE" {
	: > "$ELOG_LOG_FILE"
	: > "$ELOG_AUDIT_FILE"
	elog_event "block_added" "warn" "{sshd} banned 192.0.2.1" \
		"ip=192.0.2.1" "mod=sshd"
	# audit file has the event
	[ "$(wc -l < "$ELOG_AUDIT_FILE")" -eq 1 ]
	# app log file should be empty — event source filter prevents this
	[ "$(wc -l < "$ELOG_LOG_FILE")" -eq 0 ]
}

@test "eout: does NOT write to ELOG_AUDIT_FILE" {
	: > "$ELOG_AUDIT_FILE"
	: > "$ELOG_LOG_FILE"
	eout "test app log message" le > /dev/null
	# app log written
	[ "$(wc -l < "$ELOG_LOG_FILE")" -ge 1 ]
	# audit file should be empty — elog source filter prevents this
	[ "$(wc -l < "$ELOG_AUDIT_FILE")" -eq 0 ]
}

# --- JSON envelope ---

@test "elog_event: JSON envelope has required fields" {
	: > "$ELOG_AUDIT_FILE"
	elog_event "config_loaded" "info" "configuration initialized"
	local line
	line=$(cat "$ELOG_AUDIT_FILE")
	# mandatory fields
	[[ "$line" == *'"ts":'* ]]
	[[ "$line" == *'"host":'* ]]
	[[ "$line" == *'"app":"bfd"'* ]]
	[[ "$line" == *'"pid":'* ]]
	[[ "$line" == *'"type":"config_loaded"'* ]]
	[[ "$line" == *'"level":"info"'* ]]
	[[ "$line" == *'"msg":"configuration initialized"'* ]]
}

@test "elog_event: key=value pairs in JSON" {
	: > "$ELOG_AUDIT_FILE"
	elog_event "block_added" "warn" "{sshd} banned 192.0.2.1" \
		"ip=192.0.2.1" "mod=sshd" "backend=iptables"
	local line
	line=$(cat "$ELOG_AUDIT_FILE")
	[[ "$line" == *'"ip":"192.0.2.1"'* ]]
	[[ "$line" == *'"mod":"sshd"'* ]]
	[[ "$line" == *'"backend":"iptables"'* ]]
}

@test "elog_event: {tag} extraction in JSON" {
	: > "$ELOG_AUDIT_FILE"
	elog_event "block_added" "warn" "{sshd} banned 192.0.2.1"
	local line
	line=$(cat "$ELOG_AUDIT_FILE")
	[[ "$line" == *'"tag":"sshd"'* ]]
	[[ "$line" == *'"msg":"banned 192.0.2.1"'* ]]
}

# --- Severity filtering ---

@test "elog_event: below ELOG_LEVEL is suppressed" {
	ELOG_LEVEL="3"
	: > "$ELOG_AUDIT_FILE"
	elog_event "config_loaded" "info" "should be filtered"
	[ "$(wc -l < "$ELOG_AUDIT_FILE")" -eq 0 ]
}

# --- Input validation ---

@test "elog_event: empty type returns 1" {
	run elog_event "" "info" "no type"
	assert_failure
	assert_output --partial "requires event_type"
}

@test "elog_event: empty message returns 0 with no output" {
	: > "$ELOG_AUDIT_FILE"
	run elog_event "config_loaded" "info" ""
	assert_success
	[ "$(wc -l < "$ELOG_AUDIT_FILE")" -eq 0 ]
}

# --- elog_init ---

@test "elog_init: creates ELOG_LOG_DIR and ELOG_AUDIT_FILE" {
	local init_dir="$TEST_TMPDIR/init_test"
	ELOG_LOG_DIR="$init_dir"
	ELOG_AUDIT_FILE="$init_dir/audit.log"
	ELOG_LOG_FILE="$init_dir/bfd.log"
	# reset init state to allow re-init
	_ELOG_INIT_DONE=0
	run elog_init
	assert_success
	[ -d "$init_dir" ]
	[ -f "$init_dir/audit.log" ]
	[ -f "$init_dir/bfd.log" ]
}

# --- Convenience wrapper ---

@test "elog_critical: convenience wrapper works" {
	: > "$ELOG_LOG_FILE"
	run elog_critical "critical test"
	assert_success
	assert_output --partial "critical test"
}

# --- Cross-contamination guard ---

@test "audit file empty after elog() calls only" {
	: > "$ELOG_AUDIT_FILE"
	: > "$ELOG_LOG_FILE"
	elog info "app message 1" > /dev/null
	elog warn "app message 2" > /dev/null
	elog error "app message 3" > /dev/null
	# app log has 3 entries
	[ "$(wc -l < "$ELOG_LOG_FILE")" -eq 3 ]
	# audit log should have zero
	[ "$(wc -l < "$ELOG_AUDIT_FILE")" -eq 0 ]
}

# --- Expanded event type coverage ---

@test "elog_event: block_escalated records escalation with IP and mod" {
	: > "$ELOG_AUDIT_FILE"
	elog_event "block_escalated" "warn" "{sshd} 192.0.2.1 escalated to permanent ban" \
		"ip=192.0.2.1" "mod=sshd" "recent_bans=5"
	[ "$(wc -l < "$ELOG_AUDIT_FILE")" -eq 1 ]
	grep -q '"type":"block_escalated"' "$ELOG_AUDIT_FILE"
	grep -q '"ip":"192.0.2.1"' "$ELOG_AUDIT_FILE"
	grep -q '"recent_bans":"5"' "$ELOG_AUDIT_FILE"
}

@test "elog_event: block_added with source=cli for manual ban" {
	: > "$ELOG_AUDIT_FILE"
	elog_event "block_added" "warn" "{manual} manual ban 192.0.2.1 via CLI" \
		"ip=192.0.2.1" "mod=manual" "source=cli" "ports=all"
	[ "$(wc -l < "$ELOG_AUDIT_FILE")" -eq 1 ]
	grep -q '"source":"cli"' "$ELOG_AUDIT_FILE"
	grep -q '"type":"block_added"' "$ELOG_AUDIT_FILE"
}

@test "elog_event: block_removed with source=cli for manual unban" {
	: > "$ELOG_AUDIT_FILE"
	elog_event "block_removed" "info" "{sshd} manual unban 192.0.2.1 via CLI" \
		"ip=192.0.2.1" "mod=sshd" "source=cli"
	[ "$(wc -l < "$ELOG_AUDIT_FILE")" -eq 1 ]
	grep -q '"source":"cli"' "$ELOG_AUDIT_FILE"
	grep -q '"type":"block_removed"' "$ELOG_AUDIT_FILE"
}

@test "elog_event: block_removed with count and mode for flush" {
	: > "$ELOG_AUDIT_FILE"
	elog_event "block_removed" "warn" "flush: 3 bans removed (mode=all)" \
		"count=3" "mode=all" "source=cli"
	[ "$(wc -l < "$ELOG_AUDIT_FILE")" -eq 1 ]
	grep -q '"count":"3"' "$ELOG_AUDIT_FILE"
	grep -q '"mode":"all"' "$ELOG_AUDIT_FILE"
}

@test "elog_event: alert_sent for email delivery" {
	: > "$ELOG_AUDIT_FILE"
	elog_event "alert_sent" "info" "email alert delivered" \
		"channel=email" "recipient=admin@example.com" "count=2" "format=text"
	[ "$(wc -l < "$ELOG_AUDIT_FILE")" -eq 1 ]
	grep -q '"type":"alert_sent"' "$ELOG_AUDIT_FILE"
	grep -q '"channel":"email"' "$ELOG_AUDIT_FILE"
	grep -q '"recipient":"admin@example.com"' "$ELOG_AUDIT_FILE"
}

@test "elog_event: alert_failed for email delivery failure" {
	: > "$ELOG_AUDIT_FILE"
	elog_event "alert_failed" "error" "email alert delivery failed" \
		"channel=email" "recipient=admin@example.com" "count=1"
	[ "$(wc -l < "$ELOG_AUDIT_FILE")" -eq 1 ]
	grep -q '"type":"alert_failed"' "$ELOG_AUDIT_FILE"
	grep -q '"level":"error"' "$ELOG_AUDIT_FILE"
}

@test "elog_event: alert_sent for messaging channel" {
	: > "$ELOG_AUDIT_FILE"
	elog_event "alert_sent" "info" "messaging alert delivered" \
		"channel=slack" "count=1"
	[ "$(wc -l < "$ELOG_AUDIT_FILE")" -eq 1 ]
	grep -q '"channel":"slack"' "$ELOG_AUDIT_FILE"
}

@test "elog_event: threat_detected for pressure trip" {
	: > "$ELOG_AUDIT_FILE"
	elog_event "threat_detected" "warn" "{sshd} pressure trip for 192.0.2.1" \
		"ip=192.0.2.1" "mod=sshd" "pressure=25000" "trip=20000" "trip_type=service"
	[ "$(wc -l < "$ELOG_AUDIT_FILE")" -eq 1 ]
	grep -q '"type":"threat_detected"' "$ELOG_AUDIT_FILE"
	grep -q '"pressure":"25000"' "$ELOG_AUDIT_FILE"
	grep -q '"trip_type":"service"' "$ELOG_AUDIT_FILE"
}

@test "elog_event: threat_detected for distributed attack" {
	: > "$ELOG_AUDIT_FILE"
	elog_event "threat_detected" "warn" "{sshd} distributed attack from 192.0.2.0/24" \
		"subnet=192.0.2.0/24" "mod=sshd" "unique_ips=5" "trip_type=subnet"
	[ "$(wc -l < "$ELOG_AUDIT_FILE")" -eq 1 ]
	grep -q '"subnet":"192.0.2.0/24"' "$ELOG_AUDIT_FILE"
	grep -q '"trip_type":"subnet"' "$ELOG_AUDIT_FILE"
}

@test "elog_event: threat_detected for CDN exclude" {
	: > "$ELOG_AUDIT_FILE"
	elog_event "threat_detected" "info" "{sshd} CDN exclude for 192.0.2.1" \
		"ip=192.0.2.1" "mod=sshd" "cdn_provider=cloudflare" "cdn_treatment=exclude"
	[ "$(wc -l < "$ELOG_AUDIT_FILE")" -eq 1 ]
	grep -q '"cdn_provider":"cloudflare"' "$ELOG_AUDIT_FILE"
	grep -q '"cdn_treatment":"exclude"' "$ELOG_AUDIT_FILE"
}

@test "elog_event: scan_started and scan_completed bracket a cycle" {
	: > "$ELOG_AUDIT_FILE"
	elog_event "scan_started" "info" "detection cycle started"
	elog_event "scan_completed" "info" "detection cycle completed" \
		"active_rules=12" "events=45" "bans=3" "elapsed=2"
	[ "$(wc -l < "$ELOG_AUDIT_FILE")" -eq 2 ]
	grep -q '"type":"scan_started"' "$ELOG_AUDIT_FILE"
	grep -q '"type":"scan_completed"' "$ELOG_AUDIT_FILE"
	grep -q '"bans":"3"' "$ELOG_AUDIT_FILE"
}

@test "elog_event: alert_sent for digest flush with mode=digest" {
	: > "$ELOG_AUDIT_FILE"
	elog_event "alert_sent" "info" "digest flush completed" \
		"channel=email" "count=5" "mode=digest"
	[ "$(wc -l < "$ELOG_AUDIT_FILE")" -eq 1 ]
	grep -q '"type":"alert_sent"' "$ELOG_AUDIT_FILE"
	grep -q '"mode":"digest"' "$ELOG_AUDIT_FILE"
	grep -q '"count":"5"' "$ELOG_AUDIT_FILE"
}

@test "elog_event: alert_failed for messaging channel (telegram)" {
	: > "$ELOG_AUDIT_FILE"
	elog_event "alert_failed" "error" "messaging alert delivery failed" \
		"channel=telegram" "count=2"
	[ "$(wc -l < "$ELOG_AUDIT_FILE")" -eq 1 ]
	grep -q '"channel":"telegram"' "$ELOG_AUDIT_FILE"
	grep -q '"type":"alert_failed"' "$ELOG_AUDIT_FILE"
}
