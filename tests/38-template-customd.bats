#!/usr/bin/env bats
#
# Test suite for alert/custom.d/ template override resolution
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

setup() {
	bfd_common_setup
	INSTALL_PATH="$TEST_TMPDIR/bfd"
	mkdir -p "$INSTALL_PATH/alert"
	# copy shipped templates to test location
	cp "$PROJECT_ROOT/files/alert/"*.tpl "$INSTALL_PATH/alert/"
	ALERT_TEMPLATE_DIR="$INSTALL_PATH/alert"
}

teardown() {
	bfd_teardown
}

# ===================================================================
# _alert_tpl_resolve — unit tests
# ===================================================================

@test "_alert_tpl_resolve: returns base path when custom.d does not exist" {
	_alert_tpl_resolve "$ALERT_TEMPLATE_DIR" "text.header.tpl"
	[ "$_ALERT_TPL_RESOLVED" = "$ALERT_TEMPLATE_DIR/text.header.tpl" ]
}

@test "_alert_tpl_resolve: returns base path when custom.d exists but file does not" {
	mkdir -p "$ALERT_TEMPLATE_DIR/custom.d"
	_alert_tpl_resolve "$ALERT_TEMPLATE_DIR" "text.header.tpl"
	[ "$_ALERT_TPL_RESOLVED" = "$ALERT_TEMPLATE_DIR/text.header.tpl" ]
}

@test "_alert_tpl_resolve: returns custom.d path when override file exists" {
	mkdir -p "$ALERT_TEMPLATE_DIR/custom.d"
	echo "CUSTOM HEADER" > "$ALERT_TEMPLATE_DIR/custom.d/text.header.tpl"
	_alert_tpl_resolve "$ALERT_TEMPLATE_DIR" "text.header.tpl"
	[ "$_ALERT_TPL_RESOLVED" = "$ALERT_TEMPLATE_DIR/custom.d/text.header.tpl" ]
}

@test "_alert_tpl_resolve: per-file granularity (override one, default for others)" {
	mkdir -p "$ALERT_TEMPLATE_DIR/custom.d"
	echo "CUSTOM" > "$ALERT_TEMPLATE_DIR/custom.d/html.entry.tpl"
	# overridden file resolves to custom.d
	_alert_tpl_resolve "$ALERT_TEMPLATE_DIR" "html.entry.tpl"
	[ "$_ALERT_TPL_RESOLVED" = "$ALERT_TEMPLATE_DIR/custom.d/html.entry.tpl" ]
	# non-overridden file resolves to base
	_alert_tpl_resolve "$ALERT_TEMPLATE_DIR" "html.header.tpl"
	[ "$_ALERT_TPL_RESOLVED" = "$ALERT_TEMPLATE_DIR/html.header.tpl" ]
}

# ===================================================================
# Rendering integration — custom.d overrides used by render pipeline
# ===================================================================

@test "_alert_render_text: uses custom.d override for text.header.tpl" {
	mkdir -p "$ALERT_TEMPLATE_DIR/custom.d"
	echo "CUSTOM TEXT HEADER for {{HOSTNAME}}" > "$ALERT_TEMPLATE_DIR/custom.d/text.header.tpl"
	local af="$TEST_TMPDIR/alerts"
	echo "192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|root|5|300|3|5" > "$af"
	run _alert_render_text "$af" "$ALERT_TEMPLATE_DIR" "50"
	assert_success
	# custom header rendered
	assert_output --partial "CUSTOM TEXT HEADER for"
}

@test "_alert_render_html: uses custom.d override for html.entry.tpl" {
	mkdir -p "$ALERT_TEMPLATE_DIR/custom.d"
	echo "<div class=\"custom-entry\">{{HOST}} {{BAN_TYPE}}</div>" > "$ALERT_TEMPLATE_DIR/custom.d/html.entry.tpl"
	local af="$TEST_TMPDIR/alerts"
	echo "192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|root|5|300|3|5" > "$af"
	run _alert_render_html "$af" "$ALERT_TEMPLATE_DIR" "50"
	assert_success
	# custom entry rendered (has our custom class)
	assert_output --partial "custom-entry"
	# shipped header still renders (not overridden)
	assert_output --partial "<!DOCTYPE html>"
}

@test "_alert_render_text: works normally when custom.d is empty directory" {
	mkdir -p "$ALERT_TEMPLATE_DIR/custom.d"
	local af="$TEST_TMPDIR/alerts"
	echo "192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|root|5|300|3|5" > "$af"
	run _alert_render_text "$af" "$ALERT_TEMPLATE_DIR" "50"
	assert_success
	# shipped templates render normally (format C header: "[BFD] <host> · ...")
	assert_output --partial "[BFD]"
}

@test "_alert_render_html: mixed custom.d and default templates render correctly" {
	mkdir -p "$ALERT_TEMPLATE_DIR/custom.d"
	# override only the footer
	echo "<p>Custom footer {{BFD_VERSION}}</p>" > "$ALERT_TEMPLATE_DIR/custom.d/html.footer.tpl"
	local af="$TEST_TMPDIR/alerts"
	echo "192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|root|5|300|3|5" > "$af"
	run _alert_render_html "$af" "$ALERT_TEMPLATE_DIR" "50"
	assert_success
	# shipped header (not overridden)
	assert_output --partial "<!DOCTYPE html>"
	# custom footer
	assert_output --partial "Custom footer"
}

# ===================================================================
# Health check — custom override reporting
# ===================================================================

@test "_hc_alerts: reports custom overrides when present" {
	mkdir -p "$ALERT_TEMPLATE_DIR/custom.d"
	echo "custom" > "$ALERT_TEMPLATE_DIR/custom.d/html.entry.tpl"
	echo "custom" > "$ALERT_TEMPLATE_DIR/custom.d/text.footer.tpl"
	EMAIL_ALERTS="1"
	run _hc_alerts
	assert_output --partial "Custom override: html.entry.tpl"
	assert_output --partial "Custom override: text.footer.tpl"
	assert_output --partial "2 override(s) active"
}

@test "_hc_alerts: no custom override output when custom.d is empty" {
	mkdir -p "$ALERT_TEMPLATE_DIR/custom.d"
	EMAIL_ALERTS="1"
	run _hc_alerts
	refute_output --partial "Custom override"
	refute_output --partial "override(s) active"
}

@test "_hc_alerts: no custom override output when custom.d does not exist" {
	EMAIL_ALERTS="1"
	run _hc_alerts
	refute_output --partial "Custom override"
	refute_output --partial "custom.d"
}
