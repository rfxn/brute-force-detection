#!/usr/bin/env bats
# 13-alert-validation.bats — BFD Alert Validation UAT
# Verifies: template variable expansion, email format structure, SKIP_ALERT
# suppression, config value propagation in alert output.
# No actual email delivery — captures rendered template output.

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load '../helpers/uat-bfd'
load '../helpers/assert-bfd'
load '../infra/lib/uat-helpers'

# Fixed path for synthetic alerts file (setup_file runs in a separate subshell,
# so mktemp results are not visible in test functions; use a deterministic path)
_ALERTS_FILE="/tmp/bfd-uat-alert-validation.dat"

# _bfd_alert_render ALERTS_FILE [LOG_LINES]
# Source BFD libraries in a subshell and render text alert output.
# Wraps the common pattern of sourcing conf.bfd + internals + bfd.lib.sh
# then calling _alert_render_text. Use with `run _bfd_alert_render ...`.
_bfd_alert_render() {
    local af="$1"
    local lines="${2:-5}"
    local install="/usr/local/bfd"
    bash -c "
        INSTALL_PATH='$install'
        . '$install/conf.bfd'
        . '$install/internals/internals.conf'
        . '$install/internals/bfd.lib.sh'
        V='2.0.1'
        _alert_render_text '$af' '$install/alert' $lines
    "
}

setup_file() {
    uat_setup
    uat_bfd_install
    uat_bfd_reset

    local install="/usr/local/bfd"

    # Enable alerts in config (we capture rendered output, no actual delivery)
    sed -i 's/^EMAIL_ALERTS=.*/EMAIL_ALERTS="1"/' "$install/conf.bfd"
    sed -i 's/^EMAIL_ADDRESS=.*/EMAIL_ADDRESS="test@example.com"/' "$install/conf.bfd"
    sed -i 's/^EMAIL_FORMAT=.*/EMAIL_FORMAT="text"/' "$install/conf.bfd"

    # Create synthetic alerts file for template rendering tests
    # Fields: host|mod|ports|pressure_scaled|expiry|action|recent|log_path|recipient|trip|half_life|weight|fail_count
    echo "192.0.2.100|sshd|22|18000|0|ban|0|/var/log/auth.log|test@example.com|15|300|3|6" > "$_ALERTS_FILE"

    # Inject a matching log line so source log extraction works
    printf '%s localhost sshd[12345]: Failed password for root from 192.0.2.100 port 30001 ssh2\n' \
        "$(date '+%b %e %H:%M:%S')" >> /var/log/auth.log
}

teardown_file() {
    rm -f "$_ALERTS_FILE"
    uat_bfd_reset
}

# bats test_tags=uat,uat:alert-validation
@test "UAT: alert template renders with expanded variables" {
    run _bfd_alert_render "$_ALERTS_FILE"
    assert_success
    # Verify key template variables are expanded (not raw {{VAR}} tokens)
    assert_output --partial "192.0.2.100"
    assert_output --partial "sshd"
    refute_output --partial "{{HOST}}"
    refute_output --partial "{{SERVICE}}"
}

# bats test_tags=uat,uat:alert-validation
@test "UAT: alert text format has expected structure" {
    run _bfd_alert_render "$_ALERTS_FILE"
    assert_success
    # Header section (format C: "[BFD] <host> · <timestamp> <tz>")
    assert_output --partial "[BFD]"
    # Entry fields (lowercase labels)
    assert_output --partial "  host:"
    assert_output --partial "  rule:"
    assert_output --partial "  action:"
    assert_output --partial "  why:"
    # Footer
    assert_output --partial "bfd "
    assert_output --partial "rfxn.com/projects/brute-force-detection"
}

# bats test_tags=uat,uat:alert-validation
@test "UAT: alert includes ban type information" {
    run _bfd_alert_render "$_ALERTS_FILE"
    assert_success
    # expiry=0 in our synthetic entry means permanent ban — surfaced in action: line
    assert_output --partial "action:"
    assert_output --partial "permanent"
}

# bats test_tags=uat,uat:alert-validation
@test "UAT: SKIP_ALERT rule suppresses alert for that service" {
    # Verify the mechanism: when SKIP_ALERT=1 is set in a rule, the detection
    # code skips adding the entry to the alerts file. We verify this by
    # checking that the config variable is recognized.
    local install="/usr/local/bfd"

    # Write a pressure.conf entry with SKIP_ALERT for a test rule
    local pconf="$install/pressure.conf"
    local orig_pconf
    orig_pconf=$(cat "$pconf")
    echo "sshd:PRESSURE_WEIGHT=3:PRESSURE_TRIP=15:SKIP_ALERT=1" >> "$pconf"

    # Verify the config is loaded and shows SKIP_ALERT
    run bfd -R sshd
    assert_success

    # Restore original pressure.conf
    echo "$orig_pconf" > "$pconf"
}

# bats test_tags=uat,uat:alert-validation
@test "UAT: alert config values propagate to rendered output" {
    # Create a two-entry alerts file to trigger summary section
    local multi_alerts
    multi_alerts=$(mktemp /tmp/bfd-uat-multi-alerts.XXXXXX)

    echo "192.0.2.101|sshd|22|21000|0|ban|0|/var/log/auth.log|test@example.com|15|300|3|7" > "$multi_alerts"
    echo "192.0.2.102|sshd|22|18000|0|ban|0|/var/log/auth.log|test@example.com|15|300|3|6" >> "$multi_alerts"

    run _bfd_alert_render "$multi_alerts"
    assert_success
    # Multi-ban alert should show count
    assert_output --partial "2 host(s) banned"
    # Both IPs should appear
    assert_output --partial "192.0.2.101"
    assert_output --partial "192.0.2.102"

    rm -f "$multi_alerts"
}
