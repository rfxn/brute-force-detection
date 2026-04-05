#!/usr/bin/env bats
# 17-report-generation.bats — BFD Report Generation UAT
# Verifies: --report daily/weekly/monthly produces output, empty pool handling,
# invalid interval error, report with populated attack pool data.

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load '../helpers/uat-bfd'
load '../helpers/assert-bfd'
load '../infra/lib/uat-helpers'

setup_file() {
    uat_setup
    uat_bfd_install
    uat_bfd_reset

    # Enable reports in config
    local conf="/usr/local/bfd/conf.bfd"
    sed -i 's/^REPORT_ENABLED=.*/REPORT_ENABLED="1"/' "$conf"

    # Populate attack data — inject failures and run detection
    uat_bfd_inject_failures "192.0.2.90" 30
    uat_bfd_inject_failures "192.0.2.91" 25
    uat_bfd_clear_cursors
    bfd -s > /dev/null 2>&1
}

teardown_file() {
    uat_bfd_reset
}

# bats test_tags=uat,uat:report-generation
@test "UAT: --report daily with populated data produces output" {
    uat_capture "report" bfd --report daily
    assert_success
    # Report should contain activity data
    assert_output --partial "192.0.2"
}

# bats test_tags=uat,uat:report-generation
@test "UAT: --report weekly produces output with threat summary" {
    uat_capture "report" bfd --report weekly
    assert_success
    # Must contain report-specific content from template, not just banner
    assert_output --partial "Threat Report"
    assert_output --partial "Unique IPs"
}

# bats test_tags=uat,uat:report-generation
@test "UAT: --report monthly produces output with threat summary" {
    uat_capture "report" bfd --report monthly
    assert_success
    # Must contain report-specific content from template, not just banner
    assert_output --partial "Threat Report"
    assert_output --partial "Total Events"
}

# bats test_tags=uat,uat:report-generation
@test "UAT: --report with empty pool shows no-activity message" {
    # Reset state to clear all data
    : > /usr/local/bfd/stats/attack.pool
    : > /usr/local/bfd/tmp/bans.active
    : > /usr/local/bfd/tmp/bans.history

    uat_capture "report" bfd --report daily
    assert_success
    # Should indicate no activity
    assert_output --partial "No threat activity"
}
