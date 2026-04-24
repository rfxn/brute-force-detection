#!/usr/bin/env bats
# 16-rule-testing.bats — BFD Rule Testing UAT
# Verifies: -T rule testing against logs, --test-pattern raw pattern testing,
# error handling for missing rules, sysadmin rule-tuning workflow.

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load '../helpers/uat-bfd'
load '../helpers/assert-bfd'
load '../infra/lib/uat-helpers'

setup_file() {
    uat_setup
    uat_bfd_install
    uat_bfd_reset

    # Inject known failures for rule testing
    uat_bfd_inject_failures "192.0.2.80" 10
    uat_bfd_inject_failures "192.0.2.81" 5
}

teardown_file() {
    uat_bfd_reset
}

# bats test_tags=uat,uat:rule-testing
@test "UAT: -T sshd shows matches from injected log" {
    uat_capture "rule-test" bfd -T sshd /var/log/auth.log
    assert_success
    assert_output --partial "192.0.2.80"
}

# bats test_tags=uat,uat:rule-testing
@test "UAT: -T sshd shows match count and top IPs" {
    uat_capture "rule-test" bfd -T sshd /var/log/auth.log
    assert_success
    # Should show structured match summary (test_rule uses "Results:" label)
    assert_output --partial "Results:"
    assert_output --partial "Top IPs:"
    # 10 failures for .80 + 5 for .81 = 15 matches
    assert_output --partial "15 matches"
}

# bats test_tags=uat,uat:rule-testing
@test "UAT: -T nonexistent rule returns error" {
    run bfd -T nonexistent_rule /var/log/auth.log
    assert_failure
    assert_output --partial "error"
}

# bats test_tags=uat,uat:rule-testing
@test "UAT: --test-pattern matches injected entries" {
    uat_capture "rule-test" bfd --test-pattern "Failed password.*from <HOST>" /var/log/auth.log
    assert_success
    assert_output --partial "192.0.2.80"
}

# bats test_tags=uat,uat:rule-testing
@test "UAT: --test-pattern with no matches shows zero" {
    uat_capture "rule-test" bfd --test-pattern "ZZZZZ_NOMATCH_ZZZZZ" /var/log/auth.log
    assert_success
    # Assert exact "Matches:  0" label — not just "0" which would match version banner
    assert_output --partial "Matches:  0"
}
