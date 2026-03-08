#!/usr/bin/env bats
# 07-activity-investigation.bats — BFD Activity Investigation UAT
# Verifies: per-IP activity, events dashboard, JSON/CSV activity output

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load '../helpers/uat-bfd'
load '../infra/lib/uat-helpers'

setup_file() {
    uat_setup
    uat_bfd_install
    uat_bfd_reset

    # Create some activity: inject failures and run detection
    uat_bfd_inject_failures "192.0.2.50" 25
    uat_bfd_inject_failures "192.0.2.51" 20
    uat_bfd_clear_cursors
    bfd -s > /dev/null 2>&1
}

teardown_file() {
    uat_bfd_reset
}

# bats test_tags=uat,uat:activity-investigation
@test "UAT: events dashboard shows detected IPs" {
    uat_capture "activity" bfd -e
    assert_success
    assert_output --partial "192.0.2.50"
}

# bats test_tags=uat,uat:activity-investigation
@test "UAT: events for specific IP" {
    uat_capture "activity" bfd -e 192.0.2.50
    assert_success
    assert_output --partial "192.0.2.50"
}

# bats test_tags=uat,uat:activity-investigation
@test "UAT: attack pool shows detected activity" {
    uat_capture "activity" bfd -a
    assert_success
    assert_output --partial "192.0.2.50"
}

# bats test_tags=uat,uat:activity-investigation
@test "UAT: attack pool IP lookup" {
    uat_capture "activity" bfd -a 192.0.2.50
    assert_success
    assert_output --partial "192.0.2.50"
}

# bats test_tags=uat,uat:activity-investigation
@test "UAT: events JSON output" {
    uat_capture "activity" bfd -e --json
    assert_success
    assert_valid_json
    assert_no_banner_corruption json
}

# bats test_tags=uat,uat:activity-investigation
@test "UAT: events CSV output" {
    uat_capture "activity" bfd -e --csv
    assert_success
    assert_no_banner_corruption csv
    assert_valid_csv
}

# bats test_tags=uat,uat:activity-investigation
@test "UAT: attack pool JSON output" {
    uat_capture "activity" bfd -a --json
    assert_success
    assert_valid_json
    assert_no_banner_corruption json
}
