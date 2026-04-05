#!/usr/bin/env bats
# 10-output-quality.bats — BFD Output Quality UAT
# Verifies: empty-state messages, JSON/CSV validation, cross-view consistency

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load '../helpers/uat-bfd'
load '../helpers/assert-bfd'
load '../infra/lib/uat-helpers'

setup_file() {
    uat_setup
    uat_bfd_install
    uat_bfd_reset
}

teardown_file() {
    uat_bfd_reset
}

# -----------------------------------------------------------------------
# Empty-state behavior — every reporting command with no data
# -----------------------------------------------------------------------

# bats test_tags=uat,uat:output-quality
@test "UAT: ban listing with no bans shows message" {
    uat_capture "output-quality" bfd -l
    assert_success
    assert_empty_state_message
}

# bats test_tags=uat,uat:output-quality
@test "UAT: events with no events shows message" {
    uat_capture "output-quality" bfd -e
    assert_success
    assert_empty_state_message
}

# bats test_tags=uat,uat:output-quality
@test "UAT: attack pool with no data shows message" {
    uat_capture "output-quality" bfd -a
    assert_success
    assert_empty_state_message
}

# bats test_tags=uat,uat:output-quality
@test "UAT: status with no activity shows message" {
    uat_capture "output-quality" bfd -S
    assert_success
    assert_empty_state_message
}

# -----------------------------------------------------------------------
# Populate data for structured output tests
# -----------------------------------------------------------------------

# bats test_tags=uat,uat:output-quality
@test "UAT: setup — populate data for output tests" {
    uat_bfd_inject_failures "192.0.2.70" 25
    uat_bfd_inject_failures "192.0.2.71" 20
    uat_bfd_clear_cursors
    run bfd -s
    assert_success
}

# -----------------------------------------------------------------------
# JSON output validation
# -----------------------------------------------------------------------

# bats test_tags=uat,uat:output-quality
@test "UAT: ban listing JSON is valid" {
    uat_capture "output-quality" bfd -l --json
    assert_success
    assert_valid_json
    assert_no_banner_corruption json
}

# bats test_tags=uat,uat:output-quality
@test "UAT: events JSON is valid" {
    uat_capture "output-quality" bfd -e --json
    assert_success
    assert_valid_json
    assert_no_banner_corruption json
}

# bats test_tags=uat,uat:output-quality
@test "UAT: attack pool JSON is valid" {
    uat_capture "output-quality" bfd -a --json
    assert_success
    assert_valid_json
    assert_no_banner_corruption json
}

# -----------------------------------------------------------------------
# CSV output validation
# -----------------------------------------------------------------------

# bats test_tags=uat,uat:output-quality
@test "UAT: ban listing CSV is valid" {
    uat_capture "output-quality" bfd -l --csv
    assert_success
    assert_no_banner_corruption csv
    assert_valid_csv
}

# bats test_tags=uat,uat:output-quality
@test "UAT: events CSV is valid" {
    uat_capture "output-quality" bfd -e --csv
    assert_success
    assert_no_banner_corruption csv
    assert_valid_csv
}

# -----------------------------------------------------------------------
# Cross-view consistency
# -----------------------------------------------------------------------

# bats test_tags=uat,uat:output-quality
@test "UAT: banned IPs in -l appear in -S" {
    # Prerequisite: setup test populated bans — verify data exists first
    assert_banned 192.0.2.70
    run bfd -l
    assert_success
    assert_output --partial "192.0.2.70"
    run bfd -S
    assert_success
    # Status must reflect that bans exist
    assert_output --partial "192.0.2"
}

# bats test_tags=uat,uat:output-quality
@test "UAT: detected IPs in -e appear in -a" {
    # Prerequisite: verify event data exists before cross-checking
    run bfd -e
    assert_success
    assert_output --partial "192.0.2.70"
    local events_output="$output"
    run bfd -a
    assert_success
    assert_output --partial "192.0.2.70"
}
