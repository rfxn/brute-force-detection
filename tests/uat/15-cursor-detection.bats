#!/usr/bin/env bats
# 15-cursor-detection.bats — BFD Incremental Detection UAT
# Verifies: cursor tracking prevents re-detection of previously seen entries,
# new entries after cursor advance are detected, scan advances cursors.

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

# bats test_tags=uat,uat:cursor-detection
@test "UAT: first detection run bans offending IP" {
    uat_bfd_inject_failures "192.0.2.70" 30
    uat_bfd_clear_cursors
    uat_capture "cursor" bfd -s
    assert_success
    assert_banned 192.0.2.70
}

# bats test_tags=uat,uat:cursor-detection
@test "UAT: second run with no new log entries produces no new bans" {
    # Unban IP from prior test — leaves cursor intact
    bfd -u 192.0.2.70 > /dev/null 2>&1
    # Run detection again without clearing cursors or adding log entries
    uat_capture "cursor" bfd -s
    assert_success
    # No new bans — cursor should have advanced past existing entries
    refute_banned 192.0.2.70
}

# bats test_tags=uat,uat:cursor-detection
@test "UAT: new entries after cursor advance are detected" {
    # Inject a new IP after the cursor has already advanced
    uat_bfd_inject_failures "192.0.2.71" 30
    uat_capture "cursor" bfd -s
    assert_success
    # New IP should be banned
    assert_banned 192.0.2.71
    # Old IP (.70) must NOT be re-banned — proves cursor selectivity
    refute_banned 192.0.2.70
}

# bats test_tags=uat,uat:cursor-detection
@test "UAT: scan mode advances cursors for subsequent standard run" {
    uat_bfd_reset
    uat_bfd_inject_failures "192.0.2.72" 30
    uat_bfd_clear_cursors
    # Run scan (which advances cursors)
    bfd --scan > /dev/null 2>&1
    # Unban so we can test if standard mode re-detects
    bfd -u 192.0.2.72 > /dev/null 2>&1
    # Standard run should NOT re-ban — cursors were advanced by scan
    uat_capture "cursor" bfd -s
    assert_success
    refute_banned 192.0.2.72
}
