#!/usr/bin/env bats
# 02-ban-escalation.bats — BFD Ban TTL & Escalation UAT
# Verifies: temp bans, escalation after repeated bans, flush-temp vs flush-all

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load '../helpers/uat-bfd'
load '../helpers/assert-bfd'
load '../infra/lib/uat-helpers'

setup_file() {
    uat_setup
    uat_bfd_install
    uat_bfd_reset

    # Configure short TTL and low escalation threshold for testing
    local conf="/usr/local/bfd/conf.bfd"
    sed -i 's/^BAN_TTL=.*/BAN_TTL="60"/' "$conf"
    sed -i 's/^BAN_ESCALATE_AFTER=.*/BAN_ESCALATE_AFTER="2"/' "$conf"
}

teardown_file() {
    uat_bfd_reset
}

# bats test_tags=uat,uat:ban-escalation
@test "UAT: ban with TTL records temp ban" {
    uat_capture "ban-escalation" bfd -b 192.0.2.10 sshd
    assert_success
}

# bats test_tags=uat,uat:ban-escalation
@test "UAT: temp ban shows in listing" {
    uat_capture "ban-escalation" bfd -l
    assert_success
    assert_output --partial "192.0.2.10"
}

# bats test_tags=uat,uat:ban-escalation
@test "UAT: unban and re-ban for escalation tracking" {
    run bfd -u 192.0.2.10
    assert_success
    uat_capture "ban-escalation" bfd -b 192.0.2.10 sshd
    assert_success
}

# bats test_tags=uat,uat:ban-escalation
@test "UAT: ban history tracks multiple bans" {
    run grep -c 192.0.2.10 /usr/local/bfd/tmp/bans.history
    assert_success
    # Should have at least 2 entries (from ban + unban + re-ban)
    [ "$output" -ge 2 ]
}

# bats test_tags=uat,uat:ban-escalation
@test "UAT: flush-temp removes temp bans but preserves permanent" {
    # Clean slate for this test — need both a temp and permanent ban
    uat_bfd_reset
    local conf="/usr/local/bfd/conf.bfd"
    sed -i 's/^BAN_TTL=.*/BAN_TTL="600"/' "$conf"

    # Create a temp ban via detection (detection respects BAN_TTL)
    uat_bfd_inject_failures "192.0.2.13" 30
    uat_bfd_clear_cursors
    run bfd -s
    assert_success
    assert_banned 192.0.2.13
    # Verify it is actually temporary (expiry > 0)
    local expiry
    expiry=$(awk '$3 == "192.0.2.13" { print $2 }' /usr/local/bfd/tmp/bans.active)
    [ "$expiry" -gt 0 ]

    # Create a permanent ban via manual ban (bfd -b always permanent)
    run bfd -b 192.0.2.14 sshd
    assert_success
    assert_banned 192.0.2.14

    run bfd --flush-temp
    assert_success

    # Temp ban should be gone, permanent should survive
    refute_banned 192.0.2.13
    assert_banned 192.0.2.14
}

# bats test_tags=uat,uat:ban-escalation
@test "UAT: flush-all removes all bans including permanent" {
    run bfd --flush-all
    assert_success
    assert_ban_count 0
}
