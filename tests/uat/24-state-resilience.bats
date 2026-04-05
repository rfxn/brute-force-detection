#!/usr/bin/env bats
# 24-state-resilience.bats — BFD State Resilience UAT
# Verifies: corrupt pressure.dat, corrupt attack.pool, corrupt bans.history,
# empty state files, and recovery behavior for all state file types.
# Sysadmin scenario: disk issues corrupt state files; BFD must not crash
# and must recover gracefully on subsequent runs.

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

# bats test_tags=uat,uat:state-resilience
@test "UAT: corrupt pressure.dat does not crash detection" {
    uat_bfd_corrupt_state /usr/local/bfd/tmp/pressure.dat
    uat_bfd_inject_failures "192.0.2.80" 20
    uat_bfd_clear_cursors
    run bfd -s
    # Must not crash — exit 0
    [ "$status" -eq 0 ]
}

# bats test_tags=uat,uat:state-resilience
@test "UAT: corrupt attack.pool does not crash activity listing" {
    uat_bfd_corrupt_state /usr/local/bfd/stats/attack.pool
    run bfd -a
    [ "$status" -eq 0 ]
}

# bats test_tags=uat,uat:state-resilience
@test "UAT: corrupt bans.history does not crash events" {
    uat_bfd_corrupt_state /usr/local/bfd/tmp/bans.history
    run bfd -e
    [ "$status" -eq 0 ]
}

# bats test_tags=uat,uat:state-resilience
@test "UAT: detection after corrupt state still bans new offenders" {
    uat_bfd_reset
    # Corrupt all state files
    uat_bfd_corrupt_state /usr/local/bfd/tmp/pressure.dat
    uat_bfd_corrupt_state /usr/local/bfd/tmp/bans.history
    uat_bfd_corrupt_state /usr/local/bfd/stats/attack.pool
    # Inject and detect
    uat_bfd_inject_failures "192.0.2.81" 30
    uat_bfd_clear_cursors
    run bfd -s
    [ "$status" -eq 0 ]
    # Should still ban the IP despite corrupt state
    assert_banned 192.0.2.81
}

# bats test_tags=uat,uat:state-resilience
@test "UAT: empty state files handled cleanly on all views" {
    uat_bfd_reset
    # All state files are now empty — every view should succeed
    run bfd -l
    [ "$status" -eq 0 ]
    run bfd -e
    [ "$status" -eq 0 ]
    run bfd -a
    [ "$status" -eq 0 ]
    run bfd -S
    [ "$status" -eq 0 ]
}

# bats test_tags=uat,uat:state-resilience
@test "UAT: corrupt bans.active does not prevent new bans" {
    uat_bfd_corrupt_state /usr/local/bfd/tmp/bans.active
    uat_bfd_inject_failures "192.0.2.82" 30
    uat_bfd_clear_cursors
    run bfd -s
    [ "$status" -eq 0 ]
    # The ban should still be recorded (appended)
    assert_banned 192.0.2.82
}
