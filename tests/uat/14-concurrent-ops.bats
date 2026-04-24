#!/usr/bin/env bats
# 14-concurrent-ops.bats — BFD Concurrent Operations UAT
# Verifies: double-ban prevention, ban+unban sequence, state_bans_active_append
# duplicate prevention, and clean state after rapid operations.
# All tests are deterministic — no timing-dependent assertions.

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

# bats test_tags=uat,uat:concurrent-ops
@test "UAT: double-ban same IP prevented with error" {
    run bfd -b 192.0.2.90 sshd
    assert_success
    # Ban same IP again — should fail with "already banned"
    run bfd -b 192.0.2.90 sshd
    assert_failure
    assert_output --partial "already banned"
    # Verify only one entry in bans.active for this IP
    assert_banned 192.0.2.90
    assert_ban_count 1
}

# bats test_tags=uat,uat:concurrent-ops
@test "UAT: ban then unban leaves clean state" {
    uat_bfd_reset
    run bfd -b 192.0.2.91 sshd
    assert_success
    assert_banned 192.0.2.91
    # Unban
    run bfd -u 192.0.2.91
    assert_success
    refute_banned 192.0.2.91
}

# bats test_tags=uat,uat:concurrent-ops
@test "UAT: sequential ban-unban-reban produces single active entry" {
    uat_bfd_reset
    run bfd -b 192.0.2.92 sshd
    assert_success
    run bfd -u 192.0.2.92
    assert_success
    run bfd -b 192.0.2.92 sshd
    assert_success
    assert_banned 192.0.2.92
    assert_ban_count 1
}

# bats test_tags=uat,uat:concurrent-ops
@test "UAT: no duplicate entries after multiple bans of different IPs" {
    uat_bfd_reset
    run bfd -b 192.0.2.93 sshd
    assert_success
    run bfd -b 192.0.2.94 sshd
    assert_success
    run bfd -b 192.0.2.95 sshd
    assert_success
    # Re-ban all three — should all fail with "already banned"
    run bfd -b 192.0.2.93 sshd
    assert_failure
    run bfd -b 192.0.2.94 sshd
    assert_failure
    run bfd -b 192.0.2.95 sshd
    assert_failure
    assert_ban_count 3
    assert_banned 192.0.2.93
    assert_banned 192.0.2.94
    assert_banned 192.0.2.95
}
