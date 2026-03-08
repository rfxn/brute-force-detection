#!/usr/bin/env bats
# 14-concurrent-ops.bats — BFD Concurrent Operations UAT
# Verifies: double-ban prevention, ban+unban sequence, state_bans_active_append
# duplicate prevention, and clean state after rapid operations.
# All tests are deterministic — no timing-dependent assertions.

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load '../helpers/uat-bfd'
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
    local count
    count=$(grep -c "192.0.2.90" /usr/local/bfd/tmp/bans.active)
    [ "$count" -eq 1 ]
}

# bats test_tags=uat,uat:concurrent-ops
@test "UAT: ban then unban leaves clean state" {
    uat_bfd_reset
    run bfd -b 192.0.2.91 sshd
    assert_success
    # Verify banned
    run grep -c 192.0.2.91 /usr/local/bfd/tmp/bans.active
    assert_success
    # Unban
    run bfd -u 192.0.2.91
    assert_success
    # Verify clean — IP should not be in bans.active
    run grep -c 192.0.2.91 /usr/local/bfd/tmp/bans.active
    assert_failure
}

# bats test_tags=uat,uat:concurrent-ops
@test "UAT: rapid ban-unban-ban sequence produces single active entry" {
    uat_bfd_reset
    run bfd -b 192.0.2.92 sshd
    assert_success
    run bfd -u 192.0.2.92
    assert_success
    run bfd -b 192.0.2.92 sshd
    assert_success
    # Should have exactly one active entry
    local count
    count=$(grep -c "192.0.2.92" /usr/local/bfd/tmp/bans.active)
    [ "$count" -eq 1 ]
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
    # Count total lines — should be exactly 3 (one per IP)
    local total_lines
    total_lines=$(wc -l < /usr/local/bfd/tmp/bans.active)
    [ "$total_lines" -eq 3 ]
    # Verify each IP appears exactly once
    local c93 c94 c95
    c93=$(grep -c "192.0.2.93" /usr/local/bfd/tmp/bans.active)
    c94=$(grep -c "192.0.2.94" /usr/local/bfd/tmp/bans.active)
    c95=$(grep -c "192.0.2.95" /usr/local/bfd/tmp/bans.active)
    [ "$c93" -eq 1 ]
    [ "$c94" -eq 1 ]
    [ "$c95" -eq 1 ]
}
