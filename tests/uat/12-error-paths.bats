#!/usr/bin/env bats
# 12-error-paths.bats — BFD Error Path UAT
# Verifies: missing log file handling, invalid IP rejection, corrupt state
# recovery, lock contention detection, and correct exit codes.

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
    # Restore auth.log if tests removed it
    touch /var/log/auth.log
    chmod 640 /var/log/auth.log
    uat_bfd_reset
}

# bats test_tags=uat,uat:error-paths
@test "UAT: detection with missing auth log does not crash" {
    # Remove the auth log to simulate a missing log file
    rm -f /var/log/auth.log
    uat_bfd_clear_cursors
    # Detection should handle missing log gracefully (exit 0 with no events)
    run bfd -s
    # Should not crash — exit 0 (no events found) or exit 0 (completed)
    [ "$status" -eq 0 ]
    # Restore for subsequent tests
    touch /var/log/auth.log
    chmod 640 /var/log/auth.log
}

# bats test_tags=uat,uat:error-paths
@test "UAT: ban with invalid IP shows error message" {
    run bfd -b "not_an_ip" sshd
    assert_failure
    assert_output --partial "invalid"
}

# bats test_tags=uat,uat:error-paths
@test "UAT: ban with invalid IP returns non-zero exit code" {
    run bfd -b "999.999.999.999" sshd
    assert_failure
}

# bats test_tags=uat,uat:error-paths
@test "UAT: corrupt bans.active does not crash ban listing" {
    uat_bfd_corrupt_state /usr/local/bfd/tmp/bans.active
    run bfd -l
    # Should not crash — may show empty or garbled data, but exit cleanly
    [ "$status" -eq 0 ]
    # Restore clean state
    : > /usr/local/bfd/tmp/bans.active
}

# bats test_tags=uat,uat:error-paths
@test "UAT: lock contention exits with lock error code" {
    # Simulate active lock by creating the lock directory with a PID file
    # containing our own PID (so the dead-PID check does not clear it)
    mkdir -p /usr/local/bfd/lock.utime.lk
    echo "$$" > /usr/local/bfd/lock.utime.lk/pid
    echo "$(date +%s)" > /usr/local/bfd/lock.utime
    run bfd -s
    # EXIT_LOCK_ERROR = 2
    [ "$status" -eq 2 ]
    # Clean up lock
    rm -rf /usr/local/bfd/lock.utime.lk /usr/local/bfd/lock.utime
}
