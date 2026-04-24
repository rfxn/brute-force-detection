#!/usr/bin/env bats
# 20-operational-maintenance.bats — BFD Operational Maintenance UAT
# Verifies: verbose output (-V), per-service status (-S SERVICE),
# cron.daily execution, stale lock detection, log format JSON mode.

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load '../helpers/uat-bfd'
load '../helpers/assert-bfd'
load '../infra/lib/uat-helpers'

setup_file() {
    uat_setup
    uat_bfd_install
    uat_bfd_reset

    # Populate minimal data for status and verbose tests
    uat_bfd_inject_failures "192.0.2.110" 30
    uat_bfd_clear_cursors
    bfd -s > /dev/null 2>&1
}

teardown_file() {
    uat_bfd_reset
}

# bats test_tags=uat,uat:operational-maintenance
@test "UAT: verbose detection shows additional detail beyond standard" {
    uat_bfd_reset
    uat_bfd_inject_failures "192.0.2.111" 30
    uat_bfd_clear_cursors

    # Capture non-verbose dry-run output
    uat_capture "ops-maint" bfd -d
    assert_success
    local normal_lines
    normal_lines=$(echo "$output" | wc -l)

    # Re-inject and re-run with -V
    uat_bfd_reset
    uat_bfd_inject_failures "192.0.2.111" 30
    uat_bfd_clear_cursors
    uat_capture "ops-maint" bfd -d -V
    assert_success
    assert_output --partial "192.0.2.111"
    local verbose_lines
    verbose_lines=$(echo "$output" | wc -l)

    # Verbose MUST produce more output than non-verbose
    [ "$verbose_lines" -gt "$normal_lines" ]
}

# bats test_tags=uat,uat:operational-maintenance
@test "UAT: per-service status shows sshd details" {
    uat_capture "ops-maint" bfd -S sshd
    assert_success
    assert_output --partial "sshd"
    # Service status should show weight and trip
    assert_output --partial "Weight"
    assert_output --partial "Trip"
}

# bats test_tags=uat,uat:operational-maintenance
@test "UAT: per-service status for nonexistent service returns error" {
    run bfd -S nonexistent_service
    assert_failure
    assert_output --partial "error"
}

# bats test_tags=uat,uat:operational-maintenance
@test "UAT: cron.daily rotates bans history" {
    local hist="/usr/local/bfd/tmp/bans.history"
    # Seed bans.history with a known entry so we can verify rotation
    echo "$(date +%s) 0 192.0.2.113 sshd 22" > "$hist"
    local pre_size
    pre_size=$(wc -c < "$hist")
    [ "$pre_size" -gt 0 ]

    run bash /etc/cron.daily/bfd
    assert_success

    # After rotation: bans.history should be empty (truncated)
    local post_size
    post_size=$(wc -c < "$hist")
    [ "$post_size" -eq 0 ]

    # And a dated rotated copy should exist
    local rotated
    rotated=$(ls -1 /usr/local/bfd/tmp/bans.history.* 2>/dev/null | head -1)
    [ -n "$rotated" ]
    # Rotated copy should contain our seeded entry
    grep -q "192.0.2.113" "$rotated"

    # Clean up rotated files
    rm -f /usr/local/bfd/tmp/bans.history.*
}

# bats test_tags=uat,uat:operational-maintenance
@test "UAT: stale lock is detected and cleared" {
    local lock_dir="/usr/local/bfd/lock.utime.lk"
    local lock_file="/usr/local/bfd/lock.utime"
    # Create a fake stale lock (old timestamp)
    mkdir -p "$lock_dir"
    echo "99999" > "$lock_dir/pid"
    touch -d "2 hours ago" "$lock_file"
    touch -d "2 hours ago" "$lock_dir"
    # Set a short timeout so the lock is considered stale
    sed -i 's/^LOCK_FILE_TIMEOUT=.*/LOCK_FILE_TIMEOUT="60"/' /usr/local/bfd/conf.bfd

    # Run detection — should detect stale lock and proceed
    uat_bfd_inject_failures "192.0.2.112" 30
    uat_bfd_clear_cursors
    uat_capture "ops-maint" bfd -s
    assert_success
    # Should have cleared the stale lock and completed detection
    assert_banned 192.0.2.112

    # Clean up
    rm -rf "$lock_dir" "$lock_file"
}
