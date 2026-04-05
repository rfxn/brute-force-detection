#!/usr/bin/env bats
# 22-config-tuning.bats — BFD Config Tuning UAT
# Verifies: changing detection thresholds takes effect without restart,
# BAN_TTL change affects new bans, pressure.conf per-rule trip change
# alters sensitivity.
# Sysadmin scenario: tune pressure settings and verify behavior matches.
# Note: sshd has per-rule overrides in pressure.conf (weight=3, trip=15)
# which take precedence over conf.bfd globals.

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load '../helpers/uat-bfd'
load '../helpers/assert-bfd'
load '../infra/lib/uat-helpers'

setup_file() {
    uat_setup
    uat_bfd_install
    uat_bfd_reset
    # Save pressure.conf for cleanup
    cp /usr/local/bfd/pressure.conf /usr/local/bfd/pressure.conf.uat-clean
}

teardown_file() {
    # Restore pressure.conf
    cp /usr/local/bfd/pressure.conf.uat-clean /usr/local/bfd/pressure.conf
    uat_bfd_reset
}

# bats test_tags=uat,uat:config-tuning
@test "UAT: raising sshd trip in pressure.conf prevents ban on moderate attack" {
    # Override sshd trip to 200 — 10 failures * weight 3 = 30 < 200
    sed -i 's/^sshd.*/sshd    weight=3  trip=200/' /usr/local/bfd/pressure.conf
    uat_bfd_reset
    uat_bfd_inject_failures "192.0.2.60" 10
    uat_bfd_clear_cursors
    run bfd -s
    assert_success
    # Should NOT be banned — pressure 30 < trip 200
    refute_banned 192.0.2.60
}

# bats test_tags=uat,uat:config-tuning
@test "UAT: lowering sshd trip in pressure.conf enables ban on same volume" {
    # Override sshd trip to 5 — 10 * 3 = 30 >= 5
    sed -i 's/^sshd.*/sshd    weight=3  trip=5/' /usr/local/bfd/pressure.conf
    uat_bfd_reset
    uat_bfd_inject_failures "192.0.2.61" 10
    uat_bfd_clear_cursors
    run bfd -s
    assert_success
    # Should be banned
    assert_banned 192.0.2.61
}

# bats test_tags=uat,uat:config-tuning
@test "UAT: BAN_TTL change affects detection-based bans" {
    cp /usr/local/bfd/pressure.conf.uat-clean /usr/local/bfd/pressure.conf
    uat_bfd_reset
    # Set BAN_TTL AFTER reset (reset restores conf.bfd from .uat-clean)
    sed -i 's/^BAN_TTL=.*/BAN_TTL="120"/' /usr/local/bfd/conf.bfd
    uat_bfd_inject_failures "192.0.2.62" 15
    uat_bfd_clear_cursors
    run bfd -s
    assert_success
    # bans.active: TIMESTAMP EXPIRY — verify duration = expiry - timestamp = 120
    local ts expiry duration
    ts=$(awk '$3 == "192.0.2.62" { print $1 }' /usr/local/bfd/tmp/bans.active)
    expiry=$(awk '$3 == "192.0.2.62" { print $2 }' /usr/local/bfd/tmp/bans.active)
    [ -n "$ts" ] && [ -n "$expiry" ]
    duration=$((expiry - ts))
    [ "$duration" -eq 120 ]
}

# bats test_tags=uat,uat:config-tuning
@test "UAT: BAN_TTL=0 creates permanent ban via detection" {
    cp /usr/local/bfd/pressure.conf.uat-clean /usr/local/bfd/pressure.conf
    uat_bfd_reset
    # Set BAN_TTL AFTER reset
    sed -i 's/^BAN_TTL=.*/BAN_TTL="0"/' /usr/local/bfd/conf.bfd
    uat_bfd_inject_failures "192.0.2.63" 15
    uat_bfd_clear_cursors
    run bfd -s
    assert_success
    # Permanent ban: expiry = 0
    local expiry
    expiry=$(awk '$3 == "192.0.2.63" { print $2 }' /usr/local/bfd/tmp/bans.active)
    [ "$expiry" -eq 0 ]
}

# bats test_tags=uat,uat:config-tuning
@test "UAT: config show reflects runtime value changes" {
    sed -i 's/^BAN_TTL=.*/BAN_TTL="999"/' /usr/local/bfd/conf.bfd
    uat_capture "config-tuning" bfd -C
    assert_success
    assert_output --partial "BAN_TTL"
    assert_output --partial "999"
}
