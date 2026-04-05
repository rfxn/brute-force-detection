#!/usr/bin/env bats
# 03-detection-pressure.bats — BFD Detection & Pressure UAT
# Verifies: log injection, dry-run detection, standard detection, quiet mode

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

# bats test_tags=uat,uat:detection-pressure
@test "UAT: inject 30 failures for detection" {
    uat_bfd_inject_failures "192.0.2.20" 30
    run wc -l < /var/log/auth.log
    [ "$output" -ge 30 ]
}

# bats test_tags=uat,uat:detection-pressure
@test "UAT: dry-run detects injected failures without banning" {
    uat_bfd_clear_cursors
    uat_capture "detection" bfd -d
    assert_success
    assert_output --partial "192.0.2.20"
    assert_output --partial "dry-run"
}

# bats test_tags=uat,uat:detection-pressure
@test "UAT: standard detection bans IP above pressure trip" {
    uat_bfd_clear_cursors
    uat_capture "detection" bfd -s
    assert_success
    assert_banned 192.0.2.20
}

# bats test_tags=uat,uat:detection-pressure
@test "UAT: detection populates attack pool" {
    run cat /usr/local/bfd/stats/attack.pool
    assert_success
    assert_output --partial "192.0.2.20"
}

# bats test_tags=uat,uat:detection-pressure
@test "UAT: quiet mode suppresses stdout" {
    uat_bfd_reset
    uat_bfd_inject_failures "192.0.2.21" 30
    uat_bfd_clear_cursors
    uat_capture "detection" bfd -q
    assert_success
    # Quiet mode should have minimal output
    local line_count
    line_count=$(echo "$output" | grep -cv '^$' || true)
    [ "$line_count" -le 2 ]
}
