#!/usr/bin/env bats
# 05-config-health.bats — BFD Config & Health Check UAT
# Verifies: config display, single variable, health check, rules listing

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

# bats test_tags=uat,uat:config-health
@test "UAT: show config displays all variables" {
    uat_capture "config-health" bfd -C
    assert_success
    assert_output --partial "PRESSURE_TRIP"
    assert_output --partial "BAN_TTL"
}

# bats test_tags=uat,uat:config-health
@test "UAT: show single config variable" {
    uat_capture "config-health" bfd -C PRESSURE_TRIP
    assert_success
    # Single-variable query returns the value (numeric)
    assert_output --regexp '^[0-9]+'
}

# bats test_tags=uat,uat:config-health
@test "UAT: health check runs without error" {
    uat_capture "config-health" bfd -c
    assert_success
}

# bats test_tags=uat,uat:config-health
@test "UAT: health check reports component status" {
    uat_capture "config-health" bfd -c
    assert_success
    # Health check should report on firewall backend and rules
    assert_output --partial "sshd"
}

# bats test_tags=uat,uat:config-health
@test "UAT: rules listing shows active rules" {
    uat_capture "config-health" bfd -R
    assert_success
    assert_output --partial "sshd"
}

# bats test_tags=uat,uat:config-health
@test "UAT: specific rule listing" {
    uat_capture "config-health" bfd -R sshd
    assert_success
    assert_output --partial "sshd"
}
