#!/usr/bin/env bats
# 18-cdn-operations.bats — BFD CDN Operations UAT
# Verifies: --cdn listing, --cdn check IP, CDN disabled state,
# --cdn with JSON output, sysadmin CDN management workflow.

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
    # Restore CDN_ENABLE to default
    local conf="/usr/local/bfd/conf.bfd"
    sed -i 's/^CDN_ENABLE=.*/CDN_ENABLE="auto"/' "$conf"
    uat_bfd_reset
}

# bats test_tags=uat,uat:cdn-operations
@test "UAT: --cdn with CDN disabled shows disabled message" {
    local conf="/usr/local/bfd/conf.bfd"
    sed -i 's/^CDN_ENABLE=.*/CDN_ENABLE="0"/' "$conf"
    uat_capture "cdn" bfd --cdn
    assert_success
    assert_output --partial "disabled"
}

# bats test_tags=uat,uat:cdn-operations
@test "UAT: --cdn with CDN enabled and no providers shows none" {
    local conf="/usr/local/bfd/conf.bfd"
    sed -i 's/^CDN_ENABLE=.*/CDN_ENABLE="1"/' "$conf"
    # Ensure cdn-providers.conf has no active providers (all commented)
    local pconf="/usr/local/bfd/cdn-providers.conf"
    if [ -f "$pconf" ]; then
        sed -i '/^[^#]/s/^/# /' "$pconf"
    fi
    uat_capture "cdn" bfd --cdn
    assert_success
    assert_output --partial "none configured"
}

# bats test_tags=uat,uat:cdn-operations
@test "UAT: --cdn check with invalid IP shows error" {
    local conf="/usr/local/bfd/conf.bfd"
    sed -i 's/^CDN_ENABLE=.*/CDN_ENABLE="1"/' "$conf"
    run bfd --cdn check not_an_ip
    assert_failure
    assert_output --partial "error"
}

# bats test_tags=uat,uat:cdn-operations
@test "UAT: --cdn check with valid IP and no CDN data returns no match" {
    local conf="/usr/local/bfd/conf.bfd"
    sed -i 's/^CDN_ENABLE=.*/CDN_ENABLE="1"/' "$conf"
    # Ensure empty CDN databases
    : > /usr/local/bfd/data/cdn.dat
    : > /usr/local/bfd/data/cdn6.dat
    uat_capture "cdn" bfd --cdn check 203.0.113.1
    assert_success
    assert_output --partial "no match"
}

# bats test_tags=uat,uat:cdn-operations
@test "UAT: --cdn check --json returns valid JSON" {
    local conf="/usr/local/bfd/conf.bfd"
    sed -i 's/^CDN_ENABLE=.*/CDN_ENABLE="1"/' "$conf"
    : > /usr/local/bfd/data/cdn.dat
    : > /usr/local/bfd/data/cdn6.dat
    uat_capture "cdn" bfd --cdn check 203.0.113.1 --json
    assert_success
    assert_valid_json
}
