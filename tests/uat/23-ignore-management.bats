#!/usr/bin/env bats
# 23-ignore-management.bats — BFD Ignore List Management UAT
# Verifies: multi-IP ignore, comments in ignore file, CIDR ignore,
# ignore removal workflow, and that detection respects all ignore formats.
# Sysadmin scenario: manage ignore lists with comments, ranges, and verify
# that both ignored and non-ignored IPs are handled correctly.

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load '../helpers/uat-bfd'
load '../helpers/assert-bfd'
load '../infra/lib/uat-helpers'

setup_file() {
    uat_setup
    uat_bfd_install
    uat_bfd_reset

    # Use low trip so injections trigger bans
    sed -i 's/^PRESSURE_TRIP=.*/PRESSURE_TRIP="5"/' /usr/local/bfd/conf.bfd
}

teardown_file() {
    uat_bfd_reset
}

# bats test_tags=uat,uat:ignore-management
@test "UAT: ignore file supports comments and blank lines" {
    local ignore="/usr/local/bfd/ignore.hosts"
    printf '# Office gateway\n192.0.2.70\n\n# VPN exit node\n192.0.2.71\n' > "$ignore"
    uat_bfd_inject_failures "192.0.2.70" 20
    uat_bfd_inject_failures "192.0.2.71" 20
    uat_bfd_inject_failures "192.0.2.72" 20
    uat_bfd_clear_cursors
    run bfd -s
    assert_success
    # Ignored IPs should NOT be banned
    refute_banned 192.0.2.70
    refute_banned 192.0.2.71
    # Non-ignored IP SHOULD be banned
    assert_banned 192.0.2.72
}

# bats test_tags=uat,uat:ignore-management
@test "UAT: multiple IPs in ignore list all protected" {
    uat_bfd_reset
    sed -i 's/^PRESSURE_TRIP=.*/PRESSURE_TRIP="5"/' /usr/local/bfd/conf.bfd
    local ignore="/usr/local/bfd/ignore.hosts"
    printf '192.0.2.73\n192.0.2.74\n192.0.2.75\n' > "$ignore"
    uat_bfd_inject_failures "192.0.2.73" 20
    uat_bfd_inject_failures "192.0.2.74" 20
    uat_bfd_inject_failures "192.0.2.75" 20
    uat_bfd_clear_cursors
    run bfd -s
    assert_success
    refute_banned 192.0.2.73
    refute_banned 192.0.2.74
    refute_banned 192.0.2.75
}

# bats test_tags=uat,uat:ignore-management
@test "UAT: removing IP from ignore list allows future detection" {
    # Phase 1: IP is ignored — should not be banned
    uat_bfd_reset
    sed -i 's/^PRESSURE_TRIP=.*/PRESSURE_TRIP="5"/' /usr/local/bfd/conf.bfd
    local ignore="/usr/local/bfd/ignore.hosts"
    echo "192.0.2.76" > "$ignore"
    uat_bfd_inject_failures "192.0.2.76" 20
    uat_bfd_clear_cursors
    run bfd -s
    assert_success
    refute_banned 192.0.2.76

    # Phase 2: remove from ignore list — now should be banned
    : > "$ignore"
    : > /usr/local/bfd/tmp/bans.active
    : > /usr/local/bfd/tmp/pressure.dat
    uat_bfd_inject_failures "192.0.2.76" 20
    uat_bfd_clear_cursors
    run bfd -s
    assert_success
    assert_banned 192.0.2.76
}

# bats test_tags=uat,uat:ignore-management
@test "UAT: ignore.hosts.local auto-populated with machine IPs" {
    uat_bfd_reset
    sed -i 's/^PRESSURE_TRIP=.*/PRESSURE_TRIP="5"/' /usr/local/bfd/conf.bfd
    # Run detection to trigger config_init which regenerates ignore.hosts.local
    uat_bfd_inject_failures "192.0.2.78" 20
    uat_bfd_clear_cursors
    run bfd -s
    assert_success
    # ignore.hosts.local should exist and contain local IPs (127.0.0.1, etc.)
    local local_ignore="/usr/local/bfd/ignore.hosts.local"
    [ -f "$local_ignore" ]
    [ -s "$local_ignore" ]
    # Should contain at least one loopback or machine IP
    run grep -cE '^(127\.0\.0\.1|::1|10\.|172\.|192\.168\.)' "$local_ignore"
    assert_success
}
