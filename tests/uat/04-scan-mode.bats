#!/usr/bin/env bats
# 04-scan-mode.bats — BFD Scan Mode UAT
# Verifies: full-log scan, single-rule scan, attack pool population

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load '../helpers/uat-bfd'
load '../infra/lib/uat-helpers'

setup_file() {
    uat_setup
    uat_bfd_install
    uat_bfd_reset

    # Inject a mix of IPs for scan mode to find
    uat_bfd_inject_failures "192.0.2.30" 25
    uat_bfd_inject_failures "192.0.2.31" 25
}

teardown_file() {
    uat_bfd_reset
}

# bats test_tags=uat,uat:scan-mode
@test "UAT: scan dry-run finds injected IPs" {
    uat_bfd_clear_cursors
    uat_capture "scan-mode" bfd --scan -d
    assert_success
    assert_output --partial "192.0.2.30"
    assert_output --partial "192.0.2.31"
    # Scan dry-run records state but skips firewall commands
    assert_output --partial "dry_run"
}

# bats test_tags=uat,uat:scan-mode
@test "UAT: full scan creates bans" {
    uat_bfd_clear_cursors
    uat_capture "scan-mode" bfd --scan
    assert_success
    run grep -c 192.0.2.30 /usr/local/bfd/tmp/bans.active
    assert_success
}

# bats test_tags=uat,uat:scan-mode
@test "UAT: scan populates attack pool" {
    run cat /usr/local/bfd/stats/attack.pool
    assert_success
    assert_output --partial "192.0.2.30"
}

# bats test_tags=uat,uat:scan-mode
@test "UAT: single-rule scan targets only specified rule" {
    uat_bfd_reset
    uat_bfd_inject_failures "192.0.2.32" 25
    uat_bfd_clear_cursors
    uat_capture "scan-mode" bfd --scan sshd -d
    assert_success
    assert_output --partial "192.0.2.32"
}
