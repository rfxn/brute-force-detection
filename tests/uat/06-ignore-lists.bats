#!/usr/bin/env bats
# 06-ignore-lists.bats — BFD Ignore Lists UAT
# Verifies: exclude file, ignored IP skipped in detection, manual ban respects ignore

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

# bats test_tags=uat,uat:ignore-lists
@test "UAT: add IP to ignore hosts file" {
    # exclude.files is a meta-file listing paths to ignore files;
    # IPs go into ignore.hosts (which is listed in exclude.files)
    echo "192.0.2.40" >> /usr/local/bfd/ignore.hosts
    run grep -c 192.0.2.40 /usr/local/bfd/ignore.hosts
    assert_success
}

# bats test_tags=uat,uat:ignore-lists
@test "UAT: ignored IP not banned by detection" {
    uat_bfd_inject_failures "192.0.2.40" 30
    uat_bfd_clear_cursors
    run bfd -s
    assert_success
    # Ignored IP should NOT appear in bans.active
    refute_banned 192.0.2.40
}

# bats test_tags=uat,uat:ignore-lists
@test "UAT: non-ignored IP still banned by detection" {
    uat_bfd_inject_failures "192.0.2.41" 30
    uat_bfd_clear_cursors
    run bfd -s
    assert_success
    assert_banned 192.0.2.41
}