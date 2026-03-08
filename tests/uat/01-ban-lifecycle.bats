#!/usr/bin/env bats
# 01-ban-lifecycle.bats — BFD Ban Lifecycle UAT
# Verifies: ban → state verification → listing → unban → clean state → re-ban

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

# bats test_tags=uat,uat:ban-lifecycle
@test "UAT: ban IP succeeds with confirmation" {
    uat_capture "ban-lifecycle" bfd -b 192.0.2.1 sshd
    assert_success
    assert_output --partial "192.0.2.1"
}

# bats test_tags=uat,uat:ban-lifecycle
@test "UAT: banned IP recorded in bans.active" {
    run grep -c 192.0.2.1 /usr/local/bfd/tmp/bans.active
    assert_success
}

# bats test_tags=uat,uat:ban-lifecycle
@test "UAT: banned IP recorded in events" {
    run grep 192.0.2.1 /usr/local/bfd/tmp/bans.history
    assert_success
}

# bats test_tags=uat,uat:ban-lifecycle
@test "UAT: ban listing shows banned IP" {
    uat_capture "ban-lifecycle" bfd -l
    assert_success
    assert_output --partial "192.0.2.1"
}

# bats test_tags=uat,uat:ban-lifecycle
@test "UAT: status shows active ban count" {
    uat_capture "ban-lifecycle" bfd -S
    assert_success
    assert_output --partial "1"
}

# bats test_tags=uat,uat:ban-lifecycle
@test "UAT: ban second IP on different service" {
    uat_capture "ban-lifecycle" bfd -b 192.0.2.2 dovecot
    assert_success
    assert_output --partial "192.0.2.2"
}

# bats test_tags=uat,uat:ban-lifecycle
@test "UAT: both IPs in ban listing" {
    uat_capture "ban-lifecycle" bfd -l
    assert_success
    assert_output --partial "192.0.2.1"
    assert_output --partial "192.0.2.2"
}

# bats test_tags=uat,uat:ban-lifecycle
@test "UAT: unban removes IP" {
    uat_capture "ban-lifecycle" bfd -u 192.0.2.1
    assert_success
}

# bats test_tags=uat,uat:ban-lifecycle
@test "UAT: unbanned IP removed from bans.active" {
    run grep -c 192.0.2.1 /usr/local/bfd/tmp/bans.active
    assert_failure
}

# bats test_tags=uat,uat:ban-lifecycle
@test "UAT: other IP still banned after first unban" {
    run grep -c 192.0.2.2 /usr/local/bfd/tmp/bans.active
    assert_success
}

# bats test_tags=uat,uat:ban-lifecycle
@test "UAT: re-ban previously unbanned IP" {
    uat_capture "ban-lifecycle" bfd -b 192.0.2.1 sshd
    assert_success
    run grep -c 192.0.2.1 /usr/local/bfd/tmp/bans.active
    assert_success
}

# bats test_tags=uat,uat:ban-lifecycle
@test "UAT: unban all via flush" {
    run bfd --flush-all
    assert_success
    run wc -l < /usr/local/bfd/tmp/bans.active
    assert_output "0"
}
