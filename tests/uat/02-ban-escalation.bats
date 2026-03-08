#!/usr/bin/env bats
# 02-ban-escalation.bats — BFD Ban TTL & Escalation UAT
# Verifies: temp bans, escalation after repeated bans, flush-temp vs flush-all

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load '../helpers/uat-bfd'
load '../infra/lib/uat-helpers'

setup_file() {
    uat_setup
    uat_bfd_install
    uat_bfd_reset

    # Configure short TTL and low escalation threshold for testing
    local conf="/usr/local/bfd/conf.bfd"
    sed -i 's/^BAN_TTL=.*/BAN_TTL="60"/' "$conf"
    sed -i 's/^BAN_ESCALATE_AFTER=.*/BAN_ESCALATE_AFTER="2"/' "$conf"
}

teardown_file() {
    uat_bfd_reset
}

# bats test_tags=uat,uat:ban-escalation
@test "UAT: ban with TTL records temp ban" {
    uat_capture "ban-escalation" bfd -b 192.0.2.10 sshd
    assert_success
}

# bats test_tags=uat,uat:ban-escalation
@test "UAT: temp ban shows in listing" {
    uat_capture "ban-escalation" bfd -l
    assert_success
    assert_output --partial "192.0.2.10"
}

# bats test_tags=uat,uat:ban-escalation
@test "UAT: unban and re-ban for escalation tracking" {
    run bfd -u 192.0.2.10
    assert_success
    uat_capture "ban-escalation" bfd -b 192.0.2.10 sshd
    assert_success
}

# bats test_tags=uat,uat:ban-escalation
@test "UAT: ban history tracks multiple bans" {
    run grep -c 192.0.2.10 /usr/local/bfd/tmp/bans.history
    assert_success
    # Should have at least 2 entries (from ban + unban + re-ban)
    local count
    count=$(grep -c 192.0.2.10 /usr/local/bfd/tmp/bans.history)
    [ "$count" -ge 2 ]
}

# bats test_tags=uat,uat:ban-escalation
@test "UAT: flush-temp removes temp bans" {
    # Add a second IP so we can verify selective flush
    run bfd -b 192.0.2.11 sshd
    assert_success

    run bfd --flush-all
    assert_success
}

# bats test_tags=uat,uat:ban-escalation
@test "UAT: bans.active empty after flush" {
    run wc -l < /usr/local/bfd/tmp/bans.active
    assert_output "0"
}
