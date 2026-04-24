#!/usr/bin/env bats
# 21-escalation-semantics.bats — BFD Escalation Semantics UAT
# Verifies: repeat offender escalation to permanent ban via detection,
# escalation counter, and that escalation doesn't cross-contaminate IPs.
# Sysadmin scenario: configure BAN_ESCALATE_AFTER=2 so repeat offenders
# get permanent bans after 2 detected bans within the escalation window.

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load '../helpers/uat-bfd'
load '../helpers/assert-bfd'
load '../infra/lib/uat-helpers'

setup_file() {
    uat_setup
    uat_bfd_install
    uat_bfd_reset

    # Configure: temp bans with very low escalation threshold
    local conf="/usr/local/bfd/conf.bfd"
    sed -i 's/^BAN_TTL=.*/BAN_TTL="600"/' "$conf"
    sed -i 's/^BAN_ESCALATE_AFTER=.*/BAN_ESCALATE_AFTER="2"/' "$conf"
    sed -i 's/^BAN_ESCALATION=.*/BAN_ESCALATION="none"/' "$conf"
    sed -i 's/^BAN_ESCALATE_WINDOW=.*/BAN_ESCALATE_WINDOW="86400"/' "$conf"
    # Save as clean for this test file
    cp "$conf" "${conf}.uat-clean"
}

teardown_file() {
    uat_bfd_reset
}

# bats test_tags=uat,uat:escalation-semantics
@test "UAT: first detection-based ban is temporary" {
    uat_bfd_inject_failures "192.0.2.50" 30
    uat_bfd_clear_cursors
    run bfd -s
    assert_success
    # Verify ban exists with temp expiry (> 0)
    local expiry
    expiry=$(awk '$3 == "192.0.2.50" { print $2 }' /usr/local/bfd/tmp/bans.active)
    [ -n "$expiry" ]
    [ "$expiry" -gt 0 ]
}

# bats test_tags=uat,uat:escalation-semantics
@test "UAT: unban and re-detect for second ban" {
    run bfd -u 192.0.2.50
    assert_success
    # Re-inject and detect again
    uat_bfd_inject_failures "192.0.2.50" 30
    uat_bfd_clear_cursors
    run bfd -s
    assert_success
    # Second ban should still be temp (need 2 prior to escalate)
    local expiry
    expiry=$(awk '$3 == "192.0.2.50" { print $2 }' /usr/local/bfd/tmp/bans.active)
    [ -n "$expiry" ]
    [ "$expiry" -gt 0 ]
}

# bats test_tags=uat,uat:escalation-semantics
@test "UAT: third detection escalates to permanent" {
    run bfd -u 192.0.2.50
    assert_success
    uat_bfd_inject_failures "192.0.2.50" 30
    uat_bfd_clear_cursors
    run bfd -s
    assert_success
    # After 2 prior bans (BAN_ESCALATE_AFTER=2), this one should be permanent
    local expiry
    expiry=$(awk '$3 == "192.0.2.50" { print $2 }' /usr/local/bfd/tmp/bans.active)
    [ "$expiry" -eq 0 ]
}

# bats test_tags=uat,uat:escalation-semantics
@test "UAT: ban history tracks all ban events" {
    local count
    count=$(grep -c "192.0.2.50" /usr/local/bfd/tmp/bans.history)
    [ "$count" -ge 3 ]
}

# bats test_tags=uat,uat:escalation-semantics
@test "UAT: escalated ban recorded as escalate in history" {
    # bans.history field 6 records the action: ban or escalate
    run grep "192.0.2.50" /usr/local/bfd/tmp/bans.history
    assert_success
    assert_output --partial "escalate"
}

# bats test_tags=uat,uat:escalation-semantics
@test "UAT: different IP not escalated (no cross-IP contamination)" {
    # Ban a fresh IP — should be temp since it has no prior history
    uat_bfd_inject_failures "192.0.2.51" 30
    uat_bfd_clear_cursors
    run bfd -s
    assert_success
    local expiry
    expiry=$(awk '$3 == "192.0.2.51" { print $2 }' /usr/local/bfd/tmp/bans.active)
    [ -n "$expiry" ]
    [ "$expiry" -gt 0 ]
}

# bats test_tags=uat,uat:escalation-semantics
@test "UAT: manual ban is always permanent regardless of history" {
    # Manual bans bypass escalation — always permanent
    run bfd -u 192.0.2.51
    assert_success
    run bfd -b 192.0.2.52 sshd
    assert_success
    local expiry
    expiry=$(awk '$3 == "192.0.2.52" { print $2 }' /usr/local/bfd/tmp/bans.active)
    [ "$expiry" -eq 0 ]
}
