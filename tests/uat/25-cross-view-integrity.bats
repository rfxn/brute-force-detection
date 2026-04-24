#!/usr/bin/env bats
# 25-cross-view-integrity.bats — BFD Cross-View Data Integrity UAT
# Verifies: IPs detected via -s appear consistently in -l, -e, -a, -S;
# JSON and text views agree on the same data set; unban removes from all views.
# Sysadmin scenario: investigate an incident using multiple views and expect
# consistent data across all of them.

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load '../helpers/uat-bfd'
load '../helpers/assert-bfd'
load '../infra/lib/uat-helpers'

setup_file() {
    uat_setup
    uat_bfd_install
    uat_bfd_reset

    sed -i 's/^PRESSURE_TRIP=.*/PRESSURE_TRIP="5"/' /usr/local/bfd/conf.bfd

    # Create known attack scenario: two IPs, two services
    uat_bfd_inject_failures "192.0.2.90" 20
    uat_bfd_inject_service_failures "dovecot" "192.0.2.91" 20 /var/log/auth.log

    # Create dovecot prereq so rule activates
    if [ ! -e /usr/sbin/dovecot ]; then
        touch /usr/sbin/dovecot && chmod 755 /usr/sbin/dovecot
    fi

    uat_bfd_clear_cursors
    bfd -s > /dev/null 2>&1
}

teardown_file() {
    rm -f /usr/sbin/dovecot
    uat_bfd_reset
}

# bats test_tags=uat,uat:cross-view-integrity
@test "UAT: detected IP appears in ban listing" {
    uat_capture "cross-view" bfd -l
    assert_success
    assert_output --partial "192.0.2.90"
}

# bats test_tags=uat,uat:cross-view-integrity
@test "UAT: detected IP appears in events" {
    uat_capture "cross-view" bfd -e
    assert_success
    assert_output --partial "192.0.2.90"
}

# bats test_tags=uat,uat:cross-view-integrity
@test "UAT: detected IP appears in attack pool" {
    uat_capture "cross-view" bfd -a
    assert_success
    assert_output --partial "192.0.2.90"
}

# bats test_tags=uat,uat:cross-view-integrity
@test "UAT: status shows correct active ban count" {
    uat_capture "cross-view" bfd -S
    assert_success
    # Ground truth from bans.active
    local actual_count
    actual_count=$(wc -l < /usr/local/bfd/tmp/bans.active)
    [ "$actual_count" -gt 0 ]
    # Status output should reflect the ban count with label context
    assert_output --regexp "Active.*${actual_count}"
}

# bats test_tags=uat,uat:cross-view-integrity
@test "UAT: JSON ban listing contains same IPs as text listing" {
    run bfd -l
    assert_success
    local text_ips
    text_ips=$(echo "$output" | grep -oE '192\.0\.2\.[0-9]+' | sort -u)
    [ -n "$text_ips" ]
    run bfd -l --json
    assert_success
    local json_ips
    json_ips=$(echo "$output" | grep -oE '192\.0\.2\.[0-9]+' | sort -u)
    [ -n "$json_ips" ]
    [ "$text_ips" = "$json_ips" ]
}

# bats test_tags=uat,uat:cross-view-integrity
@test "UAT: unban removes IP from ban listing but not from history" {
    run bfd -u 192.0.2.90
    assert_success
    # Should be gone from bans.active
    refute_banned 192.0.2.90
    # Should still be in bans.history
    run grep "192.0.2.90" /usr/local/bfd/tmp/bans.history
    assert_success
    # Should still be in attack pool
    run grep "192.0.2.90" /usr/local/bfd/stats/attack.pool
    assert_success
}

# bats test_tags=uat,uat:cross-view-integrity
@test "UAT: events IP detail shows log context for detected IP" {
    # -e IP N should show log lines for that IP
    uat_capture "cross-view" bfd -e 192.0.2.91
    assert_success
    assert_output --partial "192.0.2.91"
}
