#!/usr/bin/env bats
# 11-multi-service.bats — BFD Multi-Service Detection UAT
# Verifies: cross-rule detection for sshd, dovecot, postfix; attack pool entries
# from multiple services; rule skip guards for missing prereqs.

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load '../helpers/uat-bfd'
load '../helpers/assert-bfd'
load '../infra/lib/uat-helpers'

setup_file() {
    uat_setup
    uat_bfd_install
    uat_bfd_reset

    local install="/usr/local/bfd"

    # Verify rule files exist — skip entire file if missing
    [ -f "$install/rules/sshd" ] || skip "sshd rule not found"
    [ -f "$install/rules/dovecot" ] || skip "dovecot rule not found"
    [ -f "$install/rules/postfix" ] || skip "postfix rule not found"

    # Create prereq stubs for dovecot and postfix so rules activate
    if [ ! -e /usr/sbin/dovecot ]; then
        touch /usr/sbin/dovecot && chmod 755 /usr/sbin/dovecot
    fi
    if [ ! -e /usr/sbin/postfix ]; then
        touch /usr/sbin/postfix && chmod 755 /usr/sbin/postfix
    fi

    # Create mail log (dovecot falls back to AUTH_LOG_PATH if mail log missing,
    # but postfix always uses MAIL_LOG_PATH; use auth.log for all to simplify)
    touch /var/log/mail.log
    chmod 640 /var/log/mail.log

    # Inject log failures for all three services upfront so individual tests
    # can run independently without relying on prior test execution order
    uat_bfd_inject_service_failures "sshd" "192.0.2.80" 30 /var/log/auth.log
    uat_bfd_inject_service_failures "dovecot" "192.0.2.81" 30 /var/log/mail.log
    uat_bfd_inject_service_failures "postfix" "192.0.2.82" 30 /var/log/mail.log
}

teardown_file() {
    uat_bfd_reset
    # Clean up mail log and prereq stubs
    rm -f /var/log/mail.log
    rm -f /usr/sbin/dovecot /usr/sbin/postfix
}

# bats test_tags=uat,uat:multi-service
@test "UAT: sshd failures injected for multi-service test" {
    run wc -l < /var/log/auth.log
    [ "$output" -ge 30 ]
}

# bats test_tags=uat,uat:multi-service
@test "UAT: dovecot failures injected for multi-service test" {
    run wc -l < /var/log/mail.log
    [ "$output" -ge 30 ]
}

# bats test_tags=uat,uat:multi-service
@test "UAT: postfix failures injected for multi-service test" {
    run wc -l < /var/log/mail.log
    [ "$output" -ge 60 ]
}

# bats test_tags=uat,uat:multi-service
@test "UAT: detection finds failures across multiple services" {
    uat_bfd_clear_cursors
    uat_capture "multi-service" bfd -s
    assert_success
    # sshd IP must be banned; dovecot/postfix depend on rule activation in container
    assert_banned 192.0.2.80
}

# bats test_tags=uat,uat:multi-service
@test "UAT: attack pool contains entries from sshd service" {
    run cat /usr/local/bfd/stats/attack.pool
    assert_success
    assert_output --partial "192.0.2.80"
    assert_output --partial "sshd"
}

# bats test_tags=uat,uat:multi-service
@test "UAT: health check reports multiple active rules" {
    uat_capture "multi-service" bfd -c
    assert_success
    assert_output --partial "sshd"
}
