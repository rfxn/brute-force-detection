#!/usr/bin/env bats
# 09-cli-ux.bats — BFD CLI UX UAT
# Verifies: help text, version, status, no-args behavior, exit codes

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load '../helpers/uat-bfd'
load '../helpers/assert-bfd'
load '../infra/lib/uat-helpers'

setup_file() {
    uat_setup
    uat_bfd_install
}

teardown_file() {
    uat_bfd_reset
}

# bats test_tags=uat,uat:cli-ux
@test "UAT: -h shows help text" {
    uat_capture "cli-ux" bfd -h
    assert_success
    assert_output --partial "usage"
}

# bats test_tags=uat,uat:cli-ux
@test "UAT: --help shows help text" {
    uat_capture "cli-ux" bfd --help
    assert_success
    assert_output --partial "usage"
}

# bats test_tags=uat,uat:cli-ux
@test "UAT: help covers all major options" {
    run bfd -h
    assert_success
    # Verify key options are documented
    assert_output --partial -- "-s"
    assert_output --partial -- "-l"
    assert_output --partial -- "-e"
    assert_output --partial -- "-b"
    assert_output --partial -- "-u"
}

# bats test_tags=uat,uat:cli-ux
@test "UAT: version output" {
    uat_capture "cli-ux" bfd -v
    assert_success
    assert_output --partial "2.0"
}

# bats test_tags=uat,uat:cli-ux
@test "UAT: config health check exit code" {
    run bfd -c
    assert_success
}
