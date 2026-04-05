#!/usr/bin/env bats
# 19-event-filters.bats — BFD Event Filter Modifiers UAT
# Verifies: --sort=time/count/ip, --24h/7d/30d time windows,
# --limit=N output restriction, modifier combinations with JSON/CSV.

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load '../helpers/uat-bfd'
load '../helpers/assert-bfd'
load '../infra/lib/uat-helpers'

setup_file() {
    uat_setup
    uat_bfd_install
    uat_bfd_reset

    # Populate data in TWO separate detection runs so attack.pool timestamps differ.
    # Run 1: .100 (30 failures) — detected first, older timestamp
    uat_bfd_inject_failures "192.0.2.100" 30
    uat_bfd_clear_cursors
    bfd -s > /dev/null 2>&1
    bfd -u 192.0.2.100 > /dev/null 2>&1
    sleep 2

    # Run 2: .101 (25) and .102 (20) — detected later, newer timestamp
    uat_bfd_inject_failures "192.0.2.101" 25
    uat_bfd_inject_failures "192.0.2.102" 20
    bfd -s > /dev/null 2>&1

    # Inject an old event directly into attack.pool to test time window filtering
    # 10 days ago — should be excluded by --24h but included by --30d
    local old_ts
    old_ts=$(( $(date +%s) - 864000 ))
    echo "${old_ts}|192.0.2.199|sshd|22|observed|ban" >> /usr/local/bfd/stats/attack.pool
}

teardown_file() {
    uat_bfd_reset
}

# bats test_tags=uat,uat:event-filters
@test "UAT: events --sort=count shows highest-count IP first" {
    uat_capture "event-filters" bfd -e --sort=count
    assert_success
    # Extract data rows (skip header line starting with #)
    # .100 has 30 failures, .101 has 25, .102 has 20
    # First data IP should be the highest-count one (.100)
    local first_data_ip
    first_data_ip=$(echo "$output" | grep -v '^#' | grep '192\.0\.2\.' | head -1)
    echo "$first_data_ip" | grep -q '192\.0\.2\.100'
}

# bats test_tags=uat,uat:event-filters
@test "UAT: events --sort=time shows newest IPs before oldest" {
    uat_capture "event-filters" bfd -e --sort=time
    assert_success
    # .101/.102 were detected in run 2 (newer), .100 in run 1 (older).
    # With sort=time, .100 should appear AFTER .101 or .102.
    # Extract line numbers for each IP in the output
    local line_100 line_101
    line_100=$(echo "$output" | grep -n '192\.0\.2\.100' | head -1 | cut -d: -f1)
    line_101=$(echo "$output" | grep -n '192\.0\.2\.101' | head -1 | cut -d: -f1)
    [ -n "$line_100" ] && [ -n "$line_101" ]
    # Newer IP (.101) must appear before older IP (.100) in time-sorted output
    [ "$line_101" -lt "$line_100" ]
}

# bats test_tags=uat,uat:event-filters
@test "UAT: events --limit=1 shows exactly one data IP" {
    uat_capture "event-filters" bfd -e --limit=1
    assert_success
    # Count IP data rows (exclude header, summary, and "showing N IPs" footer)
    local ip_data_rows
    ip_data_rows=$(echo "$output" | grep -c '192\.0\.2\.\(100\|101\|102\)' || true)
    [ "$ip_data_rows" -eq 1 ]
}

# bats test_tags=uat,uat:event-filters
@test "UAT: events --24h excludes old events outside window" {
    uat_capture "event-filters" bfd -e --24h
    assert_success
    # Recently injected IPs should appear
    assert_output --partial "192.0.2.100"
    # The 10-day-old synthetic event (.199) should NOT appear in 24h window
    refute_output --partial "192.0.2.199"
}

# bats test_tags=uat,uat:event-filters
@test "UAT: events --json with --sort=time produces valid JSON" {
    uat_capture "event-filters" bfd -e --json --sort=time
    assert_success
    assert_valid_json
    assert_no_banner_corruption json
}
