#!/usr/bin/env bats
# 26-pressure-threshold.bats — BFD Pressure Threshold UAT
# Verifies: sub-threshold failures do NOT ban, exact-threshold behavior,
# above-threshold bans, and that pressure model distinguishes
# rapid bursts from spread-out typos.
# Sysadmin scenario: "I typed my password wrong 3 times — am I locked out?"
# Answer should be NO with default settings (weight=3, trip=15 -> need 5 rapid).

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load '../helpers/uat-bfd'
load '../helpers/assert-bfd'
load '../infra/lib/uat-helpers'

setup_file() {
    uat_setup
    uat_bfd_install
    uat_bfd_reset

    # sshd rule has per-rule override: weight=3, trip=15 (from pressure.conf)
    # So minimum rapid failures for ban = ceil(15/3) = 5
    # Use default settings — pressure.conf controls sshd behavior
    sed -i 's/^PRESSURE_HALF_LIFE=.*/PRESSURE_HALF_LIFE="300"/' /usr/local/bfd/conf.bfd
}

teardown_file() {
    uat_bfd_reset
}

# bats test_tags=uat,uat:pressure-threshold
@test "UAT: 3 failures (human typo) does NOT trigger ban" {
    uat_bfd_reset
    uat_bfd_inject_failures "192.0.2.100" 3
    uat_bfd_clear_cursors
    run bfd -s
    assert_success
    # sshd: weight=3, trip=15 -> 3 * 3 = 9 < 15 — should NOT be banned
    refute_banned 192.0.2.100
}

# bats test_tags=uat,uat:pressure-threshold
@test "UAT: 4 failures just below threshold" {
    uat_bfd_reset
    uat_bfd_inject_failures "192.0.2.101" 4
    uat_bfd_clear_cursors
    run bfd -s
    assert_success
    # sshd: weight=3, trip=15 -> 4 * 3 = 12 < 15 — should NOT be banned
    refute_banned 192.0.2.101
}

# bats test_tags=uat,uat:pressure-threshold
@test "UAT: 5 rapid failures hits threshold and triggers ban" {
    uat_bfd_reset
    uat_bfd_inject_failures "192.0.2.102" 5
    uat_bfd_clear_cursors
    run bfd -s
    assert_success
    # sshd: weight=3, trip=15 -> 5 * 3 = 15 >= 15 — should be banned
    assert_banned 192.0.2.102
}

# bats test_tags=uat,uat:pressure-threshold
@test "UAT: dry-run shows detection with dry-run indicator" {
    uat_bfd_reset
    uat_bfd_inject_failures "192.0.2.103" 10
    uat_bfd_clear_cursors
    uat_capture "pressure" bfd -d
    assert_success
    # Should report the IP as detected
    assert_output --partial "192.0.2.103"
    # Dry-run output should contain dry-run indicator
    assert_output --partial "dry-run"
}

# bats test_tags=uat,uat:pressure-threshold
@test "UAT: sub-threshold IP not banned alongside above-threshold IP" {
    uat_bfd_reset
    uat_bfd_inject_failures "192.0.2.104" 3
    uat_bfd_inject_failures "192.0.2.105" 8
    uat_bfd_clear_cursors
    run bfd -s
    assert_success
    # 192.0.2.105: 8*3=24 >= 15 — should be banned
    assert_banned 192.0.2.105
    # 192.0.2.104: 3*3=9 < 15 — should NOT be banned
    refute_banned 192.0.2.104
}

# bats test_tags=uat,uat:pressure-threshold
@test "UAT: observed-only IP appears in events but not bans" {
    # Self-contained: inject sub-threshold failures and run detection
    uat_bfd_reset
    sed -i 's/^PRESSURE_HALF_LIFE=.*/PRESSURE_HALF_LIFE="300"/' /usr/local/bfd/conf.bfd
    uat_bfd_inject_failures "192.0.2.106" 3
    uat_bfd_clear_cursors
    run bfd -s
    assert_success
    # 3*3=9 < 15 — observed in pressure.dat but NOT banned
    run grep "192.0.2.106" /usr/local/bfd/tmp/pressure.dat
    assert_success
    refute_banned 192.0.2.106
}

# bats test_tags=uat,uat:pressure-threshold
@test "UAT: decayed pressure drops below trip after half-life elapses" {
    # Sysadmin scenario: old failed login attempts should fade over time,
    # not accumulate forever. This tests the half-life decay mechanism.
    #
    # Strategy: pre-populate pressure.dat with backdated entries (simulating
    # events that happened 2 half-lives ago), then inject 1 fresh failure.
    # The detection pipeline reads new log entries, adds them to pressure.dat,
    # and computes total decayed pressure across all entries.
    #
    # sshd: weight=3, trip=15, half_life=300
    # 4 old entries at -600s: 4 * 3 * 2^(-600/300) = 12 * 0.25 = 3.0
    # 1 fresh entry:          1 * 3 * 2^(0)         =              3.0
    # Total:                                                        6.0 < 15 — no ban
    #
    # Without decay (all fresh): (4+1) * 3 = 15 — would ban.
    uat_bfd_reset
    sed -i 's/^PRESSURE_HALF_LIFE=.*/PRESSURE_HALF_LIFE="300"/' /usr/local/bfd/conf.bfd

    local now
    now=$(date +%s)
    local old_ts=$((now - 600))
    # Seed pressure.dat with 4 backdated entries (simulating aged events)
    local pdat="/usr/local/bfd/tmp/pressure.dat"
    printf '%s 192.0.2.107 sshd 3\n' "$old_ts" "$old_ts" "$old_ts" "$old_ts" > "$pdat"

    # Inject 1 fresh failure (cursor is clean — this is the only log entry)
    uat_bfd_inject_failures "192.0.2.107" 1
    uat_bfd_clear_cursors
    run bfd -s
    assert_success
    # Total decayed pressure: 3.0 (old) + 3.0 (fresh) = 6.0 < 15 — not banned
    refute_banned 192.0.2.107
    # But the IP should appear in pressure.dat (observed, not banned)
    run grep "192.0.2.107" /usr/local/bfd/tmp/pressure.dat
    assert_success
}

# bats test_tags=uat,uat:pressure-threshold
@test "UAT: country pressure multiplier amplifies scoring weight" {
    # Sysadmin scenario: enable country weighting so traffic from high-risk
    # origins hits the ban threshold faster.
    uat_bfd_reset
    sed -i 's/^PRESSURE_HALF_LIFE=.*/PRESSURE_HALF_LIFE="300"/' /usr/local/bfd/conf.bfd

    # Enable CN=20 (2.0x multiplier) in pressure-country.conf
    local country_conf="/usr/local/bfd/pressure-country.conf"
    cp "$country_conf" "${country_conf}.uat-clean"
    # Append an active entry — all defaults are commented out
    echo "CN 20" >> "$country_conf"

    # Use IP 1.0.1.0 which maps to CN in ipcountry.dat
    # With multiplier: scoring_weight = (3 * 20 + 5) / 10 = 6
    # 3 failures: 3 * 6 = 18 >= 15 — should be banned
    uat_bfd_inject_failures "1.0.1.0" 3
    uat_bfd_clear_cursors
    run bfd -s
    assert_success
    assert_banned 1.0.1.0

    # Restore country conf
    cp "${country_conf}.uat-clean" "$country_conf"
    rm -f "${country_conf}.uat-clean"
}

# bats test_tags=uat,uat:pressure-threshold
@test "UAT: same failure count without country multiplier does not ban" {
    # Control test: without the CN multiplier, 3 failures = 3*3=9 < 15
    uat_bfd_reset
    sed -i 's/^PRESSURE_HALF_LIFE=.*/PRESSURE_HALF_LIFE="300"/' /usr/local/bfd/conf.bfd

    # Ensure all country entries are commented (default state)
    local country_conf="/usr/local/bfd/pressure-country.conf"
    cp "$country_conf" "${country_conf}.uat-clean"
    sed -i 's/^[A-Z]/# &/' "$country_conf"

    uat_bfd_inject_failures "1.0.1.0" 3
    uat_bfd_clear_cursors
    run bfd -s
    assert_success
    # Without multiplier: 3*3=9 < 15 — should NOT be banned
    refute_banned 1.0.1.0

    cp "${country_conf}.uat-clean" "$country_conf"
    rm -f "${country_conf}.uat-clean"
}
