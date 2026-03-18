#!/usr/bin/env bats
# 08-watch-mode.bats — BFD Watch Mode UAT
# Verifies: start, verify running, inject+detect, stop

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load '../helpers/uat-bfd'
load '../infra/lib/uat-helpers'

# WATCH_PID_FILE — file-level variable to track watch background PID
WATCH_PID_FILE="/tmp/bfd-uat-watch.pid"

setup_file() {
    # Skip if timeout command is unavailable (required for watch auto-kill)
    command -v timeout >/dev/null 2>&1 || skip "timeout command not available"

    uat_setup
    uat_bfd_install
    uat_bfd_reset

    # Configure fast watch interval for testing
    local conf="/usr/local/bfd/conf.bfd"
    sed -i 's/^WATCH_INTERVAL=.*/WATCH_INTERVAL="2"/' "$conf"

    # Clear BFD log so uat_wait_for_log matches the new session, not stale data
    : > /var/log/bfd_log

    # Clean up any stale PID file from a prior aborted run
    rm -f "$WATCH_PID_FILE"
}

teardown_file() {
    # Kill watch process if PID file exists
    if [ -f "$WATCH_PID_FILE" ]; then
        local pid
        pid=$(cat "$WATCH_PID_FILE")
        if [ -n "$pid" ]; then
            # Kill entire process group (negative PID catches bfd + children)
            kill -9 -- "-$pid" 2>/dev/null || true  # may already be dead — safe to ignore
        fi
        rm -f "$WATCH_PID_FILE"
    fi
    # Delegate remaining cleanup to shared helper
    uat_bfd_teardown_watch
}

# bats test_tags=uat,uat:watch-mode
@test "UAT: watch mode starts in background" {
    # timeout auto-kills bfd -w after 30s — guarantees no orphaned processes
    # that would hang the Docker container after BATS exits.
    # --signal KILL ensures immediate termination (no graceful shutdown wait).
    timeout --signal KILL 30 bfd -w > /dev/null 2>&1 &
    local pid=$!
    echo "$pid" > "$WATCH_PID_FILE"
    # Poll for startup message in BFD log (watch mode logs on successful init)
    uat_wait_for_log "/var/log/bfd_log" "watch mode started" 10
    # Verify the process is still running
    run kill -0 "$pid"
    assert_success
}

# bats test_tags=uat,uat:watch-mode
@test "UAT: watch mode detects injected failures" {
    uat_bfd_inject_failures "192.0.2.60" 30
    # Poll for ban to appear in active bans (WATCH_INTERVAL=2s + processing)
    uat_wait_for_condition "grep -q 192.0.2.60 /usr/local/bfd/tmp/bans.active" 15
    run grep 192.0.2.60 /usr/local/bfd/tmp/bans.active
    assert_success
}

# bats test_tags=uat,uat:watch-mode
@test "UAT: watch mode stops cleanly" {
    local pid
    [ -f "$WATCH_PID_FILE" ] && pid=$(cat "$WATCH_PID_FILE")
    if [ -n "$pid" ]; then
        # Kill the process group (catches bfd + children)
        kill -9 -- "-$pid" 2>/dev/null || true  # may already be dead — safe to ignore
    fi
    # Poll until process has exited (up to 5s)
    uat_wait_for_condition "! kill -0 ${pid:-0} 2>/dev/null" 5
    # Verify the process has exited
    run kill -0 "$pid"
    assert_failure
    rm -f "$WATCH_PID_FILE"
}
