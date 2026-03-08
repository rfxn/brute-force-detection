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
    uat_setup
    uat_bfd_install
    uat_bfd_reset

    # Configure fast watch interval for testing
    local conf="/usr/local/bfd/conf.bfd"
    sed -i 's/^WATCH_INTERVAL=.*/WATCH_INTERVAL="2"/' "$conf"

    # Clean up any stale PID file from a prior aborted run
    rm -f "$WATCH_PID_FILE"
}

teardown_file() {
    # Kill watch process group — setsid gives bfd -w its own group,
    # so kill -PGID catches the main process AND all children (sleep, etc.)
    if [ -f "$WATCH_PID_FILE" ]; then
        local pid
        pid=$(cat "$WATCH_PID_FILE")
        if [ -n "$pid" ]; then
            # Kill entire process group (negative PID)
            kill -9 -- "-$pid" 2>/dev/null || true
        fi
        rm -f "$WATCH_PID_FILE"
    fi
    # Safety net: kill any remaining bfd/sleep processes
    pkill -9 -f "bfd -w" 2>/dev/null || true
    pkill -9 -f "bfd -q" 2>/dev/null || true
    pkill -9 -f "bfd -s" 2>/dev/null || true
    uat_bfd_reset
}

# bats test_tags=uat,uat:watch-mode
@test "UAT: watch mode starts in background" {
    # timeout auto-kills bfd -w after 20s — guarantees no orphaned processes
    # that would hang the Docker container after BATS exits.
    # --signal KILL ensures immediate termination (no graceful shutdown wait).
    timeout --signal KILL 20 bfd -w > /dev/null 2>&1 &
    local pid=$!
    echo "$pid" > "$WATCH_PID_FILE"
    sleep 3
    # Verify the process is still running
    run kill -0 "$pid"
    assert_success
}

# bats test_tags=uat,uat:watch-mode
@test "UAT: watch mode detects injected failures" {
    uat_bfd_inject_failures "192.0.2.60" 30
    # Wait for at least one watch cycle (WATCH_INTERVAL=2s) plus processing time
    sleep 6
    run grep 192.0.2.60 /usr/local/bfd/tmp/bans.active
    assert_success
}

# bats test_tags=uat,uat:watch-mode
@test "UAT: watch mode stops cleanly" {
    local pid
    [ -f "$WATCH_PID_FILE" ] && pid=$(cat "$WATCH_PID_FILE")
    if [ -n "$pid" ]; then
        # Kill the process group (catches bfd + sleep children)
        kill -9 -- "-$pid" 2>/dev/null || true
    fi
    sleep 1
    # Verify the process has exited
    run kill -0 "$pid"
    assert_failure
    rm -f "$WATCH_PID_FILE"
}
