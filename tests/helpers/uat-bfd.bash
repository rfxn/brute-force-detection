#!/bin/bash
# uat-bfd.bash — BFD-specific UAT helper
# Provides install, reset, and log injection for UAT scenarios.
# Load in UAT .bats files with: load '../helpers/uat-bfd'

# Export INSTALL_PATH for assert-bfd.bash helpers (assert_banned, refute_banned, etc.)
export INSTALL_PATH="/usr/local/bfd"

# uat_bfd_install — Install BFD from /opt source and configure for Docker.
# Idempotent — safe to call multiple times from setup_file().
uat_bfd_install() {
    if [ -x /usr/local/sbin/bfd ]; then
        # Already installed — just clear locks from any prior run
        rm -rf /usr/local/bfd/lock.utime.lk /usr/local/bfd/lock.utime
        return 0
    fi

    cd /opt && bash install.sh > /dev/null 2>&1

    # install.sh auto-starts bfd-watch via init script — kill it in Docker
    # (watch mode is tested explicitly in 08-watch-mode.bats)
    pkill -9 -f "bfd.*watch" 2>/dev/null || true
    pkill -9 -f "bfd -w" 2>/dev/null || true
    sleep 1

    local conf="/usr/local/bfd/conf.bfd"

    # Disable features that require network/email
    sed -i 's/^EMAIL_ALERTS=.*/EMAIL_ALERTS="0"/' "$conf"
    sed -i 's/^SLACK_ALERTS=.*/SLACK_ALERTS="0"/' "$conf"
    sed -i 's/^TELEGRAM_ALERTS=.*/TELEGRAM_ALERTS="0"/' "$conf"
    sed -i 's/^DISCORD_ALERTS=.*/DISCORD_ALERTS="0"/' "$conf"

    # Use custom firewall backend with no-op commands — FIREWALL must be
    # "custom" so execute_ban() uses BAN_COMMAND_TEMPLATE (otherwise it
    # dispatches to fw_ban() which calls the auto-detected backend directly)
    sed -i 's/^FIREWALL=.*/FIREWALL="custom"/' "$conf"
    sed -i 's/^BAN_COMMAND=.*/BAN_COMMAND="\/bin\/true"/' "$conf"
    sed -i 's/^UNBAN_COMMAND=.*/UNBAN_COMMAND="\/bin\/true"/' "$conf"

    # Tell tlog to read existing content on first run (no cursor yet).
    # Without this, tlog_read() defaults to TLOG_FIRST_RUN="skip" and only
    # records the cursor position, outputting nothing — causing detection
    # tests that inject log entries before the first detection run to fail.
    echo 'TLOG_FIRST_RUN="full"' >> "$conf"

    # Ensure auth log exists (Debian path) — do NOT create /var/log/secure
    # so detect_log_paths() auto-detects /var/log/auth.log on Debian containers
    touch /var/log/auth.log
    chmod 640 /var/log/auth.log

    # Create sshd prereq stub so the sshd rule activates
    if [ ! -e /usr/sbin/sshd ]; then
        touch /usr/sbin/sshd && chmod 755 /usr/sbin/sshd
    fi

    # Clear any locks left by install.sh
    rm -rf /usr/local/bfd/lock.utime.lk /usr/local/bfd/lock.utime

    # Save clean config for reset
    cp "$conf" "${conf}.uat-clean"
}

# uat_bfd_reset — Reset BFD state between scenario files.
# Call from teardown_file().
uat_bfd_reset() {
    local install="/usr/local/bfd"
    [ -d "$install" ] || return 0

    # Clear locks
    rm -rf "$install/lock.utime.lk" "$install/lock.utime"

    # Clear all state files
    local f
    for f in tmp/bans.active tmp/bans.history tmp/pressure.dat stats/attack.pool; do
        [ -f "$install/$f" ] && : > "$install/$f"
    done

    # Clear tlog cursor files — named after log tags (e.g., sshd, pam),
    # NOT cursor.* or jts.* as in older tlog versions. Remove all non-state
    # files from tmp/ that are tlog cursors (small files named after rule tags).
    local f
    for f in "$install/tmp/"*; do
        [ -f "$f" ] || continue
        case "${f##*/}" in
            bans.active|bans.history|pressure.dat|.pool_prune_ts) continue ;;
            *) rm -f "$f" ;;
        esac
    done

    # Clear ignore hosts (IPs added by tests); leave exclude.files (meta-file) intact
    [ -f "$install/ignore.hosts" ] && : > "$install/ignore.hosts"

    # Restore clean config
    if [ -f "$install/conf.bfd.uat-clean" ]; then
        cp "$install/conf.bfd.uat-clean" "$install/conf.bfd"
    fi

    # Clear auth log
    : > /var/log/auth.log
}

# uat_bfd_clear_cursors — Remove tlog cursor files and locks.
# Call before detection commands that need to re-read the full log.
uat_bfd_clear_cursors() {
    local install="/usr/local/bfd"
    rm -rf "$install/lock.utime.lk" "$install/lock.utime"
    local f
    for f in "$install/tmp/"*; do
        [ -f "$f" ] || continue
        case "${f##*/}" in
            bans.active|bans.history|pressure.dat|.pool_prune_ts) continue ;;
            *) rm -f "$f" ;;
        esac
    done
}

# uat_bfd_teardown_watch — Clean up watch mode processes.
# Calls uat_cleanup_processes for all bfd run patterns, then resets state.
# Requires uat-helpers (batsman v1.2.0+) to be loaded.
uat_bfd_teardown_watch() {
    uat_cleanup_processes "bfd -w"
    uat_cleanup_processes "bfd -q"
    uat_cleanup_processes "bfd -s"
    uat_bfd_reset
}

# uat_bfd_inject_failures IP COUNT [SERVICE] [LOG_FILE]
# Inject synthetic auth.log entries for detection testing.
# Default service: sshd, default log: /var/log/auth.log
uat_bfd_inject_failures() {
    local ip="$1"
    local count="$2"
    local service="${3:-sshd}"
    local logfile="${4:-/var/log/auth.log}"
    local i
    for i in $(seq 1 "$count"); do
        printf '%s localhost %s[%d]: Failed password for root from %s port %d ssh2\n' \
            "$(date '+%b %e %H:%M:%S')" "$service" "$$" "$ip" "$((30000 + i))" \
            >> "$logfile"
    done
}

# uat_bfd_inject_service_failures SVC IP COUNT LOG
# Inject service-specific log entries matching actual rule MATCHED_HOSTS patterns.
# Supported services: sshd, dovecot, postfix.
# For sshd, delegates to uat_bfd_inject_failures.
uat_bfd_inject_service_failures() {
    local svc="$1" ip="$2" count="$3" logfile="$4"
    local i ts
    case "$svc" in
        sshd)
            uat_bfd_inject_failures "$ip" "$count" "sshd" "$logfile"
            ;;
        dovecot)
            # matches: imap-login.*auth failed.*rip=<HOST>
            for i in $(seq 1 "$count"); do
                ts="$(date '+%b %e %H:%M:%S')"
                printf '%s localhost dovecot[%d]: imap-login: Disconnected (auth failed, 1 attempts): user=<test>, method=PLAIN, rip=%s, lip=127.0.0.1\n' \
                    "$ts" "$$" "$ip" >> "$logfile"
            done
            ;;
        postfix)
            # matches: \[<HOST>\].*SASL.*authentication failed
            for i in $(seq 1 "$count"); do
                ts="$(date '+%b %e %H:%M:%S')"
                printf '%s localhost postfix/smtpd[%d]: warning: unknown[%s]: SASL LOGIN authentication failed: authentication failure\n' \
                    "$ts" "$$" "$ip" >> "$logfile"
            done
            ;;
        *)
            echo "uat_bfd_inject_service_failures: unsupported service '$svc'" >&2
            return 1
            ;;
    esac
}

# uat_bfd_corrupt_state FILE — inject corrupt/empty data for error path testing.
# Writes garbage content to the specified state file.
uat_bfd_corrupt_state() {
    local target="$1"
    if [ ! -f "$target" ]; then
        touch "$target"
    fi
    printf 'GARBAGE_LINE_NO_FIELDS\n\x00\xff binary junk\n' > "$target"
}
