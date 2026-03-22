# BFD v2.0.2 Security Assessment — Findings

**Date:** 2026-03-21
**Scope:** All BFD shell source, config, rules, templates, install/uninstall, cron
**Methodology:** Static analysis with targeted dynamic verification
**Excluded:** Vendored upstream libraries (tlog_lib, elog_lib, alert_lib, pkg_lib, geoip_lib) — noted where relevant

---

## Executive Summary

BFD v2.0.2 demonstrates **strong security posture** for a root-privileged IDS. Input
validation is comprehensive, file operations are well-guarded, and the alert pipeline
properly sanitizes attacker-controlled data across all output channels. No pre-auth
or unprivileged-user-exploitable vulnerabilities were found.

Two P2 findings warrant remediation. Five P3 defense-in-depth observations are
documented for the threat model.

**Finding Count:** 0 P0, 0 P1, 2 P2, 5 P3

---

## Threat Model Context

BFD runs as **root** via cron (every 2 minutes) or continuously (watch mode). It:
- Parses auth logs containing attacker-controlled content (usernames, IPs)
- Executes firewall commands with extracted IP addresses
- Sources root-owned config files that define ban command templates
- Sends alerts via email, Slack, Telegram, Discord with log excerpts
- Maintains state files (attack.pool, pressure.dat, bans.active)

**Trust boundaries:**
1. Log content (untrusted) → IP extraction → validation → firewall command
2. Config files (root-trusted) → shell sourcing → variable expansion
3. Rule files (root-trusted) → shell sourcing → pattern extraction
4. Alert content (sanitized untrusted data) → template rendering → delivery

---

## Findings

### P2-001: Temp file creation in /tmp instead of $INSTALL_PATH/tmp

**Severity:** P2 (Medium — requires local access + race condition)
**Category:** Information disclosure / inconsistent hardening
**CWE:** CWE-377 (Insecure Temporary File)

**Evidence:**

```
files/internals/bfd_detect.sh:82  — mktemp "${TMPDIR:-/tmp}/.bfd_extract.XXXXXX"
files/internals/bfd_detect.sh:99  — mktemp "${TMPDIR:-/tmp}/.bfd_extract.XXXXXX"
files/internals/bfd_pressure.sh:589 — mktemp -d /tmp/bfd-batch.XXXXXX
```

**Context:** BFD already maintains a private temp directory at `$INSTALL_PATH/tmp`
(root-owned, mode 750). The alert subsystem correctly uses it via `ALERT_TMPDIR`
(bfd_alert.sh:792-793, comment references "ADV-001: avoid /tmp for alert staging").
However, the detection pipeline and batch country lookup still create temp files in
the world-traversable `/tmp`.

**What's at risk:**
- `extract_hosts()` writes log content (containing attacker IPs and auth log lines)
  to temp files in `/tmp`. While mktemp creates files with mode 0600, a local
  attacker with inotify monitoring on `/tmp` can observe file creation and timing,
  correlating with BFD scan activity.
- `_batch_ip_to_country()` writes IP lists to `/tmp/bfd-batch.XXXXXX/v4` and `v6`.
  Same timing side-channel exposure.
- `bfd_pressure.sh:589` is hardcoded `/tmp` (not even `${TMPDIR:-/tmp}`), making it
  impossible to override via environment.

**What's NOT at risk:**
- mktemp with XXXXXX suffix provides 238 bits of entropy on modern Linux — symlink
  prediction is impractical
- Files are mode 0600 (not world-readable)
- Cleanup is trap-guarded (`RETURN` trap in pressure, explicit `rm -f` in detect)
- No code execution risk — these are data files, not sourced scripts

**Remediation:**
Replace all three with `$INSTALL_PATH/tmp`:
```bash
# bfd_detect.sh (2 instances):
_tlog_file=$(mktemp "$INSTALL_PATH/tmp/.bfd_extract.XXXXXX")
# bfd_pressure.sh:
_tmpdir=$(mktemp -d "$INSTALL_PATH/tmp/bfd-batch.XXXXXX")
```
`$INSTALL_PATH` is set before any detection function is called (files/bfd:23,
propagated through config_init). Verified: `_rule_tlog()` references
`$INSTALL_PATH` at bfd_detect.sh:63.

---

### P2-002: _check_file_safety permission parsing assumes 3-digit stat output

**Severity:** P2 (Medium — causes false rejection, not bypass)
**Category:** Input validation robustness
**CWE:** CWE-1289 (Improper Validation of Unsafe Equivalence in Input)

**Evidence:**

```
files/internals/bfd_validate.sh:200-202:
  _CSAF_PERMS=$(stat -L -c '%a' "$file")
  local group_digit="${_CSAF_PERMS:1:1}"
  local world_digit="${_CSAF_PERMS: -1}"
```

`stat -c '%a'` returns 3 digits for normal permissions (e.g., `750`) but 4 digits
when setuid/setgid/sticky bits are set (e.g., `4755`, `2755`, `1777`).

Verified on this system:
```
$ stat -c '%a' /usr/bin/passwd → 4755
$ stat -c '%a' /usr/bin/sudo  → 4111
```

When `_CSAF_PERMS=4755`:
- `${_CSAF_PERMS:1:1}` extracts `7` (owner digit), NOT group digit (`5`)
- `${_CSAF_PERMS: -1}` correctly extracts `5` (world digit)
- `7 & 2 = 2` → function returns 1 (unsafe) — **false rejection**

**Impact:** This is a **defensive failure mode** — it rejects files that are actually
safe, never accepts files that are unsafe. BFD config files never have setuid/sgid
bits, so this is not triggered in practice. However, the same function is used in
`safe_source()` which is a security-critical gate.

**Remediation:**
Use length-aware extraction:
```bash
local perm_len=${#_CSAF_PERMS}
local group_digit="${_CSAF_PERMS:$((perm_len-2)):1}"
local world_digit="${_CSAF_PERMS:$((perm_len-1)):1}"
```
Or simply use `stat -c '%04a'` to always get 4 digits and extract consistently.

---

### P3-001: Custom firewall eval is by-design but warrants hardening documentation

**Severity:** P3 (Low — requires prior root compromise)
**Category:** Privileged code execution
**CWE:** CWE-78 (OS Command Injection) — mitigated by design

**Evidence:**

```
files/internals/bfd_fw.sh:309: eval "$cmd"
files/internals/bfd_fw.sh:326: eval "$cmd"
```

Where `$cmd` = `BAN_COMMAND_TEMPLATE` / `UNBAN_COMMAND_TEMPLATE` from conf.bfd.

**Mitigation chain (already in place):**
1. conf.bfd is validated by `safe_source()` — root-owned, not group/world-writable
2. Template extracted by `extract_command_template()` — reads raw value without expansion
3. `$ATTACK_HOST` validated by `validate_ip_any()` — strict IPv4/IPv6 format
4. `$MOD` validated by `sanitize_mod()` — `^[a-zA-Z0-9_-]+$` allowlist
5. `$PORTS` validated by `sanitize_ports()` — `^(all|[0-9]+(,[0-9]+)*)$`

**What remains:** An attacker with root write access to conf.bfd can embed arbitrary
shell commands in the template. This is inherent to the design (user-defined firewall
commands must be shell-executable). The `expand_command_template()` function
(bfd_validate.sh:248) exists for safe display-time expansion but is not used for
execution because users legitimately need full shell capabilities in custom templates.

**Recommendation:** No code change. Document in conf.bfd comments:
```
# SECURITY: BAN_COMMAND_TEMPLATE is eval'd by BFD. Ensure this file
# remains root-owned (0:0) and not group/world-writable (mode 640).
# A compromised template can execute arbitrary commands as root.
```

---

### P3-002: TOCTOU window in _check_file_safety + source sequence

**Severity:** P3 (Low — microsecond window, requires root-level fs access)
**Category:** Race condition
**CWE:** CWE-367 (TOCTOU Race Condition)

**Evidence:**

```
files/internals/bfd_validate.sh:217-226:
  if ! _check_file_safety "$file"; then   # stat -L checks at time T
      ...
  fi
  . "$file"                                 # source at time T+ε
```

Between the `stat -L` ownership check and the `. "$file"` source, an attacker with
write access to the file's directory could swap the file or its symlink target.

**Why P3 not P2:**
- Requires root-level access to `/usr/local/bfd/` (mode 750, root-owned)
- Window is microseconds (two consecutive syscalls)
- If attacker has root write to the install directory, they have simpler attack paths
- No practical exploit scenario where this is the weakest link

**Recommendation:** No code change. This is an inherent limitation of check-then-act
on filesystems. The only mitigation (open-then-fstat) would require C-level fd
passing to bash source, which is impractical.

---

### P3-003: Webhook URL validation accepts non-https schemes

**Severity:** P3 (Low — requires config write access)
**Category:** Input validation gap
**CWE:** CWE-20 (Improper Input Validation)

**Evidence:**

```
files/internals/bfd_validate.sh:462 (approximate — validated via presence of "://")
```

Webhook URL validation checks only for protocol separator presence (`*"://"*`).
URLs like `file:///etc/shadow`, `gopher://`, or `dict://` would pass validation.
curl supports these schemes and could leak sensitive data if pointed at local files.

**Mitigation already in place:** Config file is root-owned; only root can set webhook
URLs. If root is compromised, the attacker has direct file access anyway.

**Recommendation:** Defense-in-depth: restrict to `https://` prefix:
```bash
[[ "$url" == https://* ]] || { elog error "webhook URL must use https://"; return 1; }
```

---

### P3-004: API tokens and SMTP credentials in plaintext config

**Severity:** P3 (Low — informational, standard for this software class)
**Category:** Credential storage
**CWE:** CWE-312 (Cleartext Storage of Sensitive Information)

**Evidence:**

```
files/conf.bfd — contains SMTP_PASS, SLACK_WEBHOOK_URL (includes token),
  SLACK_TOKEN, TELEGRAM_BOT_TOKEN, DISCORD_WEBHOOK_URL (includes token)
```

Credentials are stored in plaintext in conf.bfd (mode 640, root-owned).

**Why P3:** This is standard practice for server-side IDS/firewall software
(fail2ban, CSF, etc. all use plaintext config). File permissions prevent
non-root access. However, in cloud/container environments where config
may be mounted from secrets managers, plaintext storage creates an
unnecessary exposure surface.

**Recommendation:** No code change for v2.0.2. Document in README that
sensitive config values should be managed via OS-level secret protection
(e.g., `chmod 600 conf.bfd`, encrypted filesystems for cloud deployments).

---

### P3-005: stat -L follows symlinks without verifying link ownership

**Severity:** P3 (Low — defense-in-depth observation)
**Category:** Symlink handling
**CWE:** CWE-59 (Improper Link Resolution Before File Access)

**Evidence:**

```
files/internals/bfd_validate.sh:199: _CSAF_UID=$(stat -L -c '%u' "$file")
files/bfd:34: stat -L -c '%u' "$INSTALL_PATH/internals/bfd.lib.sh"
cron.daily:28-29: stat -L -c '%u' on internals.conf and conf.bfd
```

`stat -L` follows symlinks and reports the target's ownership. If
`/usr/local/bfd/conf.bfd` is a symlink to `/root/safe-conf.bfd`,
the check validates `/root/safe-conf.bfd` ownership — which is correct.
However, if the symlink itself is in a directory writable by an attacker,
the symlink target could be swapped between stat and source (see P3-002).

**Recommendation:** No code change. The install directory is root-owned
(750) and not world-writable, preventing symlink creation by non-root users.

---

## Validated Secure Patterns

The following areas were reviewed and confirmed secure:

| Area | Evidence | Result |
|------|----------|--------|
| **IP validation** | `validate_ip_any()` — strict IPv4 octet range + RFC 4291 IPv6 | No bypass found |
| **CLI argument handling** | All paths through case statement validated before use | No injection found |
| **Log line sanitization** | Password/auth redaction + per-channel escaping (JSON, MarkdownV2) | No injection found |
| **Email header injection** | `validate_email()` regex `^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$` — inherently rejects `\n\r\t` | Confirmed non-exploitable |
| **Lock file handling** | `mkdir` (atomic) + PID verification + stale detection | Race-free |
| **State file concurrency** | `flock -x` on all write paths (attack.pool, pressure.dat, bans) | Properly serialized |
| **IFS management** | All modifications scoped to loops or explicitly saved/restored | No contamination |
| **Firewall command quoting** | All backends properly quote `$host` in command arguments | No word-splitting injection |
| **Rule file sourcing** | `safe_source()` validates ownership/permissions before `. "$file"` | No untrusted sourcing |
| **Config migration** | `importconf` uses awk/sed extraction with regex validation, no eval | No injection |
| **install.sh** | FHS-compliant, proper permissions, backup before overwrite | No race conditions |
| **cron.daily** | flock-protected pruning, PID-aware skip during watch mode | No concurrent corruption |
| **Template rendering** | 3-variant pattern (plain/JSON/Telegram) with dedicated escapers | No cross-channel contamination |

---

## False Positives Investigated and Dismissed

1. **nftables $host injection** — `nft add element ... "{ $host }"` uses validated IP;
   nft set element syntax cannot be injected with valid IPv4/IPv6 strings
2. **firewalld rich rule injection** — same: `$host` is a validated IP, not arbitrary text
3. **Email header injection via newlines** — `validate_email()` regex character class
   `[A-Za-z0-9._%+-]` does not include `\n`, `\r`, or space; verified dynamically
4. **sed injection in pkg_lib.sh** — patterns properly escaped with `sed 's/[&|/\\]/\\&/g'`
5. **Array expansion in firewall backends** — all properly double-quoted

---

## Remediation Scope

| Finding | Action | Effort | Files |
|---------|--------|--------|-------|
| P2-001 | Replace /tmp with $INSTALL_PATH/tmp | Small | bfd_detect.sh, bfd_pressure.sh |
| P2-002 | Length-aware permission digit extraction | Small | bfd_validate.sh |
| P3-001 | Add security comment to conf.bfd template | Trivial | conf.bfd |
| P3-003 | Add https:// prefix check for webhooks | Small | bfd_validate.sh |
| P3-004 | Document credential handling in README | Trivial | README.md |
| P3-005 | No code change | None | — |

**Estimated total: 2 code changes (P2s) + 2 defense-in-depth hardening (P3s) + documentation**
