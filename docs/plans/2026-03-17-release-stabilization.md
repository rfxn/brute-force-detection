# BFD v2.0.1 Release Stabilization Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Get the `2.0.1` branch into a deterministically verified, release-ready state and cut a PR to `master`.

**Architecture:** 3-stage pipeline — parallel read-only diagnostics, serial fix pass, serial final gate. No new features; validation and fixes only.

**Tech Stack:** Bash 4.1+, BATS (batsman), Docker (test containers), GitHub Actions CI, GNU diff

**Spec:** `docs/superpowers/specs/2026-03-17-release-stabilization-design.md`

---

## Chunk 1: Stage 1 — Parallel Diagnostics

All tasks in this chunk are read-only and independent. Run them concurrently.
Collect all output before proceeding to Chunk 2.

### Task 1: Local Test Suite (Debian 12)

**Files:**
- Read: `tests/Makefile`, `tests/*.bats` (46 files), `tests/helpers/*.bash`
- Output: `/tmp/test-bfd-rel-debian12.log`

- [ ] **Step 1: Run full test suite on Debian 12**

```bash
make -C tests test 2>&1 | tee /tmp/test-bfd-rel-debian12.log | tail -30
```

Expected: All tests pass (1583+ `@test` markers). Look for `not ok` lines.

- [ ] **Step 2: Extract failure summary**

```bash
grep -c "^ok" /tmp/test-bfd-rel-debian12.log
grep -c "^not ok" /tmp/test-bfd-rel-debian12.log
grep "^not ok" /tmp/test-bfd-rel-debian12.log || echo "ALL PASS"
```

Record: total pass count, total fail count, any failing test names.

---

### Task 2: Local UAT Suite

**Files:**
- Read: `tests/uat/*.bats` (10 files, 86 tests), `tests/helpers/uat-bfd.bash`
- Output: `/tmp/test-bfd-rel-uat.log`

- [ ] **Step 1: Run UAT suite**

```bash
make -C tests uat 2>&1 | tee /tmp/test-bfd-rel-uat.log | tail -30
```

Expected: 86/86 pass.

- [ ] **Step 2: Extract failure summary**

```bash
grep -c "^ok" /tmp/test-bfd-rel-uat.log
grep -c "^not ok" /tmp/test-bfd-rel-uat.log
grep "^not ok" /tmp/test-bfd-rel-uat.log || echo "ALL PASS"
```

---

### Task 3: Library Freshness Audit

**Files:**
- Compare: `files/internals/tlog_lib.sh` vs `/root/admin/work/proj/tlog_lib/files/tlog_lib.sh`
- Compare: `files/internals/elog_lib.sh` vs `/root/admin/work/proj/elog_lib/files/elog_lib.sh`
- Compare: `files/internals/alert_lib.sh` vs `/root/admin/work/proj/alert_lib/files/alert_lib.sh`
- Compare: `files/internals/pkg_lib.sh` vs `/root/admin/work/proj/pkg_lib/files/pkg_lib.sh`
- Compare: `files/internals/geoip_lib.sh` vs `/root/admin/work/proj/geoip_lib/files/geoip_lib.sh`

- [ ] **Step 1: Diff each vendored library against canonical upstream**

```bash
for lib in tlog_lib elog_lib alert_lib pkg_lib geoip_lib; do
  vendored="files/internals/${lib}.sh"
  # tlog_lib canonical is at tlog_lib/files/tlog_lib.sh, etc.
  canonical="/root/admin/work/proj/${lib}/files/${lib}.sh"
  echo "=== ${lib} ==="
  if diff -q "$vendored" "$canonical" >/dev/null 2>&1; then
    echo "MATCH"
  else
    echo "DRIFT DETECTED"
    diff --unified=3 "$vendored" "$canonical" | head -40
  fi
done
```

- [ ] **Step 2: Also compare tlog CLI wrapper**

```bash
echo "=== tlog CLI ==="
# BFD's tlog wrapper vs canonical (if exists)
canonical_tlog="/root/admin/work/proj/tlog_lib/files/tlog"
if [ -f "$canonical_tlog" ]; then
  diff -q files/tlog "$canonical_tlog" && echo "MATCH" || { echo "DRIFT"; diff --unified=3 files/tlog "$canonical_tlog" | head -40; }
else
  echo "No canonical tlog CLI — BFD-specific wrapper (expected)"
fi
```

- [ ] **Step 3: Record version comparison**

```bash
for lib in tlog_lib elog_lib alert_lib pkg_lib geoip_lib; do
  vendored="files/internals/${lib}.sh"
  canonical="/root/admin/work/proj/${lib}/files/${lib}.sh"
  v_ver=$(grep -m1 'VERSION=' "$vendored" | head -1)
  c_ver=$(grep -m1 'VERSION=' "$canonical" | head -1)
  echo "${lib}: vendored=${v_ver}  canonical=${c_ver}"
done
```

Record: any drifted libraries with version deltas.

---

### Task 4: Changelog Dedup

- [ ] **Step 1: Run `/rel-chg-dedup` skill**

Invoke the `rel-chg-dedup` skill. It scans CHANGELOG and CHANGELOG.RELEASE for
the current branch version (2.0.1) only, identifying duplicate or overlapping entries.

Record: list of duplicates found (if any).

---

### Task 5: AI Slop Scrub

- [ ] **Step 1: Run `/rel-scrub` skill**

Invoke the `rel-scrub` skill. It scans all shipped files for Claude/Anthropic/AI
attribution that must be removed before release.

Record: list of hits (if any), with file paths and line numbers.

---

### Task 6: Release Prep Checklist

- [ ] **Step 1: Run `/rel-prep` skill**

Invoke the `rel-prep` skill. It runs the pre-release verification checklist:
version consistency, doc sync, packaging, config primitives, bash completion,
CLI help text accuracy.

Record: all checklist items with pass/fail status.

---

### Task 7: Performance Benchmarks

**Files:**
- Read: `tests/45-perf-benchmark.bats`, `tests/helpers/perf-generate.bash`
- Output: `/tmp/test-bfd-rel-bench.log`

- [ ] **Step 1: Run benchmark suite**

```bash
make -C tests bench 2>&1 | tee /tmp/test-bfd-rel-bench.log | tail -50
```

Expected: All 3 tier groups (small/medium/large) complete within 30s each.

- [ ] **Step 2: Extract KPI baselines**

```bash
grep "^# KPI:" /tmp/test-bfd-rel-bench.log
```

Record: KPI values for regression comparison in Stage 3.

---

## Chunk 2: Stage 2 — Triage and Fix Pass

**Prerequisites:** All 7 tasks from Chunk 1 complete with output collected.

### Task 8: Triage Findings

- [ ] **Step 1: Collect all Stage 1 outputs into a single findings summary**

Review outputs from Tasks 1-7 and categorize each finding:

| Category | Criteria | Action |
|----------|----------|--------|
| Must-fix | Test failures, lib drift, doc errors, slop hits, security | Fix in this stage |
| Won't-fix | Cosmetic, upstream-owned, deferred advisory | Document and skip |

- [ ] **Step 2: If no must-fix findings, skip to Chunk 3**

If all 7 diagnostics are clean, proceed directly to Task 10 (Stage 3).

---

### Task 9: Apply Fixes

This task is conditional — only execute if Task 8 identified must-fix items.

- [ ] **Step 1: Fix each must-fix item**

For each must-fix finding:
1. Make the minimal code change
2. Run the specific validation that caught it (e.g., re-run the failing test)
3. Verify the fix passes

Group related fixes into a single commit where they share a logical unit.

- [ ] **Step 2: Commit fixes**

```bash
# Stage specific files (never git add -A)
git add <specific-files>
git commit -m "$(cat <<'EOF'
2.0.1 | <description of fix>

[Fix] <details>
EOF
)"
```

- [ ] **Step 3: Update CHANGELOG and CHANGELOG.RELEASE if code changed**

Add entries for any code-changing fixes. Commit separately if needed.

---

## Chunk 3: Stage 3 — Final Gate

**Prerequisites:** All must-fix items from Chunk 2 resolved (or Chunk 2 skipped if clean).

### Task 10: Full Re-validation

- [ ] **Step 1: Run lint verification**

```bash
bash -n files/bfd files/internals/bfd.lib.sh files/internals/elog_lib.sh \
       files/tlog files/internals/tlog_lib.sh files/update-ipcountry.sh \
       files/internals/alert_lib.sh files/internals/bfd_alert.sh \
       files/internals/pkg_lib.sh files/internals/geoip_lib.sh
shellcheck -S warning files/bfd files/internals/bfd.lib.sh files/internals/elog_lib.sh \
       files/tlog files/internals/tlog_lib.sh files/update-ipcountry.sh \
       files/internals/alert_lib.sh files/internals/bfd_alert.sh \
       files/internals/pkg_lib.sh files/internals/geoip_lib.sh
```

Both must exit 0.

- [ ] **Step 2: Run CLAUDE.md grep checks**

```bash
grep -rn '/usr/bin/\(rm\|mv\|cp\)' files/
grep -rn '^\s*cp \|^\s*mv \|^\s*rm ' files/
grep -rn '\\cp \|\\mv \|\\rm ' files/
grep -rn 'local [a-z_]*=\$(' files/
grep -rn '^\s*cd ' files/
grep -rn '\bwhich\b' files/
grep -rn '\begrep\b' files/
grep -rn '`' files/
grep -rn '|| true' files/
grep -rn '2>/dev/null' files/
```

All `|| true` and `2>/dev/null` hits must have inline comments. No `which`, `egrep`,
backticks, bare `cp`/`mv`/`rm`, or hardcoded `/usr/bin/rm` etc. Every `cd` must
have `|| exit`/`|| return` guard.

- [ ] **Step 3: Re-run tests (Debian 12)**

```bash
make -C tests test 2>&1 | tee /tmp/test-bfd-final-debian12.log | tail -30
grep "^not ok" /tmp/test-bfd-final-debian12.log || echo "ALL PASS"
```

Must: 0 failures.

- [ ] **Step 4: Re-run UAT**

```bash
make -C tests uat 2>&1 | tee /tmp/test-bfd-final-uat.log | tail -30
grep "^not ok" /tmp/test-bfd-final-uat.log || echo "ALL PASS"
```

Must: 86/86 pass.

- [ ] **Step 5: Run tests on Rocky 9**

```bash
make -C tests test-rocky9 2>&1 | tee /tmp/test-bfd-final-rocky9.log | tail -30
grep "^not ok" /tmp/test-bfd-final-rocky9.log || echo "ALL PASS"
```

Must: 0 failures.

---

### Task 11: Push and CI Verification

- [ ] **Step 1: Push to origin**

```bash
git push origin 2.0.1
```

- [ ] **Step 2: Wait for CI and verify green**

```bash
# Check latest CI run status
gh run list --branch 2.0.1 --limit 1
```

Wait for completion. All 11 jobs (lint + 9 OS test matrix + UAT) must pass.
If any fail, investigate logs:

```bash
gh run view <RUN_ID> --log-failed | head -80
```

---

### Task 12: Cut PR to Master

- [ ] **Step 1: Create PR**

```bash
gh pr create --base master --head 2.0.1 \
  --title "Release v2.0.1" \
  --body "$(cat <<'EOF'
## Summary

BFD v2.0.1 release candidate.

- Periodic threat reports (daily/weekly/monthly, multi-channel)
- Events CLI enhancements (--limit, batch ban status, CIDR search)
- Rule expansion: 42 -> 57 service rules (10 new services)
- Performance: extract_hosts ~85x throughput, check() 4.5x at scale
- Security hardening: safe source, credential masking, temp file traps
- Full dual-stack IPv6 country lookup
- 8 vendored libraries synced to latest
- Packaging fixes: RPM/DEB missing libraries resolved
- Watch mode reload: config_init() extraction, SIGHUP correctness
- Deep-legacy portability: command prefix for all coreutils

## Verification

- [ ] Local tests: Debian 12 + Rocky 9 (all pass)
- [ ] UAT: 86/86 pass
- [ ] CI: 9 OS targets + lint + UAT (all green)
- [ ] Libraries: all 5 match canonical upstream
- [ ] CHANGELOG.RELEASE: deduped
- [ ] AI slop scrub: clean
- [ ] rel-prep checklist: clean
- [ ] Performance benchmarks: no regression
EOF
)"
```

- [ ] **Step 2: Record PR URL**

Save the PR number/URL for reference.

---

### Task 13: PR Diff Security Review

- [ ] **Step 1: Review the full diff against master**

```bash
git diff master...2.0.1 --stat
git diff master...2.0.1 -- files/ | head -500
```

Check for:
- Command injection vectors (especially around `$ATTACK_HOST`, `$BAN_COMMAND`)
- Unquoted variables in command context
- Unsafe temp file patterns (PID-based instead of mktemp)
- Credential/secret exposure in logs or alerts
- eval usage without documented security justification
- Unsafe file sourcing without ownership/permission validation

- [ ] **Step 2: Spot-check new rule files**

```bash
git diff master...2.0.1 -- files/rules/ | head -200
```

Verify: no command injection in MATCHED_HOSTS patterns, no executable permissions.

---

### Task 14: Performance Regression Check

- [ ] **Step 1: Compare Stage 3 benchmark KPIs against Stage 1 baselines**

If any fixes were applied in Chunk 2, re-run benchmarks:

```bash
make -C tests bench 2>&1 | tee /tmp/test-bfd-final-bench.log | tail -50
grep "^# KPI:" /tmp/test-bfd-final-bench.log
```

Compare against `/tmp/test-bfd-rel-bench.log` KPIs from Task 7.
Any regression >20% warrants investigation.

If no fixes were applied, Stage 1 baselines are the final baselines — skip re-run.

---

### Task 15: Update MEMORY.md

- [ ] **Step 1: Update CI status and test counts**

Update MEMORY.md to reflect:
- CI status: GREEN (with latest run ID)
- Final test pass counts
- PR number/URL
- Any won't-fix items documented

- [ ] **Step 2: Save memory**

Run `/mem-save` to persist session state.
