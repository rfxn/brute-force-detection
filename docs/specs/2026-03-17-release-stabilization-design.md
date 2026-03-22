# BFD v2.0.1 Release Stabilization

> **Date:** 2026-03-17
> **Branch:** `2.0.1` (HEAD: 49adbe1)
> **Goal:** Get to deterministically verified release-ready state; cut PR to master

## Scope

Validation, fixes, and documentation sync only. No new features.

## Stage 1: Parallel Diagnostics (read-only)

All independent, all concurrent. No code changes.

| Task | Command / Skill | Output |
|------|-----------------|--------|
| 1a. Local tests (Debian 12) | `make -C tests test 2>&1 \| tee /tmp/test-bfd-rel-debian12.log` | pass/fail count |
| 1b. Local UAT | `make -C tests uat 2>&1 \| tee /tmp/test-bfd-rel-uat.log` | pass/fail count |
| 1c. Library freshness | diff vendored vs canonical for 5 libs | drift report |
| 1d. Changelog dedup | `/rel-chg-dedup` | duplicate entries |
| 1e. AI slop scrub | `/rel-scrub` | attribution hits |
| 1f. rel-prep checklist | `/rel-prep` | checklist items |
| 1g. Perf benchmarks | `make -C tests bench 2>&1 \| tee /tmp/test-bfd-rel-bench.log` | KPI baselines |

## Stage 2: Fix Pass (serial)

Collect all Stage 1 findings. Triage:
- **Must-fix:** test failures, stale libs, doc inaccuracies, slop, security issues
- **Won't-fix:** cosmetic, deferred-to-next-release, upstream-owned

Fix must-fix items in minimal commits. Re-run affected validations after each fix.

## Stage 3: Final Gate (serial)

1. Re-run full local tests + UAT (must pass)
2. Lint verification (bash -n + shellcheck + grep checks per CLAUDE.md)
3. Push, confirm CI green on all 9 OS targets
4. Cut PR to master as review surface (do NOT merge)
5. Security spot-check on PR diff
6. Performance regression check against Stage 1 baselines

## Success Criteria

- All local tests pass (Debian 12 + Rocky 9)
- All 86 UAT tests pass
- CI green on all 9 OS targets
- All vendored libraries match canonical upstream (or documented delta)
- CHANGELOG.RELEASE deduped
- No AI attribution/slop in shipped files
- rel-prep checklist clean
- PR to master created, ready for human review

## Out of Scope

- Merging the PR (human decision)
- Tag creation / GitHub release (post-merge, `/rel-ship`)
- Fixing upstream library issues (deferred to canonical repos)
- Advisory items documented in MEMORY.md as deferred
