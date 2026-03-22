# CIDR Alert Enrichment Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enrich CIDR subnet ban alerts with aggregate pressure/failure stats and a per-IP contributing hosts breakdown across all alert channels.

**Architecture:** Extend the existing `count_subnet_attackers()` AWK pass to emit per-IP detail alongside its existing stdout contract. `check_distributed()` reads that detail to compute aggregates (total failures, total weighted pressure, unique count), writes a sidecar file for the alert renderer, and encodes real values into alert pipeline fields 4 and 13. `_alert_set_entry_vars()` reads the sidecar to render a contributing hosts table in SOURCE_LOGS placeholders (email) and a new SUBNET_HOSTS_SECTION placeholder (messaging). A new FAIL_COUNT_DISPLAY variable distinguishes "N failed logins across M IPs" (CIDR) from "N failed logins" (individual).

**Tech Stack:** Bash 4.1+, mawk-compatible AWK, BATS (batsman), BFD alert pipeline

**Spec:** `docs/superpowers/specs/2026-03-17-cidr-alert-enrichment-design.md`

**Convention note:** CHANGELOG updates are batched in Task 8 rather than per-commit.
This is an intentional relaxation of the per-commit changelog rule for multi-commit
feature work on a feature branch — the feature ships as a single logical unit.

---

## File Structure

| File | Role | Action |
|------|------|--------|
| `files/internals/bfd.lib.sh` | Core library: `count_subnet_attackers()`, `check_distributed()` | Modify |
| `files/internals/bfd_alert.sh` | Alert rendering: `_alert_set_entry_vars()` | Modify |
| `files/internals/internals.conf` | Internal defaults | Modify (add 1 variable) |
| `files/alert/text.entry.tpl` | Email text template | Modify |
| `files/alert/html.entry.tpl` | Email HTML template | Modify |
| `files/alert/slack.entry.tpl` | Slack messaging template | Modify |
| `files/alert/telegram.entry.tpl` | Telegram messaging template | Modify |
| `files/alert/discord.entry.tpl` | Discord messaging template | Modify |
| `cron.daily` | Daily cleanup | Modify (add 1 glob) |
| `tests/19-subnet-detection.bats` | Subnet detection tests | Modify (extend) |
| `tests/47-cidr-alert-enrichment.bats` | New: enrichment-specific tests | Create |

---

## Chunk 1: Data Pipeline (count_subnet_attackers + check_distributed)

### Task 1: Extend count_subnet_attackers() to emit detail file

**Context for the engineer:**

`count_subnet_attackers()` lives at `files/internals/bfd.lib.sh:2312-2389`. It reads `pressure.dat` (format: `TIMESTAMP IP MOD [WEIGHT]`) and uses a single-pass AWK to group events by subnet+service, counting unique IPs. It outputs `subnet mod unique_count` on stdout for subnets meeting the `min_unique` threshold. The function signature is:

```bash
count_subnet_attackers() {
    local install_path="$1" window="$2" now="$3"
    local mask="$4" mask_v6="$5" min_unique="$6"
```

It is called from exactly one place: `check_distributed()` at line 2428:
```bash
done < <(count_subnet_attackers "$install_path" "$window" "$now" \
    "$SUBNET_MASK" "$SUBNET_MASK_V6" "$SUBNET_TRIG")
```

The change: add a 7th argument `detail_file` (optional, for backward compat). When provided, the AWK writes per-IP rows to that file for qualifying subnets. The stdout contract is unchanged.

**pressure.dat weight field:** Field 4 (`$4` in AWK) is optional. Older events lack it. mawk returns `""` for unset fields, and `""+0` yields `0`. Use `w = ($4+0 > 0) ? $4+0 : 1` to default missing weights to 1.

**Files:**
- Modify: `files/internals/bfd.lib.sh:2312-2389` (count_subnet_attackers)
- Test: `tests/19-subnet-detection.bats`

---

- [ ] **Step 1: Write failing tests for detail file emission**

Add these tests to `tests/19-subnet-detection.bats` at the end of the `count_subnet_attackers` section (after line 285):

```bash
@test "count_subnet_attackers: writes detail file with per-IP rows" {
	local now=1000000
	local events_file="$INSTALL_PATH/tmp/pressure.dat"
	local detail_file="$TEST_TMPDIR/detail.dat"
	# 3 unique IPs, IP .1 has 2 events (weight 2 and 3), .2 has 1 (weight 1), .3 has 1 (no weight field)
	echo "$now 192.0.2.1 sshd 2" >> "$events_file"
	echo "$now 192.0.2.1 sshd 3" >> "$events_file"
	echo "$now 192.0.2.2 sshd 1" >> "$events_file"
	echo "$now 192.0.2.3 sshd" >> "$events_file"

	run count_subnet_attackers "$INSTALL_PATH" "300" "$now" "24" "48" "3" "$detail_file"
	assert_success
	# stdout contract unchanged
	assert_output --partial "192.0.2.0/24 sshd 3"

	# detail file must exist with per-IP rows
	[ -f "$detail_file" ]
	# 3 unique IPs = 3 rows
	[ "$(wc -l < "$detail_file")" -eq 3 ]
	# verify IP .1: 2 failures, weighted sum = 2+3 = 5
	run grep "192.0.2.1" "$detail_file"
	assert_output "192.0.2.0/24 sshd 192.0.2.1 2 5"
	# verify IP .3: 1 failure, weight defaults to 1
	run grep "192.0.2.3" "$detail_file"
	assert_output "192.0.2.0/24 sshd 192.0.2.3 1 1"
}

@test "count_subnet_attackers: no detail file arg = backward compat" {
	local now=1000000
	local events_file="$INSTALL_PATH/tmp/pressure.dat"
	echo "$now 192.0.2.1 sshd" >> "$events_file"
	echo "$now 192.0.2.2 sshd" >> "$events_file"
	echo "$now 192.0.2.3 sshd" >> "$events_file"

	# call without 7th arg — must still work
	run count_subnet_attackers "$INSTALL_PATH" "300" "$now" "24" "48" "3"
	assert_success
	assert_output --partial "192.0.2.0/24 sshd 3"
}

@test "count_subnet_attackers: detail file excludes sub-threshold subnets" {
	local now=1000000
	local events_file="$INSTALL_PATH/tmp/pressure.dat"
	local detail_file="$TEST_TMPDIR/detail.dat"
	# subnet A: 3 IPs (meets threshold)
	echo "$now 192.0.2.1 sshd 1" >> "$events_file"
	echo "$now 192.0.2.2 sshd 1" >> "$events_file"
	echo "$now 192.0.2.3 sshd 1" >> "$events_file"
	# subnet B: 2 IPs (below threshold)
	echo "$now 10.0.0.1 sshd 1" >> "$events_file"
	echo "$now 10.0.0.2 sshd 1" >> "$events_file"

	run count_subnet_attackers "$INSTALL_PATH" "300" "$now" "24" "48" "3" "$detail_file"
	assert_success
	# only subnet A in detail — sub-threshold subnet B excluded
	[ -f "$detail_file" ]
	run cat "$detail_file"
	refute_output --partial "10.0.0"
	[ "$(wc -l < "$detail_file")" -eq 3 ]
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
make -C tests test 2>&1 | tee /tmp/test-bfd-t1.log | tail -30
grep "count_subnet_attackers: writes detail" /tmp/test-bfd-t1.log
```

Expected: FAIL (detail_file not written — function ignores 7th arg)

- [ ] **Step 3: Implement detail file emission in count_subnet_attackers()**

In `files/internals/bfd.lib.sh`, modify `count_subnet_attackers()`:

1. Add the `detail_file` parameter at line 2314:
```bash
count_subnet_attackers() {
	local install_path="$1" window="$2" now="$3"
	local mask="$4" mask_v6="$5" min_unique="$6"
	local detail_file="${7:-}"
	local events_file="$install_path/tmp/pressure.dat"
```

2. Pass `detail_file` to AWK as a new `-v` variable at line 2320:
```bash
	awk -v cutoff="$cutoff" -v mask="$mask" -v mask_v6="$mask_v6" \
		-v min_unique="$min_unique" -v detail_file="$detail_file" '
```

3. In the AWK main block (lines 2367-2383), replace the body from `{` to the closing `}` before `END`. The `ipv4_subnet` and `ipv6_subnet` functions above are unchanged. Replace:

```awk
	{
		if ($1+0 < cutoff) next
		ip = $2; mod = $3
		if (index(ip, ":") > 0)
			subnet = ipv6_subnet(ip, mask_v6)
		else
			subnet = ipv4_subnet(ip, mask)
		if (subnet == "") next
		key = subnet SUBSEP mod
		ipkey = key SUBSEP ip
		if (!(ipkey in seen)) {
			seen[ipkey] = 1
			unique[key]++
		}
		snet[key] = subnet
		smod[key] = mod
	}
```

With:

```awk
	{
		if ($1+0 < cutoff) next
		ip = $2; mod = $3
		w = ($4+0 > 0) ? $4+0 : 1
		if (index(ip, ":") > 0)
			subnet = ipv6_subnet(ip, mask_v6)
		else
			subnet = ipv4_subnet(ip, mask)
		if (subnet == "") next
		key = subnet SUBSEP mod
		ipkey = key SUBSEP ip
		if (!(ipkey in seen)) {
			seen[ipkey] = 1
			unique[key]++
		}
		snet[key] = subnet
		smod[key] = mod
		# per-IP detail tracking
		ip_fail[ipkey]++
		ip_wsum[ipkey] += w
		ip_addr[ipkey] = ip
	}
```

4. Replace the existing END block:

```awk
	END {
		for (key in unique)
			if (unique[key] >= min_unique)
				print snet[key] " " smod[key] " " unique[key]
	}' "$events_file"
```

With:

```awk
	END {
		for (key in unique) {
			if (unique[key] >= min_unique) {
				print snet[key] " " smod[key] " " unique[key]
				if (detail_file != "") {
					for (ipkey in ip_addr) {
						split(ipkey, kp, SUBSEP)
						if (kp[1] SUBSEP kp[2] == key) {
							print snet[key] " " smod[key] " " ip_addr[ipkey] " " ip_fail[ipkey] " " ip_wsum[ipkey] > detail_file
						}
					}
				}
			}
		}
	}' "$events_file"
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
make -C tests test 2>&1 | tee /tmp/test-bfd-t1b.log | tail -30
grep "count_subnet_attackers" /tmp/test-bfd-t1b.log
```

Expected: All `count_subnet_attackers` tests PASS (including existing ones — backward compat preserved)

- [ ] **Step 5: Run lint**

```bash
bash -n files/internals/bfd.lib.sh && echo "syntax ok"
shellcheck -S warning files/internals/bfd.lib.sh 2>&1 | head -20
```

- [ ] **Step 6: Commit**

```bash
git add files/internals/bfd.lib.sh tests/19-subnet-detection.bats
git commit -m "$(cat <<'EOF'
2.0.1 | Extend count_subnet_attackers() to emit per-IP detail file

[New] count_subnet_attackers() accepts optional 7th arg (detail_file path)
[New] When detail_file provided, AWK writes per-IP rows: subnet mod ip fail_count weighted_sum
[New] Weight field ($4) defaults to 1 when absent (mawk-safe)
[Change] Existing stdout contract unchanged — backward compatible
[New] 3 new tests: detail file emission, backward compat, sub-threshold exclusion
EOF
)"
```

---

### Task 2: Add SUBNET_ALERT_TOP_N to internals.conf + cron.daily cleanup

**Context for the engineer:**

`files/internals/internals.conf` holds internal defaults. The last variable is `ELOG_LOG_MAX_LINES` at line 70. New variable `SUBNET_ALERT_TOP_N` defaults to 5 — controls how many contributing IPs to show in the alert breakdown. Internal-only: NOT exposed in `conf.bfd`, `help()`, man page, or README.

`cron.daily` cleans transient state at lines 128-131. The new sidecar files (`.cidr_detail_*`) need a cleanup glob there as a safety net for any sidecar not consumed during the alert cycle.

**Files:**
- Modify: `files/internals/internals.conf:70`
- Modify: `cron.daily:131`

---

- [ ] **Step 1: Add SUBNET_ALERT_TOP_N to internals.conf**

Append after line 70 of `files/internals/internals.conf`:

```bash

# max contributing IPs shown in CIDR subnet ban alert breakdown
SUBNET_ALERT_TOP_N="${SUBNET_ALERT_TOP_N:-5}"
```

- [ ] **Step 2: Add .cidr_detail_* cleanup to cron.daily**

In `cron.daily`, after line 131 (`command rm -f "$INSTALL_PATH"/tmp/.bfd_rpt_*`), add:

```bash
command rm -f "$INSTALL_PATH"/tmp/.cidr_detail_*
```

- [ ] **Step 3: Run lint on both files**

```bash
bash -n files/internals/internals.conf cron.daily && echo "syntax ok"
```

- [ ] **Step 4: Commit**

```bash
git add files/internals/internals.conf cron.daily
git commit -m "$(cat <<'EOF'
2.0.1 | Add SUBNET_ALERT_TOP_N config and CIDR sidecar cleanup

[New] SUBNET_ALERT_TOP_N in internals.conf (default 5) — max IPs in alert breakdown
[New] cron.daily cleans orphaned .cidr_detail_* sidecar files
EOF
)"
```

---

### Task 3: Rewrite check_distributed() to compute aggregates and write sidecar

**Context for the engineer:**

`check_distributed()` lives at `files/internals/bfd.lib.sh:2395-2432`. It reads the stdout of `count_subnet_attackers()` and for each qualifying subnet: checks if already banned, executes ban, records state, and appends a 13-field pipe-delimited alert line.

Currently at line 2425, the alert line hardcodes broken values:
```bash
echo "${subnet}|${mod}|all|${unique_count}|${ban_expiry}|${ban_action}|${recent_bans}|(multiple)|${EMAIL_ADDRESS}|${SUBNET_TRIG}|${window}|1|0" >> "$alerts_file"
```
- Field 4 (`pressure_scaled`): set to `unique_count` (e.g., `3`) — should be `total_pressure_raw * 1000`
- Field 13 (`fail_count`): hardcoded `0` — should be `total_failures`

The change:
1. Create a temp detail file, pass it as 7th arg to `count_subnet_attackers()`
2. After each qualifying subnet, read matching rows from detail to compute aggregates
3. Write a sidecar file at `$INSTALL_PATH/tmp/.cidr_detail_<sanitized_subnet>` for the alert renderer
4. Encode real aggregate values in fields 4 and 13

**Sidecar file format:**
```
HEADER 45.143.162.0/24 6 47 47000
45.143.162.12 mod_sec 14 14000
45.143.162.88 sshd 9 9000
...
OVERFLOW 1
```

**Sidecar filename sanitization:** Replace `/` with `_` and `:` with `-` for IPv6 safety:
`45.143.162.0/24` -> `.cidr_detail_45.143.162.0_24`
`2001:db8::/48` -> `.cidr_detail_2001-db8--_48`

**Files:**
- Modify: `files/internals/bfd.lib.sh:2395-2432` (check_distributed)
- Test: `tests/19-subnet-detection.bats`

---

- [ ] **Step 1: Write failing tests for aggregate encoding and sidecar generation**

Add to the end of `tests/19-subnet-detection.bats`:

```bash
# ============================================================
# check_distributed — CIDR alert enrichment
# ============================================================

@test "check_distributed: alert fields 4+13 carry aggregate values" {
	local now=1000000
	local events_file="$INSTALL_PATH/tmp/pressure.dat"
	local alerts_file="$TEST_TMPDIR/alerts"
	touch "$alerts_file"

	# 3 IPs: .1 has 2 events (weight 2 each), .2 has 1 (weight 1), .3 has 1 (weight 3)
	echo "$now 192.0.2.1 sshd 2" >> "$events_file"
	echo "$now 192.0.2.1 sshd 2" >> "$events_file"
	echo "$now 192.0.2.2 sshd 1" >> "$events_file"
	echo "$now 192.0.2.3 sshd 3" >> "$events_file"

	SUBNET_TRIG="3"
	SUBNET_MASK="24"
	SUBNET_MASK_V6="48"
	TRIG_WINDOW="300"
	EMAIL_ALERTS="1"
	EMAIL_ADDRESS="admin@example.com"

	check_distributed "$INSTALL_PATH" "$TRIG_WINDOW" "$now" "$alerts_file" >/dev/null

	# field 4 = total_pressure_raw * 1000 = (2+2+1+3) * 1000 = 8000
	local f4
	f4=$(awk -F'|' '{print $4}' "$alerts_file")
	[ "$f4" = "8000" ]

	# field 13 = total_failures = 4 (2+1+1)
	local f13
	f13=$(awk -F'|' '{print $13}' "$alerts_file")
	[ "$f13" = "4" ]
}

@test "check_distributed: writes sidecar file for alert renderer" {
	local now=1000000
	local events_file="$INSTALL_PATH/tmp/pressure.dat"
	local alerts_file="$TEST_TMPDIR/alerts"
	touch "$alerts_file"

	echo "$now 192.0.2.1 sshd 2" >> "$events_file"
	echo "$now 192.0.2.1 sshd 2" >> "$events_file"
	echo "$now 192.0.2.2 sshd 1" >> "$events_file"
	echo "$now 192.0.2.3 sshd 3" >> "$events_file"

	SUBNET_TRIG="3"
	SUBNET_MASK="24"
	SUBNET_MASK_V6="48"
	TRIG_WINDOW="300"
	EMAIL_ALERTS="1"
	EMAIL_ADDRESS="admin@example.com"
	SUBNET_ALERT_TOP_N="5"

	check_distributed "$INSTALL_PATH" "$TRIG_WINDOW" "$now" "$alerts_file" >/dev/null

	# sidecar file must exist
	local sidecar="$INSTALL_PATH/tmp/.cidr_detail_192.0.2.0_24"
	[ -f "$sidecar" ]

	# header line
	run head -1 "$sidecar"
	assert_output "HEADER 192.0.2.0/24 3 4 8000"

	# per-IP rows sorted by weighted sum descending — .1 has highest (4000)
	run sed -n '2p' "$sidecar"
	assert_output --partial "192.0.2.1"
}

@test "check_distributed: sidecar has OVERFLOW when IPs > TOP_N" {
	local now=1000000
	local events_file="$INSTALL_PATH/tmp/pressure.dat"
	local alerts_file="$TEST_TMPDIR/alerts"
	touch "$alerts_file"

	# 4 unique IPs but TOP_N=2
	local i
	for i in 1 2 3 4; do
		echo "$now 192.0.2.${i} sshd 1" >> "$events_file"
	done

	SUBNET_TRIG="3"
	SUBNET_MASK="24"
	SUBNET_MASK_V6="48"
	TRIG_WINDOW="300"
	EMAIL_ALERTS="1"
	EMAIL_ADDRESS="admin@example.com"
	SUBNET_ALERT_TOP_N="2"

	check_distributed "$INSTALL_PATH" "$TRIG_WINDOW" "$now" "$alerts_file" >/dev/null

	local sidecar="$INSTALL_PATH/tmp/.cidr_detail_192.0.2.0_24"
	[ -f "$sidecar" ]
	# header + 2 IP rows + OVERFLOW line = 4 lines
	[ "$(wc -l < "$sidecar")" -eq 4 ]
	run tail -1 "$sidecar"
	assert_output "OVERFLOW 2"
}

@test "check_distributed: sidecar filename sanitizes IPv6 colons" {
	local now=1000000
	local events_file="$INSTALL_PATH/tmp/pressure.dat"
	local alerts_file="$TEST_TMPDIR/alerts"
	touch "$alerts_file"

	echo "$now 2001:db8:1234::1 sshd 1" >> "$events_file"
	echo "$now 2001:db8:1234::2 sshd 1" >> "$events_file"
	echo "$now 2001:db8:1234::3 sshd 1" >> "$events_file"

	SUBNET_TRIG="3"
	SUBNET_MASK="24"
	SUBNET_MASK_V6="48"
	TRIG_WINDOW="300"
	EMAIL_ALERTS="1"
	EMAIL_ADDRESS="admin@example.com"
	SUBNET_ALERT_TOP_N="5"

	check_distributed "$INSTALL_PATH" "$TRIG_WINDOW" "$now" "$alerts_file" >/dev/null

	# colons replaced with -, slash replaced with _
	local sidecar="$INSTALL_PATH/tmp/.cidr_detail_2001-db8-1234--_48"
	[ -f "$sidecar" ]
}

@test "check_distributed: no sidecar when EMAIL_ALERTS=0" {
	local now=1000000
	local events_file="$INSTALL_PATH/tmp/pressure.dat"
	local alerts_file="$TEST_TMPDIR/alerts"
	touch "$alerts_file"

	for i in 1 2 3; do
		echo "$now 192.0.2.${i} sshd 1" >> "$events_file"
	done

	SUBNET_TRIG="3"
	SUBNET_MASK="24"
	SUBNET_MASK_V6="48"
	TRIG_WINDOW="300"
	EMAIL_ALERTS="0"

	check_distributed "$INSTALL_PATH" "$TRIG_WINDOW" "$now" "$alerts_file" >/dev/null

	# no sidecar written when alerts disabled
	[ ! -f "$INSTALL_PATH/tmp/.cidr_detail_192.0.2.0_24" ]
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
make -C tests test 2>&1 | tee /tmp/test-bfd-t3.log | tail -30
grep "check_distributed: alert fields" /tmp/test-bfd-t3.log
```

Expected: FAIL (fields still have old values)

- [ ] **Step 3: Implement the new check_distributed()**

Replace the entire `check_distributed()` function at `files/internals/bfd.lib.sh:2395-2432` with:

```bash
# check_distributed install_path window now alerts_file
# Post-loop distributed attack detection: bans entire subnets when
# SUBNET_TRIG unique IPs from the same subnet attack the same service.
# Writes sidecar files for alert enrichment with per-IP breakdown.
# Echoes the number of subnet bans executed.
check_distributed() {
	local install_path="$1" window="$2" now="$3" alerts_file="$4"
	local ban_count=0

	# detail file for per-IP data from count_subnet_attackers
	local detail_file
	detail_file=$(mktemp "$install_path/tmp/.cidr_detail_raw.XXXXXX")

	local subnet mod unique_count
	while IFS=' ' read -r subnet mod unique_count; do
		[ -z "$subnet" ] && continue
		if state_bans_active_check "$install_path" "$subnet"; then
			eout "{$mod} subnet $subnet already banned, skipping." le
			continue
		fi
		elog warn "{$mod} distributed attack detected: $unique_count unique IPs from $subnet."
		if execute_ban "$subnet" "$mod" "$DRY_RUN" "all"; then
			ban_count=$((ban_count + 1))
			local ban_result
			ban_result=$(record_ban "$install_path" "$now" "$subnet" "$mod" "all" "ban")
			local ban_expiry ban_action recent_bans
			IFS='|' read -r ban_expiry ban_action recent_bans <<< "$ban_result"
			local _dist_duration="-1"
			if [ "$ban_expiry" = "0" ]; then
				_dist_duration="0"
			else
				_dist_duration=$((ban_expiry - now))
			fi

			# compute aggregates from detail file
			local total_failures=0 total_pressure_raw=0
			local _d_ip _d_mod _d_fc _d_ws _d_sn
			while IFS=' ' read -r _d_sn _d_mod _d_ip _d_fc _d_ws; do
				[ "$_d_sn" = "$subnet" ] || continue
				total_failures=$((total_failures + _d_fc))
				total_pressure_raw=$((total_pressure_raw + _d_ws))
			done < "$detail_file"
			local pressure_scaled=$((total_pressure_raw * 1000))

			# write sidecar file for alert renderer
			if [ "$EMAIL_ALERTS" = "1" ] && [ "$DRY_RUN" != "1" ]; then
				local _san_subnet
				_san_subnet=$(printf '%s' "$subnet" | tr ':' '-' | tr '/' '_')
				local sidecar="$install_path/tmp/.cidr_detail_${_san_subnet}"
				# header: subnet unique_count total_failures total_pressure_raw_scaled
				echo "HEADER $subnet $unique_count $total_failures $pressure_scaled" > "$sidecar"
				# per-IP rows sorted by weighted sum descending, capped at TOP_N
				local _top_n="${SUBNET_ALERT_TOP_N:-5}"
				local _ip_count=0 _overflow=0
				while IFS=' ' read -r _d_sn _d_mod _d_ip _d_fc _d_ws; do
					_ip_count=$((_ip_count + 1))
					if [ "$_ip_count" -le "$_top_n" ]; then
						echo "$_d_ip $_d_mod $_d_fc $((_d_ws * 1000))" >> "$sidecar"
					fi
				done < <(awk -v sn="$subnet" '$1 == sn { print }' "$detail_file" | sort -k5 -rn)
				_overflow=$((_ip_count - _top_n))
				if [ "$_overflow" -gt 0 ]; then
					echo "OVERFLOW $_overflow" >> "$sidecar"
				fi

				echo "${subnet}|${mod}|all|${pressure_scaled}|${ban_expiry}|${ban_action}|${recent_bans}|(multiple)|${EMAIL_ADDRESS}|${SUBNET_TRIG}|${window}|1|${total_failures}" >> "$alerts_file"
			fi

			local _dist_cc
			_dist_cc=$(_resolve_cidr_cc "$subnet" "--")
			state_pool_append "$install_path" "$now" "$subnet" "$mod" \
				"$unique_count" "$_dist_cc" "$ban_action" "$_dist_duration" "all" \
				"0" "subnet"
		fi
	done < <(count_subnet_attackers "$install_path" "$window" "$now" \
		"$SUBNET_MASK" "$SUBNET_MASK_V6" "$SUBNET_TRIG" "$detail_file")

	command rm -f "$detail_file"
	echo "$ban_count"
}
```

**Key changes from original:**
- Creates temp `detail_file`, passes as 7th arg to `count_subnet_attackers()`
- Reads detail file to sum `total_failures` and `total_pressure_raw` per subnet
- Field 4 now: `pressure_scaled = total_pressure_raw * 1000` (proper thousandths)
- Field 13 now: `total_failures` (real failure count)
- Writes sidecar file with HEADER, sorted per-IP rows (capped at TOP_N), optional OVERFLOW
- Sidecar filename: `.cidr_detail_<sanitized_subnet>` (`:` -> `-`, `/` -> `_`)
- Sidecar and alert line only written when `EMAIL_ALERTS=1` and `DRY_RUN!=1`
- Cleans up raw detail file at function end
- `state_pool_append` moved after the alert block (still passes `unique_count`, unchanged)

- [ ] **Step 4: Run all subnet tests**

```bash
make -C tests test 2>&1 | tee /tmp/test-bfd-t3b.log | tail -30
grep "not ok" /tmp/test-bfd-t3b.log
```

Expected: All tests PASS (both new and existing)

- [ ] **Step 5: Run lint**

```bash
bash -n files/internals/bfd.lib.sh && echo "syntax ok"
shellcheck -S warning files/internals/bfd.lib.sh 2>&1 | head -20
```

- [ ] **Step 6: Commit**

```bash
git add files/internals/bfd.lib.sh tests/19-subnet-detection.bats
git commit -m "$(cat <<'EOF'
2.0.1 | Enrich check_distributed() with aggregate stats and sidecar file

[Fix] Field 4 (pressure_scaled) now carries total_pressure_raw * 1000 (was unique_count)
[Fix] Field 13 (fail_count) now carries total_failures (was hardcoded 0)
[New] Sidecar file written at tmp/.cidr_detail_<subnet> for alert renderer
[New] Sidecar has HEADER line (aggregates) + top-N per-IP rows + OVERFLOW count
[New] IPv6 sidecar filename sanitization (colons to dashes)
[New] 5 new tests: field 4+13 values, sidecar generation, OVERFLOW, IPv6 filename, no-alert guard
EOF
)"
```

---

### Task 4: Verify existing check_distributed tests still pass with new behavior

**Context for the engineer:**

The existing tests at lines 154-332 of `tests/19-subnet-detection.bats` were written before CIDR enrichment. Some set `EMAIL_ALERTS="0"` (the setup default), so they won't generate alert lines or sidecars. The test at line 287 ("alert entry has (multiple)") sets `EMAIL_ALERTS="1"` — this one now needs updated field assertions since fields 4 and 13 changed.

**Files:**
- Modify: `tests/19-subnet-detection.bats:287-309`

---

- [ ] **Step 1: Update the existing alert entry test to assert new field values**

The test at line 287 seeds 3 IPs with no weight field (defaults to 1). Expected aggregates:
- `total_failures` = 3 (one event per IP)
- `total_pressure_raw` = 3 (weight 1 each)
- `pressure_scaled` = 3000

In `tests/19-subnet-detection.bats`, after the existing assertion `assert_output "(multiple)"` at line 308, add:

```bash
	# field 4 = pressure_scaled (total_pressure * 1000) — 3 events at weight 1 = 3000
	run awk -F'|' '{print $4}' "$alerts_file"
	assert_output "3000"

	# field 13 = total_failures — 3 IPs, 1 event each = 3
	run awk -F'|' '{print $13}' "$alerts_file"
	assert_output "3"
```

- [ ] **Step 2: Run the full 19-subnet test file**

```bash
make -C tests test 2>&1 | tee /tmp/test-bfd-t4.log | tail -30
grep "not ok" /tmp/test-bfd-t4.log
```

Expected: All PASS

- [ ] **Step 3: Commit**

```bash
git add tests/19-subnet-detection.bats
git commit -m "$(cat <<'EOF'
2.0.1 | Add field 4+13 assertions to existing subnet alert entry test

[Change] Test "alert entry has (multiple)" now asserts pressure_scaled=3000 and fail_count=3
EOF
)"
```

---

## Chunk 2: Alert Rendering (bfd_alert.sh + templates)

### Task 5: Enrich _alert_set_entry_vars() for CIDR alerts

**Context for the engineer:**

`_alert_set_entry_vars()` lives at `files/internals/bfd_alert.sh:276-524`. It parses the 13-field pipe-delimited alert line and exports template variables. The function detects CIDR alerts via `lp == "(multiple)"` at line 507.

**Current `(multiple)` branch (lines 507-514):**
```bash
	elif [ "$lp" = "(multiple)" ]; then
		# distributed subnet ban — no single log source
		SOURCE_LOGS_SECTION_TEXT="  Source logs: not available (distributed subnet ban)"
		export SOURCE_LOGS_SECTION_TEXT
		SOURCE_LOGS_SECTION_HTML='<tr>...'
		export SOURCE_LOGS_SECTION_HTML
	fi
```

This needs to:
1. Read the sidecar file to get the contributing hosts table
2. Format text and HTML variants of the breakdown
3. Export `FAIL_COUNT_DISPLAY` (e.g., "47 across 6 IPs") instead of plain integer
4. Export `SUBNET_IP_COUNT` for template use
5. Export `SUBNET_HOSTS_SECTION` for messaging templates (compact text)
6. Fall back gracefully if sidecar is missing (race, cleanup)

**New template variables:**
- `FAIL_COUNT_DISPLAY` — always exported; equals `FAIL_COUNT` for non-CIDR, "N across M IPs" for CIDR
- `SUBNET_IP_COUNT` — unique contributing IP count (empty for non-CIDR)
- `SUBNET_HOSTS_SECTION` — JSON-escaped compact text for Slack/Discord (empty for non-CIDR)
- `SUBNET_HOSTS_SECTION_TG` — Telegram MarkdownV2-escaped variant (empty for non-CIDR)

**Channel escaping pattern:** Follows the existing `COUNTRY_DISPLAY` / `COUNTRY_DISPLAY_TG` pattern.
The template engine (`_alert_tpl_render` in `alert_lib.sh:126`) substitutes `ENVIRON[token]` values literally via AWK. Slack and Discord templates are JSON — literal newlines in a JSON string break parsing. Telegram uses MarkdownV2 where dots, parens, and dashes are special chars. Therefore:
- `SUBNET_HOSTS_SECTION` is JSON-escaped via `_alert_json_escape()` (newlines become `\n` literals)
- `SUBNET_HOSTS_SECTION_TG` is MarkdownV2-escaped via `_alert_telegram_escape()`
- Both are empty strings for non-CIDR alerts — no visual change in templates

**Files:**
- Modify: `files/internals/bfd_alert.sh:276-524`
- Test: `tests/47-cidr-alert-enrichment.bats` (new file)

---

- [ ] **Step 1: Create new test file with failing tests**

Create `tests/47-cidr-alert-enrichment.bats`:

```bash
#!/usr/bin/env bats
#
# Test suite for CIDR alert enrichment — _alert_set_entry_vars with sidecar
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

setup() {
	bfd_standard_setup
	BAN_COMMAND_TEMPLATE="echo ban \$ATTACK_HOST"
	_FW_BACKEND="custom"
	BAN_ESCALATE_AFTER="0"
	BAN_ESCALATION="none"
	EMAIL_REPUTATION_LINKS=""
	SUBNET_ALERT_TOP_N="5"
}

teardown() {
	bfd_teardown
}

# helper: create a sidecar file for a given subnet
_create_sidecar() {
	local subnet="$1" unique="$2" failures="$3" pressure="$4"
	shift 4
	local san_subnet
	san_subnet=$(printf '%s' "$subnet" | tr ':' '-' | tr '/' '_')
	local sidecar="$INSTALL_PATH/tmp/.cidr_detail_${san_subnet}"
	echo "HEADER $subnet $unique $failures $pressure" > "$sidecar"
	# remaining args are "ip mod fail_count pressure_scaled" lines
	while [ $# -gt 0 ]; do
		echo "$1" >> "$sidecar"
		shift
	done
}

# ============================================================
# FAIL_COUNT_DISPLAY
# ============================================================

@test "CIDR alert: FAIL_COUNT_DISPLAY shows 'N across M IPs'" {
	_create_sidecar "192.0.2.0/24" 3 47 47000 \
		"192.0.2.12 sshd 20 20000" \
		"192.0.2.88 sshd 15 15000" \
		"192.0.2.201 sshd 12 12000"

	local line="192.0.2.0/24|sshd|all|47000|0|ban|0|(multiple)|root|5|300|1|47"
	_alert_set_entry_vars "$line" 1 1
	[ "$FAIL_COUNT_DISPLAY" = "47 across 3 IPs" ]
	[ "$FAIL_COUNT" = "47" ]
	[ "$SUBNET_IP_COUNT" = "3" ]
}

@test "non-CIDR alert: FAIL_COUNT_DISPLAY equals FAIL_COUNT" {
	local line="192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|root|10|300|1|5"
	_alert_set_entry_vars "$line" 1 1
	[ "$FAIL_COUNT_DISPLAY" = "5" ]
	[ "$SUBNET_IP_COUNT" = "" ]
}

# ============================================================
# Contributing hosts table
# ============================================================

@test "CIDR alert: SOURCE_LOGS_SECTION_TEXT contains contributing hosts" {
	_create_sidecar "192.0.2.0/24" 3 47 47000 \
		"192.0.2.12 mod_sec 14 14000" \
		"192.0.2.88 sshd 9 9000" \
		"192.0.2.201 sshd 8 8000"

	local line="192.0.2.0/24|sshd|all|47000|0|ban|0|(multiple)|root|5|300|1|47"
	_alert_set_entry_vars "$line" 1 1
	[[ "$SOURCE_LOGS_SECTION_TEXT" == *"Contributing hosts"* ]]
	[[ "$SOURCE_LOGS_SECTION_TEXT" == *"192.0.2.12"* ]]
	[[ "$SOURCE_LOGS_SECTION_TEXT" == *"192.0.2.88"* ]]
	[[ "$SOURCE_LOGS_SECTION_TEXT" == *"192.0.2.201"* ]]
}

@test "CIDR alert: SOURCE_LOGS_SECTION_HTML contains styled table" {
	_create_sidecar "192.0.2.0/24" 2 10 10000 \
		"192.0.2.1 sshd 6 6000" \
		"192.0.2.2 sshd 4 4000"

	local line="192.0.2.0/24|sshd|all|10000|0|ban|0|(multiple)|root|5|300|1|10"
	_alert_set_entry_vars "$line" 1 1
	[[ "$SOURCE_LOGS_SECTION_HTML" == *"<table"* ]] || [[ "$SOURCE_LOGS_SECTION_HTML" == *"<div"* ]]
	[[ "$SOURCE_LOGS_SECTION_HTML" == *"192.0.2.1"* ]]
}

@test "CIDR alert: SUBNET_HOSTS_SECTION is JSON-escaped for messaging" {
	_create_sidecar "192.0.2.0/24" 2 10 10000 \
		"192.0.2.1 sshd 6 6000" \
		"192.0.2.2 sshd 4 4000"

	local line="192.0.2.0/24|sshd|all|10000|0|ban|0|(multiple)|root|5|300|1|10"
	_alert_set_entry_vars "$line" 1 1
	[[ "$SUBNET_HOSTS_SECTION" == *"192.0.2.1"* ]]
	[ -n "$SUBNET_HOSTS_SECTION" ]
	# JSON-escaped: literal newlines converted to \n sequences
	[[ "$SUBNET_HOSTS_SECTION" != *$'\n'* ]]
}

@test "CIDR alert: SUBNET_HOSTS_SECTION_TG is Telegram-escaped" {
	_create_sidecar "192.0.2.0/24" 2 10 10000 \
		"192.0.2.1 sshd 6 6000" \
		"192.0.2.2 sshd 4 4000"

	local line="192.0.2.0/24|sshd|all|10000|0|ban|0|(multiple)|root|5|300|1|10"
	_alert_set_entry_vars "$line" 1 1
	[[ "$SUBNET_HOSTS_SECTION_TG" == *"192\.0\.2\.1"* ]]
	[ -n "$SUBNET_HOSTS_SECTION_TG" ]
}

@test "non-CIDR alert: SUBNET_HOSTS_SECTION is empty" {
	local line="192.0.2.1|sshd|22|5000|0|ban|0|/dev/null|root|10|300|1|5"
	_alert_set_entry_vars "$line" 1 1
	[ "$SUBNET_HOSTS_SECTION" = "" ]
	[ "$SUBNET_HOSTS_SECTION_TG" = "" ]
}

# ============================================================
# Sidecar fallback
# ============================================================

@test "CIDR alert: missing sidecar falls back to static message" {
	# no sidecar created — simulate race/cleanup
	local line="192.0.2.0/24|sshd|all|47000|0|ban|0|(multiple)|root|5|300|1|47"
	_alert_set_entry_vars "$line" 1 1
	# FAIL_COUNT_DISPLAY still works from field 13 alone, but no IP count
	[ "$FAIL_COUNT_DISPLAY" = "47" ]
	[[ "$SOURCE_LOGS_SECTION_TEXT" == *"not available"* ]]
	[ "$SUBNET_HOSTS_SECTION" = "" ]
	[ "$SUBNET_HOSTS_SECTION_TG" = "" ]
}

@test "CIDR alert: sidecar with OVERFLOW shows overflow line" {
	_create_sidecar "10.0.0.0/24" 6 47 47000 \
		"10.0.0.1 sshd 14 14000" \
		"10.0.0.2 sshd 9 9000" \
		"OVERFLOW 4"

	local line="10.0.0.0/24|sshd|all|47000|0|ban|0|(multiple)|root|5|300|1|47"
	_alert_set_entry_vars "$line" 1 1
	[[ "$SOURCE_LOGS_SECTION_TEXT" == *"4 more"* ]]
	[ "$SUBNET_IP_COUNT" = "6" ]
}

@test "CIDR alert: sidecar cleaned up after reading" {
	_create_sidecar "192.0.2.0/24" 2 10 10000 \
		"192.0.2.1 sshd 6 6000" \
		"192.0.2.2 sshd 4 4000"

	local line="192.0.2.0/24|sshd|all|10000|0|ban|0|(multiple)|root|5|300|1|10"
	_alert_set_entry_vars "$line" 1 1
	[ ! -f "$INSTALL_PATH/tmp/.cidr_detail_192.0.2.0_24" ]
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
make -C tests test 2>&1 | tee /tmp/test-bfd-t5.log | tail -30
grep "CIDR alert\|non-CIDR" /tmp/test-bfd-t5.log
```

Expected: FAIL (FAIL_COUNT_DISPLAY not exported, sidecar not read)

- [ ] **Step 3: Implement the enrichment in _alert_set_entry_vars()**

In `files/internals/bfd_alert.sh`, make two changes:

**Change A:** After the `FAIL_COUNT` and `PRESSURE_CONTRIB` exports (lines 340-343), add the default `FAIL_COUNT_DISPLAY` and new CIDR variables:

After line 343 (`export PRESSURE_CONTRIB=$(( _fc * ${weight:-1} ))`), add:

```bash
	# FAIL_COUNT_DISPLAY: human-readable failure count
	# default: same as FAIL_COUNT (overridden for CIDR below)
	export FAIL_COUNT_DISPLAY="$_fc"
	# CIDR-only variables (empty for individual IP alerts)
	export SUBNET_IP_COUNT=""
	export SUBNET_HOSTS_SECTION=""
	export SUBNET_HOSTS_SECTION_TG=""
```

**Change B:** Replace the `(multiple)` branch (lines 507-514) with the enriched version.
**Important boundary note:** This replaces ONLY lines 507-514. The `elif` at line 507 is part
of an `if/elif/elif/fi` chain (lines 480-523). The replacement starts with `elif` and ends
before the next `elif [ -z "$lp" ]` at line 515 — that `elif` and the final `fi` at line 523
remain unchanged. The inner `fi` in the replacement closes the `if [ -f "$_sidecar" ]` block,
NOT the outer `elif`.

```bash
	elif [ "$lp" = "(multiple)" ]; then
		# distributed subnet ban — read sidecar for enriched breakdown
		local _san_host
		_san_host=$(printf '%s' "$host" | tr ':' '-' | tr '/' '_')
		local _sidecar="${INSTALL_PATH:-}/tmp/.cidr_detail_${_san_host}"

		if [ -f "$_sidecar" ]; then
			# parse header: HEADER subnet unique_count total_failures pressure_scaled
			local _hdr_tag _hdr_sn _hdr_uc _hdr_tf _hdr_ps
			IFS=' ' read -r _hdr_tag _hdr_sn _hdr_uc _hdr_tf _hdr_ps < "$_sidecar"

			export SUBNET_IP_COUNT="$_hdr_uc"
			export FAIL_COUNT_DISPLAY="${_fc} across ${_hdr_uc} IPs"

			# build contributing hosts text table
			local _hosts_text _hosts_html _hosts_msg _overflow="" _line_data
			_hosts_text="  Contributing hosts (${_hdr_uc} IPs from ${host}):"
			_hosts_html='<tr><td colspan="2" style="padding:8px 16px;"><div style="background-color:#f4f4f5;border:1px solid #d4d4d8;border-radius:6px;padding:10px;font-family:'"'"'Courier New'"'"',Courier,monospace;font-size:11px;color:#09090b;">'
			_hosts_html="${_hosts_html}<strong>Contributing hosts (${_hdr_uc} IPs from ${host}):</strong><br>"
			_hosts_msg="Contributing hosts (${_hdr_uc} IPs from ${host}):"

			local _r_ip _r_mod _r_fc _r_ps _r_p_fmt
			while IFS=' ' read -r _r_ip _r_mod _r_fc _r_ps; do
				[ -z "$_r_ip" ] && continue
				if [ "$_r_ip" = "OVERFLOW" ]; then
					_overflow="$_r_mod"
					continue
				fi
				[ "$_r_ip" = "HEADER" ] && continue
				_r_p_fmt=$(pressure_format "$_r_ps")
				_hosts_text=$(printf '%s\n    %-18s %-10s %3s failures  %6s pressure' \
					"$_hosts_text" "$_r_ip" "$_r_mod" "$_r_fc" "$_r_p_fmt")
				_hosts_html="${_hosts_html}$(printf '%-18s %-10s %3s failures  %6s pressure' \
					"$_r_ip" "$_r_mod" "$_r_fc" "$_r_p_fmt")<br>"
				_hosts_msg=$(printf '%s\n  %s  %s  %s failures  %s pressure' \
					"$_hosts_msg" "$_r_ip" "$_r_mod" "$_r_fc" "$_r_p_fmt")
			done < "$_sidecar"

			if [ -n "$_overflow" ] && [ "$_overflow" -gt 0 ] 2>/dev/null; then  # suppress non-numeric comparison error
				_hosts_text="${_hosts_text}
    ... and ${_overflow} more IP(s)"
				_hosts_html="${_hosts_html}... and ${_overflow} more IP(s)<br>"
				_hosts_msg="${_hosts_msg}
  ... and ${_overflow} more IP(s)"
			fi

			_hosts_html="${_hosts_html}</div></td></tr>"

			SOURCE_LOGS_SECTION_TEXT="$_hosts_text"
			export SOURCE_LOGS_SECTION_TEXT
			SOURCE_LOGS_SECTION_HTML="$_hosts_html"
			export SOURCE_LOGS_SECTION_HTML

			# channel-specific escaping (follows COUNTRY_DISPLAY / COUNTRY_DISPLAY_TG pattern)
			# Slack/Discord: JSON templates — literal newlines break JSON string parsing
			export SUBNET_HOSTS_SECTION
			SUBNET_HOSTS_SECTION=$(_alert_json_escape "$_hosts_msg")
			# Telegram: MarkdownV2 — dots, parens, dashes are special chars
			export SUBNET_HOSTS_SECTION_TG
			SUBNET_HOSTS_SECTION_TG=$(_alert_telegram_escape "$_hosts_msg")

			# clean up sidecar after reading
			command rm -f "$_sidecar"
		else
			# sidecar missing (race, cleanup) — static fallback
			SOURCE_LOGS_SECTION_TEXT="  Source logs: not available (distributed subnet ban)"
			export SOURCE_LOGS_SECTION_TEXT
			# shellcheck disable=SC2089  # variable contains HTML with literal quotes, not shell quoting
			SOURCE_LOGS_SECTION_HTML='<tr><td colspan="2" style="padding:8px 16px;color:#71717a;font-style:italic;">Source logs not available (distributed subnet ban)</td></tr>'
			# shellcheck disable=SC2090  # variable contains HTML output
			export SOURCE_LOGS_SECTION_HTML
		fi
```

- [ ] **Step 4: Run the enrichment tests**

```bash
make -C tests test 2>&1 | tee /tmp/test-bfd-t5b.log | tail -30
grep "not ok" /tmp/test-bfd-t5b.log
```

Expected: All PASS

- [ ] **Step 5: Run the full alert engine tests to check for regressions**

```bash
make -C tests test 2>&1 | tee /tmp/test-bfd-t5c.log | tail -30
grep "_alert_set_entry_vars" /tmp/test-bfd-t5c.log
```

Expected: All existing `_alert_set_entry_vars` tests PASS

- [ ] **Step 6: Run lint**

```bash
bash -n files/internals/bfd_alert.sh && echo "syntax ok"
shellcheck -S warning files/internals/bfd_alert.sh 2>&1 | head -20
```

- [ ] **Step 7: Commit**

```bash
git add files/internals/bfd_alert.sh tests/47-cidr-alert-enrichment.bats
git commit -m "$(cat <<'EOF'
2.0.1 | Enrich CIDR alert rendering with aggregate stats and hosts breakdown

[New] _alert_set_entry_vars reads sidecar file for CIDR alerts (contributing hosts table)
[New] FAIL_COUNT_DISPLAY: "N across M IPs" for CIDR, plain integer for individual
[New] SUBNET_IP_COUNT: unique contributing IP count exported for CIDR alerts
[New] SUBNET_HOSTS_SECTION: JSON-escaped compact breakdown for Slack/Discord
[New] SUBNET_HOSTS_SECTION_TG: Telegram MarkdownV2-escaped variant
[New] SOURCE_LOGS_SECTION_TEXT/HTML: enriched contributing hosts table replaces static message
[Change] Sidecar cleaned up after reading; graceful fallback if missing
[New] 11 tests in 47-cidr-alert-enrichment.bats: display vars, hosts table, escaping, fallback, cleanup
EOF
)"
```

---

### Task 6: Update all five entry templates

**Context for the engineer:**

Five alert entry templates need changes:
1. Replace `{{FAIL_COUNT}}` with `{{FAIL_COUNT_DISPLAY}}` in the "failed logins" text
2. Add `{{SUBNET_HOSTS_SECTION}}` to Slack and Discord templates (JSON-escaped variant)
3. Add `{{SUBNET_HOSTS_SECTION_TG}}` to Telegram template (MarkdownV2-escaped variant)

Email templates (`text.entry.tpl`, `html.entry.tpl`) already render via `{{SOURCE_LOGS_SECTION_TEXT}}` / `{{SOURCE_LOGS_SECTION_HTML}}` — the enriched table flows through those existing placeholders. They do NOT need `{{SUBNET_HOSTS_SECTION}}`.

Messaging templates have no source-log placeholders at all, so they need the new section added after the pressure line. The `SUBNET_HOSTS_SECTION` value starts with `\n` (JSON-escaped newline) when non-empty, so appending it to the pressure line avoids extra blank lines for non-CIDR alerts. `SUBNET_HOSTS_SECTION_TG` starts with a literal newline for the same reason.

**Files:**
- Modify: `files/alert/text.entry.tpl:5`
- Modify: `files/alert/html.entry.tpl:39`
- Modify: `files/alert/slack.entry.tpl:8`
- Modify: `files/alert/telegram.entry.tpl:3`
- Modify: `files/alert/discord.entry.tpl:3`

---

- [ ] **Step 1: Update text.entry.tpl**

In `files/alert/text.entry.tpl`, line 5, replace `{{FAIL_COUNT}}` with `{{FAIL_COUNT_DISPLAY}}`:

```
  Pressure:    {{FAIL_COUNT_DISPLAY}} failed logins = +{{PRESSURE_CONTRIB}} this scan
```

- [ ] **Step 2: Update html.entry.tpl**

In `files/alert/html.entry.tpl`, line 39, replace `{{FAIL_COUNT}}` with `{{FAIL_COUNT_DISPLAY}}`:

```html
<span style="font-size:13px;font-weight:bold;color:#09090b;">{{FAIL_COUNT_DISPLAY}} failed logins = +{{PRESSURE_CONTRIB}} this scan</span>
```

- [ ] **Step 3: Update slack.entry.tpl**

In `files/alert/slack.entry.tpl`, line 8:
1. Replace `{{FAIL_COUNT}}` with `{{FAIL_COUNT_DISPLAY}}`
2. Append `{{SUBNET_HOSTS_SECTION}}` after the pressure text (before the closing `"`)

New line 8:
```
			"text": "*{{HOST}}* ({{HOST_VERSION}}) {{COUNTRY_FLAG}} {{COUNTRY_DISPLAY}}\n`{{SERVICE}}` on {{PORTS}} | {{BAN_TYPE}}{{BAN_DURATION_DETAIL}}\nPressure: {{FAIL_COUNT_DISPLAY}} failed logins = +{{PRESSURE_CONTRIB}} | {{PRESSURE}} accumulated, trips at {{PRESSURE_TRIP}} (weight {{WEIGHT}}, half-life {{HALF_LIFE_FMT}}){{SUBNET_HOSTS_SECTION}}"
```

Note: `SUBNET_HOSTS_SECTION` is JSON-escaped via `_alert_json_escape()`. For non-CIDR alerts it's empty (no visual change). For CIDR alerts it starts with `\n` (literal two-char escape) followed by the contributing hosts text — valid in JSON and rendered as newlines by Slack.

- [ ] **Step 4: Update telegram.entry.tpl**

In `files/alert/telegram.entry.tpl`, line 3:
1. Replace `{{FAIL_COUNT}}` with `{{FAIL_COUNT_DISPLAY}}`
2. Append `{{SUBNET_HOSTS_SECTION_TG}}` at end of line 3 (before the closing `\)`)

Full file becomes:
```
{{COUNTRY_FLAG}} *{{HOST}}* \({{HOST_VERSION}}\) {{COUNTRY_DISPLAY_TG}}
`{{SERVICE}}` on {{PORTS}} \| {{BAN_TYPE}}{{BAN_DURATION_DETAIL}}
Pressure: {{FAIL_COUNT_DISPLAY}} failed logins \= \+{{PRESSURE_CONTRIB}} \| {{PRESSURE}} accumulated, trips at {{PRESSURE_TRIP}} \(weight {{WEIGHT}}, half\-life {{HALF_LIFE_FMT}}\){{SUBNET_HOSTS_SECTION_TG}}

```

Note: Uses `{{SUBNET_HOSTS_SECTION_TG}}` (MarkdownV2-escaped via `_alert_telegram_escape()`). For non-CIDR alerts it's empty (no visual change — trailing `\)` remains). For CIDR alerts the value starts with a literal newline, so the contributing hosts block appears on the next line. Dots in IPs are escaped (`192\.0\.2\.1`), parens in "IP(s)" escaped, etc.

- [ ] **Step 5: Update discord.entry.tpl**

In `files/alert/discord.entry.tpl`, line 3:
1. Replace `{{FAIL_COUNT}}` with `{{FAIL_COUNT_DISPLAY}}`
2. Append `{{SUBNET_HOSTS_SECTION}}` before the closing `"` (same JSON-escaped variant as Slack):

New line 3:
```
				"value": "`{{SERVICE}}` on {{PORTS}} | {{BAN_TYPE}}{{BAN_DURATION_DETAIL}}\nPressure: {{FAIL_COUNT_DISPLAY}} failed logins = +{{PRESSURE_CONTRIB}} | {{PRESSURE}} accumulated, trips at {{PRESSURE_TRIP}} (weight {{WEIGHT}}, half-life {{HALF_LIFE_FMT}}){{SUBNET_HOSTS_SECTION}}",
```

Note: `SUBNET_HOSTS_SECTION` is JSON-escaped — same as Slack. Discord embed field values support `\n` for line breaks. Discord embed limit is 1024 chars per field value — the top-5 cap (SUBNET_ALERT_TOP_N) keeps the output well within this limit.

- [ ] **Step 6: Commit**

```bash
git add files/alert/text.entry.tpl files/alert/html.entry.tpl \
        files/alert/slack.entry.tpl files/alert/telegram.entry.tpl \
        files/alert/discord.entry.tpl
git commit -m "$(cat <<'EOF'
2.0.1 | Update alert templates for CIDR enrichment

[Change] All 5 entry templates: {{FAIL_COUNT}} -> {{FAIL_COUNT_DISPLAY}} in pressure line
[New] Slack, Discord templates: add {{SUBNET_HOSTS_SECTION}} (JSON-escaped)
[New] Telegram template: add {{SUBNET_HOSTS_SECTION_TG}} (MarkdownV2-escaped)
[Note] Email templates use existing SOURCE_LOGS placeholders — no new placeholder needed
EOF
)"
```

---

## Chunk 3: Integration Test + Changelogs

### Task 7: End-to-end integration test

**Context for the engineer:**

This test validates the full pipeline: synthetic pressure.dat -> check_distributed -> alert line -> _alert_set_entry_vars -> template variables. It exercises everything from Chunks 1 and 2 together.

**Files:**
- Modify: `tests/47-cidr-alert-enrichment.bats`

---

- [ ] **Step 1: Add end-to-end integration test**

Append to `tests/47-cidr-alert-enrichment.bats`:

```bash
# ============================================================
# End-to-end integration
# ============================================================

@test "E2E: CIDR ban produces enriched alert with correct template vars" {
	local now=1000000
	local events_file="$INSTALL_PATH/tmp/pressure.dat"
	local alerts_file="$TEST_TMPDIR/alerts"
	touch "$alerts_file"

	# 4 IPs in same /24 with varying weights
	echo "$now 10.0.0.1 sshd 3" >> "$events_file"
	echo "$now 10.0.0.1 sshd 3" >> "$events_file"
	echo "$now 10.0.0.2 sshd 2" >> "$events_file"
	echo "$now 10.0.0.3 sshd 1" >> "$events_file"
	echo "$now 10.0.0.4 sshd 1" >> "$events_file"

	SUBNET_TRIG="3"
	SUBNET_MASK="24"
	SUBNET_MASK_V6="48"
	TRIG_WINDOW="300"
	EMAIL_ALERTS="1"
	EMAIL_ADDRESS="admin@example.com"
	SUBNET_ALERT_TOP_N="3"
	BAN_DURATION="600"

	# run check_distributed to generate alert line + sidecar
	check_distributed "$INSTALL_PATH" "$TRIG_WINDOW" "$now" "$alerts_file" >/dev/null

	# verify alert line exists
	[ -s "$alerts_file" ]

	# read the alert line and render template vars
	local line
	line=$(head -1 "$alerts_file")
	_alert_set_entry_vars "$line" 1 1

	# total_failures = 2+1+1+1 = 5
	[ "$FAIL_COUNT" = "5" ]
	# FAIL_COUNT_DISPLAY includes IP count
	[ "$FAIL_COUNT_DISPLAY" = "5 across 4 IPs" ]
	# total_pressure_raw = 3+3+2+1+1 = 10, field 4 = 10000 -> PRESSURE = "10.0"
	[ "$PRESSURE" = "10.0" ]
	# contributing hosts table populated
	[[ "$SOURCE_LOGS_SECTION_TEXT" == *"Contributing hosts"* ]]
	[[ "$SOURCE_LOGS_SECTION_TEXT" == *"10.0.0.1"* ]]
	# SUBNET_HOSTS_SECTION populated for messaging (JSON-escaped)
	[[ "$SUBNET_HOSTS_SECTION" == *"10.0.0.1"* ]]
	# Telegram variant also populated
	[[ "$SUBNET_HOSTS_SECTION_TG" == *"10\.0\.0\.1"* ]]
	# sidecar cleaned up
	[ ! -f "$INSTALL_PATH/tmp/.cidr_detail_10.0.0.0_24" ]

	# TOP_N=3 with 4 IPs — overflow present
	# (OVERFLOW is in the text but was consumed when sidecar was read)
	[[ "$SOURCE_LOGS_SECTION_TEXT" == *"1 more"* ]]
}

@test "E2E: SUBNET_TRIG=1 single-IP subnet triggers enriched alert" {
	local now=1000000
	local events_file="$INSTALL_PATH/tmp/pressure.dat"
	local alerts_file="$TEST_TMPDIR/alerts"
	touch "$alerts_file"

	# single IP, 3 events at weight 2
	echo "$now 10.0.0.5 sshd 2" >> "$events_file"
	echo "$now 10.0.0.5 sshd 2" >> "$events_file"
	echo "$now 10.0.0.5 sshd 2" >> "$events_file"

	SUBNET_TRIG="1"
	SUBNET_MASK="24"
	SUBNET_MASK_V6="48"
	TRIG_WINDOW="300"
	EMAIL_ALERTS="1"
	EMAIL_ADDRESS="admin@example.com"
	SUBNET_ALERT_TOP_N="5"
	BAN_DURATION="600"

	check_distributed "$INSTALL_PATH" "$TRIG_WINDOW" "$now" "$alerts_file" >/dev/null
	[ -s "$alerts_file" ]

	local line
	line=$(head -1 "$alerts_file")
	_alert_set_entry_vars "$line" 1 1

	# total_failures = 3 (3 events), total_pressure_raw = 6 (3*2)
	[ "$FAIL_COUNT" = "3" ]
	[ "$FAIL_COUNT_DISPLAY" = "3 across 1 IPs" ]
	[ "$SUBNET_IP_COUNT" = "1" ]
	[ "$PRESSURE" = "6.0" ]
	# contributing hosts table has the single IP
	[[ "$SOURCE_LOGS_SECTION_TEXT" == *"10.0.0.5"* ]]
	# no overflow with 1 IP and TOP_N=5
	[[ "$SOURCE_LOGS_SECTION_TEXT" != *"more"* ]]
}

@test "E2E: single-IP alert unaffected by CIDR enrichment" {
	# verify non-CIDR path is clean
	BAN_COMMAND_TEMPLATE="echo ban \$ATTACK_HOST"
	_FW_BACKEND="custom"
	local line="192.0.2.1|sshd|22|18400|0|ban|0|/dev/null|root|10|300|3|6"
	_alert_set_entry_vars "$line" 1 1
	[ "$FAIL_COUNT" = "6" ]
	[ "$FAIL_COUNT_DISPLAY" = "6" ]
	[ "$SUBNET_IP_COUNT" = "" ]
	[ "$SUBNET_HOSTS_SECTION" = "" ]
	[ "$SUBNET_HOSTS_SECTION_TG" = "" ]
	[ "$PRESSURE" = "18.4" ]
	[ "$PRESSURE_CONTRIB" = "18" ]
}
```

- [ ] **Step 2: Run the full enrichment test file**

```bash
make -C tests test 2>&1 | tee /tmp/test-bfd-e2e.log | tail -30
grep "not ok" /tmp/test-bfd-e2e.log
```

Expected: All PASS

- [ ] **Step 3: Run full Debian 12 suite to check for regressions**

```bash
make -C tests test 2>&1 | tee /tmp/test-bfd-full.log | tail -30
grep "not ok" /tmp/test-bfd-full.log
```

Expected: All PASS (no regressions)

- [ ] **Step 4: Commit**

```bash
git add tests/47-cidr-alert-enrichment.bats
git commit -m "$(cat <<'EOF'
2.0.1 | Add end-to-end integration tests for CIDR alert enrichment

[New] E2E test: full pipeline from pressure.dat through check_distributed to template vars
[New] Edge case test: SUBNET_TRIG=1 single-IP subnet triggers enriched alert
[New] Regression test: single-IP alert unaffected by CIDR enrichment changes
EOF
)"
```

---

### Task 8: Changelogs

**Context for the engineer:**

Both `CHANGELOG` and `CHANGELOG.RELEASE` must be updated on every code-changing commit. Since Tasks 1-7 produced multiple commits, a single changelog entry covering the feature is appropriate.

**Files:**
- Modify: `CHANGELOG`
- Modify: `CHANGELOG.RELEASE`

---

- [ ] **Step 1: Add changelog entry**

Add to the top of the current version section in both `CHANGELOG` and `CHANGELOG.RELEASE`:

```
[New] CIDR subnet ban alerts enriched with aggregate pressure and failure stats
[New] Contributing hosts breakdown in all alert channels (email, Slack, Telegram, Discord)
[Fix] CIDR alert pipeline fields 4 and 13 now carry real aggregate values (was broken)
```

- [ ] **Step 2: Commit**

```bash
git add CHANGELOG CHANGELOG.RELEASE
git commit -m "$(cat <<'EOF'
2.0.1 | Update changelogs for CIDR alert enrichment feature

[Note] Changelog entries for CIDR alert enrichment (Tasks 1-7)
EOF
)"
```

---

### Task 9: Full verification

**Files:** None (verification only)

---

- [ ] **Step 1: Lint all modified shell files**

```bash
bash -n files/internals/bfd.lib.sh files/internals/bfd_alert.sh \
       files/internals/internals.conf cron.daily && echo "syntax ok"
shellcheck -S warning files/internals/bfd.lib.sh files/internals/bfd_alert.sh \
       cron.daily 2>&1 | head -20
```

- [ ] **Step 2: Run verification greps**

```bash
grep -rn '/usr/bin/\(rm\|mv\|cp\)' files/
grep -rn '^\s*cd ' files/ cron.daily | grep -v '|| \(exit\|return\)'
grep -rn 'local [a-z_]*=\$(' files/internals/bfd.lib.sh files/internals/bfd_alert.sh
```

Expected: No new violations

- [ ] **Step 3: Full Debian 12 test suite**

```bash
make -C tests test 2>&1 | tee /tmp/test-bfd-final.log | tail -30
grep -c "^ok" /tmp/test-bfd-final.log
grep "not ok" /tmp/test-bfd-final.log
```

Expected: All tests PASS, count should be previous total + ~17 new tests

- [ ] **Step 4: Rocky 9 test suite**

```bash
make -C tests test-rocky9 2>&1 | tee /tmp/test-bfd-rocky9.log | tail -30
grep "not ok" /tmp/test-bfd-rocky9.log
```

Expected: All PASS
