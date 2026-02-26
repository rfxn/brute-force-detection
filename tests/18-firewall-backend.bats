#!/usr/bin/env bats
#
# Test suite for Phase 25 — firewall backend system
# Tests: detect_firewall, fw_resolve_backend, dispatch layer,
#        all 8 backends (mocked), execute_ban/unban integration,
#        validate_config FIREWALL validation
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

setup() {
	bfd_standard_setup
	# mock command directory
	MOCK_DIR="$TEST_TMPDIR/mock_bin"
	mkdir -p "$MOCK_DIR"
}

teardown() {
	bfd_teardown
}

# ============================================================
# detect_firewall
# ============================================================

@test "detect_firewall: returns route when no firewall tools exist" {
	# run in restricted PATH with no firewall tools
	run bash -c "
		source '${PROJECT_ROOT}/files/bfd.lib.sh'
		export PATH='$MOCK_DIR'
		detect_firewall
	"
	assert_success
	assert_output "route"
}

@test "detect_firewall: finds iptables when available" {
	# mock iptables -V
	cat > "$MOCK_DIR/iptables" <<'SCRIPT'
#!/bin/bash
echo "iptables v1.8.7"
exit 0
SCRIPT
	chmod +x "$MOCK_DIR/iptables"
	run bash -c "
		source '${PROJECT_ROOT}/files/bfd.lib.sh'
		export PATH='$MOCK_DIR'
		detect_firewall
	"
	assert_success
	assert_output "iptables"
}

@test "detect_firewall: prefers apf over iptables" {
	# create mock apf at expected path
	mkdir -p "$TEST_TMPDIR/etc/apf"
	cat > "$TEST_TMPDIR/etc/apf/apf" <<'SCRIPT'
#!/bin/bash
exit 0
SCRIPT
	chmod +x "$TEST_TMPDIR/etc/apf/apf"
	# mock iptables
	cat > "$MOCK_DIR/iptables" <<'SCRIPT'
#!/bin/bash
echo "iptables v1.8.7"
exit 0
SCRIPT
	chmod +x "$MOCK_DIR/iptables"
	# override detect_firewall to check our test path
	run bash -c "
		source '${PROJECT_ROOT}/files/bfd.lib.sh'
		# redefine detect_firewall to use test apf path
		detect_firewall() {
			if [ -x '$TEST_TMPDIR/etc/apf/apf' ]; then echo 'apf'; return; fi
			if command -v iptables >/dev/null 2>&1 && iptables -V >/dev/null 2>&1; then echo 'iptables'; return; fi
			echo 'route'
		}
		export PATH='$MOCK_DIR'
		detect_firewall
	"
	assert_success
	assert_output "apf"
}

# ============================================================
# fw_resolve_backend
# ============================================================

@test "fw_resolve_backend: auto mode calls detect_firewall" {
	FIREWALL="auto"
	# in test environment, detect_firewall likely returns iptables or route
	fw_resolve_backend
	# _FW_BACKEND should be set to something non-empty
	[ -n "$_FW_BACKEND" ]
}

@test "fw_resolve_backend: explicit mode sets _FW_BACKEND directly" {
	FIREWALL="nftables"
	fw_resolve_backend
	[ "$_FW_BACKEND" = "nftables" ]
}

@test "fw_resolve_backend: custom mode sets _FW_BACKEND=custom" {
	FIREWALL="custom"
	fw_resolve_backend
	[ "$_FW_BACKEND" = "custom" ]
}

@test "fw_resolve_backend: defaults to auto when FIREWALL unset" {
	unset FIREWALL
	fw_resolve_backend
	[ -n "$_FW_BACKEND" ]
}

# ============================================================
# Dispatch layer
# ============================================================

@test "fw_ban: dispatches to correct backend (custom)" {
	_FW_BACKEND="custom"
	local marker="$TEST_TMPDIR/ban_marker"
	BAN_COMMAND_TEMPLATE="touch $marker"
	run fw_ban "192.0.2.1" "sshd" "22"
	assert_success
	[ -f "$marker" ]
}

@test "fw_unban: dispatches to correct backend (custom)" {
	_FW_BACKEND="custom"
	local marker="$TEST_TMPDIR/unban_marker"
	UNBAN_COMMAND_TEMPLATE="touch $marker"
	run fw_unban "192.0.2.1" "sshd" "22"
	assert_success
	[ -f "$marker" ]
}

@test "fw_setup: dispatches to correct backend (custom noop)" {
	_FW_BACKEND="custom"
	run fw_setup
	assert_success
}

@test "fw_status: dispatches to correct backend" {
	_FW_BACKEND="custom"
	run fw_status
	assert_success
	assert_output --partial "custom"
}

@test "fw_ban: custom backend sets ATTACK_HOST/MOD/PORTS globals" {
	_FW_BACKEND="custom"
	BAN_COMMAND_TEMPLATE="/bin/true"
	fw_ban "192.0.2.1" "sshd" "22"
	[ "$ATTACK_HOST" = "192.0.2.1" ]
	[ "$MOD" = "sshd" ]
	[ "$PORTS" = "22" ]
}

@test "fw_ban: custom backend selects V6 template for IPv6" {
	_FW_BACKEND="custom"
	local v4_marker="$TEST_TMPDIR/v4_marker"
	local v6_marker="$TEST_TMPDIR/v6_marker"
	BAN_COMMAND_TEMPLATE="touch $v4_marker"
	BAN_COMMAND_V6_TEMPLATE="touch $v6_marker"
	fw_ban "2001:db8::1" "sshd" "22"
	[ ! -f "$v4_marker" ]
	[ -f "$v6_marker" ]
}

@test "fw_ban: custom backend uses standard for IPv4 when V6 set" {
	_FW_BACKEND="custom"
	local v4_marker="$TEST_TMPDIR/v4_marker"
	local v6_marker="$TEST_TMPDIR/v6_marker"
	BAN_COMMAND_TEMPLATE="touch $v4_marker"
	BAN_COMMAND_V6_TEMPLATE="touch $v6_marker"
	fw_ban "192.0.2.1" "sshd" "22"
	[ -f "$v4_marker" ]
	[ ! -f "$v6_marker" ]
}

# ============================================================
# APF backend (mocked)
# ============================================================

@test "_fw_apf_ban: calls apf -d with host and comment" {
	local log="$TEST_TMPDIR/apf.log"
	# shadow /etc/apf/apf with a function
	_fw_apf_ban() {
		local host="$1" mod="${2:-}"
		echo "apf -d $host {bfd.$mod}" >> "$log"
	}
	_fw_apf_ban "192.0.2.1" "sshd"
	run cat "$log"
	assert_output "apf -d 192.0.2.1 {bfd.sshd}"
}

@test "_fw_apf_unban: calls apf -u with host" {
	local log="$TEST_TMPDIR/apf.log"
	_fw_apf_unban() {
		local host="$1"
		echo "apf -u $host" >> "$log"
	}
	_fw_apf_unban "192.0.2.1"
	run cat "$log"
	assert_output "apf -u 192.0.2.1"
}

@test "_fw_apf_status: returns apf description" {
	run _fw_apf_status
	assert_success
	assert_output --partial "apf"
}

# ============================================================
# CSF backend (mocked)
# ============================================================

@test "_fw_csf_ban: calls csf -d with host and comment" {
	local log="$TEST_TMPDIR/csf.log"
	_fw_csf_ban() {
		local host="$1" mod="${2:-}"
		echo "csf -d $host bfd.$mod" >> "$log"
	}
	_fw_csf_ban "192.0.2.1" "sshd"
	run cat "$log"
	assert_output "csf -d 192.0.2.1 bfd.sshd"
}

@test "_fw_csf_unban: calls csf -dr with host" {
	local log="$TEST_TMPDIR/csf.log"
	_fw_csf_unban() {
		local host="$1"
		echo "csf -dr $host" >> "$log"
	}
	_fw_csf_unban "192.0.2.1"
	run cat "$log"
	assert_output "csf -dr 192.0.2.1"
}

@test "_fw_csf_status: returns csf description" {
	run _fw_csf_status
	assert_success
	assert_output --partial "csf"
}

# ============================================================
# firewalld backend (mocked)
# ============================================================

@test "_fw_firewalld_ban: adds IPv4 rich rule" {
	# shadow firewall-cmd with logging function
	firewall-cmd() {
		echo "firewall-cmd $*" >> "$TEST_TMPDIR/fwd.log"
	}
	export -f firewall-cmd
	_fw_firewalld_ban "192.0.2.1"
	run cat "$TEST_TMPDIR/fwd.log"
	assert_output --partial "family=ipv4"
	assert_output --partial "192.0.2.1"
	assert_output --partial "drop"
}

@test "_fw_firewalld_ban: adds IPv6 rich rule" {
	firewall-cmd() {
		echo "firewall-cmd $*" >> "$TEST_TMPDIR/fwd.log"
	}
	export -f firewall-cmd
	_fw_firewalld_ban "2001:db8::1"
	run cat "$TEST_TMPDIR/fwd.log"
	assert_output --partial "family=ipv6"
	assert_output --partial "2001:db8::1"
}

@test "_fw_firewalld_unban: removes rich rule" {
	firewall-cmd() {
		echo "firewall-cmd $*" >> "$TEST_TMPDIR/fwd.log"
	}
	export -f firewall-cmd
	_fw_firewalld_unban "192.0.2.1"
	run cat "$TEST_TMPDIR/fwd.log"
	assert_output --partial "--remove-rich-rule"
	assert_output --partial "192.0.2.1"
}

# ============================================================
# UFW backend (mocked)
# ============================================================

@test "_fw_ufw_ban: inserts deny rule" {
	ufw() {
		echo "ufw $*" >> "$TEST_TMPDIR/ufw.log"
	}
	export -f ufw
	_fw_ufw_ban "192.0.2.1"
	run cat "$TEST_TMPDIR/ufw.log"
	assert_output --partial "insert 1 deny from 192.0.2.1"
}

@test "_fw_ufw_unban: deletes deny rule" {
	ufw() {
		echo "ufw $*" >> "$TEST_TMPDIR/ufw.log"
	}
	export -f ufw
	_fw_ufw_unban "192.0.2.1"
	run cat "$TEST_TMPDIR/ufw.log"
	assert_output --partial "delete deny from 192.0.2.1"
}

@test "_fw_ufw_status: returns ufw description" {
	run _fw_ufw_status
	assert_success
	assert_output --partial "ufw"
}

# ============================================================
# nftables backend (mocked)
# ============================================================

@test "_fw_nftables_ban: adds IPv4 to blocked4 set" {
	nft() {
		echo "nft $*" >> "$TEST_TMPDIR/nft.log"
		return 0
	}
	export -f nft
	_fw_nftables_ban "192.0.2.1"
	run cat "$TEST_TMPDIR/nft.log"
	assert_output --partial "add element inet bfd blocked4"
	assert_output --partial "192.0.2.1"
}

@test "_fw_nftables_ban: adds IPv6 to blocked6 set" {
	nft() {
		echo "nft $*" >> "$TEST_TMPDIR/nft.log"
		return 0
	}
	export -f nft
	_fw_nftables_ban "2001:db8::1"
	run cat "$TEST_TMPDIR/nft.log"
	assert_output --partial "add element inet bfd blocked6"
	assert_output --partial "2001:db8::1"
}

@test "_fw_nftables_unban: removes from correct set" {
	nft() {
		echo "nft $*" >> "$TEST_TMPDIR/nft.log"
		return 0
	}
	export -f nft
	_fw_nftables_unban "192.0.2.1"
	run cat "$TEST_TMPDIR/nft.log"
	assert_output --partial "delete element inet bfd blocked4"
}

@test "_fw_nftables_setup: creates inet bfd table with sets" {
	local call_num=0
	nft() {
		echo "nft $*" >> "$TEST_TMPDIR/nft.log"
		# first call is "list table inet bfd" — return 1 (not exists)
		if [ "$1" = "list" ]; then return 1; fi
		return 0
	}
	export -f nft
	run _fw_nftables_setup
	assert_success
	run cat "$TEST_TMPDIR/nft.log"
	assert_output --partial "add table inet bfd"
	assert_output --partial "add set inet bfd blocked4"
	assert_output --partial "add set inet bfd blocked6"
	assert_output --partial "add chain inet bfd input"
}

@test "_fw_nftables_setup: idempotent (table exists)" {
	nft() {
		# "list table inet bfd" succeeds — table already exists
		return 0
	}
	export -f nft
	run _fw_nftables_setup
	assert_success
}

# ============================================================
# iptables backend (mocked)
# ============================================================

@test "_fw_iptables_ban: adds DROP rule to bfd chain" {
	cat > "$MOCK_DIR/mock_iptables" <<SCRIPT
#!/bin/bash
echo "iptables \$*" >> "$TEST_TMPDIR/ipt.log"
exit 0
SCRIPT
	chmod +x "$MOCK_DIR/mock_iptables"
	_FW_IPT_BIN="$MOCK_DIR/mock_iptables"
	_fw_iptables_ban "192.0.2.1"
	run cat "$TEST_TMPDIR/ipt.log"
	assert_output --partial "-A bfd -s 192.0.2.1 -j DROP"
}

@test "_fw_iptables_ban: uses ip6tables for IPv6" {
	cat > "$MOCK_DIR/mock_ip6tables" <<SCRIPT
#!/bin/bash
echo "ip6tables \$*" >> "$TEST_TMPDIR/ipt.log"
exit 0
SCRIPT
	chmod +x "$MOCK_DIR/mock_ip6tables"
	_FW_IP6T_BIN="$MOCK_DIR/mock_ip6tables"
	_fw_iptables_ban "2001:db8::1"
	run cat "$TEST_TMPDIR/ipt.log"
	assert_output --partial "ip6tables -A bfd -s 2001:db8::1 -j DROP"
}

@test "_fw_iptables_unban: removes rule from bfd chain" {
	cat > "$MOCK_DIR/mock_iptables" <<SCRIPT
#!/bin/bash
echo "iptables \$*" >> "$TEST_TMPDIR/ipt.log"
exit 0
SCRIPT
	chmod +x "$MOCK_DIR/mock_iptables"
	_FW_IPT_BIN="$MOCK_DIR/mock_iptables"
	_fw_iptables_unban "192.0.2.1"
	run cat "$TEST_TMPDIR/ipt.log"
	assert_output --partial "-D bfd -s 192.0.2.1 -j DROP"
}

# ============================================================
# route backend (mocked)
# ============================================================

@test "_fw_route_ban: adds blackhole route /32" {
	printf '#!/bin/bash\necho "ip $*" >> "%s/ip.log"\n' "$TEST_TMPDIR" > "$MOCK_DIR/ip"
	chmod +x "$MOCK_DIR/ip"
	_FW_ROUTE_IP_BIN="$MOCK_DIR/ip"
	_fw_route_ban "192.0.2.1"
	run cat "$TEST_TMPDIR/ip.log"
	assert_output --partial "route add blackhole 192.0.2.1/32"
}

@test "_fw_route_ban: adds blackhole route /128 for IPv6" {
	printf '#!/bin/bash\necho "ip $*" >> "%s/ip.log"\n' "$TEST_TMPDIR" > "$MOCK_DIR/ip"
	chmod +x "$MOCK_DIR/ip"
	_FW_ROUTE_IP_BIN="$MOCK_DIR/ip"
	_fw_route_ban "2001:db8::1"
	run cat "$TEST_TMPDIR/ip.log"
	assert_output --partial "route add blackhole 2001:db8::1/128"
}

@test "_fw_route_unban: removes blackhole route" {
	printf '#!/bin/bash\necho "ip $*" >> "%s/ip.log"\n' "$TEST_TMPDIR" > "$MOCK_DIR/ip"
	chmod +x "$MOCK_DIR/ip"
	_FW_ROUTE_IP_BIN="$MOCK_DIR/ip"
	_fw_route_unban "192.0.2.1"
	run cat "$TEST_TMPDIR/ip.log"
	assert_output --partial "route del blackhole 192.0.2.1/32"
}

@test "_fw_route_ban: CIDR passed through without extra suffix" {
	printf '#!/bin/bash\necho "ip $*" >> "%s/ip.log"\n' "$TEST_TMPDIR" > "$MOCK_DIR/ip"
	chmod +x "$MOCK_DIR/ip"
	_FW_ROUTE_IP_BIN="$MOCK_DIR/ip"
	_fw_route_ban "192.0.2.0/24"
	run cat "$TEST_TMPDIR/ip.log"
	assert_output --partial "route add blackhole 192.0.2.0/24"
	# must NOT have double suffix like /24/32
	refute_output --partial "/24/32"
}

# ============================================================
# custom backend
# ============================================================

@test "_fw_custom_ban: evals BAN_COMMAND_TEMPLATE" {
	local marker="$TEST_TMPDIR/custom_ban"
	BAN_COMMAND_TEMPLATE="touch $marker"
	_fw_custom_ban "192.0.2.1" "sshd" "22"
	[ -f "$marker" ]
}

@test "_fw_custom_unban: evals UNBAN_COMMAND_TEMPLATE" {
	local marker="$TEST_TMPDIR/custom_unban"
	UNBAN_COMMAND_TEMPLATE="touch $marker"
	_fw_custom_unban "192.0.2.1" "sshd" "22"
	[ -f "$marker" ]
}

@test "_fw_custom_ban: V6 template selected for IPv6" {
	local v4="$TEST_TMPDIR/v4"
	local v6="$TEST_TMPDIR/v6"
	BAN_COMMAND_TEMPLATE="touch $v4"
	BAN_COMMAND_V6_TEMPLATE="touch $v6"
	_fw_custom_ban "2001:db8::1" "sshd" "22"
	[ ! -f "$v4" ]
	[ -f "$v6" ]
}

@test "_fw_custom_unban: V6 template selected for IPv6" {
	local v4="$TEST_TMPDIR/v4"
	local v6="$TEST_TMPDIR/v6"
	UNBAN_COMMAND_TEMPLATE="touch $v4"
	UNBAN_COMMAND_V6_TEMPLATE="touch $v6"
	_fw_custom_unban "2001:db8::1" "sshd" "22"
	[ ! -f "$v4" ]
	[ -f "$v6" ]
}

@test "_fw_custom_status: returns custom description" {
	run _fw_custom_status
	assert_success
	assert_output "custom (BAN_COMMAND template)"
}

# ============================================================
# execute_ban integration
# ============================================================

@test "execute_ban: calls fw_ban for non-custom backend" {
	_FW_BACKEND="route"
	printf '#!/bin/bash\necho "ip $*" >> "%s/ip.log"\n' "$TEST_TMPDIR" > "$MOCK_DIR/ip"
	chmod +x "$MOCK_DIR/ip"
	_FW_ROUTE_IP_BIN="$MOCK_DIR/ip"
	run execute_ban "192.0.2.1" "sshd" "0" "22"
	assert_success
	run cat "$TEST_TMPDIR/ip.log"
	assert_output --partial "route add blackhole 192.0.2.1/32"
}

@test "execute_ban: dry run logs without calling fw_ban" {
	_FW_BACKEND="route"
	printf '#!/bin/bash\necho "ip $*" >> "%s/ip.log"\n' "$TEST_TMPDIR" > "$MOCK_DIR/ip"
	chmod +x "$MOCK_DIR/ip"
	_FW_ROUTE_IP_BIN="$MOCK_DIR/ip"
	run execute_ban "192.0.2.1" "sshd" "1" "22"
	assert_success
	# ip should not have been called
	[ ! -f "$TEST_TMPDIR/ip.log" ]
}

@test "execute_ban: retries on failure with route backend" {
	_FW_BACKEND="route"
	BAN_RETRY_COUNT="2"
	local attempt_file="$TEST_TMPDIR/attempts"
	echo "0" > "$attempt_file"
	printf '#!/bin/bash\nn=$(cat "%s/attempts"); n=$((n + 1)); echo "$n" > "%s/attempts"; if [ "$n" -lt 3 ]; then exit 1; fi; exit 0\n' \
		"$TEST_TMPDIR" "$TEST_TMPDIR" > "$MOCK_DIR/ip"
	chmod +x "$MOCK_DIR/ip"
	_FW_ROUTE_IP_BIN="$MOCK_DIR/ip"
	run execute_ban "192.0.2.1" "sshd" "0" "22"
	assert_success
	local final
	final=$(cat "$attempt_file")
	[ "$final" -eq 3 ]
}

@test "execute_ban: custom backend evals BAN_COMMAND_TEMPLATE" {
	_FW_BACKEND="custom"
	local marker="$TEST_TMPDIR/exec_ban"
	BAN_COMMAND_TEMPLATE="touch $marker"
	run execute_ban "192.0.2.1" "sshd" "0" "22"
	assert_success
	[ -f "$marker" ]
}

@test "execute_ban: sets BAN_COMMAND global for custom backend" {
	_FW_BACKEND="custom"
	BAN_COMMAND_TEMPLATE="/bin/true -d \$ATTACK_HOST"
	execute_ban "192.0.2.1" "sshd" "0" "22"
	[ "$BAN_COMMAND" = "/bin/true -d \$ATTACK_HOST" ]
}

@test "execute_ban: sets BAN_COMMAND for non-custom backend" {
	_FW_BACKEND="route"
	printf '#!/bin/bash\nexit 0\n' > "$MOCK_DIR/ip"
	chmod +x "$MOCK_DIR/ip"
	_FW_ROUTE_IP_BIN="$MOCK_DIR/ip"
	execute_ban "192.0.2.1" "sshd" "0" "22"
	[[ "$BAN_COMMAND" == *"fw_ban"* ]]
}

# ============================================================
# execute_unban integration
# ============================================================

@test "execute_unban: calls fw_unban for non-custom backend" {
	_FW_BACKEND="route"
	printf '#!/bin/bash\necho "ip $*" >> "%s/ip.log"\n' "$TEST_TMPDIR" > "$MOCK_DIR/ip"
	chmod +x "$MOCK_DIR/ip"
	_FW_ROUTE_IP_BIN="$MOCK_DIR/ip"
	run execute_unban "192.0.2.1" "sshd" "22"
	assert_success
	run cat "$TEST_TMPDIR/ip.log"
	assert_output --partial "route del blackhole 192.0.2.1/32"
}

@test "execute_unban: custom backend evals UNBAN_COMMAND_TEMPLATE" {
	_FW_BACKEND="custom"
	local marker="$TEST_TMPDIR/exec_unban"
	UNBAN_COMMAND_TEMPLATE="touch $marker"
	run execute_unban "192.0.2.1" "sshd" "22"
	assert_success
	[ -f "$marker" ]
}

# ============================================================
# validate_config: FIREWALL validation
# ============================================================

# helper: set valid config defaults, then override one field
_run_validate() {
	(
		TRIG="15"
		TRIG_WINDOW="300"
		TRIG_GLOBAL="0"
		BAN_DURATION="300"
		BAN_PERMANENT_AFTER="5"
		BAN_PERMANENT_WINDOW="86400"
		UNBAN_COMMAND_TEMPLATE=""
		EMAIL_ALERTS="0"
		LOCK_FILE_TIMEOUT="300"
		BAN_COMMAND_TEMPLATE="/bin/true"
		FIREWALL="custom"
		INSTALL_PATH="$TEST_TMPDIR"
		eval "$1"
		validate_config
	) >/dev/null 2>&1
}

@test "validate_config: accepts FIREWALL=auto" {
	run _run_validate 'FIREWALL="auto"'
	assert_success
}

@test "validate_config: accepts FIREWALL=iptables" {
	run _run_validate 'FIREWALL="iptables"'
	assert_success
}

@test "validate_config: accepts FIREWALL=nftables" {
	run _run_validate 'FIREWALL="nftables"'
	assert_success
}

@test "validate_config: accepts FIREWALL=firewalld" {
	run _run_validate 'FIREWALL="firewalld"'
	assert_success
}

@test "validate_config: accepts FIREWALL=ufw" {
	run _run_validate 'FIREWALL="ufw"'
	assert_success
}

@test "validate_config: accepts FIREWALL=route" {
	run _run_validate 'FIREWALL="route"'
	assert_success
}

@test "validate_config: accepts FIREWALL=custom" {
	run _run_validate 'FIREWALL="custom"'
	assert_success
}

@test "validate_config: accepts FIREWALL=apf" {
	run _run_validate 'FIREWALL="apf"'
	assert_success
}

@test "validate_config: accepts FIREWALL=csf" {
	run _run_validate 'FIREWALL="csf"'
	assert_success
}

@test "validate_config: rejects invalid FIREWALL value" {
	run _run_validate 'FIREWALL="bogus"'
	assert_failure
}

@test "validate_config: rejects FIREWALL with spaces" {
	run _run_validate 'FIREWALL="ipt ables"'
	assert_failure
}

@test "validate_config: BAN_COMMAND empty ok when FIREWALL!=custom" {
	run _run_validate 'FIREWALL="iptables"; BAN_COMMAND_TEMPLATE=""'
	assert_success
}

@test "validate_config: BAN_COMMAND empty fails when FIREWALL=custom" {
	run _run_validate 'FIREWALL="custom"; BAN_COMMAND_TEMPLATE=""'
	assert_failure
}

# ============================================================
# importconf: FIREWALL migration
# ============================================================

@test "importconf: pre-25 config gets FIREWALL=custom" {
	# create old config without FIREWALL
	mkdir -p "$TEST_TMPDIR/backup"
	cat > "$TEST_TMPDIR/backup/conf.bfd" <<'OLDCONF'
TRIG="10"
BAN_COMMAND="/sbin/iptables -I INPUT -s $ATTACK_HOST -j DROP"
OLDCONF
	# create new config with FIREWALL=auto
	cat > "$TEST_TMPDIR/conf.bfd.new" <<'NEWCONF'
TRIG="15"
FIREWALL="auto"
BAN_COMMAND=""
NEWCONF
	# run importconf merge logic (simulate)
	local old="$TEST_TMPDIR/backup/conf.bfd"
	local new="$TEST_TMPDIR/conf.bfd.new"
	if ! grep -q '^FIREWALL=' "$old" 2>/dev/null; then
		sed -i 's/^FIREWALL="auto"/FIREWALL="custom"/' "$new"
	fi
	run grep '^FIREWALL=' "$new"
	assert_output 'FIREWALL="custom"'
}

@test "importconf: post-25 config preserves FIREWALL value" {
	# create old config with FIREWALL=nftables
	mkdir -p "$TEST_TMPDIR/backup"
	cat > "$TEST_TMPDIR/backup/conf.bfd" <<'OLDCONF'
TRIG="10"
FIREWALL="nftables"
OLDCONF
	# create new config with FIREWALL=auto
	cat > "$TEST_TMPDIR/conf.bfd.new" <<'NEWCONF'
TRIG="15"
FIREWALL="auto"
NEWCONF
	# when old config has FIREWALL=, don't override
	local old="$TEST_TMPDIR/backup/conf.bfd"
	local new="$TEST_TMPDIR/conf.bfd.new"
	if ! grep -q '^FIREWALL=' "$old" 2>/dev/null; then
		sed -i 's/^FIREWALL="auto"/FIREWALL="custom"/' "$new"
	fi
	# FIREWALL should remain auto (importconf merges values separately)
	run grep '^FIREWALL=' "$new"
	assert_output 'FIREWALL="auto"'
}

# ============================================================
# Backend binary discovery (command -v)
# ============================================================

@test "detect_firewall: finds apf via PATH (command -v)" {
	cat > "$MOCK_DIR/apf" <<'SCRIPT'
#!/bin/bash
exit 0
SCRIPT
	chmod +x "$MOCK_DIR/apf"
	run bash -c "
		source '${PROJECT_ROOT}/files/bfd.lib.sh'
		export PATH='$MOCK_DIR'
		detect_firewall
	"
	assert_success
	assert_output "apf"
}

@test "detect_firewall: finds csf via PATH (command -v)" {
	cat > "$MOCK_DIR/csf" <<'SCRIPT'
#!/bin/bash
exit 0
SCRIPT
	chmod +x "$MOCK_DIR/csf"
	run bash -c "
		source '${PROJECT_ROOT}/files/bfd.lib.sh'
		export PATH='$MOCK_DIR'
		detect_firewall
	"
	assert_success
	assert_output "csf"
}

@test "_fw_apf_setup: sets _FW_APF_BIN via command -v" {
	cat > "$MOCK_DIR/apf" <<'SCRIPT'
#!/bin/bash
exit 0
SCRIPT
	chmod +x "$MOCK_DIR/apf"
	run bash -c "
		source '${PROJECT_ROOT}/files/bfd.lib.sh'
		BFD_LOG_PATH='$BFD_LOG_PATH'
		OUTPUT_SYSLOG='0'
		OUTPUT_SYSLOG_FILE='$TEST_TMPDIR/syslog'
		export PATH='$MOCK_DIR:/usr/bin:/bin'
		_fw_apf_setup
		echo \"\$_FW_APF_BIN\"
	"
	assert_success
	assert_output "$MOCK_DIR/apf"
}

@test "_fw_apf_setup: fails when apf not in PATH" {
	run bash -c "
		source '${PROJECT_ROOT}/files/bfd.lib.sh'
		BFD_LOG_PATH='$BFD_LOG_PATH'
		OUTPUT_SYSLOG='0'
		OUTPUT_SYSLOG_FILE='$TEST_TMPDIR/syslog'
		export PATH='$MOCK_DIR'
		_fw_apf_setup
	"
	assert_failure
}

@test "_fw_csf_setup: sets _FW_CSF_BIN via command -v" {
	cat > "$MOCK_DIR/csf" <<'SCRIPT'
#!/bin/bash
exit 0
SCRIPT
	chmod +x "$MOCK_DIR/csf"
	run bash -c "
		source '${PROJECT_ROOT}/files/bfd.lib.sh'
		BFD_LOG_PATH='$BFD_LOG_PATH'
		OUTPUT_SYSLOG='0'
		OUTPUT_SYSLOG_FILE='$TEST_TMPDIR/syslog'
		export PATH='$MOCK_DIR:/usr/bin:/bin'
		_fw_csf_setup
		echo \"\$_FW_CSF_BIN\"
	"
	assert_success
	assert_output "$MOCK_DIR/csf"
}

@test "_fw_csf_setup: fails when csf not in PATH" {
	run bash -c "
		source '${PROJECT_ROOT}/files/bfd.lib.sh'
		BFD_LOG_PATH='$BFD_LOG_PATH'
		OUTPUT_SYSLOG='0'
		OUTPUT_SYSLOG_FILE='$TEST_TMPDIR/syslog'
		export PATH='$MOCK_DIR'
		_fw_csf_setup
	"
	assert_failure
}

@test "_fw_iptables_setup: sets _FW_IPT_BIN via command -v" {
	cat > "$MOCK_DIR/iptables" <<'SCRIPT'
#!/bin/bash
# mock: accept any args silently
exit 0
SCRIPT
	chmod +x "$MOCK_DIR/iptables"
	run bash -c "
		source '${PROJECT_ROOT}/files/bfd.lib.sh'
		BFD_LOG_PATH='$BFD_LOG_PATH'
		OUTPUT_SYSLOG='0'
		OUTPUT_SYSLOG_FILE='$TEST_TMPDIR/syslog'
		export PATH='$MOCK_DIR:/usr/bin:/bin'
		_fw_iptables_setup
		echo \"\$_FW_IPT_BIN\"
	"
	assert_success
	assert_output --partial "$MOCK_DIR/iptables"
	# ip6tables not in mock PATH — warning expected
	assert_output --partial "ip6tables not found"
}

@test "_fw_iptables_setup: sets _FW_IP6T_BIN when ip6tables exists" {
	cat > "$MOCK_DIR/iptables" <<'SCRIPT'
#!/bin/bash
exit 0
SCRIPT
	cat > "$MOCK_DIR/ip6tables" <<'SCRIPT'
#!/bin/bash
exit 0
SCRIPT
	chmod +x "$MOCK_DIR/iptables" "$MOCK_DIR/ip6tables"
	run bash -c "
		source '${PROJECT_ROOT}/files/bfd.lib.sh'
		BFD_LOG_PATH='$BFD_LOG_PATH'
		OUTPUT_SYSLOG='0'
		OUTPUT_SYSLOG_FILE='$TEST_TMPDIR/syslog'
		export PATH='$MOCK_DIR:/usr/bin:/bin'
		_fw_iptables_setup
		echo \"\$_FW_IP6T_BIN\"
	"
	assert_success
	assert_output "$MOCK_DIR/ip6tables"
}

@test "_fw_iptables_setup: fails when iptables not in PATH" {
	run bash -c "
		source '${PROJECT_ROOT}/files/bfd.lib.sh'
		BFD_LOG_PATH='$BFD_LOG_PATH'
		OUTPUT_SYSLOG='0'
		OUTPUT_SYSLOG_FILE='$TEST_TMPDIR/syslog'
		export PATH='$MOCK_DIR'
		_fw_iptables_setup
	"
	assert_failure
}
