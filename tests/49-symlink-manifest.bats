#!/usr/bin/env bats
#
# Test suite for symlink manifest generation and runtime self-healing
# (pkg_lib v1.0.6 pkg_fhs_verify_farm integration)
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

setup() {
	bfd_standard_setup
	mkdir -p "$INSTALL_PATH/internals"

	# Create mock executable at install path (target for symlink repair)
	touch "$INSTALL_PATH/bfd"
	chmod 750 "$INSTALL_PATH/bfd"

	# Set up BINPATH in test tmpdir (avoid touching real /usr/local/sbin)
	BINPATH="$TEST_TMPDIR/sbin/bfd"
	mkdir -p "$(dirname "$BINPATH")"

	# Create symlinks as install.sh would
	ln -sf "$INSTALL_PATH/bfd" "$BINPATH"

	# Generate manifest matching test layout
	{
		printf '# pkg_lib:symlink-manifest:1\n'
		printf '%s\t%s\n' "$BINPATH" "$INSTALL_PATH/bfd"
	} > "$INSTALL_PATH/internals/.symlink-manifest"
	chmod 640 "$INSTALL_PATH/internals/.symlink-manifest"
}

teardown() {
	bfd_teardown
}

# ============================================================
# Manifest file structure
# ============================================================

@test "symlink-manifest: manifest file exists after setup" {
	[ -f "$INSTALL_PATH/internals/.symlink-manifest" ]
}

@test "symlink-manifest: manifest has correct header" {
	local header
	header=$(head -1 "$INSTALL_PATH/internals/.symlink-manifest")
	[ "$header" = "# pkg_lib:symlink-manifest:1" ]
}

@test "symlink-manifest: manifest has 1 entry" {
	local count
	count=$(grep -cve '^\s*$' -e '^\s*#' "$INSTALL_PATH/internals/.symlink-manifest")
	[ "$count" -eq 1 ]
}

@test "symlink-manifest: manifest entries match installed symlinks" {
	while IFS=$'\t' read -r link_path target; do
		[[ "$link_path" = \#* ]] && continue
		[[ -z "$link_path" ]] && continue
		local actual
		actual=$(readlink "$link_path")
		[ "$actual" = "$target" ]
	done < "$INSTALL_PATH/internals/.symlink-manifest"
}

# ============================================================
# Missing manifest — graceful no-op
# ============================================================

@test "symlink-manifest: missing manifest is silent no-op" {
	run pkg_fhs_verify_farm "$INSTALL_PATH/internals/.nonexistent-manifest"
	assert_success
}

# ============================================================
# Self-healing — broken symlink
# ============================================================

@test "symlink-manifest: broken sbin symlink auto-repairs" {
	# Break the bfd symlink — point to nonexistent target
	rm -f "$BINPATH"
	ln -sf "/nonexistent/path" "$BINPATH"

	# Verify it is broken
	[ -L "$BINPATH" ]
	[ ! -e "$BINPATH" ]

	# Run verify — should repair
	run pkg_fhs_verify_farm "$INSTALL_PATH/internals/.symlink-manifest"
	assert_success

	# Verify repaired: symlink now points to correct target
	local actual
	actual=$(readlink "$BINPATH")
	[ "$actual" = "$INSTALL_PATH/bfd" ]
	[ -e "$BINPATH" ]
}

# ============================================================
# Self-healing — wrong-target symlink
# ============================================================

@test "symlink-manifest: wrong-target sbin symlink auto-repairs" {
	# Point bfd symlink to wrong (but existing) target
	rm -f "$BINPATH"
	ln -sf "/tmp" "$BINPATH"

	# Verify symlink exists but points to wrong target
	[ -L "$BINPATH" ]
	local wrong_target
	wrong_target=$(readlink "$BINPATH")
	[ "$wrong_target" = "/tmp" ]

	# Run verify — should repair
	run pkg_fhs_verify_farm "$INSTALL_PATH/internals/.symlink-manifest"
	assert_success

	# Verify repaired: symlink now points to correct target
	local actual
	actual=$(readlink "$BINPATH")
	[ "$actual" = "$INSTALL_PATH/bfd" ]
}
