#!/bin/bash
#
# BFD mock binary helpers
# Loaded by bfd-common.bash; available to all test files
#

# create_mock_bin NAME [BODY]
# Creates an executable mock script in MOCK_DIR (auto-created under TEST_TMPDIR)
create_mock_bin() {
	local name="$1" body="${2:-exit 0}"
	if [ -z "${MOCK_DIR:-}" ]; then
		MOCK_DIR="$TEST_TMPDIR/mock_bin"
		mkdir -p "$MOCK_DIR"
	fi
	printf '#!/bin/bash\n%s\n' "$body" > "$MOCK_DIR/$name"
	chmod +x "$MOCK_DIR/$name"
}

# create_mock_rule NAME BODY
# Creates a rule file in RULES_PATH with correct ownership/permissions
create_mock_rule() {
	local name="$1" body="$2"
	if [ -z "${RULES_PATH:-}" ]; then
		RULES_PATH="$INSTALL_PATH/rules"
	fi
	mkdir -p "$RULES_PATH"
	printf '%s\n' "$body" > "$RULES_PATH/$name"
	chown root "$RULES_PATH/$name" 2>/dev/null || true
	chmod 644 "$RULES_PATH/$name"
}
