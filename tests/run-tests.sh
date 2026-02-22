#!/bin/bash
#
# BFD Test Runner
# Usage: ./tests/run-tests.sh [--os OS] [bats args...]
# Examples:
#   ./tests/run-tests.sh                          # Run all tests (Debian 12)
#   ./tests/run-tests.sh --os rocky9              # Run on Rocky Linux 9
#   ./tests/run-tests.sh --os centos6             # Run on CentOS 6
#   ./tests/run-tests.sh --filter "validate_ip"   # Filter by name
#
# Supported OS values (CI matrix marked with *):
#   debian12     * Debian 12 slim (default)
#   centos6        CentOS 6 (EOL, vault repos)
#   centos7      * CentOS 7 (EOL)
#   rocky8       * Rocky Linux 8
#   rocky9       * Rocky Linux 9
#   rocky10        Rocky Linux 10 (pending stable)
#   ubuntu1204     Ubuntu 12.04 (EOL, old-releases repos)
#   ubuntu2004   * Ubuntu 20.04 LTS
#   ubuntu2404   * Ubuntu 24.04 LTS
#
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Parse --os flag
OS="debian12"
if [ "$1" = "--os" ]; then
	OS="$2"
	shift 2
fi

# Map OS to Dockerfile
case "$OS" in
	debian12)
		DOCKERFILE="$SCRIPT_DIR/Dockerfile"
		;;
	centos6|centos7|rocky8|rocky9|rocky10|ubuntu1204|ubuntu2004|ubuntu2404)
		DOCKERFILE="$SCRIPT_DIR/Dockerfile.${OS}"
		;;
	*)
		echo "Unknown OS: $OS"
		echo "Supported: debian12, centos6, centos7, rocky8, rocky9, rocky10, ubuntu1204, ubuntu2004, ubuntu2404"
		exit 1
		;;
esac

if [ ! -f "$DOCKERFILE" ]; then
	echo "Dockerfile not found: $DOCKERFILE"
	exit 1
fi

IMAGE_NAME="bfd-test-${OS}"

echo "Building BFD test image ($OS)..."
docker build -f "$DOCKERFILE" -t "$IMAGE_NAME" "$PROJECT_DIR"

echo "Running tests on $OS..."
if [ $# -eq 0 ]; then
	# No args: use default CMD (all tests, tap format)
	docker run --rm "$IMAGE_NAME"
else
	# Custom args: pass to bats
	docker run --rm "$IMAGE_NAME" bats "$@"
fi
