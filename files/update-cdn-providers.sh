#!/bin/bash
#
# Brute Force Detection 2.0.2 <bfd@rfxn.com>
# Copyright (C) 1999-2026, R-fx Networks <proj@rfxn.com>
# Copyright (C) 2026, Ryan MacDonald <ryan@rfxn.com>
# This program may be freely redistributed under the terms of the GNU GPL
#
# update-cdn-providers.sh — rebuild CDN/trusted proxy IP databases
#
# Fetches provider IP ranges from configured URLs, converts CIDRs to
# sorted integer-range (IPv4) and hex-range (IPv6) databases for
# binary-search lookup by the BFD detection pipeline.
#
# Usage: update-cdn-providers.sh [conf_file]
#   conf_file defaults to $INSTALL_PATH/cdn-providers.conf

INSTALL_PATH="${INSTALL_PATH:-/usr/local/bfd}"
DATA_PATH="${DATA_PATH:-$INSTALL_PATH/data}"
CONF_FILE="${1:-$INSTALL_PATH/cdn-providers.conf}"
OUTPUT_V4="$DATA_PATH/cdn.dat"
OUTPUT_V6="$DATA_PATH/cdn6.dat"

# Source bfd_cdn.sh for compile/fetch functions
_script_dir="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
_cdn_lib="$_script_dir/internals/bfd_cdn.sh"
if [ ! -f "$_cdn_lib" ]; then
	echo "error: bfd_cdn.sh not found at $_cdn_lib"
	exit 1
fi
# shellcheck disable=SC1090
. "$_cdn_lib"

# Validate config exists
if [ ! -f "$CONF_FILE" ]; then
	echo "error: CDN provider config not found: $CONF_FILE"
	exit 1
fi

echo "Building CDN provider databases..."

if ! _cdn_compile_db "$CONF_FILE" "$OUTPUT_V4" "$OUTPUT_V6"; then
	echo "error: CDN database build failed."
	exit 1
fi

# Set secure permissions
if [ -f "$OUTPUT_V4" ]; then
	command chmod 640 "$OUTPUT_V4"
fi
if [ -f "$OUTPUT_V6" ]; then
	command chmod 640 "$OUTPUT_V6"
fi

echo "Updated CDN databases ($_CDN_BUILD_COUNT providers, $_CDN_BUILD_RANGES ranges, $_CDN_BUILD_FAIL failed)."
if [ -s "$OUTPUT_V4" ]; then
	echo "  IPv4: $OUTPUT_V4 ($(wc -l < "$OUTPUT_V4") ranges)"
fi
if [ -s "$OUTPUT_V6" ]; then
	echo "  IPv6: $OUTPUT_V6 ($(wc -l < "$OUTPUT_V6") ranges)"
fi
