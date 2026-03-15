#!/bin/bash
#
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
# Copyright (C) 1999-2026, R-fx Networks <proj@rfxn.com>
# Copyright (C) 2026, Ryan MacDonald <ryan@rfxn.com>
# This program may be freely redistributed under the terms of the GNU GPL
#
# update-ipcountry.sh — rebuild ipcountry.dat from CIDR zone data
#
# Uses geoip_lib.sh geoip_build_ipdb() for IPv4 (bulk tarball with
# per-country fallback) and geoip_build_ip6db() for IPv6 (hex-range format).
#
# Usage: update-ipcountry.sh [output_file]
#   output_file defaults to $INSTALL_PATH/ipcountry.dat

INSTALL_PATH="${INSTALL_PATH:-/usr/local/bfd}"
OUTPUT="${1:-$INSTALL_PATH/ipcountry.dat}"
OUTPUT6="${OUTPUT%.*}6.${OUTPUT##*.}"
DL_TIMEOUT="${DL_TIMEOUT:-120}"

# Source geoip_lib.sh for download functions and CC metadata
_script_dir="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
_geoip_lib="$_script_dir/internals/geoip_lib.sh"
if [ ! -f "$_geoip_lib" ]; then
	echo "error: geoip_lib.sh not found at $_geoip_lib"
	exit 1
fi
# shellcheck disable=SC1090
. "$_geoip_lib"

# Export download timeout for geoip_lib
export GEOIP_DL_TIMEOUT="$DL_TIMEOUT"

# ---------------------------------------------------------------------------
# IPv4: use geoip_build_ipdb (bulk tarball + per-country fallback)
# ---------------------------------------------------------------------------
echo "Building IPv4 country database..."

if ! geoip_build_ipdb "$OUTPUT" 1000; then
	echo "error: IPv4 database build failed. Aborting."
	exit 1
fi
chmod 640 "$OUTPUT"
echo "Updated $OUTPUT ($_GEOIP_BUILD_COUNT countries, $_GEOIP_BUILD_RANGES IPv4 ranges, $_GEOIP_BUILD_FAIL failed)."

# ---------------------------------------------------------------------------
# IPv6: use geoip_build_ip6db (per-country cascade, hex-range format)
# ---------------------------------------------------------------------------
echo "Building IPv6 country database..."
if geoip_build_ip6db "$OUTPUT6" 500; then
	chmod 640 "$OUTPUT6"
	echo "Updated $OUTPUT6 ($_GEOIP_BUILD6_COUNT countries, $_GEOIP_BUILD6_RANGES IPv6 ranges, $_GEOIP_BUILD6_FAIL failed)."
else
	echo "warning: IPv6 database build failed (non-fatal)."
fi

# Mark update timestamp for staleness tracking
_dat_dir="$(dirname "$OUTPUT")"
if [ -d "$_dat_dir" ]; then
	geoip_mark_updated "$_dat_dir"
fi
