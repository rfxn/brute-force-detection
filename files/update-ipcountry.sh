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
# per-country fallback) and per-country downloads for IPv6.
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
chmod 644 "$OUTPUT"
echo "Updated $OUTPUT ($_GEOIP_BUILD_COUNT countries, $_GEOIP_BUILD_RANGES IPv4 ranges, $_GEOIP_BUILD_FAIL failed)."

# ---------------------------------------------------------------------------
# IPv6: per-country downloads (no bulk tarball available)
# ---------------------------------------------------------------------------

# prefer INSTALL_PATH/tmp for temp files; fall back to /tmp
if [ -d "$INSTALL_PATH/tmp" ] && [ -w "$INSTALL_PATH/tmp" ]; then
	tmpdir=$(mktemp -d "$INSTALL_PATH/tmp/ipcountry.XXXXXX")
else
	tmpdir=$(mktemp -d /tmp/bfd-ipcountry.XXXXXX)
fi
trap 'rm -rf "$tmpdir"' EXIT INT TERM

v6_count=0
while IFS= read -r cc; do
	cidr6_file="$tmpdir/${cc}.zone6"
	if geoip_download "$cc" "6" "$cidr6_file"; then
		"$GEOIP_AWK_BIN" -v cc="$cc" '/^[0-9a-fA-F:]/ { printf "%s %s\n", $0, cc }' \
			"$cidr6_file" >> "$tmpdir/merged6.dat"
		v6_count=$(( v6_count + 1 ))
	fi
	rm -f "$cidr6_file"
done < <(geoip_all_cc)

if [ -f "$tmpdir/merged6.dat" ] && [ -s "$tmpdir/merged6.dat" ]; then
	sort "$tmpdir/merged6.dat" > "$tmpdir/ipcountry6.dat"
	v6_lines=$(wc -l < "$tmpdir/ipcountry6.dat")
	cp "$tmpdir/ipcountry6.dat" "$OUTPUT6"
	chmod 644 "$OUTPUT6"
	echo "Updated $OUTPUT6 ($v6_lines IPv6 prefixes)."
fi

# Mark update timestamp for staleness tracking
_dat_dir="$(dirname "$OUTPUT")"
if [ -d "$_dat_dir" ]; then
	geoip_mark_updated "$_dat_dir"
fi
