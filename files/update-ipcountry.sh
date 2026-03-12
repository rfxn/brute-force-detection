#!/bin/bash
#
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
# Copyright (C) 1999-2026, R-fx Networks <proj@rfxn.com>
# Copyright (C) 2026, Ryan MacDonald <ryan@rfxn.com>
# This program may be freely redistributed under the terms of the GNU GPL
#
# update-ipcountry.sh — rebuild ipcountry.dat from CIDR zone data
#
# Downloads per-country CIDR zone files via geoip_lib.sh (ipverse/ipdeny
# cascade) and converts them to the sorted integer-range format used by
# ip_to_country(). Also downloads IPv6 CIDR data to ipcountry6.dat for
# future use.
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

# prefer INSTALL_PATH/tmp for temp files (owned by root, mode 750);
# fall back to /tmp if install path is not yet available
if [ -d "$INSTALL_PATH/tmp" ] && [ -w "$INSTALL_PATH/tmp" ]; then
	tmpdir=$(mktemp -d "$INSTALL_PATH/tmp/ipcountry.XXXXXX")
else
	tmpdir=$(mktemp -d /tmp/bfd-ipcountry.XXXXXX)
fi
trap 'rm -rf "$tmpdir"' EXIT INT TERM

# _all_cc_codes — emit all known country codes (one per line)
# Iterates the 6 continent CC lists from geoip_lib module variables.
_all_cc_codes() {
	local _cont _code _save_ifs
	for _cont in "$_GEOIP_CC_AF" "$_GEOIP_CC_AS" "$_GEOIP_CC_EU" \
	             "$_GEOIP_CC_NA" "$_GEOIP_CC_SA" "$_GEOIP_CC_OC"; do
		_save_ifs="$IFS"
		IFS=","
		for _code in $_cont; do
			echo "$_code"
		done
		IFS="$_save_ifs"
	done
}

# _cidr4_to_ranges — convert CIDR file to integer-range format.
# Input: file of CIDR lines (1.0.0.0/24), one per line (comments/blanks ignored)
# Output: "START_INT END_INT CC" lines to stdout
# Uses mawk-compatible awk: no gensub, no strftime. 2^(32-n) is safe in mawk
# (proven in APF _geoip_cidr4_search and tested for edge cases /0,/1,/8,/32).
_cidr4_to_ranges() {
	local cidr_file="$1" cc="$2"
	awk -v cc="$cc" '
/^[0-9]/ {
	n = split($0, p, "[./]")
	if (n < 5) next
	net = (p[1]+0) * 16777216 + (p[2]+0) * 65536 + (p[3]+0) * 256 + (p[4]+0)
	bits = int(p[5]+0)
	if (bits < 0 || bits > 32) next
	size = 2 ^ (32 - bits)
	end = net + size - 1
	printf "%d %d %s\n", net, end, cc
}' "$cidr_file"
}

echo "Downloading IP country CIDR zones..."

dl_count=0
dl_fail=0
v6_count=0

while IFS= read -r cc; do
	cidr_file="$tmpdir/${cc}.zone"
	if geoip_download "$cc" "4" "$cidr_file"; then
		_cidr4_to_ranges "$cidr_file" "$cc" >> "$tmpdir/merged.dat"
		dl_count=$(( dl_count + 1 ))
	else
		dl_fail=$(( dl_fail + 1 ))
	fi
	rm -f "$cidr_file"

	# IPv6: download to separate file for future use
	cidr6_file="$tmpdir/${cc}.zone6"
	if geoip_download "$cc" "6" "$cidr6_file"; then
		awk -v cc="$cc" '/^[0-9a-fA-F:]/ { printf "%s %s\n", $0, cc }' \
			"$cidr6_file" >> "$tmpdir/merged6.dat"
		v6_count=$(( v6_count + 1 ))
	fi
	rm -f "$cidr6_file"
done < <(_all_cc_codes)

echo "Downloaded $dl_count countries ($dl_fail failed)."

# Sort IPv4 ranges by start integer
if [ -f "$tmpdir/merged.dat" ]; then
	sort -n -k1 "$tmpdir/merged.dat" > "$tmpdir/ipcountry.dat"
else
	: > "$tmpdir/ipcountry.dat"
fi

lines=$(wc -l < "$tmpdir/ipcountry.dat")
if [ "$lines" -lt 1000 ]; then
	echo "error: output has only $lines ranges, expected 100k+. Aborting."
	exit 1
fi

cp "$tmpdir/ipcountry.dat" "$OUTPUT"
chmod 644 "$OUTPUT"
echo "Updated $OUTPUT ($lines IPv4 ranges)."

# Write IPv6 data if any was collected
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
