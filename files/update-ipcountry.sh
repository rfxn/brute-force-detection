#!/bin/bash
#
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
# Copyright (C) 1999-2026, R-fx Networks <proj@rfxn.com>
# Copyright (C) 2026, Ryan MacDonald <ryan@rfxn.com>
# This program may be freely redistributed under the terms of the GNU GPL
#
# update-ipcountry.sh — rebuild ipcountry.dat from a CSV source
#
# Downloads the DB-IP Lite country CSV and converts it to the sorted
# integer-range format used by ip_to_country(). Run periodically to
# keep the country database current.
#
# Usage: update-ipcountry.sh [output_file]
#   output_file defaults to $INSTALL_PATH/ipcountry.dat

INSTALL_PATH="${INSTALL_PATH:-/usr/local/bfd}"
OUTPUT="${1:-$INSTALL_PATH/ipcountry.dat}"
DBIP_URL="https://download.db-ip.com/free/dbip-country-lite-$(date +%Y-%m).csv.gz"
DL_TIMEOUT="${DL_TIMEOUT:-120}"

WGET_BIN=$(command -v wget 2>/dev/null)
CURL_BIN=$(command -v curl 2>/dev/null)
GZIP_BIN=$(command -v gzip 2>/dev/null)

if [ -z "$GZIP_BIN" ]; then
	echo "error: gzip not found, cannot decompress download."
	exit 1
fi

# prefer INSTALL_PATH/tmp for temp files (owned by root, mode 750);
# fall back to /tmp if install path is not yet available
if [ -d "$INSTALL_PATH/tmp" ] && [ -w "$INSTALL_PATH/tmp" ]; then
	tmpdir=$(mktemp -d "$INSTALL_PATH/tmp/ipcountry.XXXXXX")
else
	tmpdir=$(mktemp -d /tmp/bfd-ipcountry.XXXXXX)
fi
trap 'rm -rf "$tmpdir"' EXIT INT TERM

csv_gz="$tmpdir/dbip.csv.gz"
csv_file="$tmpdir/dbip.csv"

# _download url output — download with timeout, TLS fallback for legacy systems
_download() {
	local url="$1" out="$2"
	if [ -n "$WGET_BIN" ]; then
		"$WGET_BIN" -q --timeout="$DL_TIMEOUT" -O "$out" "$url" 2>/dev/null && return 0
		# TLS fallback: retry without certificate verification (legacy CA bundles)
		echo "warning: TLS download failed, retrying without certificate verification."
		"$WGET_BIN" -q --timeout="$DL_TIMEOUT" --no-check-certificate -O "$out" "$url" && return 0
	elif [ -n "$CURL_BIN" ]; then
		"$CURL_BIN" -sL --connect-timeout 15 --max-time "$DL_TIMEOUT" -o "$out" "$url" 2>/dev/null && return 0
		# TLS fallback: retry without certificate verification (legacy CA bundles)
		echo "warning: TLS download failed, retrying without certificate verification."
		"$CURL_BIN" -sL --connect-timeout 15 --max-time "$DL_TIMEOUT" -k -o "$out" "$url" && return 0
	else
		echo "error: neither wget nor curl found."
		return 1
	fi
	return 1
}

echo "Downloading DB-IP country database..."
if ! _download "$DBIP_URL" "$csv_gz"; then
	echo "error: download failed."
	exit 1
fi

"$GZIP_BIN" -d "$csv_gz" || {
	echo "error: decompression failed."
	exit 1
}

echo "Converting to integer-range format..."
# DB-IP CSV format: start_ip,end_ip,country_code
# We convert IPv4 addresses to integers for binary search.
# IPv6 ranges are skipped (not supported in v1).
awk -F, '
function ip2int(ip,    parts, n) {
	n = split(ip, parts, ".")
	if (n != 4) return -1
	return (parts[1]+0) * 16777216 + (parts[2]+0) * 65536 + (parts[3]+0) * 256 + (parts[4]+0)
}
{
	# skip IPv6 ranges
	if (index($1, ":") > 0) next
	start = ip2int($1)
	end = ip2int($2)
	cc = toupper($3)
	if (start >= 0 && end >= 0 && cc != "")
		printf "%d %d %s\n", start, end, cc
}' "$csv_file" | sort -n -k1 > "$tmpdir/ipcountry.dat"

lines=$(wc -l < "$tmpdir/ipcountry.dat")
if [ "$lines" -lt 1000 ]; then
	echo "error: output has only $lines lines, expected 100k+. Aborting."
	exit 1
fi

cp "$tmpdir/ipcountry.dat" "$OUTPUT"
chmod 644 "$OUTPUT"
echo "Updated $OUTPUT ($lines ranges)."
