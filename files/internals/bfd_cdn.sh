#!/bin/bash
#
# Brute Force Detection 2.0.2 - CDN/Trusted Proxy Subsystem
###
# Copyright (C) 1999-2026, R-fx Networks <proj@rfxn.com>
# Copyright (C) 2026, Ryan MacDonald <ryan@rfxn.com>
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
###
#
# Sourced by bfd.lib.sh or standalone by update-cdn-providers.sh.
# Provides CDN provider config parsing, CIDR-to-range compilation,
# database building, and binary-search IP lookup (IPv4 integer + IPv6 hex).

# Source guard — prevent double-sourcing
[[ -n "${_BFD_CDN_LOADED:-}" ]] && return 0 2>/dev/null
_BFD_CDN_LOADED=1

# shellcheck disable=SC2034
BFD_CDN_VERSION="1.0.0"

# ---------------------------------------------------------------------------
# Logging helper — use elog if available, fall back to stderr
# ---------------------------------------------------------------------------
_cdn_warn() {
	if declare -f elog >/dev/null 2>&1; then
		elog warn "$1"
	else
		echo "warning: $1" >&2
	fi
}

_cdn_info() {
	if declare -f elog >/dev/null 2>&1; then
		elog info "$1"
	else
		echo "$1" >&2
	fi
}

# ---------------------------------------------------------------------------
# Binary discovery at source time — allows env override for testing.
# ---------------------------------------------------------------------------
CDN_CURL_BIN="${CDN_CURL_BIN:-$(command -v curl 2>/dev/null || true)}"   # may be absent
CDN_WGET_BIN="${CDN_WGET_BIN:-$(command -v wget 2>/dev/null || true)}"   # may be absent
CDN_AWK_BIN="${CDN_AWK_BIN:-$(command -v awk 2>/dev/null || true)}"      # may be absent

# ---------------------------------------------------------------------------
# Provider config arrays (parallel indexed — no declare -A for global state)
# ---------------------------------------------------------------------------
_CDN_NAMES=()
_CDN_TREATMENTS=()
_CDN_MULTS=()
_CDN_FORMATS=()
_CDN_URLS_V4=()
_CDN_URLS_V6=()
_CDN_COUNT=0

# Build statistics (set by _cdn_compile_db)
_CDN_BUILD_COUNT=0
_CDN_BUILD_RANGES=0
_CDN_BUILD_FAIL=0

# ---------------------------------------------------------------------------
# _cdn_load_providers conf_file — parse cdn-providers.conf into parallel arrays.
# Validates treatment in {ignore, exclude, derate}; skips invalid with warning.
# Skips comments (#) and blank lines.
# Args: conf_file — path to cdn-providers.conf
# Returns: 0 on success (even if 0 providers loaded), 1 on missing file
# ---------------------------------------------------------------------------
_cdn_load_providers() {
	local conf_file="$1"

	# Reset arrays
	_CDN_NAMES=()
	_CDN_TREATMENTS=()
	_CDN_MULTS=()
	_CDN_FORMATS=()
	_CDN_URLS_V4=()
	_CDN_URLS_V6=()
	_CDN_COUNT=0

	if [ ! -f "$conf_file" ]; then
		_cdn_warn "cdn config not found: $conf_file"
		return 1
	fi

	local _name _treatment _mult _format _url_v4 _url_v6
	while IFS= read -r _line; do
		# Skip comments and blank lines
		case "$_line" in
			\#*|"") continue ;;
		esac
		# Strip inline comments (anything after # preceded by whitespace)
		_line="${_line%%#*}"
		# Trim trailing whitespace
		_line="${_line%"${_line##*[![:space:]]}"}"
		[ -z "$_line" ] && continue

		# Parse fields via default awk splitting
		read -r _name _treatment _mult _format _url_v4 _url_v6 <<< "$_line"

		# Validate required fields
		if [ -z "$_name" ] || [ -z "$_treatment" ] || [ -z "$_mult" ] || \
		   [ -z "$_format" ] || [ -z "$_url_v4" ]; then
			_cdn_warn "cdn config: skipping incomplete line: $_name"
			continue
		fi

		# Validate treatment
		case "$_treatment" in
			ignore|exclude|derate) ;;
			*)
				_cdn_warn "cdn config: invalid treatment '$_treatment' for provider '$_name', skipping"
				continue
				;;
		esac

		# Validate format
		case "$_format" in
			text|json) ;;
			*)
				_cdn_warn "cdn config: invalid format '$_format' for provider '$_name', skipping"
				continue
				;;
		esac

		# Validate multiplier is a positive integer
		local _mult_re='^[0-9]+$'
		if ! [[ "$_mult" =~ $_mult_re ]]; then
			_cdn_warn "cdn config: invalid multiplier '$_mult' for provider '$_name', skipping"
			continue
		fi

		# Validate name: alphanumeric + hyphens only
		local _name_re='^[a-zA-Z0-9-]+$'
		if ! [[ "$_name" =~ $_name_re ]]; then
			_cdn_warn "cdn config: invalid name '$_name', skipping"
			continue
		fi

		_CDN_NAMES+=("$_name")
		_CDN_TREATMENTS+=("$_treatment")
		_CDN_MULTS+=("$_mult")
		_CDN_FORMATS+=("$_format")
		_CDN_URLS_V4+=("$_url_v4")
		_CDN_URLS_V6+=("${_url_v6:--}")
		_CDN_COUNT=$((_CDN_COUNT + 1))
	done < "$conf_file"

	return 0
}

# ---------------------------------------------------------------------------
# _cdn_cidr_to_range_v4 cidr — convert IPv4 CIDR to START_INT END_INT.
# Uses same math as ip_to_country()/geoip_cidr4_to_ranges():
#   ip_int = o1*16777216 + o2*65536 + o3*256 + o4
#   end = start + 2^(32-prefix) - 1
# Args: cidr — e.g., "172.70.0.0/13"
# Prints: "START_INT END_INT" to stdout
# Returns: 0 on success, 1 on invalid input
# ---------------------------------------------------------------------------
_cdn_cidr_to_range_v4() {
	local cidr="$1"
	[[ -n "$CDN_AWK_BIN" ]] || { echo "_cdn_cidr_to_range_v4: awk not available" >&2; return 1; }

	"$CDN_AWK_BIN" -v cidr="$cidr" 'BEGIN {
		n = split(cidr, p, "[./]")
		if (n < 5) exit 1
		net = (p[1]+0) * 16777216 + (p[2]+0) * 65536 + (p[3]+0) * 256 + (p[4]+0)
		bits = int(p[5]+0)
		if (bits < 0 || bits > 32) exit 1
		size = 2 ^ (32 - bits)
		end = net + size - 1
		printf "%d %d\n", net, end
	}'
}

# ---------------------------------------------------------------------------
# Shared AWK for IPv6 hex normalization — same v6hex() as geoip_lib.sh.
# Set once; embedded in awk programs via string concatenation.
# ---------------------------------------------------------------------------
# shellcheck disable=SC2034
_CDN_V6_AWK='
function _v6_hexval(c,    p) {
	p = index("0123456789abcdef", c)
	if (p > 0) return p - 1
	return 0
}
function _v6_hexchar(n) {
	return substr("0123456789abcdef", n + 1, 1)
}
function v6hex(addr,    n, halves, lp, rp, nl, nr, full, zf, i, j, g, c, hex) {
	if (index(addr, ".") > 0) return ""
	addr = tolower(addr)
	if (index(addr, "::") > 0) {
		n = split(addr, halves, "::")
		if (n != 2) return ""
		nl = split(halves[1], lp, ":")
		if (halves[1] == "") nl = 0
		nr = split(halves[2], rp, ":")
		if (halves[2] == "") nr = 0
		if (nl + nr > 7) return ""
		for (i = 1; i <= nl; i++) full[i] = lp[i]
		zf = 8 - nl - nr
		for (i = 1; i <= zf; i++) full[nl + i] = "0"
		for (i = 1; i <= nr; i++) full[nl + zf + i] = rp[i]
	} else {
		if (split(addr, full, ":") != 8) return ""
	}
	hex = ""
	for (i = 1; i <= 8; i++) {
		g = full[i]
		while (length(g) < 4) g = "0" g
		if (length(g) > 4) return ""
		for (j = 1; j <= 4; j++) {
			c = substr(g, j, 1)
			if (index("0123456789abcdef", c) == 0) return ""
		}
		hex = hex g
	}
	if (length(hex) != 32) return ""
	return hex
}
'

# ---------------------------------------------------------------------------
# _cdn_cidr_to_range_v6 cidr — convert IPv6 CIDR to START_HEX END_HEX.
# Expand to full 8 groups, convert to 32-char hex, compute end by flipping
# host bits (same approach as _geoip_cidr6_to_ranges in geoip_lib.sh).
# Args: cidr — e.g., "2400:cb00::/32"
# Prints: "START_HEX END_HEX" to stdout (32-char lowercase hex each)
# Returns: 0 on success, 1 on invalid input
# ---------------------------------------------------------------------------
_cdn_cidr_to_range_v6() {
	local cidr="$1"
	[[ -n "$CDN_AWK_BIN" ]] || { echo "_cdn_cidr_to_range_v6: awk not available" >&2; return 1; }

	"$CDN_AWK_BIN" -v cidr="$cidr" "${_CDN_V6_AWK}"'BEGIN {
		n = split(cidr, parts, "/")
		if (n < 2) exit 1
		prefix_len = int(parts[2] + 0)
		if (prefix_len < 0 || prefix_len > 128) exit 1
		hex = v6hex(parts[1])
		if (hex == "") exit 1

		pos = int(prefix_len / 4)
		rem = prefix_len % 4

		if (pos > 0) {
			start = substr(hex, 1, pos)
			end_hex = substr(hex, 1, pos)
		} else {
			start = ""
			end_hex = ""
		}

		if (rem > 0) {
			boundary = substr(hex, pos + 1, 1)
			nval = _v6_hexval(boundary)
			mask_hi = 1
			for (j = 1; j <= 4 - rem; j++) mask_hi = mask_hi * 2
			start_nib = int(nval / mask_hi) * mask_hi
			end_nib = start_nib + mask_hi - 1
			start = start _v6_hexchar(start_nib)
			end_hex = end_hex _v6_hexchar(end_nib)
			pos = pos + 1
		}

		while (length(start) < 32) start = start "0"
		while (length(end_hex) < 32) end_hex = end_hex "f"

		printf "%s %s\n", start, end_hex
	}'
}

# ---------------------------------------------------------------------------
# _cdn_fetch_provider name url format — fetch URL, extract CIDRs to stdout.
# Uses curl with wget fallback. Extracts CIDRs from text or JSON format.
# Text: strip comments/blanks, one CIDR per line.
# JSON IPv4: grep for quoted CIDRs.
# JSON IPv6: grep for quoted IPv6 CIDRs.
# Args: name — provider name (for logging)
#       url — URL to fetch
#       format — "text" or "json"
# Prints: extracted CIDRs to stdout (one per line)
# Returns: 0 on success, 1 on fetch failure
# ---------------------------------------------------------------------------
_cdn_fetch_provider() {
	local name="$1" url="$2" format="$3"
	local raw_data=""

	# Fetch via curl (preferred) or wget fallback
	if [ -n "$CDN_CURL_BIN" ]; then
		raw_data=$("$CDN_CURL_BIN" --max-time 30 -fsSL "$url" 2>/dev/null) || true  # capture failure, check below
	fi
	if [ -z "$raw_data" ] && [ -n "$CDN_WGET_BIN" ]; then
		raw_data=$("$CDN_WGET_BIN" --timeout=30 -qO- "$url" 2>/dev/null) || true  # wget fallback
	fi
	if [ -z "$raw_data" ]; then
		_cdn_warn "cdn fetch failed for provider '$name' at $url"
		return 1
	fi

	local _v4_cidr_re='"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+"'
	local _v6_cidr_re='"[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{0,4}){1,7}/[0-9]{1,3}"'
	local _valid_v4='^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/([0-9]|[12][0-9]|3[0-2])$'
	local _valid_v6='^[0-9a-fA-F:]+/([0-9]{1,2}|1[01][0-9]|12[0-8])$'

	case "$format" in
		text)
			# Strip comments and blank lines, emit one CIDR per line
			echo "$raw_data" | grep -Ev '^\s*(#|$)' | while IFS= read -r _cidr; do
				# Trim whitespace
				_cidr="${_cidr#"${_cidr%%[![:space:]]*}"}"
				_cidr="${_cidr%"${_cidr##*[![:space:]]}"}"
				[ -z "$_cidr" ] && continue
				# Validate: must look like a CIDR
				if [[ "$_cidr" =~ $_valid_v4 ]] || [[ "$_cidr" =~ $_valid_v6 ]]; then
					echo "$_cidr"
				fi
			done
			;;
		json)
			# Extract IPv4 CIDRs from JSON
			echo "$raw_data" | grep -oE "$_v4_cidr_re" | tr -d '"' | while IFS= read -r _cidr; do
				if [[ "$_cidr" =~ $_valid_v4 ]]; then
					echo "$_cidr"
				fi
			done
			# Extract IPv6 CIDRs from JSON
			echo "$raw_data" | grep -oE "$_v6_cidr_re" | tr -d '"' | while IFS= read -r _cidr; do
				if [[ "$_cidr" =~ $_valid_v6 ]]; then
					echo "$_cidr"
				fi
			done
			;;
	esac
	return 0
}

# ---------------------------------------------------------------------------
# _cdn_compile_db conf_file output_v4 output_v6 — build CDN lookup databases.
# Loads providers from config, fetches each, converts CIDRs to ranges,
# sorts, writes output. Per-provider failures are non-fatal.
# Database format (cdn.dat):  START_INT END_INT PROVIDER TREATMENT MULT
# Database format (cdn6.dat): START_HEX END_HEX PROVIDER TREATMENT MULT
# Both sorted by first field ascending.
# Args: conf_file — path to cdn-providers.conf
#       output_v4 — path to write IPv4 database
#       output_v6 — path to write IPv6 database
# Returns: 0 on success (even if some providers failed)
# ---------------------------------------------------------------------------
_cdn_compile_db() {
	local conf_file="$1" output_v4="$2" output_v6="$3"

	_CDN_BUILD_COUNT=0
	_CDN_BUILD_RANGES=0
	_CDN_BUILD_FAIL=0

	if ! _cdn_load_providers "$conf_file"; then
		return 1
	fi

	if [ "$_CDN_COUNT" -eq 0 ]; then
		_cdn_info "cdn: no providers configured"
		# Create empty database files
		: > "$output_v4"
		: > "$output_v6"
		return 0
	fi

	local _tmpdir
	_tmpdir=$(mktemp -d "${output_v4}.build-XXXXXX") || return 1

	local _v4_merged="$_tmpdir/v4.merged"
	local _v6_merged="$_tmpdir/v6.merged"
	: > "$_v4_merged"
	: > "$_v6_merged"

	local i _name _treatment _mult _format _url_v4 _url_v6
	for (( i=0; i<_CDN_COUNT; i++ )); do
		_name="${_CDN_NAMES[$i]}"
		_treatment="${_CDN_TREATMENTS[$i]}"
		_mult="${_CDN_MULTS[$i]}"
		_format="${_CDN_FORMATS[$i]}"
		_url_v4="${_CDN_URLS_V4[$i]}"
		_url_v6="${_CDN_URLS_V6[$i]}"

		_cdn_info "cdn: fetching provider '$_name'..."

		# Fetch IPv4 ranges
		local _cidrs_file="$_tmpdir/${_name}.cidrs"
		if _cdn_fetch_provider "$_name" "$_url_v4" "$_format" > "$_cidrs_file"; then
			if [ -s "$_cidrs_file" ]; then
				# Convert each CIDR to range and append provider metadata
				local _cidr _range
				while IFS= read -r _cidr; do
					[ -z "$_cidr" ] && continue
					if [[ "$_cidr" == *:* ]]; then
						# IPv6 CIDR in v4 feed — convert to v6 range
						_range=$(_cdn_cidr_to_range_v6 "$_cidr") || continue
						echo "$_range $_name $_treatment $_mult" >> "$_v6_merged"
					else
						_range=$(_cdn_cidr_to_range_v4 "$_cidr") || continue
						echo "$_range $_name $_treatment $_mult" >> "$_v4_merged"
					fi
					_CDN_BUILD_RANGES=$((_CDN_BUILD_RANGES + 1))
				done < "$_cidrs_file"
				_CDN_BUILD_COUNT=$((_CDN_BUILD_COUNT + 1))
			else
				_cdn_warn "cdn: no CIDRs extracted for provider '$_name' (v4)"
				_CDN_BUILD_FAIL=$((_CDN_BUILD_FAIL + 1))
			fi
		else
			_CDN_BUILD_FAIL=$((_CDN_BUILD_FAIL + 1))
		fi

		# Fetch IPv6 ranges (optional)
		if [ "$_url_v6" != "-" ] && [ -n "$_url_v6" ]; then
			local _cidrs6_file="$_tmpdir/${_name}.cidrs6"
			if _cdn_fetch_provider "$_name" "$_url_v6" "$_format" > "$_cidrs6_file"; then
				if [ -s "$_cidrs6_file" ]; then
					local _cidr6 _range6
					while IFS= read -r _cidr6; do
						[ -z "$_cidr6" ] && continue
						if [[ "$_cidr6" == *:* ]]; then
							_range6=$(_cdn_cidr_to_range_v6 "$_cidr6") || continue
							echo "$_range6 $_name $_treatment $_mult" >> "$_v6_merged"
							_CDN_BUILD_RANGES=$((_CDN_BUILD_RANGES + 1))
						fi
					done < "$_cidrs6_file"
				fi
			fi
		fi

		command rm -f "$_cidrs_file" "${_cidrs_file}6" 2>/dev/null || true  # temp files, safe to ignore
	done

	# Sort IPv4 by START_INT ascending (numeric)
	if [ -s "$_v4_merged" ]; then
		sort -n -k1 "$_v4_merged" > "$output_v4"
	else
		: > "$output_v4"
	fi

	# Sort IPv6 by START_HEX ascending (lexicographic = numeric for equal-length hex)
	if [ -s "$_v6_merged" ]; then
		sort -k1 "$_v6_merged" > "$output_v6"
	else
		: > "$output_v6"
	fi

	command rm -rf "$_tmpdir"
	return 0
}

# ---------------------------------------------------------------------------
# _cdn_lookup ip db_file — single IP binary-search lookup in CDN database.
# IPv4: integer comparison on "START_INT END_INT PROVIDER TREATMENT MULT"
# IPv6: hex-string comparison on "START_HEX END_HEX PROVIDER TREATMENT MULT"
# Args: ip — IPv4 or IPv6 address
#       db_file — cdn.dat (v4) or cdn6.dat (v6)
# Prints: "PROVIDER TREATMENT MULT" on match, empty on no match
# Returns: 0 on match, 1 on no match
# ---------------------------------------------------------------------------
_cdn_lookup() {
	local ip="$1" db_file="$2"

	[ -n "$ip" ] || return 1
	[ -n "$db_file" ] || return 1
	[ -f "$db_file" ] || return 1
	[ -s "$db_file" ] || return 1
	[[ -n "$CDN_AWK_BIN" ]] || { echo "_cdn_lookup: awk not available" >&2; return 1; }

	local result=""

	if [[ "$ip" == *:* ]]; then
		# IPv6 binary search on hex strings
		result=$("$CDN_AWK_BIN" -v ip="$ip" "${_CDN_V6_AWK}"'
		BEGIN {
			target = v6hex(ip)
			if (target == "") exit 1
		}
		NR == FNR {
			if (/^#/) next
			lo[++n] = $1; hi[n] = $2; prov[n] = $3; treat[n] = $4; mult[n] = $5
			next
		}
		END {
			l = 1; r = n; f = 0
			while (l <= r) {
				m = int((l + r) / 2)
				if (target < lo[m]) r = m - 1
				else if (target > hi[m]) l = m + 1
				else { f = m; break }
			}
			if (f > 0) printf "%s %s %s\n", prov[f], treat[f], mult[f]
		}' "$db_file" /dev/stdin <<< "")
	else
		# IPv4 binary search on integers
		result=$("$CDN_AWK_BIN" -v ip="$ip" '
		BEGIN {
			n = split(ip, p, ".")
			if (n != 4) exit 1
			target = (p[1]+0) * 16777216 + (p[2]+0) * 65536 + (p[3]+0) * 256 + (p[4]+0)
		}
		NR == FNR {
			if (/^#/) next
			lo[++n] = $1+0; hi[n] = $2+0; prov[n] = $3; treat[n] = $4; mult[n] = $5
			next
		}
		END {
			l = 1; r = n; f = 0
			while (l <= r) {
				m = int((l + r) / 2)
				if (target < lo[m]) r = m - 1
				else if (target > hi[m]) l = m + 1
				else { f = m; break }
			}
			if (f > 0) printf "%s %s %s\n", prov[f], treat[f], mult[f]
		}' "$db_file" /dev/stdin <<< "")
	fi

	if [ -n "$result" ]; then
		echo "$result"
		return 0
	fi
	return 1
}

# ---------------------------------------------------------------------------
# _batch_cdn_lookup db_file < ip_list — batch lookup for multiple IPs.
# Dual-stack: partitions IPv4/IPv6, runs separate binary-search awk passes.
# Same pattern as _batch_ip_to_country() in bfd_pressure.sh.
# Args: db_file — IPv4 CDN database (cdn.dat)
# Optional: db6_file derived as cdn6.dat from db_file path
# stdin: one IP per line
# Prints: "IP PROVIDER TREATMENT MULT" for each matching IP
# Non-matching IPs are NOT output.
# Returns: 0
# ---------------------------------------------------------------------------
_batch_cdn_lookup() {
	local db_file="$1"

	[ -n "$db_file" ] || return 0

	# Derive IPv6 db path from IPv4 db path (cdn.dat -> cdn6.dat)
	local db6_file="${db_file%.*}6.${db_file##*.}"
	local _have_v4=0 _have_v6=0
	[ -f "$db_file" ] && [ -s "$db_file" ] && _have_v4=1
	[ -f "$db6_file" ] && [ -s "$db6_file" ] && _have_v6=1

	if [ "$_have_v4" -eq 0 ] && [ "$_have_v6" -eq 0 ]; then
		# No databases — consume stdin, output nothing
		cat > /dev/null
		return 0
	fi

	local _tmpdir
	_tmpdir=$(mktemp -d "${db_file%/*}/.cdn-batch.XXXXXX" 2>/dev/null) || \
		_tmpdir=$(mktemp -d)  # fallback to /tmp if db_file dir not writable
	# shellcheck disable=SC2064
	trap "command rm -rf '$_tmpdir'" RETURN

	local _v4="$_tmpdir/v4" _v6="$_tmpdir/v6"

	# Split input: IPv4 to one file, IPv6 to another
	while IFS= read -r _ip; do
		[ -z "$_ip" ] && continue
		if [[ "$_ip" == *:* ]]; then
			echo "$_ip" >> "$_v6"
		else
			echo "$_ip" >> "$_v4"
		fi
	done

	# IPv4 batch: binary-search awk
	if [ "$_have_v4" -eq 1 ] && [ -f "$_v4" ]; then
		"$CDN_AWK_BIN" 'NR==FNR {
			if (/^#/) next
			lo[++n] = $1+0; hi[n] = $2+0; prov[n] = $3; treat[n] = $4; mult[n] = $5
			next
		}
		{
			split($0, p, ".")
			t = (p[1]+0) * 16777216 + (p[2]+0) * 65536 + (p[3]+0) * 256 + (p[4]+0)
			l = 1; r = n; f = 0
			while (l <= r) {
				m = int((l + r) / 2)
				if (t < lo[m]) r = m - 1
				else if (t > hi[m]) l = m + 1
				else { f = m; break }
			}
			if (f > 0) print $0, prov[f], treat[f], mult[f]
		}' "$db_file" "$_v4"
	fi

	# IPv6 batch: hex-range binary-search awk
	if [ "$_have_v6" -eq 1 ] && [ -f "$_v6" ]; then
		"$CDN_AWK_BIN" "${_CDN_V6_AWK}"'
		BEGIN {
			while ((getline line < db6) > 0) {
				if (line ~ /^#/) continue
				nn = split(line, f, " ")
				if (nn >= 5) { lo[++m] = f[1]; hi[m] = f[2]; prov[m] = f[3]; treat[m] = f[4]; mult[m] = f[5] }
			}
			close(db6)
		}
		{
			ip = $0
			hex = v6hex(ip)
			if (hex == "") next
			l = 1; r = m; found = 0
			while (l <= r) {
				mid = int((l + r) / 2)
				if (hex < lo[mid]) r = mid - 1
				else if (hex > hi[mid]) l = mid + 1
				else { found = mid; break }
			}
			if (found > 0) print ip, prov[found], treat[found], mult[found]
		}' db6="$db6_file" "$_v6"
	fi

	# trap RETURN handles cleanup; explicit rm as belt-and-suspenders
	command rm -rf "$_tmpdir"
}
