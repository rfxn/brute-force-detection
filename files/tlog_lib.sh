#!/bin/bash
# tlog_lib.sh — shared library for incremental log file reading
# Provides multi-mode tracking (byte-offset and line-count), rotation-aware
# delta reads, systemd journal fallback, and atomic cursor writes.
# Consumed by BFD and LMD via source inclusion.
#
# Copyright (C) 2002-2026 R-fx Networks <proj@rfxn.com>
#                         Ryan MacDonald <ryan@rfxn.com>
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

# Source guard — prevent double-sourcing
[[ -n "${_TLOG_LIB_LOADED:-}" ]] && return 0 2>/dev/null
_TLOG_LIB_LOADED=1

# shellcheck disable=SC2034
TLOG_LIB_VERSION="2.0.1"

# Journal filter registry — consuming projects populate via tlog_journal_register()
# Uses parallel indexed arrays instead of declare -A to avoid scope issues
# when sourced from inside a function (e.g., BATS load, wrapper functions).
# Simple array assignment creates globals; declare -A creates locals in functions.
_TLOG_JOURNAL_NAMES=()
_TLOG_JOURNAL_FILTERS=()

###########################################################################
# Internal helpers
###########################################################################

# _tlog_parse_cursor(tlog_name, baserun)
# Read and validate cursor file. Sets _tlog_cursor_value and
# _tlog_cursor_mode for the caller. Returns 0 on success/first-run,
# 2 on corrupt cursor (auto-reset).
_tlog_parse_cursor() {
	local tlog_name="$1" baserun="$2"
	local cursor_file="$baserun/$tlog_name"
	local raw_value=""
	local numeric_pat='^[0-9]+$'

	# shellcheck disable=SC2034
	_tlog_cursor_value=""
	# shellcheck disable=SC2034
	_tlog_cursor_mode=""

	# No cursor file → first run
	if [[ ! -f "$cursor_file" ]]; then
		return 0
	fi

	read -r raw_value < "$cursor_file" 2>/dev/null || true

	# Empty content → first run
	if [[ -z "$raw_value" ]]; then
		return 0
	fi

	# Detect mode from prefix
	if [[ "$raw_value" == L:* ]]; then
		# shellcheck disable=SC2034
		_tlog_cursor_mode="lines"
		# shellcheck disable=SC2034
		_tlog_cursor_value="${raw_value#L:}"
	else
		# shellcheck disable=SC2034
		_tlog_cursor_mode="bytes"
		# shellcheck disable=SC2034
		_tlog_cursor_value="$raw_value"
	fi

	# Validate numeric
	if [[ ! "$_tlog_cursor_value" =~ $numeric_pat ]]; then
		echo "tlog: corrupt cursor $cursor_file: '$raw_value'" >&2
		# shellcheck disable=SC2034
		_tlog_cursor_value=""
		# shellcheck disable=SC2034
		_tlog_cursor_mode=""
		return 2
	fi

	return 0
}

# _tlog_write_cursor(tlog_name, baserun, value, mode)
# Atomic cursor write via mktemp + mv -f.
# Mode dispatch: lines → L:N, bytes → bare N, raw → verbatim.
_tlog_write_cursor() {
	local tlog_name="$1" baserun="$2" value="$3" mode="$4"
	local cursor_file="$baserun/$tlog_name"
	local tmp_file formatted

	case "$mode" in
		lines) formatted="L:${value}" ;;
		raw)   formatted="$value" ;;
		*)     formatted="$value" ;;
	esac

	tmp_file=$(mktemp "$baserun/.${tlog_name}.XXXXXX") || return 1
	printf '%s\n' "$formatted" > "$tmp_file"

	if ! mv -f "$tmp_file" "$cursor_file"; then
		rm -f "$tmp_file"
		return 1
	fi

	return 0
}

# _tlog_get_size(file, mode)
# Dispatch: bytes → stat -c %s (fallback wc -c), lines → wc -l.
# Outputs size on stdout.
_tlog_get_size() {
	local file="$1" mode="$2"
	local size

	case "$mode" in
		lines)
			size=$(wc -l < "$file")
			size="${size## }"
			;;
		*)
			size=$(stat -c %s "$file" 2>/dev/null) || size=$(wc -c < "$file")
			size="${size## }"
			;;
	esac

	printf '%s' "$size"
}

# _tlog_output_content(file, delta, mode)
# Dispatch: bytes → tail -c, lines → tail -n.
# Guards delta <= 0 (prevents undefined tail behavior).
_tlog_output_content() {
	local file="$1" delta="$2" mode="$3"

	if [[ "$delta" -le 0 ]]; then
		return 0
	fi

	case "$mode" in
		lines) tail -n "$delta" "$file" ;;
		*)     tail -c "$delta" "$file" ;;
	esac
}

# _tlog_is_compressed(file)
# Returns 0 if file has a known compressed extension.
# Pure case match — no I/O.
_tlog_is_compressed() {
	case "$1" in
		*.gz|*.xz|*.bz2|*.zst|*.lz4) return 0 ;;
		*) return 1 ;;
	esac
}

# _tlog_cat_file(file)
# Stream decompressed content to stdout via TOOL -dc pattern.
# Falls back to cat for uncompressed files.
_tlog_cat_file() {
	local file="$1"
	case "$file" in
		*.gz)  gzip -dc "$file" ;;
		*.xz)  xz -dc "$file" ;;
		*.bz2) bzip2 -dc "$file" ;;
		*.zst) zstd -dc "$file" 2>/dev/null ;;
		*.lz4) lz4 -dc "$file" 2>/dev/null ;;
		*)     cat "$file" ;;
	esac
}

# _tlog_find_rotated(file)
# Locate rotated log file in priority order: uncompressed .1 first,
# then compressed variants (.gz, .xz, .bz2, .zst, .lz4).
# Compressed variants only returned if the decompression tool is available.
# Outputs path on stdout, returns 1 if not found.
_tlog_find_rotated() {
	local file="$1"
	local ext tool

	# Uncompressed — always preferred, no tool needed
	if [[ -f "${file}.1" ]]; then
		printf '%s' "${file}.1"
		return 0
	fi

	# Compressed variants — check tool availability before returning
	for ext in gz xz bz2 zst lz4; do
		if [[ -f "${file}.1.${ext}" ]]; then
			case "$ext" in
				gz)  tool="gzip" ;;
				xz)  tool="xz" ;;
				bz2) tool="bzip2" ;;
				zst) tool="zstd" ;;
				lz4) tool="lz4" ;;
			esac
			if command -v "$tool" >/dev/null 2>&1; then
				printf '%s' "${file}.1.${ext}"
				return 0
			fi
		fi
	done

	return 1
}

###########################################################################
# Public utility functions
###########################################################################

# tlog_get_file_size(file)
# Byte size via stat -c %s, fallback wc -c. Outputs on stdout.
tlog_get_file_size() {
	local file="$1" size

	if [[ ! -f "$file" ]]; then
		return 1
	fi

	size=$(stat -c %s "$file" 2>/dev/null) || size=$(wc -c < "$file")
	size="${size## }"
	printf '%s' "$size"
}

# tlog_get_line_count(file)
# Line count via wc -l. Outputs on stdout.
tlog_get_line_count() {
	local file="$1" count

	if [[ ! -f "$file" ]]; then
		return 1
	fi

	count=$(wc -l < "$file")
	count="${count## }"
	printf '%s' "$count"
}

###########################################################################
# Core API
###########################################################################

# tlog_read(file, tlog_name, baserun [, mode])
# Core delta reader with mode-selectable tracking.
# Mode resolution: explicit arg > TLOG_MODE env > bytes default.
# Returns: 0=success, 1=file/path error, 2=cursor corrupt (auto-reset),
#          3=journal unavailable, 4=lock acquisition failed.
tlog_read() {
	local file="$1" tlog_name="$2" baserun="$3"
	local mode="${4:-${TLOG_MODE:-bytes}}"
	local newsize delta size rtfile rtsize _tlog_fd
	local cursor_corrupt=0 rc=0
	local stored_mode parse_rc rt_delta

	# Mode validation — reject typos before any I/O
	if [[ "$mode" != "bytes" ]] && [[ "$mode" != "lines" ]]; then
		echo "tlog: invalid mode '$mode' (must be 'bytes' or 'lines')" >&2
		return 1
	fi

	# Journal dispatch: file missing and journal not disabled
	if [[ ! -f "$file" ]] && [[ "${LOG_SOURCE}" != "file" ]]; then
		tlog_journal_read "$tlog_name" "$baserun"
		return $?
	fi

	# Validation
	if [[ ! -f "$file" ]]; then
		echo "tlog: file not found: $file" >&2
		return 1
	fi

	if [[ ! -d "$baserun" ]]; then
		echo "tlog: baserun directory not found: $baserun" >&2
		return 1
	fi

	# Optional flock
	if [[ "${TLOG_FLOCK:-0}" == "1" ]]; then
		exec {_tlog_fd}>"$baserun/${tlog_name}.lock"
		if ! flock -x -w 5 "$_tlog_fd"; then
			exec {_tlog_fd}>&-
			return 4
		fi
	fi

	# Parse cursor
	_tlog_parse_cursor "$tlog_name" "$baserun"
	parse_rc=$?
	if [[ $parse_rc -eq 2 ]]; then
		cursor_corrupt=1
	fi

	size="${_tlog_cursor_value}"
	stored_mode="${_tlog_cursor_mode}"

	# Mode mismatch → reset
	if [[ -n "$stored_mode" ]] && [[ "$stored_mode" != "$mode" ]]; then
		echo "tlog: mode mismatch for $tlog_name: stored=$stored_mode requested=$mode, resetting" >&2
		size=""
		cursor_corrupt=1
	fi

	# Get current size
	newsize=$(_tlog_get_size "$file" "$mode")

	# First run (no cursor or corrupt)
	if [[ -z "$size" ]]; then
		_tlog_write_cursor "$tlog_name" "$baserun" "$newsize" "$mode"

		if [[ "${TLOG_FIRST_RUN:-skip}" == "full" ]] && [[ "$newsize" -gt 0 ]]; then
			_tlog_output_content "$file" "$newsize" "$mode"
		fi

		if [[ $cursor_corrupt -eq 1 ]]; then
			rc=2
		fi

	# Growth: newsize > size
	elif [[ "$newsize" -gt "$size" ]]; then
		delta=$((newsize - size))
		_tlog_output_content "$file" "$delta" "$mode"
		_tlog_write_cursor "$tlog_name" "$baserun" "$newsize" "$mode"

	# Rotation: newsize < size
	elif [[ "$newsize" -lt "$size" ]]; then
		rtfile=$(_tlog_find_rotated "$file") || true
		if [[ -n "$rtfile" ]]; then
			# Get rotated file size in correct mode
			if _tlog_is_compressed "$rtfile"; then
				if [[ "$mode" == "lines" ]]; then
					rtsize=$(_tlog_cat_file "$rtfile" | wc -l)
				else
					rtsize=$(_tlog_cat_file "$rtfile" | wc -c)
				fi
				rtsize="${rtsize## }"
			else
				rtsize=$(_tlog_get_size "$rtfile" "$mode")
			fi

			# Bounds check: only output if rotated file covers our cursor
			if [[ "$rtsize" -ge "$size" ]]; then
				rt_delta=$((rtsize - size))
				if [[ "$rt_delta" -gt 0 ]]; then
					if _tlog_is_compressed "$rtfile"; then
						if [[ "$mode" == "lines" ]]; then
							_tlog_cat_file "$rtfile" | tail -n "$rt_delta"
						else
							_tlog_cat_file "$rtfile" | tail -c "$rt_delta"
						fi
					else
						_tlog_output_content "$rtfile" "$rt_delta" "$mode"
					fi
				fi
			fi
		fi

		# Output current file content if any
		if [[ "$newsize" -gt 0 ]]; then
			_tlog_output_content "$file" "$newsize" "$mode"
		fi

		_tlog_write_cursor "$tlog_name" "$baserun" "$newsize" "$mode"
	fi
	# No change (newsize == size): no output, no cursor write

	# Stale protection — update cursor mtime on every call
	touch "$baserun/$tlog_name"

	# Release lock
	if [[ "${TLOG_FLOCK:-0}" == "1" ]]; then
		exec {_tlog_fd}>&-
	fi

	return $rc
}

# tlog_read_full(file, max_lines)
# Full file read without cursor tracking (scan mode).
# max_lines > 0 → tail -n, else cat.
tlog_read_full() {
	local file="$1" max_lines="${2:-0}"

	if [[ ! -f "$file" ]]; then
		return 1
	fi

	if [[ "$max_lines" -gt 0 ]]; then
		tail -n "$max_lines" "$file"
	else
		cat "$file"
	fi

	return 0
}

# tlog_adjust_cursor(tlog_name, baserun, delta_removed)
# Mode-aware cursor subtraction for log trim operations.
# Detects mode from stored cursor. Clamps to 0.
tlog_adjust_cursor() {
	local tlog_name="$1" baserun="$2" delta_removed="$3"
	local numeric_pat='^[0-9]+$'
	local new_value mode

	# Validate delta is numeric
	if [[ ! "$delta_removed" =~ $numeric_pat ]]; then
		echo "tlog: invalid delta: $delta_removed" >&2
		return 1
	fi

	# Parse current cursor
	_tlog_parse_cursor "$tlog_name" "$baserun"
	if [[ -z "$_tlog_cursor_value" ]]; then
		return 0
	fi

	mode="${_tlog_cursor_mode:-bytes}"

	# Subtract and clamp to 0
	new_value=$((_tlog_cursor_value - delta_removed))
	if [[ "$new_value" -lt 0 ]]; then
		new_value=0
	fi

	_tlog_write_cursor "$tlog_name" "$baserun" "$new_value" "$mode"
}

# tlog_advance_cursors(baserun, log_pairs)
# Fast-forward cursors for multiple files. Processes FILE|TAG pairs
# (newline-separated). For existing files, records current size.
# For journal-capable tags, captures journal cursor position.
tlog_advance_cursors() {
	local baserun="$1" log_pairs="$2"
	local file tag newsize cursor_line
	local mode="${TLOG_MODE:-bytes}"

	while IFS='|' read -r file tag; do
		[[ -z "$tag" ]] && continue

		if [[ -f "$file" ]]; then
			# File cursor: record current size
			newsize=$(_tlog_get_size "$file" "$mode")
			_tlog_write_cursor "$tag" "$baserun" "$newsize" "$mode"
		elif command -v journalctl >/dev/null 2>&1 && tlog_journal_filter "$tag" >/dev/null 2>&1; then
			# Journal cursor: capture current position
			cursor_line=$(journalctl -n 0 --show-cursor 2>/dev/null | grep -E '^-- cursor:' | sed 's/^-- cursor: //')
			if [[ -n "$cursor_line" ]]; then
				_tlog_write_cursor "$tag" "$baserun" "$cursor_line" "raw"
				_tlog_write_cursor "${tag}.jts" "$baserun" "$(date +%s)" "raw"
			fi
		fi
	done <<< "$log_pairs"

	return 0
}

###########################################################################
# Journal functions
###########################################################################

# tlog_journal_register(tlog_name, jfilter)
# Register a service-to-journalctl filter mapping. Consuming projects
# call this after sourcing tlog_lib.sh to define their service mappings.
tlog_journal_register() {
	_TLOG_JOURNAL_NAMES+=("$1")
	_TLOG_JOURNAL_FILTERS+=("$2")
}

# tlog_journal_filter(tlog_name)
# Look up journalctl filter string for a service tag.
# Returns filter on stdout, exit 1 for unknown/unregistered service.
tlog_journal_filter() {
	local tlog_name="$1"
	local i
	for i in "${!_TLOG_JOURNAL_NAMES[@]}"; do
		if [[ "${_TLOG_JOURNAL_NAMES[$i]}" == "$tlog_name" ]]; then
			printf '%s' "${_TLOG_JOURNAL_FILTERS[$i]}"
			return 0
		fi
	done
	return 1
}

# tlog_journal_read(tlog_name, baserun)
# Cursor-based journal reader with timestamp fallback.
# First run: capture cursor, output nothing.
# Returns: 0=success, 1=unknown service, 3=journal unavailable.
tlog_journal_read() {
	local tlog_name="$1" baserun="$2"
	local cursor_file="$baserun/$tlog_name"
	local jts_file="$baserun/${tlog_name}.jts"
	local jfilter stored_cursor stored_jts new_cursor new_jts
	local output_data

	# Check journalctl available
	if ! command -v journalctl >/dev/null 2>&1; then
		return 3
	fi

	# Get filter for this service
	jfilter=$(tlog_journal_filter "$tlog_name") || return 1

	# Read stored cursor
	stored_cursor=""
	if [[ -f "$cursor_file" ]]; then
		read -r stored_cursor < "$cursor_file" 2>/dev/null || true
	fi

	# Read stored journal timestamp
	stored_jts=""
	if [[ -f "$jts_file" ]]; then
		read -r stored_jts < "$jts_file" 2>/dev/null || true
	fi

	# First run: capture position, output nothing
	if [[ -z "$stored_cursor" ]] && [[ -z "$stored_jts" ]]; then
		# shellcheck disable=SC2086
		new_cursor=$(journalctl $jfilter -n 0 --show-cursor 2>/dev/null | grep -E '^-- cursor:' | sed 's/^-- cursor: //')
		new_jts=$(date +%s)

		if [[ -n "$new_cursor" ]]; then
			_tlog_write_cursor "$tlog_name" "$baserun" "$new_cursor" "raw"
		fi
		_tlog_write_cursor "${tlog_name}.jts" "$baserun" "$new_jts" "raw"

		touch "$baserun/$tlog_name"
		return 0
	fi

	# Subsequent run: try cursor first, fallback to timestamp
	if [[ -n "$stored_cursor" ]]; then
		# shellcheck disable=SC2086
		if ! output_data=$(journalctl $jfilter --after-cursor="$stored_cursor" --no-pager 2>/dev/null); then
			if [[ -n "$stored_jts" ]]; then
				# shellcheck disable=SC2086
				output_data=$(journalctl $jfilter --since="@${stored_jts}" --no-pager 2>/dev/null) || true
			fi
		fi
	elif [[ -n "$stored_jts" ]]; then
		# shellcheck disable=SC2086
		output_data=$(journalctl $jfilter --since="@${stored_jts}" --no-pager 2>/dev/null) || true
	fi

	# Output if any data
	if [[ -n "$output_data" ]]; then
		printf '%s\n' "$output_data"
	fi

	# Capture new cursor + timestamp
	# shellcheck disable=SC2086
	new_cursor=$(journalctl $jfilter -n 0 --show-cursor 2>/dev/null | grep -E '^-- cursor:' | sed 's/^-- cursor: //')
	new_jts=$(date +%s)

	if [[ -n "$new_cursor" ]]; then
		_tlog_write_cursor "$tlog_name" "$baserun" "$new_cursor" "raw"
	fi
	_tlog_write_cursor "${tlog_name}.jts" "$baserun" "$new_jts" "raw"

	# Stale protection
	touch "$baserun/$tlog_name"

	return 0
}

# tlog_journal_read_full(tlog_name, scan_timeout, max_lines)
# Full journal read without cursor tracking.
# Returns: 0=success, 1=unknown service, 3=journal unavailable.
tlog_journal_read_full() {
	local tlog_name="$1"
	local scan_timeout="${2:-${SCAN_TIMEOUT:-0}}"
	local max_lines="${3:-${SCAN_MAX_LINES:-0}}"
	local jfilter
	local cmd_args=()

	# Check journalctl available
	if ! command -v journalctl >/dev/null 2>&1; then
		return 3
	fi

	# Get filter for this service
	jfilter=$(tlog_journal_filter "$tlog_name") || return 1

	if [[ "$max_lines" -gt 0 ]]; then
		cmd_args+=(-n "$max_lines")
	fi
	cmd_args+=(--no-pager)

	if [[ "$scan_timeout" -gt 0 ]] && command -v timeout >/dev/null 2>&1; then
		# shellcheck disable=SC2086
		timeout "$scan_timeout" journalctl $jfilter "${cmd_args[@]}" 2>/dev/null
	else
		# shellcheck disable=SC2086
		journalctl $jfilter "${cmd_args[@]}" 2>/dev/null
	fi

	return 0
}
