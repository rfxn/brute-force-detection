#!/usr/bin/env bats
#
# Test suite for format_table()
#

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load 'helpers/bfd-common'

@test "format_table: pipe delimiters removed from output" {
	local out
	out=$(echo "col1|col2|col3" | format_table)
	[[ "$out" != *"|"* ]]
}

@test "format_table: output preserves all field values" {
	local out
	out=$(echo "col1|col2|col3" | format_table)
	[[ "$out" == *"col1"* ]]
	[[ "$out" == *"col2"* ]]
	[[ "$out" == *"col3"* ]]
}

@test "format_table: multi-line input produces multi-line output" {
	local out
	out=$(printf "a|b|c\nd|e|f\n" | format_table)
	local line_count
	line_count=$(echo "$out" | wc -l)
	[ "$line_count" -eq 2 ]
}

@test "format_table: single field unchanged" {
	local out
	out=$(echo "nopipes" | format_table)
	[ "$out" = "nopipes" ]
}

@test "format_table: empty input produces empty output" {
	local out
	out=$(echo "" | format_table)
	[ "$out" = "" ]
}

@test "format_table: header and data fields preserved" {
	local out
	out=$(printf "NAME|COUNT|STATUS\nalpha|42|active\n" | format_table)
	[[ "$out" == *"NAME"* ]]
	[[ "$out" == *"alpha"* ]]
	[[ "$out" == *"42"* ]]
}
