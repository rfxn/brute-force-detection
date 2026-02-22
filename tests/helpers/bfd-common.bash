#!/bin/bash
#
# Common BFD test setup for BATS
# Load in .bats files with: load 'helpers/bfd-common'
#

PROJECT_ROOT="$(cd "${BATS_TEST_DIRNAME}/.." && pwd)"
export PROJECT_ROOT

# Source the BFD function library
# shellcheck disable=SC1091
source "${PROJECT_ROOT}/files/bfd.lib.sh"
