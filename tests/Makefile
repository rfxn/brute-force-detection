BATSMAN_OS_MODERN := debian12 rocky9 ubuntu2404
BATSMAN_OS_LEGACY := centos7 rocky8 ubuntu2004
BATSMAN_OS_DEEP   := centos6 ubuntu1204
BATSMAN_OS_EXTRA  := rocky10
BATSMAN_OS_ALL    := $(BATSMAN_OS_MODERN) $(BATSMAN_OS_LEGACY) $(BATSMAN_OS_DEEP) $(BATSMAN_OS_EXTRA)
BATSMAN_RUN_TESTS := ./run-tests.sh
BATSMAN_PROJECT   := bfd
BATSMAN_TEST_TIMEOUT ?= 120

include infra/include/Makefile.tests

# UAT override: --init reaps orphaned background processes (watch mode tests),
# --stop-timeout 3 ensures fast container shutdown when background bfd processes
# linger after bats exits.
uat:
	BATSMAN_DOCKER_FLAGS="--init --stop-timeout 3" \
	  BATSMAN_TEST_TIMEOUT=$(BATSMAN_TEST_TIMEOUT) \
	  $(BATSMAN_RUN_TESTS) -- $(BATSMAN_UAT_PATH)

# Performance benchmarks: run only the benchmark test file.
# Output includes KPI diagnostics in TAP format.
.PHONY: bench
bench:
	$(BATSMAN_RUN_TESTS) -- /opt/tests/45-perf-benchmark.bats
