#!/usr/bin/env bash
#
# endesive/mayhem/test.sh — RUN endesive's own unittest known-answer suite and emit a CTRF
# summary. exit 0 iff no test failed.
#
# PATCH-grade behavioral oracle: tests/test_cert.py, test_pdf.py, test_email.py and test_plain.py
# are known-answer cases — they sign fixture PDFs/emails/blobs and assert that
# endesive.pdf/email/plain verify() returns the expected (hashok, signatureok, certok) tuples, and
# assert cert/PKCS#12 structure. A no-op / "exit(0)" / behavior-altering patch to endesive cannot
# pass them.
#
# The suite is run through the `/mayhem/endesive-tests` ELF launcher (which exec()s
# `python3 mayhem/run_tests.py`), NOT python directly. That matters for the verify-repo §6.3
# anti-reward-hack check: it LD_PRELOADs a constructor that _exit(0)s every NON-system
# executable. The system `python3` under /usr/bin is SPARED, but `/mayhem/endesive-tests` is not —
# so under sabotage the launcher exits before the tests run, no RUNTESTS line is produced, and this
# script reports a failure. The normal run is unaffected.
#
# This script only RUNS the suite (build.sh compiled the launcher); it never compiles.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

SRC="${SRC:-/mayhem}"
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

if [ ! -x /mayhem/endesive-tests ]; then
  echo "FATAL: /mayhem/endesive-tests launcher missing — run mayhem/build.sh first" >&2
  emit_ctrf "unittest" 0 1 0
  exit 2
fi

echo "=== running endesive known-answer unittest suite via /mayhem/endesive-tests ==="
out="$(/mayhem/endesive-tests 2>&1)"; rc=$?
echo "$out"

line="$(printf '%s\n' "$out" | sed -n 's/^RUNTESTS //p' | head -1)"
if [ -z "$line" ]; then
  # No summary line: the suite did not run (e.g. neutered launcher under the sabotage oracle,
  # an import error, or a crash). That is a FAILURE — do not pass vacuously.
  echo "no RUNTESTS summary line from the test runner (rc=$rc)" >&2
  emit_ctrf "unittest" 0 1 0
  exit 1
fi

# line looks like: tests=N passed=P failed=F skipped=S
TESTS=$(echo "$line"   | sed -n 's/.*tests=\([0-9][0-9]*\).*/\1/p')
PASSED=$(echo "$line"  | sed -n 's/.*passed=\([0-9][0-9]*\).*/\1/p')
FAILED=$(echo "$line"  | sed -n 's/.*failed=\([0-9][0-9]*\).*/\1/p')
SKIPPED=$(echo "$line" | sed -n 's/.*skipped=\([0-9][0-9]*\).*/\1/p')
: "${TESTS:=0}" "${PASSED:=0}" "${FAILED:=0}" "${SKIPPED:=0}"

# Guard against a parsed-but-empty suite.
if [ "$TESTS" -eq 0 ]; then
  echo "test runner reported 0 tests collected" >&2
  emit_ctrf "unittest" 0 1 0
  exit 1
fi

emit_ctrf "unittest" "$PASSED" "$FAILED" "$SKIPPED"
