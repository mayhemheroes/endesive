#!/usr/bin/python3
"""run_tests.py — RUN endesive's own unittest suite and print a parseable summary.

Invoked via the `/mayhem/endesive-tests` ELF launcher (NOT directly), so the verify-repo §6.3
sabotage oracle can neuter the launcher and prove the test oracle is behavioral.

It runs the real known-answer suite shipped in tests/:
  * test_cert  — builds CA/leaf certs + PKCS#12 bundles and asserts their structure,
  * test_pdf   — signs endesive/PyPDF2 fixture PDFs with pdf.cms.sign() and asserts that
                 endesive.pdf.verify() returns (hashok, signatureok, certok) == (True, True, ...),
  * test_email — S/MIME sign + verify round-trips,
  * test_plain — detached CMS sign + verify round-trips.

test_hsm is intentionally excluded (needs a live SoftHSM2/PKCS#11 token — no smartcard/HSM in CI).

It prints exactly one machine-readable line:
    RUNTESTS tests=<n> passed=<p> failed=<f> skipped=<s>
Exit 0 iff failed == 0. mayhem/test.sh parses that line into a CTRF report.

We drive unittest (NOT pytest) on purpose: endesive's pyproject sets `filterwarnings = ["error"]`,
which would turn every benign cryptography DeprecationWarning into a spurious failure under pytest.
The suite modules import one another by bare name (`import test_cert`) and read CWD-relative
fixtures, so we chdir into tests/ and put it on sys.path first.
"""
from __future__ import annotations

import os
import sys
import unittest

SRC = os.environ.get("SRC", "/mayhem")
TESTS_DIR = os.path.join(SRC, "tests")
MODULES = ["test_cert", "test_pdf", "test_email", "test_plain"]


def main() -> int:
    os.chdir(TESTS_DIR)
    if TESTS_DIR not in sys.path:
        sys.path.insert(0, TESTS_DIR)

    loader = unittest.TestLoader()
    try:
        suite = loader.loadTestsFromNames(MODULES)
    except Exception as exc:  # collection/import error is a hard failure, not a vacuous pass
        print(f"collection error: {exc}", file=sys.stderr)
        print("RUNTESTS tests=0 passed=0 failed=1 skipped=0")
        return 1

    runner = unittest.TextTestRunner(verbosity=1, stream=sys.stderr)
    result = runner.run(suite)

    failed = len(result.failures) + len(result.errors)
    skipped = len(result.skipped)
    tests = result.testsRun
    passed = tests - failed - skipped

    if tests == 0:
        print("RUNTESTS tests=0 passed=0 failed=1 skipped=0")
        return 1

    print(f"RUNTESTS tests={tests} passed={passed} failed={failed} skipped={skipped}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
