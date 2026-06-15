#!/usr/bin/env bash
#
# endesive/mayhem/build.sh — build the ELF launcher shims for the Atheris fuzz harness and the
# test-oracle runner. endesive (m32/endesive) is a PURE-PYTHON library; the Python dependencies
# (atheris, the package itself + its native deps cryptography/pykcs11/lxml/Pillow, and the test
# extras) are installed into the image's system Python by the Dockerfile — that step needs the
# network and root, which this script (re-run OFFLINE as the non-root `mayhem` user at the PATCH
# tier) MUST NOT require. This script only compiles the tiny C launcher shims (see
# mayhem/launcher.c), so it is idempotent and fully air-gapped (clang only, no network, no pip).
#
# Mayhem requires the target `cmd:` to be an ELF, not a `.py`; each shim exec()s
# `python3 <script>` and forwards argv (the libFuzzer/Atheris flags), so the Python process
# becomes the libFuzzer target. The oracle runner is compiled the same way so the verify-repo
# sabotage check can neuter it (see mayhem/test.sh).
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

SRC="${SRC:-/mayhem}"
cd "$SRC"

: "${CC:=clang}"

# $DEBUG_FLAGS threads DWARF < 4 debug info onto the shims (SPEC §6.2 item 10): clang-19's plain
# `-g` emits DWARF-5, which Mayhem's triage can't read, so force DWARF-3 explicitly.
: "${DEBUG_FLAGS:=-gdwarf-3}"

# The base exports $SANITIZER_FLAGS (ASan+UBSan, halting) for projects with compiled code;
# endesive has none of its own, and the shims are pure exec() wrappers (instrumenting them would
# only add noise on the wrapper itself, never on the fuzzed Python). The real fuzzed code runs
# under Atheris/libFuzzer at runtime. Referenced here for parity / so an override is visible.
echo "SANITIZER_FLAGS=${SANITIZER_FLAGS:-<unset>} (pure-Python project; not applied to the exec shims)"
echo "DEBUG_FLAGS=$DEBUG_FLAGS"

build_launcher() {
  local out="$1" script="$2"
  echo "--- compiling launcher /mayhem/$out -> $script ---"
  # Dynamically linked (default) so the verify-repo sabotage oracle's LD_PRELOAD can reach it.
  "$CC" $DEBUG_FLAGS -O1 -DPY_SCRIPT="\"$script\"" -o "/mayhem/$out" mayhem/launcher.c
  chmod +x "/mayhem/$out"
}

# Fuzz target: the Atheris harness that drives endesive.pdf.verify() on attacker-controlled PDFs.
build_launcher endesive-fuzz /mayhem/mayhem/fuzz_verify.py
# Test oracle runner: runs endesive's real unittest suite (driven by mayhem/test.sh through this
# ELF so the sabotage check can neuter it).
build_launcher endesive-tests /mayhem/mayhem/run_tests.py

echo "build.sh complete:"
ls -la /mayhem/endesive-fuzz /mayhem/endesive-tests
