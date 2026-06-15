# syntax=docker/dockerfile:1.7
#
# Commit-image Dockerfile (SMALL form) — builds ON TOP of the org base image
# (ghcr.io/mayhemheroes/base). The base provides debian + clang/llvm + libFuzzer + Python 3 + the
# identities + the build-contract ENV. endesive is a PURE-PYTHON library (digital signing /
# verification of PDF, email and XML). Its runtime deps include native wheels (cryptography, lxml,
# Pillow) and a swig C++ extension (pykcs11), so this image apt-installs the toolchain those need,
# then pip-installs the Atheris harness engine + endesive + its test extras into the base's system
# Python as root. build.sh (run as the non-root `mayhem` user) then only compiles the ELF launcher
# shims and test.sh runs the real known-answer suite — neither needs the network, so the PATCH-tier
# offline re-run of build.sh stays air-gapped.
#
# Build (from the repo root):
#   DOCKER_BUILDKIT=1 docker build -f mayhem/Dockerfile \
#       --build-arg COMMIT=$(git rev-parse HEAD) \
#       [--build-arg SOURCE_DATE_EPOCH=$(date +%s)] \
#       -t endesive-commit:test .

FROM ghcr.io/mayhemheroes/base:20260621

ARG COMMIT
ARG REPO_URL
# SOURCE_DATE_EPOCH stays an ARG (available to build.sh); never bake it as ENV — an empty value
# breaks clang. build.sh unsets it when empty.
ARG SOURCE_DATE_EPOCH
# Declared for parity with the build contract; endesive has no native code of its own to sanitize.
ARG SANITIZER_FLAGS

# Native build deps for endesive's dependency wheels/extensions: swig + libpcsclite-dev (pykcs11),
# libssl-dev (crypto bits), fonts-dejavu (PDF signature-appearance rendering in the tests).
USER root
RUN apt-get update && apt-get install -yq --no-install-recommends \
      python3-dev python3-venv python-is-python3 \
      build-essential swig libpcsclite-dev libssl-dev \
      fonts-dejavu-core fonts-dejavu-extra \
    && rm -rf /var/lib/apt/lists/*

# Atheris (the libFuzzer harness engine — builds a native module against the base's clang/libFuzzer)
# plus the test extra `attrs` (used by endesive's PDF signature-appearance code the suite exercises)
# go into the base's SYSTEM Python. PEP 668 marks that interpreter externally-managed, so
# --break-system-packages. This is the (networked) install step; build.sh deliberately does NOT
# pip-install, so its offline PATCH-tier re-run stays air-gapped. Atheris is pinned for a
# reproducible engine.
RUN pip install --no-cache-dir --break-system-packages atheris==3.1.0 attrs

# Source enters from the build CONTEXT (the CI checkout): the FULL repo (incl. .git history) is
# copied to /mayhem; build.sh builds in place.
WORKDIR /mayhem
COPY --chown=2000:2000 . /mayhem

# Install endesive itself (+ its runtime deps: cryptography, asn1crypto, lxml, pykcs11, Pillow,
# requests, paramiko) into the system Python so the harness/oracle can `import endesive`.
# endesive uses setuptools flat-layout autodiscovery, which hard-errors when it sees TWO top-level
# package dirs (our additive `mayhem/` next to upstream `endesive/`): "Multiple top-level packages
# discovered in a flat-layout". Install from a pruned copy that drops `mayhem/`+`.git` (tests/docs/
# examples are already auto-excluded by setuptools), so autodiscovery sees only `endesive` — we
# never touch upstream's pyproject.toml (port stays additive).
RUN cp -a /mayhem /tmp/endesive-src \
    && rm -rf /tmp/endesive-src/mayhem /tmp/endesive-src/.git \
    && pip install --no-cache-dir --break-system-packages /tmp/endesive-src \
    && rm -rf /tmp/endesive-src

USER mayhem

# Compile the ELF launcher shims (Mayhem needs an ELF target, not a .py).
RUN bash mayhem/build.sh

# Run endesive's real known-answer unittest suite at build time; a failing suite fails the build.
RUN if [ -f mayhem/test.sh ]; then bash mayhem/test.sh; else echo "no mayhem/test.sh"; fi

LABEL org.opencontainers.image.source="${REPO_URL}" \
      org.opencontainers.image.revision="${COMMIT}" \
      rlenv.tier="commit" \
      rlenv.source_date_epoch="${SOURCE_DATE_EPOCH}" \
      rlenv.user="mayhem"

USER mayhem
WORKDIR /mayhem
