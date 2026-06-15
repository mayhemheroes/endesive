#!/usr/bin/env python3
"""Atheris harness for endesive's PDF signature verifier.

Drives endesive.pdf.verify(pdfdata) -- the honest successor of the old
mayhemheroes `endesive-fuzz` target. It parses an attacker-controlled PDF
document: locates the /ByteRange, slices out the embedded PKCS#7/CMS blob,
hex-decodes it, parses it with asn1crypto, hashes the signed range and runs
the cryptography x509 verifier. A failed verification that returns
(hashok, signatureok, certok) tuples is NORMAL output, not a crash.
"""
import sys

import atheris

with atheris.instrument_imports(include=["endesive"]):
    from endesive import pdf

from cryptography import exceptions as _crypto_exc

# Errors endesive/asn1crypto/cryptography legitimately raise on malformed
# input. pdf.verify uses bare `assert` statements + int()/bytes.fromhex()
# parsing on raw bytes, so AssertionError/ValueError/IndexError are expected.
_EXPECTED = (
    AssertionError,
    ValueError,
    KeyError,
    IndexError,
    TypeError,
    AttributeError,
    OverflowError,
    UnicodeDecodeError,
    _crypto_exc.InvalidSignature,
    _crypto_exc.UnsupportedAlgorithm,
)


def TestOneInput(data):
    try:
        pdf.verify(data)
    except _EXPECTED:
        return -1


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
