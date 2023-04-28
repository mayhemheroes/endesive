#!/usr/bin/env python3

import sys
import os.path
import atheris

from cryptography.hazmat import backends
from cryptography.hazmat.primitives.serialization import pkcs12

with atheris.instrument_imports(include=['endesive']):
    from endesive.email import sign
    from endesive.email import verify
    from endesive.email import decrypt
    from endesive.email import encrypt


def TestOneInput(input_data):
    global runs, p12
    fdp = atheris.FuzzedDataProvider(input_data)
    ran = fdp.ConsumeInt(fdp.ConsumeIntInRange(0, 4))
    runs += 1
    try:
        if ran == 0:
            hash_alg = 'sha1'
        elif ran == 1:
            hash_alg = 'sha256'
        elif ran == 2:
            hash_alg = 'sha384'
        else:
            hash_alg = 'sha512'

        consumed_bytes = fdp.ConsumeBytes(fdp.remaining_bytes())
        b = sign(consumed_bytes,
                 p12[0], p12[1], p12[2],
                 hash_alg,
                 attrs=False,
                 pss=True
                 )
        verify(b.decode('utf-8'), p12)
        encrypt(b, p12)
        decrypt(b.decode('utf-8'), p12)
    except (AttributeError, UnicodeDecodeError, ValueError, TypeError):
        # skip the first few exceptions
        if runs > 1000:
            raise
        return


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    runs = 0
    path = os.path.dirname(os.path.abspath(__file__))
    with open(path + '/demo2_user1.p12', 'rb') as fp:
        p12 = pkcs12.load_key_and_certificates(fp.read(), b'1234', backends.default_backend())
    main()
