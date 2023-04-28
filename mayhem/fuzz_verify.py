#!/usr/bin/env python3
import os.path
import atheris
import sys

from cryptography.hazmat import backends
from cryptography.hazmat.primitives.serialization import pkcs12

with atheris.instrument_imports(include=['endesive']):
    from endesive.email import sign
    from endesive.email import verify
    from endesive.email import decrypt
    from endesive.email import encrypt


def TestOneInput(input_data):
    global error_from_verify, error_from_enc, error_from_dec, runs, p12, dct
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
        # The functions will have an exception almost immediately when called
        # if runs > 1000:
        #     if not error_from_verify:
        #         try:
        #             verify(b.decode('utf-8'))
        #         except UnicodeError:
        #             error_from_verify = True
        #             raise
        #     if not error_from_enc:
        #         try:
        #             encrypt(b, p12)
        #         except AttributeError:
        #             error_from_enc = True
        #             raise
        #     if not error_from_dec:
        #         try:
        #             decrypt(b.decode('utf-8'), p12)
        #         except AttributeError:
        #             error_from_dec = True
        #             raise
    except TypeError:
        raise


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    error_from_verify = False
    error_from_dec = False
    error_from_enc = False
    runs = 0
    path = os.path.dirname(os.path.abspath(__file__))
    with open(path + '/demo2_user1.p12', 'rb') as fp:
        p12 = pkcs12.load_key_and_certificates(fp.read(), b'1234', backends.default_backend())
    dct = {
        'sigflags': 3,
        'contact': 'jake@mayhem.com',
        'location': 'Elsewhere',
        'signingdate': '01-01-2023',
        'reason': 'For Mayhem',
    }
    main()
