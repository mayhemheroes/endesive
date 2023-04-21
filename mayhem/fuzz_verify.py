#!/usr/bin/env python3
import os.path

import atheris
import sys
import datetime
from random import random
from cryptography.hazmat import backends
from cryptography.hazmat.primitives.serialization import pkcs12

with atheris.instrument_imports():
    from endesive.pdf.cms import sign
    from endesive.pdf import verify
    from endesive.pdf import PyPDF2


@atheris.instrument_func
def fuzz_test_verify(input_data):
    fdp = atheris.FuzzedDataProvider(input_data)
    dct = {
        'sigflags': 3,
        'contact': 'jake@mayhem.com',
        'location': 'Elsewhere',
        'signingdate': datetime.date.today,
        'reason': 'For Mayhem',
    }
    try:
        with fdp.ConsumeBytes(fdp.remaining_bytes()) as f:
            d = sign(f.encode('utf-8'),
                         dct,
                         p12[0],
                         p12[1],
                         p12[2],
                         'sha256')
            verify(d)
    except Exception:
        if random() > 0.99:
            raise
        return 1


def main():
    atheris.Setup(sys.argv, fuzz_test_verify)
    atheris.Fuzz()


if __name__ == "__main__":
    path = os.path.dirname(os.path.abspath(__file__))
    with open(path + '/demo2_user1.p12', 'rb') as fp:
        p12 = pkcs12.load_key_and_certificates(fp.read(), b'1234', backends.default_backend())

    main()
