#!/usr/bin/env python3
# import os.path
import atheris
import sys
import io

# from random import random
# from cryptography.hazmat import backends
# from cryptography.hazmat.primitives.serialization import pkcs12

with atheris.instrument_imports(include=['endesive']):
    # from endesive.pdf.cms import sign
    # from endesive.pdf import verify
    from endesive.pdf import PyPDF2

from endesive.pdf.PyPDF2.utils import PdfReadError


@atheris.instrument_func
def TestOneInput(input_data):
    fdp = atheris.FuzzedDataProvider(input_data)
    try:
        file = io.BytesIO(fdp.ConsumeBytes(fdp.remaining_bytes()))
        PyPDF2.PdfFileReader(file)
        # print(file.read())
        # d = sign(file,
        #          dct,
        #          p12[0],
        #          p12[1],
        #          p12[2],
        #          'sha256')
        # verify(d)
    except (PdfReadError, ValueError, TypeError, AssertionError):
        return -1
    # except Exception:
    #     if random() > 0.99:
    #         raise
    #     return -1


def main():
    atheris.Setup(sys.argv, TestOneInput)  # , corpus_dir=path + '/testsuite/')
    atheris.Fuzz()


if __name__ == "__main__":
    # path = os.path.dirname(os.path.abspath(__file__))
    # with open(path + '/demo2_user1.p12', 'rb') as fp:
    #     p12 = pkcs12.load_key_and_certificates(fp.read(), b'1234', backends.default_backend())
    # dct = {
    #     'sigflags': 3,
    #     'contact': 'jake@mayhem.com',
    #     'location': 'Elsewhere',
    #     'signingdate': '01-01-2023',
    #     'reason': 'For Mayhem',
    # }
    main()
