FROM fuzzers/atheris:2.0.7-python3.9
ADD . /endesive
WORKDIR /src
RUN python3 -m pip install --upgrade pip
RUN python3 -m pip install asn1crypto
RUN python3 -m pip install oscrypto
RUN python3 -m pip install pyPDF2
RUN python3 -m pip install certvalidator
RUN python3 -m pip install PdfReader

RUN chmod +x /endesive/mayhem/fuzz_verify.py

CMD ["/endesive/mayhem/fuzz_verify.py"]
