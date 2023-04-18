FROM fuzzers/atheris:2.0.7-python3.9
ADD ./mayhem/fuzz_verify.py /fuzz_verify.py
RUN python3 -m pip install --upgrade pip
RUN chmod +x /fuzz_verify.py



CMD ["/fuzz_verify.py"]
