FROM fuzzers/atheris:2.0.7-python3.9

ADD . /src
WORKDIR /src

RUN apt install swig -y

RUN python3 -m pip install PyPDF2
RUN python3 -m pip install .

CMD ["/src/mayhem/fuzz_verify.py"]
