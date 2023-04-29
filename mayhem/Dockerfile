#FROM fuzzers/atheris:2.0.7-python3.9
FROM bcapuano/atheris:2.1.1-python3.10

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y clang cmake make ninja-build python3 python3-pip git libeccodes-dev

ADD . /src
WORKDIR /src

RUN apt install swig -y

RUN python3 -m pip install PyPDF2
RUN python3 -m pip install .

CMD ["/src/mayhem/fuzz_verify.py"]
