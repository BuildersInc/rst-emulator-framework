FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update

RUN apt install -y python3 python3-full python3-pip

COPY setup.cfg pyproject.toml README.md LICENSE /app/
COPY src/ /app/src/
WORKDIR /app

RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN pip install .
