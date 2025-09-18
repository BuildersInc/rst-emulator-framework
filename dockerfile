FROM python:3.12-slim

WORKDIR /app

COPY setup.cfg pyproject.toml README.md LICENSE /app/
COPY src/ /app/src/

RUN pip install --no-cache-dir .

