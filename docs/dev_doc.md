# Development commands

## Install and Launch

```sh
python3 -m venv .env
source ./.env/bin/activate
pip install .
python3 -m RSTemulator -v -asm testfiles/main.s
```

## Build & Run docker Container

```sh
# Build the container
docker build -t "ContainerName" .
docker run --rm -v "$(pwd)":/app -w /app "ContainerName" python3 -m RSTemulator --test-file testfile/example.py
```
