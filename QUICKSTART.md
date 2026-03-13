# Quickstart

## Set up the development environment

```bash
python3 -m venv env
source env/bin/activate
./test/refresh.sh
```

## Run the test suite

```bash
./test/run.sh
```

## Build the docs

```bash
REFRESH_SPHINX=true ./test/refresh.sh
make docs-html
```

## Shortcuts

```bash
make env
make test
```
