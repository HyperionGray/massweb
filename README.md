# MassWeb

MassWeb is a legacy Python web fuzzing and mass-request toolkit originally
published by Hyperion Gray.

This repository now includes a standard Python 3 development environment setup
so it can be bootstrapped consistently in local shells, CI jobs, and cloud
coding agents.

## Requirements

- Python 3.11
- `make` (optional, but convenient)

## Quick start

```bash
python3 -m venv env
source env/bin/activate
./test/refresh.sh
./test/run.sh
```

Or use the root Makefile:

```bash
make env
make test
```

## Repository layout

- `massweb/` - package source
- `test/` - bootstrap and test scripts plus unittest suites
- `docs/` - Sphinx documentation

## Environment files

- `.python-version` pins the expected interpreter version for tooling.
- `requirements.txt` contains the base Python dependencies.
- `requirements-dev.txt` adds documentation and build-time tooling.
- `pyproject.toml` provides modern setuptools build metadata.

## Additional docs

- `QUICKSTART.md` - shortest path to a working environment
- `README.txt` - original upstream project notes
