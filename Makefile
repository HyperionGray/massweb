.DEFAULT_GOAL := test

PYTHON ?= python3
VENV_DIR ?= $(CURDIR)/env

.PHONY: env install test docs-html clean

env:
	PYTHON_BIN="$(PYTHON)" VENV_DIR="$(VENV_DIR)" ./test/refresh.sh

install: env

test:
	PYTHON_BIN="$(VENV_DIR)/bin/python" VENV_DIR="$(VENV_DIR)" ./test/run.sh

docs-html: env
	PYTHON_BIN="$(PYTHON)" VENV_DIR="$(VENV_DIR)" REFRESH_SPHINX=true ./test/refresh.sh
	"$(VENV_DIR)/bin/python" -m sphinx -b html docs docs/_build/html

clean:
	rm -rf "$(VENV_DIR)" build dist massweb.egg-info
