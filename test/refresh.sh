#!/bin/sh
# Run from anywhere. Creates a clean virtual environment and installs MassWeb.

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
VENV_DIR=${VENV_DIR:-"$REPO_ROOT/env"}
PYTHON_BIN=${PYTHON_BIN:-python3}

rm -rf "$VENV_DIR"
"$PYTHON_BIN" -m venv "$VENV_DIR"

"$VENV_DIR/bin/python" -m pip install --upgrade pip setuptools wheel
"$VENV_DIR/bin/pip" install -r "$REPO_ROOT/requirements.txt"

if [ "${REFRESH_SPHINX:-false}" = "true" ]; then
    "$VENV_DIR/bin/pip" install -r "$REPO_ROOT/requirements-dev.txt"
fi

"$VENV_DIR/bin/pip" install -e "$REPO_ROOT"
