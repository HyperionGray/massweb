#!/bin/sh

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
PYTHON_BIN=${PYTHON_BIN:-"$REPO_ROOT/env/bin/python"}

cd "$REPO_ROOT/test"
"$PYTHON_BIN" -m unittest discover -t "$REPO_ROOT"
