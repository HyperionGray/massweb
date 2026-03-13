#!/bin/sh

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
PYTHON_BIN=${PYTHON_BIN:-"$REPO_ROOT/env/bin/python"}

"$PYTHON_BIN" -m unittest discover -s "$REPO_ROOT/test" -t "$REPO_ROOT"
