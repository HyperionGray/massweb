#!/bin/sh
# run from repo root
# cleans out the virtualenv and installs the module

set -e


virtualenv --clear env/
./env/bin/python setup.py install
