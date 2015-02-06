#!/bin/sh
# run from repo root
# cleans out the virtualenv and installs the module

set -e


virtualenv --clear env/
pip install Sphinx
./env/bin/python setup.py install
