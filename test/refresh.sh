#!/bin/sh
# run from repo root
# cleans out the virtualenv and installs the module

set -e


virtualenv --clear env/
if $REFRESH_SPHINX ;then
	pip install Sphinx
	pip install alabaster
	pip install sphinxcontrib-napoleon
fi
./env/bin/python setup.py install
