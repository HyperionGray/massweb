#!/bin/sh

cd $(dirname $0)
python=../env/bin/python

$python -m unittest discover -t .

cd -
