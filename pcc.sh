#!/bin/bash

pcc=/opt/pcc/pcc.py
virtualenv=/opt/venv

cd $(dirname $0)
test -e $virtualenv && VIRTUALENV=$virtualenv
export PYTHONPATH=$PYTHONPATH:$(pwd)
source $VIRTUALENV/bin/activate
CMD="$VIRTUALENV/bin/python $pcc $*"

exec $CMD
