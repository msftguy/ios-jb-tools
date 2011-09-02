#!/bin/bash
DIR="$( cd "$( dirname "$0" )" && pwd )"
test $# -gt 1 || { echo "Usage: $0 Path_To_CommCenterClassic OutputFile.h"; exit 1; } 
/Applications/idaq.app/Contents/MacOS/idaq -c -TMach-O -S"$DIR/commcenter.py \"$2\"" $1
