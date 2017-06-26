#!/bin/bash

# Get important paths
projdir=$(dirname "$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )")
bindir="$projdir/bin" 
so_path="$bindir/libwsaesengine.so"
test_exec="$bindir/wsaesenginetest"

echo "*******************************************"
echo "Running test script:"
echo "  $projdir/test/runtest.sh"
echo "From project directory:"
echo "  $projdir"
echo "With the following command and arguments:"
echo "  $test_exec $so_path"
echo ""

$test_exec $so_path


