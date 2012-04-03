#!/bin/bash

DIR=$(dirname $0)

tests=( $DIR/run-ust-global-tests.sh $DIR/nprocesses/run \
		$DIR/high-throughput/run $DIR/before-after/run )

# $DIR/low-throughput/run --> DEACTIVATED.
# Use only for release. This test last 20 minutes

exit_code=0

function start_tests ()
{
    for bin in ${tests[@]};
    do
        ./$bin
        # Test must return 0 to pass.
        if [ $? -ne 0 ]; then
            exit_code=1
            break
        fi
    done
}

start_tests

exit $exit_code
