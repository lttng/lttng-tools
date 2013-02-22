#!/bin/bash

DIR=$(dirname $0)

tests=( $DIR/run-ust-global-tests.sh $DIR/nprocesses/test_nprocesses \
		$DIR/high-throughput/test_high_throughput $DIR/before-after/test_before_after \
		$DIR/multi-session/test_multi_session $DIR/overlap/test_overlap )

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
