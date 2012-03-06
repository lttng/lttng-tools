#!/bin/bash

DIR=$(dirname $0)

tests=( $DIR/run-ust-global-tests.sh $DIR/nevents/run $DIR/nprocesses/run )
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
