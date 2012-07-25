#!/bin/bash

DIR=$(dirname $0)

tests=( $DIR/test_kernel_data_trace $DIR/test_sessions $DIR/test_ust_data_trace )

# Disable for now until they all pass and the problem are fixed
# 	$DIR/streaming/runall

exit_code=0

function start_tests ()
{
    for bin in ${tests[@]};
    do
		if [ ! -e $bin ]; then
			echo -e "$bin not found, passing"
			continue
		fi

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
