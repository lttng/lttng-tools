#!/bin/bash

SESSIOND_BIN="lttng-sessiond"
CURDIR=$(dirname $0)
TESTDIR=$CURDIR/..

source $TESTDIR/utils.sh

tmpdir=`mktemp -d`
tests=( $CURDIR/ust_global_event_basic $CURDIR/ust_global_event_wildcard )
exit_code=0

function start_tests ()
{
    for bin in ${tests[@]};
    do
		if [ ! -e $bin ]; then
			echo -e "$bin not found, passing"
			continue
		fi

		start_lttng_sessiond

        ./$bin $tmpdir
        # Test must return 0 to pass.
        if [ $? -ne 0 ]; then
            exit_code=1
			stop_lttng_sessiond
            break
        fi
		stop_lttng_sessiond
    done

	# Cleaning up
	rm -rf $tmpdir
}

TEST_DESC="UST tracer - Global domain (LTTNG_DOMAIN_UST)"

print_test_banner "$TEST_DESC"

start_tests

exit $exit_code
