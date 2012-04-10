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

		start_sessiond

        ./$bin $tmpdir
        # Test must return 0 to pass.
        if [ $? -ne 0 ]; then
            exit_code=1
			stop_sessiond
            break
        fi
		stop_sessiond
    done

	# Cleaning up
	rm -rf $tmpdir
}

echo -e "\n-------------------------------------------"
echo -e "UST tracer - Global domain (LTTNG_DOMAIN_UST)"
echo -e "---------------------------------------------"

start_tests

exit $exit_code
