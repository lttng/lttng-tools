#!/bin/bash

SESSIOND_BIN="lttng-sessiond"
TESTDIR=$(dirname $0)/..

source $TESTDIR/utils.sh

tmpdir=`mktemp -d`
tests=( ust_global_event_basic ust_global_all_events_basic )
exit_code=0

function start_tests ()
{
    for bin in ${tests[@]};
    do
		if [ ! -e $bin ]; then
			echo -e "$bin not found, passing"
			continue
		fi

        ./$bin $tmpdir
        # Test must return 0 to pass.
        if [ $? -ne 0 ]; then
            exit_code=1
            break
        fi
    done

	# Cleaning up
	rm -rf $tmpdir
}

echo -e "\n-------------------------------------------"
echo -e "UST tracer - Global domain (LTTNG_DOMAIN_UST)"
echo -e "---------------------------------------------"

PID_SESSIOND=`pidof lt-$SESSIOND_BIN`

# Simply wait for the session daemon bootstrap
sleep 1

start_tests

exit $exit_code
