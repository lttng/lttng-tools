#!/bin/bash

SESSIOND_BIN="lttng-sessiond"
CURDIR=$(dirname $0)
TESTDIR=$CURDIR/..

source $TESTDIR/utils.sh

tmpdir=`mktemp -d`
tests=( $CURDIR/kernel_event_basic $CURDIR/kernel_all_events_basic )
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

function check_lttng_modules ()
{
	local out=`lsmod | grep lttng`
	if [ -z "$out" ]; then
		echo "LTTng modules not detected. Aborting kernel tests!"
		echo ""
		# Exit status 0 so the tests can continue
		exit 0
	fi
}

echo -e "\n---------------------"
echo -e "Testing Kernel tracer"
echo -e "---------------------"

# Detect lttng-modules installed
check_lttng_modules

start_tests

exit $exit_code
