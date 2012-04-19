#!/bin/bash

SESSIOND_BIN="lttng-sessiond"
TESTDIR=$(dirname $0)/..

source $TESTDIR/utils.sh

tmpdir=`mktemp -d`
tests=( kernel_event_basic kernel_all_events_basic )
exit_code=0

function start_tests ()
{
    for bin in ${tests[@]};
    do
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

function check_lttng_modules ()
{
	local out=`ls /lib/modules/$(uname -r)/extra | grep lttng`
	if [ -z "$out" ]; then
		echo "LTTng modules not detected. Aborting kernel tests!"
		echo ""
		# Exit status 0 so the tests can continue
		exit 0
	fi
}

echo -e "\n--------------------------------------------------"
echo -e "Kernel tracer - Testing lttng client (liblttngctl)"
echo -e "--------------------------------------------------"

# Detect lttng-modules installed

check_lttng_modules

# Simply wait for the session daemon bootstrap
sleep 1

start_tests

exit $exit_code
