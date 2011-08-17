#!/bin/bash

SESSIOND_BIN="ltt-sessiond"

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
		# Cleaning up
		rm -rf $tmpdir
    done
}

function check_lttng_modules ()
{
	local out=`modprobe -l | grep lttng`
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

if [ -z $(pidof $SESSIOND_BIN) ]; then
	echo -n "Starting session daemon... "
	../ltt-sessiond/$SESSIOND_BIN --daemonize --quiet
	if [ $? -eq 1 ]; then
		echo -e '\e[1;31mFAILED\e[0m'
		rm -rf $tmpdir
		exit 1
	else
		echo -e "\e[1;32mOK\e[0m"
	fi
fi

PID_SESSIOND=`pidof lt-$SESSIOND_BIN`

# Simply wait for the session daemon bootstrap
sleep 1

start_tests

echo -e -n "\nKilling session daemon... "
kill $PID_SESSIOND >/dev/null 2>&1
if [ $? -eq 1 ]; then
    echo -e '\e[1;31mFAILED\e[0m'
else
    echo -e "\e[1;32mOK\e[0m"
fi

exit $exit_code
