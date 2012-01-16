#!/bin/bash

SESSIOND_BIN="lttng-sessiond"

tmpdir=`mktemp -d`
tests=( ust_global_event_basic ust_global_all_events_basic )
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

echo -e "\n-------------------------------------------"
echo -e "UST tracer - GLOBAL DOMAIN (LTTNG_DOMAIN_UST)"
echo -e "---------------------------------------------"

if [ -z $(pidof $SESSIOND_BIN) ]; then
	echo -n "Starting session daemon... "
	../lttng-sessiond/$SESSIOND_BIN --daemonize --quiet
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
