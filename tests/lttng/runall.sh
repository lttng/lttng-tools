#!/bin/bash

SESSIOND_BIN="ltt-sessiond"

tmpdir=`mktemp -d`
tests=( kernel_all_events_basic )
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
}

echo -e "\n----------------------------------"
echo -e "Testing lttng client (liblttngctl)"
echo -e "----------------------------------"

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

rm -rf $tmpdir

exit $exit_code
