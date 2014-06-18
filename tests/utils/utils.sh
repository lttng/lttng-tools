#!/src/bin/bash
#
# Copyright (C) - 2012 David Goulet <dgoulet@efficios.com>
#
# This library is free software; you can redistribute it and/or modify it under
# the terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; version 2.1 of the License.
#
# This library is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this library; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA

SESSIOND_BIN="lttng-sessiond"
CONSUMERD_BIN="lttng-consumerd"
RELAYD_BIN="lttng-relayd"
LTTNG_BIN="lttng"
BABELTRACE_BIN="babeltrace"

# Minimal kernel version supported for session daemon tests
KERNEL_MAJOR_VERSION=2
KERNEL_MINOR_VERSION=6
KERNEL_PATCHLEVEL_VERSION=27

source $TESTDIR/utils/tap/tap.sh

function print_ok ()
{
	# Check if we are a terminal
	if [ -t 1 ]; then
		echo -e "\e[1;32mOK\e[0m"
	else
		echo -e "OK"
	fi
}

function print_fail ()
{
	# Check if we are a terminal
	if [ -t 1 ]; then
		echo -e "\e[1;31mFAIL\e[0m"
	else
		echo -e "FAIL"
	fi
}

function print_test_banner ()
{
	desc="$1"
	diag "$desc"
}

function validate_kernel_version ()
{
	kern_version=($(uname -r | awk -F. '{ printf("%d.%d.%d\n",$1,$2,$3); }' | tr '.' '\n'))
	if [ ${kern_version[0]} -gt $KERNEL_MAJOR_VERSION ]; then
		return 0
	fi
	if [ ${kern_version[1]} -gt $KERNEL_MINOR_VERSION ]; then
		return 0
	fi
	if [ ${kern_version[2]} -ge $KERNEL_PATCHLEVEL_VERSION ]; then
		return 0
	fi
	return 1
}

# Generate a random string
#  $1 = number of characters; defaults to 16
#  $2 = include special characters; 1 = yes, 0 = no; defaults to yes
function randstring()
{
	[ "$2" == "0" ] && CHAR="[:alnum:]" || CHAR="[:graph:]"
	cat /dev/urandom | tr -cd "$CHAR" | head -c ${1:-16}
	echo
}

function lttng_enable_kernel_event
{
	sess_name=$1
	event_name=$2
	channel_name=$3

	if [ -z $event_name ]; then
		# Enable all event if no event name specified
		event_name="-a"
	fi

	if [ -z $channel_name ]; then
		# default channel if none specified
		chan=""
	else
		chan="-c $channel_name"
	fi

	$TESTDIR/../src/bin/lttng/$LTTNG_BIN enable-event "$event_name" $chan -s $sess_name -k >/dev/null 2>&1
	ok $? "Enable kernel event $event_name for session $sess_name"
}

function start_lttng_relayd
{
	local opt=$1

	DIR=$(readlink -f $TESTDIR)

	if [ -z $(pidof lt-$RELAYD_BIN) ]; then
		$DIR/../src/bin/lttng-relayd/$RELAYD_BIN -b $opt >/dev/null 2>&1
		#$DIR/../src/bin/lttng-relayd/$RELAYD_BIN $opt -vvv >>/tmp/relayd.log 2>&1 &
		if [ $? -eq 1 ]; then
			fail "Start lttng-relayd (opt: $opt)"
			return 1
		else
			pass "Start lttng-relayd (opt: $opt)"
		fi
	else
		pass "Start lttng-relayd (opt: $opt)"
	fi
}

function stop_lttng_relayd_nocheck
{
	PID_RELAYD=`pidof lt-$RELAYD_BIN`

	diag "Killing lttng-relayd (pid: $PID_RELAYD)"
	kill $PID_RELAYD >/dev/null 2>&1
	retval=$?

	if [ $retval -eq 1 ]; then
		out=1
		while [ -n "$out" ]; do
			out=$(pidof lt-$RELAYD_BIN)
			sleep 0.5
		done
	fi
	return $retval
}

function stop_lttng_relayd
{
	stop_lttng_relayd_nocheck

	if [ $? -eq 1 ]; then
		fail "Killed lttng-relayd (pid: $PID_RELAYD)"
		return 1
	else
		pass "Killed lttng-relayd (pid: $PID_RELAYD)"
		return 0
	fi
}

function start_lttng_sessiond()
{
	if [ -n $TEST_NO_SESSIOND ] && [ "$TEST_NO_SESSIOND" == "1" ]; then
		# Env variable requested no session daemon
		return
	fi

	validate_kernel_version
	if [ $? -ne 0 ]; then
	    fail "Start session daemon"
	    BAIL_OUT "*** Kernel too old for session daemon tests ***"
	fi

	DIR=$(readlink -f $TESTDIR)
	: ${LTTNG_SESSION_CONFIG_XSD_PATH=${DIR}/../src/common/config/}
	export LTTNG_SESSION_CONFIG_XSD_PATH

	if [ -z $(pidof lt-$SESSIOND_BIN) ]; then
		$DIR/../src/bin/lttng-sessiond/$SESSIOND_BIN --background --consumerd32-path="$DIR/../src/bin/lttng-consumerd/lttng-consumerd" --consumerd64-path="$DIR/../src/bin/lttng-consumerd/lttng-consumerd"
		#$DIR/../src/bin/lttng-sessiond/$SESSIOND_BIN --consumerd32-path="$DIR/../src/bin/lttng-consumerd/lttng-consumerd" --consumerd64-path="$DIR/../src/bin/lttng-consumerd/lttng-consumerd" --verbose-consumer >>/tmp/sessiond.log 2>&1 &
		status=$?
		ok $status "Start session daemon"
	fi
}

function stop_lttng_sessiond ()
{
	if [ -n $TEST_NO_SESSIOND ] && [ "$TEST_NO_SESSIOND" == "1" ]; then
		# Env variable requested no session daemon
		return
	fi

	PID_SESSIOND=`pidof lt-$SESSIOND_BIN`

	kill $PID_SESSIOND >/dev/null 2>&1

	if [ $? -eq 1 ]; then
		fail "Kill sessions daemon"
		return 1
	else
		out=1
		while [ -n "$out" ]; do
			out=$(pidof lt-$SESSIOND_BIN)
			sleep 0.5
		done
		out=1
		while [ -n "$out" ]; do
			out=$(pidof $CONSUMERD_BIN)
			sleep 0.5
		done
		pass "Kill session daemon"
	fi
}

function create_lttng_session_no_output ()
{
	sess_name=$1

	$TESTDIR/../src/bin/lttng/$LTTNG_BIN create $sess_name --no-output >/dev/null 2>&1
	ok $? "Create session $sess_name in no-output mode"
}

function create_lttng_session ()
{
	sess_name=$1
	trace_path=$2

	$TESTDIR/../src/bin/lttng/$LTTNG_BIN create $sess_name -o $trace_path >/dev/null 2>&1
	ok $? "Create session $sess_name in $trace_path"
}

function enable_ust_lttng_channel()
{
	sess_name=$1
	channel_name=$2

	$TESTDIR/../src/bin/lttng/$LTTNG_BIN enable-channel -u $channel_name -s $sess_name >/dev/null 2>&1
	ok $? "Enable channel $channel_name for session $sess_name"
}

function disable_ust_lttng_channel()
{
	sess_name=$1
	channel_name=$2

	$TESTDIR/../src/bin/lttng/$LTTNG_BIN disable-channel -u $channel_name -s $sess_name >/dev/null 2>&1
	ok $? "Disable channel $channel_name for session $sess_name"
}

function enable_lttng_mmap_overwrite_kernel_channel()
{
	sess_name=$1
	channel_name=$2

	$TESTDIR/../src/bin/lttng/$LTTNG_BIN enable-channel -s $sess_name $channel_name -k --output mmap --overwrite >/dev/null 2>&1
	ok $? "Enable channel $channel_name for session $sess_name"
}

function enable_lttng_mmap_overwrite_ust_channel()
{
	sess_name=$1
	channel_name=$2

	$TESTDIR/../src/bin/lttng/$LTTNG_BIN enable-channel -s $sess_name $channel_name -u --output mmap --overwrite >/dev/null 2>&1
	ok $? "Enable channel $channel_name for session $sess_name"
}

function enable_ust_lttng_event ()
{
	sess_name=$1
	event_name="$2"
	channel_name=$3

	if [ -z $channel_name ]; then
		# default channel if none specified
		chan=""
	else
		chan="-c $channel_name"
	fi

	$TESTDIR/../src/bin/lttng/$LTTNG_BIN enable-event "$event_name" $chan -s $sess_name -u >/dev/null 2>&1
	ok $? "Enable event $event_name for session $sess_name"
}

function enable_jul_lttng_event()
{
	sess_name=$1
	event_name="$2"
	channel_name=$3

	if [ -z $channel_name ]; then
		# default channel if none specified
		chan=""
	else
		chan="-c $channel_name"
	fi

	$TESTDIR/../src/bin/lttng/$LTTNG_BIN enable-event "$event_name" $chan -s $sess_name -j >/dev/null 2>&1
	ok $? "Enable JUL event $event_name for session $sess_name"
}

function enable_jul_lttng_event_loglevel()
{
	sess_name=$1
	event_name="$2"
	loglevel=$3
	channel_name=$4

	if [ -z $channel_name ]; then
		# default channel if none specified
		chan=""
	else
		chan="-c $channel_name"
	fi

	$TESTDIR/../src/bin/lttng/$LTTNG_BIN enable-event --loglevel $loglevel "$event_name" $chan -s $sess_name -j >/dev/null 2>&1
	ok $? "Enable JUL event $event_name for session $sess_name with loglevel $loglevel"
}

function enable_ust_lttng_event_filter()
{
	sess_name="$1"
	event_name="$2"
	filter="$3"

	$TESTDIR/../src/bin/lttng/$LTTNG_BIN enable-event "$event_name" -s $sess_name -u --filter "$filter" >/dev/null 2>&1
	ok $? "Enable event $event_name with filtering for session $sess_name"
}

function enable_ust_lttng_event_loglevel()
{
	sess_name="$1"
	event_name="$2"
	loglevel="$3"

	$TESTDIR/../src/bin/lttng/$LTTNG_BIN enable-event "$event_name" -s $sess_name -u --loglevel $loglevel >/dev/null 2>&1
	ok $? "Enable event $event_name with loglevel $loglevel"
}

function enable_ust_lttng_event_loglevel_only()
{
	sess_name="$1"
	event_name="$2"
	loglevel="$3"

	$TESTDIR/../src/bin/lttng/$LTTNG_BIN enable-event "$event_name" -s $sess_name -u --loglevel-only $loglevel >/dev/null 2>&1
	ok $? "Enable event $event_name with loglevel-only $loglevel"
}

function disable_ust_lttng_event ()
{
	sess_name="$1"
	event_name="$2"

	$TESTDIR/../src/bin/lttng/$LTTNG_BIN disable-event "$event_name" -s $sess_name -u >/dev/null 2>&1
	ok $? "Disable event $event_name for session $sess_name"
}

function disable_jul_lttng_event ()
{
	local sess_name="$1"
	local event_name="$2"

	$TESTDIR/../src/bin/lttng/$LTTNG_BIN disable-event "$event_name" -s $sess_name -j >/dev/null 2>&1
	ok $? "Disable JUL event $event_name for session $sess_name"
}

function start_lttng_tracing ()
{
	sess_name=$1

	$TESTDIR/../src/bin/lttng/$LTTNG_BIN start $sess_name >/dev/null 2>&1
	ok $? "Start tracing for session $sess_name"
}

function stop_lttng_tracing ()
{
	sess_name=$1

	$TESTDIR/../src/bin/lttng/$LTTNG_BIN stop $sess_name >/dev/null 2>&1
	ok $? "Stop lttng tracing for session $sess_name"
}

function destroy_lttng_session ()
{
	sess_name=$1


	$TESTDIR/../src/bin/lttng/$LTTNG_BIN destroy $sess_name >/dev/null 2>&1
	ok $? "Destroy lttng session $sess_name"
}

function lttng_snapshot_add_output ()
{
	sess_name=$1
	trace_path=$2

	$TESTDIR/../src/bin/lttng/$LTTNG_BIN snapshot add-output -s $sess_name file://$trace_path >/dev/null 2>&1
	ok $? "Added snapshot output file://$trace_path"
}

function lttng_snapshot_del_output ()
{
	local sess_name=$1
	local id=$2

	$TESTDIR/../src/bin/lttng/$LTTNG_BIN snapshot del-output -s $sess_name $id >/dev/null 2>&1
	ok $? "Deleted snapshot output id $id"
}

function lttng_snapshot_record ()
{
	sess_name=$1
	trace_path=$2

	$TESTDIR/../src/bin/lttng/$LTTNG_BIN snapshot record -s $sess_name >/dev/null 2>&1
	ok $? "Snapshot recorded"
}

function lttng_save()
{
	local sess_name=$1
	local opts=$2

	$TESTDIR/../src/bin/lttng/$LTTNG_BIN save $sess_name $opts >/dev/null 2>&1
	ok $? "Session successfully saved"
}

function lttng_load()
{
	local opts=$1

	$TESTDIR/../src/bin/lttng/$LTTNG_BIN load $opts >/dev/null 2>&1
	ok $? "Load command successful"
}

function trace_matches ()
{
	event_name=$1
	nr_iter=$2
	trace_path=$3

	which $BABELTRACE_BIN >/dev/null
	skip $? -ne 0 "Babeltrace binary not found. Skipping trace matches"

	count=$($BABELTRACE_BIN $trace_path | grep $event_name | wc -l)

	if [ "$count" -ne "$nr_iter" ]; then
		fail "Trace match"
		diag "$count events found in trace"
	else
		pass "Trace match"
	fi
}

function validate_trace
{
	event_name=$1
	trace_path=$2

	which $BABELTRACE_BIN >/dev/null
	if [ $? -ne 0 ]; then
	    skip 0 "Babeltrace binary not found. Skipping trace validation"
	fi

	OLDIFS=$IFS
	IFS=","
	for i in $event_name; do
		traced=$($BABELTRACE_BIN $trace_path 2>/dev/null | grep $i | wc -l)
		if [ "$traced" -ne 0 ]; then
			pass "Validate trace for event $i, $traced events"
		else
			fail "Validate trace for event $i"
			diag "Found $traced occurences of $i"
		fi
	done
	ret=$?
	IFS=$OLDIFS
	return $ret
}
