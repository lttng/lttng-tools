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
LTTNG_BIN="lttng"
BABELTRACE_BIN="babeltrace"

# Minimal kernel version supported for session daemon tests
KERNEL_MAJOR_VERSION=2
KERNEL_MINOR_VERSION=6
KERNEL_PATCHLEVEL_VERSION=27

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

function start_sessiond ()
{
	echo ""
	echo -n "Starting session daemon... "
	validate_kernel_version
	if [ $? -ne 0 ]; then
		echo -e "\n*** Kernel too old for session daemon tests ***\n"
		return 2
	fi

	if [ -z $(pidof lt-$SESSIOND_BIN) ]; then
		$TESTDIR/../src/bin/lttng-sessiond/$SESSIOND_BIN --daemonize --quiet --consumerd32-path="$(pwd)/../src/bin/lttng-consumerd/lttng-consumerd" --consumerd64-path="$(pwd)/../src/bin/lttng-consumerd/lttng-consumerd"
		if [ $? -eq 1 ]; then
			echo -e "\e[1;31mFAILED\e[0m"
			return 1
		else
			echo -e "\e[1;32mOK\e[0m"
		fi
	fi

	return 0
}

function stop_sessiond ()
{
	PID_SESSIOND=`pidof lt-$SESSIOND_BIN`

	echo -e -n "Killing session daemon... "
	kill $PID_SESSIOND >/dev/null 2>&1
	if [ $? -eq 1 ]; then
		echo -e "\e[1;31mFAILED\e[0m"
		return 1
	else
		out=1
		while [ -n "$out" ]; do
			out=$(pidof lt-$SESSIOND_BIN)
			sleep 0.5
		done
		echo -e "\e[1;32mOK\e[0m"
	fi
}

function create_lttng_session ()
{
	sess_name=$1
	trace_path=$2

	echo -n "Creating lttng session $SESSION_NAME in $TRACE_PATH "
	$TESTDIR/../src/bin/lttng/$LTTNG_BIN create $sess_name -o $trace_path >/dev/null 2>&1
	if [ $? -eq 1 ]; then
		echo -e "\e[1;31mFAILED\e[0m"
		return 1
	else
		echo -e "\e[1;32mOK\e[0m"
		#echo $out | grep "written in" | cut -d' ' -f6
	fi
}

function enable_ust_lttng_event ()
{
	sess_name=$1
	event_name=$2

	echo -n "Enabling lttng event $event_name for session $sess_name "
	$TESTDIR/../src/bin/lttng/$LTTNG_BIN enable-event $event_name -s $sess_name -u >/dev/null 2>&1
	if [ $? -eq 1 ]; then
		echo -e '\e[1;31mFAILED\e[0m'
		return 1
	else
		echo -e "\e[1;32mOK\e[0m"
	fi
}

function start_tracing ()
{
	sess_name=$1

	echo -n "Start lttng tracing for session $sess_name "
	$TESTDIR/../src/bin/lttng/$LTTNG_BIN start $sess_name >/dev/null 2>&1
	if [ $? -eq 1 ]; then
		echo -e '\e[1;31mFAILED\e[0m'
		return 1
	else
		echo -e "\e[1;32mOK\e[0m"
	fi
}

function stop_tracing ()
{
	sess_name=$1

	echo -n "Stop lttng tracing for session $sess_name "
	$TESTDIR/../src/bin/lttng/$LTTNG_BIN stop $sess_name >/dev/null 2>&1
	if [ $? -eq 1 ]; then
		echo -e '\e[1;31mFAILED\e[0m'
		return 1
	else
		echo -e "\e[1;32mOK\e[0m"
	fi
}

function destroy_lttng_session ()
{
	sess_name=$1

	echo -n "Destroy lttng session $sess_name "
	$TESTDIR/../src/bin/lttng/$LTTNG_BIN destroy $sess_name >/dev/null 2>&1
	if [ $? -eq 1 ]; then
		echo -e '\e[1;31mFAILED\e[0m'
		return 1
	else
		echo -e "\e[1;32mOK\e[0m"
	fi
}

function trace_matches ()
{
	event_name=$1
	nr_iter=$2
	trace_path=$3

	which $BABELTRACE_BIN >/dev/null
	if [ $? -eq 1 ]; then
		echo "Babeltrace binary not found. Skipping trace matches"
		return 0
	fi

	echo -n "Looking for $nr_iter $event_name in $trace_path "

	count=$($BABELTRACE_BIN $trace_path | grep $event_name | wc -l)
	if [ "$count" -ne "$nr_iter" ]; then
		echo -e "$count found in trace \e[1;31mFAILED\e[0m"
		return 1
	else
		echo -e "Trace is coherent \e[1;32mOK\e[0m"
		return 0
	fi
}
