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

LOCAL_COMMAND="bash -c"
SESSIOND_BIN="lttng-sessiond"
RUNAS_BIN="lttng-runas"
CONSUMERD_BIN="lttng-consumerd"
RELAYD_BIN="lttng-relayd"
LTTNG_BIN="lttng"
BABELTRACE_BIN="babeltrace"
OUTPUT_DEST=/dev/null
ERROR_OUTPUT_DEST=/dev/null

SESSIOND="$TESTDIR/../src/bin/lttng-sessiond/$SESSIOND_BIN"
RELAYD="$(readlink -f $TESTDIR)/../src/bin/lttng-relayd/$RELAYD_BIN"
LTTNG="$TESTDIR/../src/bin/lttng/$LTTNG_BIN"
CONSUMERD="$(readlink -f $TESTDIR)/../src/bin/lttng-consumerd/$CONSUMERD_BIN"
BABELTRACE="$BABELTRACE_BIN"
LTTNG_SESSION_CONFIG_XSD_PATH="$(readlink -f $TESTDIR)/../src/common/config/"

# Minimal kernel version supported for session daemon tests
KERNEL_MAJOR_VERSION=2
KERNEL_MINOR_VERSION=6
KERNEL_PATCHLEVEL_VERSION=27

# We set the default UST register timeout to "wait forever", so that
# basic tests don't have to worry about hitting timeouts on busy
# systems. Specialized tests should test those corner-cases.
export LTTNG_UST_REGISTER_TIMEOUT=-1

# We set the default lttng-sessiond path to /bin/true to prevent the spawning
# of a daemonized sessiond. This is necessary since 'lttng create' will spawn
# its own sessiond if none is running. It also ensures that 'lttng create'
# fails when no sessiond is running.
export LTTNG_SESSIOND_PATH="/bin/true"

source $TESTDIR/utils/tap/tap.sh


BASE_COMMAND="bash -c"
if [ ! -z "$REMOTE_RELAYD_TEST" ]; then

	if [[ -z ${REMOTE_RELAYD_HOST+x} ]]; then
		echo "Remote: Missing relayd host variable"
		exit
	fi

	if [[ -z ${REMOTE_RELAYD_USER+x} ]]; then
		echo "Remote: Missing relayd user variable"
		exit
	fi

	if [[ -z ${REMOTE_RELAYD_ID_FILE+x} ]]; then
		echo "Remote: path to id file not specified"
	fi

	if [[ -z ${REMOTE_RELAYD_PATH+x} ]]; then
		echo "Remote: Missing remote relayd_path for remote test"
		exit
	fi

	if [[ -z ${REMOTE_RELAYD_BIN+x} ]]; then
		echo "Remote: Missing remote relayd_path for remote test"
		exit
	fi

	if [[ -z ${REMOTE_BABELTRACE_PATH+x} ]]; then
		echo "Remote: Missing remote relayd_path for remote test"
		exit
	fi

	if [[ -z ${REMOTE_BABELTRACE_BIN+x} ]]; then
		echo "Remote: Missing remote relayd_path for remote test"
		exit
	fi

	if [[ ! -z "$REMOTE_RELAYD_PATH" ]]; then
		# Add a trailing slash just in case
		REMOTE_RELAYD_PATH="$REMOTE_RELAYD_PATH/"
	fi

	if [[ ! -z "$REMOTE_BABELTRACE_PATH" ]]; then
		# Add a trailing slash just in case
		REMOTE_BABELTRACE_PATH="$REMOTE_BABELTRACE_PATH/"
	fi
fi

# Override the base command
function override_base_command_ssh ()
{
	local host=$1
	local user=$2

	# Optional
	local identify_file="$3"

	local identity_opt=""

	if [[ ! -z "$identify_file" ]]; then
		identity_opt="-i $identify_file"
	fi

	BASE_COMMAND="ssh -l $user $identity_opt $host"
}

function reestablish_base_command ()
{
	BASE_COMMAND="$LOCAL_COMMAND"
}

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
	local desc="$1"
	diag "$desc"
}

function validate_kernel_version ()
{
	local kern_version=($(uname -r | awk -F. '{ printf("%d.%d.%d\n",$1,$2,$3); }' | tr '.' '\n'))
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
	cat /dev/urandom 2>/dev/null | tr -cd "$CHAR" 2>/dev/null | head -c ${1:-16} 2>/dev/null
	echo
}

# Return the number of _configured_ CPUs.
function conf_proc_count()
{
	getconf _NPROCESSORS_CONF
	if [ $? -ne 0 ]; then
		diag "Failed to get the number of configured CPUs"
	fi
	echo
}

function enable_kernel_lttng_event
{
	local expected_to_fail="$1"
	local sess_name="$2"
	local event_name="$3"
	local channel_name="$4"

	if [ -z "$event_name" ]; then
		# Enable all event if no event name specified
		event_name="-a"
	fi

	if [ -z "$channel_name" ]; then
		# default channel if none specified
		chan=""
	else
		chan="-c $channel_name"
	fi

	$LTTNG enable-event "$event_name" $chan -s $sess_name -k 1> $OUTPUT_DEST 2> $ERROR_OUTPUT_DEST
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test $ret -ne "0"
		ok $? "Enable kernel event $event_name for session $session_name on channel $channel_name failed as expected"
	else
		ok $ret "Enable kernel event $event_name for session $sess_name"
	fi
}

function enable_kernel_lttng_event_ok ()
{
	enable_kernel_lttng_event 0 "$@"
}

function enable_kernel_lttng_event_fail ()
{
	enable_kernel_lttng_event 1 "$@"
}

# Old interface
function lttng_enable_kernel_event
{
	enable_kernel_lttng_event_ok "$@"
}

function lttng_enable_kernel_syscall()
{
	local expected_to_fail=$1
	local sess_name=$2
	local syscall_name=$3
	local channel_name=$4

	if [ -z $syscall_name ]; then
		# Enable all event if no syscall name specified
		syscall_name="-a"
	fi

	if [ -z $channel_name ]; then
		# default channel if none specified
		chan=""
	else
		chan="-c $channel_name"
	fi

	$LTTNG enable-event --syscall "$syscall_name" $chan -s $sess_name -k 1> $OUTPUT_DEST 2> $ERROR_OUTPUT_DEST
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test $ret -ne "0"
		ok $? "Enable kernel syscall $syscall_name for session $sess_name on channel $channel_name fail as expected"
	else
		ok $ret "Enable kernel syscall $syscall_name for session $sess_name on channel $channel_name"
	fi
}

function lttng_enable_kernel_syscall_ok()
{
	lttng_enable_kernel_syscall 0 "$@"
}

function lttng_enable_kernel_syscall_fail()
{
	lttng_enable_kernel_syscall 1 "$@"
}

function lttng_disable_kernel_syscall()
{
	local expected_to_fail=$1
	local sess_name=$2
	local syscall_name=$3
	local channel_name=$4

	if [ -z $syscall_name ]; then
		# Enable all event if no syscall name specified
		syscall_name="-a"
	fi

	if [ -z $channel_name ]; then
		# default channel if none specified
		chan=""
	else
		chan="-c $channel_name"
	fi

	$LTTNG disable-event --syscall "$syscall_name" $chan -s $sess_name -k 1> $OUTPUT_DEST 2> $ERROR_OUTPUT_DEST

	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test $ret -ne "0"
		ok $? "Disable kernel syscall $syscall_name for session $sess_name on channel $channel_name failed as expected"
	else
		ok $ret "Disable kernel syscall $syscall_name for session $sess_name on channel $channel_name"
	fi
}

function lttng_disable_kernel_syscall_ok()
{
	lttng_disable_kernel_syscall 0 "$@"
}

function lttng_disable_kernel_syscall_fail()
{
	lttng_disable_kernel_syscall 1 "$@"
}

function lttng_enable_kernel_channel()
{
	local expected_to_fail=$1
	local sess_name=$2
	local channel_name=$3

	$LTTNG enable-channel -k $channel_name -s $sess_name 1> $OUTPUT_DEST 2> $ERROR_OUTPUT_DEST
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test "$ret" -ne "0"
		ok $? "Enable channel $channel_name for session $sess_name failed as expected"
	else
		ok $ret "Enable channel $channel_name for session $sess_name"
	fi
}

function lttng_enable_kernel_channel_ok()
{
	lttng_enable_kernel_channel 0 "$@"
}

function lttng_enable_kernel_channel_fail()
{
	lttng_enable_kernel_channel 1 "$@"
}

function lttng_disable_kernel_channel()
{
	local expected_to_fail=$1
	local sess_name=$2
	local channel_name=$3

	$LTTNG disable-channel -k $channel_name -s $sess_name 1> $OUTPUT_DEST 2> $ERROR_OUTPUT_DEST
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test "$ret" -ne "0"
		ok $? "Disable channel $channel_name for session $sess_name failed as expected"
	else
		ok $ret "Disable channel $channel_name for session $sess_name"
	fi
}

function lttng_disable_kernel_channel_ok()
{
	lttng_disable_kernel_channel 0 "$@"
}

function lttng_disable_kernel_channel_fail()
{
	lttng_disable_kernel_channel 1 "$@"
}

function start_lttng_relayd_opt()
{
	local remote=$1
	local withtap=$2
	local opt=$3

	# Normal emplacement of lttng-relayd
	local relayd_full_path=$RELAYD
	local relayd_bin_name="lt-$RELAYD_BIN"

	if [ $remote -eq 1 -a ! -z "$REMOTE_RELAYD_TEST" ]; then
		if [[ "$BASE_COMMAND" == "$LOCAL_COMMAND" ]]; then
			fail "Start remote lttng-relayd: base command not overridden"
			return 1
		fi

		# Override the default value for bin and regex name
		relayd_full_path="$REMOTE_RELAYD_PATH$REMOTE_RELAYD_BIN"
		relayd_bin_name=$REMOTE_RELAYD_BIN
	fi

	if [ -z $($BASE_COMMAND "pgrep -f $relayd_bin_name[^\[]") ]; then
		$BASE_COMMAND "$relayd_full_path -b $opt 1> $OUTPUT_DEST 2> $ERROR_OUTPUT_DEST"
		if [ $? -ne 0 ]; then
			if [ $withtap -eq "1" ]; then
				fail "Start lttng-relayd (opt: $opt) (base command: $BASE_COMMAND)"
			fi
			return 1
		else
			if [ $withtap -eq "1" ]; then
				pass "Start lttng-relayd (opt: $opt) (base command: $BASE_COMMAND)"
			fi
		fi
	else
		pass "Start lttng-relayd (opt: $opt)"
	fi
}

function start_lttng_relayd()
{
	start_lttng_relayd_opt 0 1 "$@"
}

function start_lttng_relayd_notap()
{
	start_lttng_relayd_opt 0 0 "$@"
}

function start_lttng_relayd_remote_support()
{
	start_lttng_relayd_opt 1 1 "$@"
}

function start_lttng_relayd_remote_support_no_tap()
{
	start_lttng_relayd_opt 1 0 "$@"
}

function stop_lttng_relayd_opt()
{
	local remote=$1
	local withtap=$2

	local relayd_bin_name="lt-$RELAYD_BIN"

	if [ $remote -eq 1 -a ! -z "$REMOTE_RELAYD_TEST" ]; then
		if [[ "$BASE_COMMAND" == "$LOCAL_COMMAND" ]]; then
			fail "Kill remote relay daemon: base command not overridden"
			return 1
		fi
		# Override default value of regex name
		relayd_bin_name="$REMOTE_RELAYD_BIN"
	fi

	PID_RELAYD=$($BASE_COMMAND "pgrep -f $relayd_bin_name[^\[]")

	if [ $withtap -eq "1" ]; then
		diag "Killing lttng-relayd (pid: $PID_RELAYD) (base command: $BASE_COMMAND)"
	fi
	$BASE_COMMAND "kill $PID_RELAYD" 1> $OUTPUT_DEST 2> $ERROR_OUTPUT_DEST
	retval=$?

	if [ $? -eq 1 ]; then
		if [ $withtap -eq "1" ]; then
			fail "Kill relay daemon (base command: $BASE_COMMAND)"
		fi
		return 1
	else
		out=1
		while [ -n "$out" ]; do
			out=$($BASE_COMMAND "pgrep -f $relayd_bin_name[^\[]")
			sleep 0.5
		done
		if [ $withtap -eq "1" ]; then
			pass "Kill relay daemon (base command: $BASE_COMMAND)"
		fi
	fi
	return $retval
}

function stop_lttng_relayd()
{
	stop_lttng_relayd_opt 0 1 "$@"
}

function stop_lttng_relayd_notap()
{
	stop_lttng_relayd_opt 0 0 "$@"
}

function stop_lttng_relayd_remote_support()
{
	stop_lttng_relayd_opt 1 1 "$@"
}

function stop_lttng_relayd_remote_support_notap()
{
	stop_lttng_relayd_opt 1 0 "$@"
}

#First arg: show tap output
#Second argument: load path for automatic loading
function start_lttng_sessiond_opt()
{
	local withtap=$1
	local load_path=$2
	local raw_opts="$4"

	if [ -n $TEST_NO_SESSIOND ] && [ "$TEST_NO_SESSIOND" == "1" ]; then
		# Env variable requested no session daemon
		return
	fi

	validate_kernel_version
	if [ $? -ne 0 ]; then
	    fail "Start session daemon"
	    BAIL_OUT "*** Kernel too old for session daemon tests ***"
	fi

	export LTTNG_SESSION_CONFIG_XSD_PATH

	if [ -z $(pgrep -f lt-$SESSIOND_BIN[^\[]) ]; then
		# Have a load path ?
		if [ -n "$load_path" ]; then
			$SESSIOND --load "$load_path" --background $raw_opts\
			--consumerd32-path="$CONSUMERD"\
			--consumerd64-path="$CONSUMERD"\
			1> $OUTPUT_DEST \
			2> $ERROR_OUTPUT_DEST
		else
			$SESSIOND --background $raw_opts\
			--consumerd32-path="$CONSUMERD"\
			--consumerd64-path="$CONSUMERD"\
			1> $OUTPUT_DEST \
			2> $ERROR_OUTPUT_DEST
		fi
		status=$?
		if [ $withtap -eq "1" ]; then
			ok $status "Start session daemon"
		fi
	fi
}

function start_lttng_sessiond()
{
	start_lttng_sessiond_opt 1 "$@"
}

function start_lttng_sessiond_notap()
{
	start_lttng_sessiond_opt 0 "$@"
}

function stop_lttng_sessiond_opt()
{
	local withtap=$1
	local signal=$2
	local kill_opt=""

	if [ -n $TEST_NO_SESSIOND ] && [ "$TEST_NO_SESSIOND" == "1" ]; then
		# Env variable requested no session daemon
		return
	fi

	PID_SESSIOND="$(pgrep -f lt-$SESSIOND_BIN[^\[]) $(pgrep -f $RUNAS_BIN[^\[])"

	if [ -n "$2" ]; then
		kill_opt="$kill_opt -s $signal"
	fi
	if [ $withtap -eq "1" ]; then
		diag "Killing lt-$SESSIOND_BIN pids: $(echo $PID_SESSIOND | tr '\n' ' ')"
	fi
	kill $kill_opt $PID_SESSIOND 1> $OUTPUT_DEST 2> $ERROR_OUTPUT_DEST

	if [ $? -eq 1 ]; then
		if [ $withtap -eq "1" ]; then
			fail "Kill sessions daemon"
		fi
	else
		out=1
		while [ -n "$out" ]; do
			out=$(pgrep -f lt-$SESSIOND_BIN[^\[])
			sleep 0.5
		done
		out=1
		while [ -n "$out" ]; do
			out=$(pgrep -f $CONSUMERD_BIN[^\[])
			sleep 0.5
		done
		if [ $withtap -eq "1" ]; then
			pass "Kill session daemon"
		fi
	fi
}

function stop_lttng_sessiond()
{
	stop_lttng_sessiond_opt 1 "$@"
}

function stop_lttng_sessiond_notap()
{
	stop_lttng_sessiond_opt 0 "$@"
}

function sigstop_lttng_sessiond_opt()
{
	local withtap=$1
	local signal=SIGSTOP
	local kill_opt=""

	if [ -n $TEST_NO_SESSIOND ] && [ "$TEST_NO_SESSIOND" == "1" ]; then
		# Env variable requested no session daemon
		return
	fi

	PID_SESSIOND="$(pgrep --full lt-$SESSIOND_BIN) $(pgrep --full $RUNAS_BIN)"

	kill_opt="$kill_opt -s $signal"

	if [ $withtap -eq "1" ]; then
		diag "Sending SIGSTOP to lt-$SESSIOND_BIN pids: $(echo $PID_SESSIOND | tr '\n' ' ')"
	fi
	kill $kill_opt $PID_SESSIOND 1> $OUTPUT_DEST 2> $ERROR_OUTPUT_DEST

	if [ $? -eq 1 ]; then
		if [ $withtap -eq "1" ]; then
			fail "Sending SIGSTOP to session daemon"
		fi
	else
		out=1
		while [ $out -ne 0 ]; do
			pid=$(pgrep --full lt-$SESSIOND_BIN)

			# Wait until state becomes stopped for session
			# daemon(s).
			out=0
			for sessiond_pid in $pid; do
				state=$(ps -p $sessiond_pid -o state= )
				if [[ -n "$state" && "$state" != "T" ]]; then
					out=1
				fi
			done
			sleep 0.5
		done
		if [ $withtap -eq "1" ]; then
			pass "Sending SIGSTOP to session daemon"
		fi
	fi
}

function sigstop_lttng_sessiond()
{
	sigstop_lttng_sessiond_opt 1 "$@"
}

function sigstop_lttng_sessiond_notap()
{
	sigstop_lttng_sessiond_opt 0 "$@"
}

function stop_lttng_consumerd_opt()
{
	local withtap=$1
	local signal=$2
	local kill_opt=""

	PID_CONSUMERD=`pgrep -f $CONSUMERD_BIN[^\[]`

	if [ -n "$2" ]; then
		kill_opt="$kill_opt -s $signal"
	fi

	if [ $withtap -eq "1" ]; then
		diag "Killing $CONSUMERD_BIN pids: $(echo $PID_CONSUMERD | tr '\n' ' ')"
	fi

	kill $kill_opt $PID_CONSUMERD 1> $OUTPUT_DEST 2> $ERROR_OUTPUT_DEST
	retval=$?

	if [ $? -eq 1 ]; then
		if [ $withtap -eq "1" ]; then
			fail "Kill consumer daemon"
		fi
		return 1
	else
		out=1
		while [ $out -ne 0 ]; do
			pid=$(pgrep -f $CONSUMERD_BIN[^\[])

			# If consumerds are still present check their status.
			# A zombie status qualifies the consumerd as *killed*
			out=0
			for consumer_pid in $pid; do
				state=$(ps -p $consumer_pid -o state= )
				if [[ -n "$state" && "$state" != "Z" ]]; then
					out=1
				fi
			done
			sleep 0.5
		done
		if [ $withtap -eq "1" ]; then
			pass "Kill consumer daemon"
		fi
	fi
	return $retval
}

function stop_lttng_consumerd()
{
	stop_lttng_consumerd_opt 1 "$@"
}

function stop_lttng_consumerd_notap()
{
	stop_lttng_consumerd_opt 0 "$@"
}

function sigstop_lttng_consumerd_opt()
{
	local withtap=$1
	local signal=SIGSTOP
	local kill_opt=""

	PID_CONSUMERD=`pgrep --full $CONSUMERD_BIN`

	kill_opt="$kill_opt -s $signal"

	if [ $withtap -eq "1" ]; then
		diag "Sending SIGSTOP to $CONSUMERD_BIN pids: $(echo $PID_CONSUMERD | tr '\n' ' ')"
	fi
	kill $kill_opt $PID_CONSUMERD 1> $OUTPUT_DEST 2> $ERROR_OUTPUT_DEST
	retval=$?
	set +x

	if [ $? -eq 1 ]; then
		if [ $withtap -eq "1" ]; then
			fail "Sending SIGSTOP to consumer daemon"
		fi
		return 1
	else
		out=1
		while [ $out -ne 0 ]; do
			pid=$(pgrep --full $CONSUMERD_BIN)

			# Wait until state becomes stopped for all
			# consumers.
			out=0
			for consumer_pid in $pid; do
				state=$(ps -p $consumer_pid -o state= )
				if [[ -n "$state" && "$state" != "T" ]]; then
					out=1
				fi
			done
			sleep 0.5
		done
		if [ $withtap -eq "1" ]; then
			pass "Sending SIGSTOP to consumer daemon"
		fi
	fi
	return $retval
}

function sigstop_lttng_consumerd()
{
	sigstop_lttng_consumerd_opt 1 "$@"
}

function sigstop_lttng_consumerd_notap()
{
	sigstop_lttng_consumerd_opt 0 "$@"
}

function list_lttng_with_opts ()
{
	local opts=$1
	$LTTNG list $opts 1> $OUTPUT_DEST 2> $ERROR_OUTPUT_DEST
	ok $? "Lttng-tool list command with option $opts"
}

function create_lttng_session_no_output ()
{
	local sess_name=$1

	$LTTNG create $sess_name --no-output 1> $OUTPUT_DEST 2> $ERROR_OUTPUT_DEST
	ok $? "Create session $sess_name in no-output mode"
}

function create_lttng_session ()
{
	local expected_to_fail=$1
	local sess_name=$2
	local trace_path=$3
	local opt="$4"

	if [[ ! -z $trace_path ]]; then
		trace_path="-o $trace_path"
	fi

	$LTTNG create $sess_name $trace_path $opt > $OUTPUT_DEST
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test "$ret" -ne "0"
		ok $? "Create session $sess_name in $trace_path failed as expected"
	else
		ok $ret "Create session $sess_name in $trace_path"
	fi
}

function create_lttng_session_ok ()
{
	create_lttng_session 0 "$@"
}

function create_lttng_session_fail ()
{
	create_lttng_session 1 "$@"
}


function enable_ust_lttng_channel ()
{
	local expected_to_fail=$1
	local sess_name=$2
	local channel_name=$3
	local opt=$4

	$LTTNG enable-channel -u $channel_name -s $sess_name $opt 1> $OUTPUT_DEST 2> $ERROR_OUTPUT_DEST
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test "$ret" -ne "0"
		ok $? "Enable channel $channel_name for session $sess_name failed as expected"
	else
		ok $ret "Enable channel $channel_name for session $sess_name"
	fi
}

function enable_ust_lttng_channel_ok ()
{
	enable_ust_lttng_channel 0 "$@"
}

function enable_ust_lttng_channel_fail ()
{
	enable_ust_lttng_channel 1 "$@"
}

function disable_ust_lttng_channel()
{
	local sess_name=$1
	local channel_name=$2

	$LTTNG disable-channel -u $channel_name -s $sess_name 1> $OUTPUT_DEST 2> $ERROR_OUTPUT_DEST
	ok $? "Disable channel $channel_name for session $sess_name"
}

function enable_lttng_mmap_overwrite_kernel_channel()
{
	local sess_name=$1
	local channel_name=$2

	$LTTNG enable-channel -s $sess_name $channel_name -k --output mmap --overwrite 1> $OUTPUT_DEST 2> $ERROR_OUTPUT_DEST
	ok $? "Enable channel $channel_name for session $sess_name"
}

function enable_lttng_mmap_overwrite_ust_channel()
{
	local sess_name=$1
	local channel_name=$2

	$LTTNG enable-channel -s $sess_name $channel_name -u --output mmap --overwrite 1> $OUTPUT_DEST 2> $ERROR_OUTPUT_DEST
	ok $? "Enable channel $channel_name for session $sess_name"
}

function enable_ust_lttng_event ()
{
	local expected_to_fail=$1
	local sess_name=$2
	local event_name="$3"
	local channel_name=$4

	if [ -z $channel_name ]; then
		# default channel if none specified
		chan=""
	else
		chan="-c $channel_name"
	fi

	$LTTNG enable-event "$event_name" $chan -s $sess_name -u 1> $OUTPUT_DEST 2> $ERROR_OUTPUT_DEST
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test $ret -ne "0"
		ok $? "Enable ust event $event_name for session $session_name failed as expected"
	else
		ok $ret "Enable ust event $event_name for session $sess_name"
	fi
}

function enable_ust_lttng_event_ok ()
{
	enable_ust_lttng_event 0 "$@"
}

function enable_ust_lttng_event_fail ()
{
	enable_ust_lttng_event 1 "$@"
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

	$LTTNG enable-event "$event_name" $chan -s $sess_name -j 1> $OUTPUT_DEST 2> $ERROR_OUTPUT_DEST
	ok $? "Enable JUL event $event_name for session $sess_name"
}

function enable_jul_lttng_event_loglevel()
{
	local sess_name=$1
	local event_name="$2"
	local loglevel=$3
	local channel_name=$4

	if [ -z $channel_name ]; then
		# default channel if none specified
		chan=""
	else
		chan="-c $channel_name"
	fi

	$LTTNG enable-event --loglevel $loglevel "$event_name" $chan -s $sess_name -j 1> $OUTPUT_DEST 2> $ERROR_OUTPUT_DEST
	ok $? "Enable JUL event $event_name for session $sess_name with loglevel $loglevel"
}

function enable_log4j_lttng_event()
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

	$LTTNG enable-event "$event_name" $chan -s $sess_name -l 1> $OUTPUT_DEST 2> $ERROR_OUTPUT_DEST
	ok $? "Enable LOG4J event $event_name for session $sess_name"
}

function enable_log4j_lttng_event_loglevel()
{
	local sess_name=$1
	local event_name="$2"
	local loglevel=$3
	local channel_name=$4

	if [ -z $channel_name ]; then
		# default channel if none specified
		chan=""
	else
		chan="-c $channel_name"
	fi

	$LTTNG enable-event --loglevel $loglevel "$event_name" $chan -s $sess_name -l 1> $OUTPUT_DEST 2> $ERROR_OUTPUT_DEST
	ok $? "Enable LOG4J event $event_name for session $sess_name with loglevel $loglevel"
}

function enable_python_lttng_event()
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

	$LTTNG enable-event "$event_name" $chan -s $sess_name -p 1> $OUTPUT_DEST 2> $ERROR_OUTPUT_DEST
	ok $? "Enable Python event $event_name for session $sess_name"
}

function enable_python_lttng_event_loglevel()
{
	local sess_name=$1
	local event_name="$2"
	local loglevel=$3
	local channel_name=$4

	if [ -z $channel_name ]; then
		# default channel if none specified
		chan=""
	else
		chan="-c $channel_name"
	fi

	$LTTNG enable-event --loglevel $loglevel "$event_name" $chan -s $sess_name -p 1> $OUTPUT_DEST 2> $ERROR_OUTPUT_DEST
	ok $? "Enable Python event $event_name for session $sess_name with loglevel $loglevel"
}

function enable_ust_lttng_event_filter()
{
	local sess_name="$1"
	local event_name="$2"
	local filter="$3"

	$LTTNG enable-event "$event_name" -s $sess_name -u --filter "$filter" 1> $OUTPUT_DEST 2> $ERROR_OUTPUT_DEST
	ok $? "Enable event $event_name with filtering for session $sess_name"
}

function enable_ust_lttng_event_loglevel()
{
	local sess_name="$1"
	local event_name="$2"
	local loglevel="$3"

	$LTTNG enable-event "$event_name" -s $sess_name -u --loglevel $loglevel 1> $OUTPUT_DEST 2> $ERROR_OUTPUT_DEST
	ok $? "Enable event $event_name with loglevel $loglevel"
}

function enable_ust_lttng_event_loglevel_only()
{
	local sess_name="$1"
	local event_name="$2"
	local loglevel="$3"

	$LTTNG enable-event "$event_name" -s $sess_name -u --loglevel-only $loglevel 1> $OUTPUT_DEST 2> $ERROR_OUTPUT_DEST
	ok $? "Enable event $event_name with loglevel-only $loglevel"
}

function disable_ust_lttng_event ()
{
	local sess_name="$1"
	local event_name="$2"
	local channel_name="$3"

	if [ -z $channel_name ]; then
		# default channel if none specified
		chan=""
	else
		chan="-c $channel_name"
	fi

	$LTTNG disable-event "$event_name" -s $sess_name $chan -u 1> $OUTPUT_DEST 2> $ERROR_OUTPUT_DEST
	ok $? "Disable event $event_name for session $sess_name"
}

function disable_jul_lttng_event ()
{
	local sess_name="$1"
	local event_name="$2"

	$LTTNG disable-event "$event_name" -s $sess_name -j >/dev/null 2>&1
	ok $? "Disable JUL event $event_name for session $sess_name"
}

function disable_log4j_lttng_event ()
{
	local sess_name="$1"
	local event_name="$2"

	$LTTNG disable-event "$event_name" -s $sess_name -l >/dev/null 2>&1
	ok $? "Disable LOG4J event $event_name for session $sess_name"
}

function disable_python_lttng_event ()
{
	local sess_name="$1"
	local event_name="$2"

	$LTTNG disable-event "$event_name" -s $sess_name -p 1> $OUTPUT_DEST 2> $ERROR_OUTPUT_DEST
	ok $? "Disable Python event $event_name for session $sess_name"
}

function start_lttng_tracing ()
{
	local expected_to_fail=$1
	local sess_name=$2

	$LTTNG start $sess_name 1> $OUTPUT_DEST 2> $ERROR_OUTPUT_DEST
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test "$ret" -ne "0"
		ok $? "Start tracing for session $sess_name failed as expected"
	else
		ok $ret "Start tracing for session $sess_name"
	fi
}

function start_lttng_tracing_ok ()
{
	start_lttng_tracing 0 "$@"
}

function start_lttng_tracing_fail ()
{
	start_lttng_tracing 1 "$@"
}

function stop_lttng_tracing ()
{
	local expected_to_fail=$1
	local sess_name=$2

	$LTTNG stop $sess_name 1> $OUTPUT_DEST 2> $ERROR_OUTPUT_DEST
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test "$ret" -ne "0"
		ok $? "Stop lttng tracing for session $sess_name failed as expected"
	else
		ok $ret "Stop lttng tracing for session $sess_name"
	fi
}

function stop_lttng_tracing_ok ()
{
	stop_lttng_tracing 0 "$@"
}

function stop_lttng_tracing_fail ()
{
	stop_lttng_tracing 1 "$@"
}

function destroy_lttng_session ()
{
	local expected_to_fail=$1
	local sess_name=$2

	$LTTNG destroy $sess_name 1> $OUTPUT_DEST 2> $ERROR_OUTPUT_DEST
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test "$ret" -ne "0"
		ok $? "Destroy session $sess_name failed as expected"
	else
		ok $ret "Destroy session $sess_name"
	fi
}

function destroy_lttng_session_ok ()
{
	destroy_lttng_session 0 "$@"

}

function destroy_lttng_session_fail ()
{
	destroy_lttng_session 1 "$@"
}


function destroy_lttng_sessions ()
{
	$LTTNG destroy --all 1> $OUTPUT_DEST 2> $ERROR_OUTPUT_DEST
	ok $? "Destroy all lttng sessions"
}

# The trace_path must be in an URI format
function lttng_snapshot_add_output ()
{
	local expected_to_fail=$1
	local sess_name=$2
	local trace_path=$3
	local name=$4
	local max_size=$5

	local extra_opt=""

	if [[ ! -z "$name" ]]; then
		extra_opt+="-n $name"
	fi

	if [[ ! -z "$max_size" ]]; then
		extra_opt+="-m $max_size"
	fi

	$LTTNG snapshot add-output \
		-s $sess_name $extra_opt $trace_path \
		1> $OUTPUT_DEST 2> $ERROR_OUTPUT_DEST
	ret=$?
	if [[ $expected_to_fail -eq 1 ]]; then
		test "$ret" -ne "0"
		ok $? "Added snapshot output $trace_path failed as expected (extra options $extra_opt)"
	else
		ok $ret "Added snapshot output $trace_path (extra options: $extra_opt)"
	fi
}

function lttng_snapshot_add_output_ok ()
{
	lttng_snapshot_add_output 0 "$@"
}

function lttng_snapshot_add_output_fail ()
{
	lttng_snapshot_add_output 1 "$@"
}

function lttng_snapshot_del_output ()
{
	local expected_to_fail=$1
	local sess_name=$2
	local id=$3

	$LTTNG snapshot del-output -s $sess_name $id 1> $OUTPUT_DEST 2> $ERROR_OUTPUT_DEST
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test "$ret" -ne "0"
		ok $? "Deleted snapshot output id $id failed as expected"
	else
		ok $ret "Deleted snapshot output id $id"
	fi
}

function lttng_snapshot_del_output_ok ()
{
	lttng_snapshot_del_output 0 "$@"
}

function lttng_snapshot_del_output_fail ()
{
	lttng_snapshot_del_output 1 "$@"
}

function lttng_snapshot_record ()
{
	local sess_name=$1
	local trace_path=$2

	$LTTNG snapshot record -s $sess_name 1> $OUTPUT_DEST 2> $ERROR_OUTPUT_DEST
	ok $? "Snapshot recorded"
}

function lttng_snapshot_list ()
{
	local sess_name=$1
	$LTTNG snapshot list-output -s $sess_name 1> $OUTPUT_DEST 2> $ERROR_OUTPUT_DEST
	ok $? "Snapshot list"
}

function lttng_save()
{
	local sess_name=$1
	local opts=$2

	$LTTNG save $sess_name $opts 1> $OUTPUT_DEST 2> $ERROR_OUTPUT_DEST
	ok $? "Session saved"
}

function lttng_load()
{
	local opts=$1

	$LTTNG load $opts 1> $OUTPUT_DEST 2> $ERROR_OUTPUT_DEST
	ok $? "Load command with opts: $opts"
}

function lttng_track()
{
	local expected_to_fail=$1
	local opts=$2
	$LTTNG track $opts >$OUTPUT_DEST
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test $ret -ne "0"
		ok $? "Track command failed as expected with opts: $opts"
	else
		ok $ret "Track command with opts: $opts"
	fi
}

function lttng_track_ok()
{
	lttng_track 0 "$@"
}

function lttng_track_fail()
{
	lttng_track 1 "$@"
}

function lttng_untrack()
{
	local expected_to_fail=$1
	local opts=$2
	$LTTNG untrack $opts >$OUTPUT_DEST
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test $ret -ne "0"
		ok $? "Untrack command failed as expected with opts: $opts"
	else
		ok $ret "Untrack command with opts: $opts"
	fi
}

function lttng_untrack_ok()
{
	lttng_untrack 0 "$@"
}

function lttng_untrack_fail()
{
	lttng_untrack 1 "$@"
}

function add_context_lttng()
{
	local expected_to_fail="$1"
	local domain="$2"
	local session_name="$3"
	local channel_name="$4"
	local type="$5"

	$LTTNG add-context -s $session_name -c $channel_name -t $type $domain  1> $OUTPUT_DEST 2> $ERROR_OUTPUT_DEST
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test $ret -ne "0"
		ok $? "Add context command failed as expected for type: $type"
	else
		ok $ret "Add context command for type: $type"
	fi
}

function add_context_ust_ok()
{
	add_context_lttng 0 -u "$@"
}

function add_context_ust_fail()
{
	add_context_lttng 1 -u "$@"
}

function add_context_kernel_ok()
{
	add_context_lttng 0 -k "$@"
}

function add_context_kernel_fail()
{
	add_context_lttng 1 -k "$@"
}

function trace_matches ()
{
	local event_name=$1
	local nr_iter=$2
	local trace_path=$3

	type $BABELTRACE >/dev/null
	skip $? -ne 0 "Babeltrace binary not found. Skipping trace matches"

	local count=$($BABELTRACE $trace_path | grep $event_name | wc -l)

	if [ "$count" -ne "$nr_iter" ]; then
		fail "Trace match"
		diag "$count events found in trace"
	else
		pass "Trace match"
	fi
}

function trace_match_only_opt()
{
	local remote=$1
	local event_name=$2
	local nr_iter=$3
	local trace_path=$4

	local babeltrace=$BABELTRACE

	if [ $remote -eq 1 -a ! -z "$REMOTE_RELAYD_TEST" ]; then
		if [[ "$BASE_COMMAND" == "$LOCAL_COMMAND" ]]; then
			fail "Match only remote trace: base command not overridden"
			return 1
		fi
		babeltrace="$REMOTE_BABELTRACE_PATH$REMOTE_BABELTRACE_BIN"
	fi

	$BASE_COMMAND "type $babeltrace >/dev/null"
	skip $? -ne 0 "Babeltrace binary not found. Skipping trace matches"

	local count=$($BASE_COMMAND "$babeltrace $trace_path" | grep $event_name | wc -l)
	local total=$($BASE_COMMAND "$babeltrace $trace_path" | wc -l)

	if [ "$nr_iter" -eq "$count" ] && [ "$total" -eq "$nr_iter" ]; then
		pass "Trace match with $total event $event_name"
	else
		fail "Trace match"
		diag "$total event(s) found, expecting $nr_iter of event $event_name and only found $count"
	fi
}

function trace_match_only()
{
	trace_match_only_opt 0 "$@"
}

function trace_match_only_remote_support()
{
	trace_match_only_opt 1 "$@"
}

function validate_trace_opt
{
	local remote=$1
	local event_name=$2
	local trace_path=$3

	local babeltrace=$BABELTRACE

	if [ $remote -eq 1 -a ! -z "$REMOTE_RELAYD_TEST" ]; then
		if [[ "$BASE_COMMAND" == "$LOCAL_COMMAND" ]]; then
			fail "Validate remote trace: base command not overridden"
			return 1
		fi
		babeltrace="$REMOTE_BABELTRACE_PATH$REMOTE_BABELTRACE_BIN"
	fi

	$BASE_COMMAND "type $babeltrace >/dev/null"
	if [ $? -ne 0 ]; then
	    skip 0 "Babeltrace binary not found. Skipping trace validation"
	fi

	OLDIFS="$IFS"
	IFS=","
	event_name=($event_name)
	IFS="$OLDIFS"

	for i in "${event_name[@]}"; do
		traced=$($BASE_COMMAND "$babeltrace $trace_path 2>/dev/null" | grep $i | wc -l)
		if [ "$traced" -ne 0 ]; then
			pass "Validate trace for event $i, $traced events (base command: $BASE_COMMAND)"
		else
			fail "Validate trace for event $i (base command: $BASE_COMMAND)"
			diag "Found $traced occurences of $i"
		fi
	done
	return $ret
}

function validate_trace()
{
	validate_trace_opt 0 "$@"
}

function validate_trace_remote_support()
{
	validate_trace_opt 1 "$@"
}

function validate_trace_exp()
{
	local event_exp=$1
	local trace_path=$2

	type $BABELTRACE >/dev/null
	skip $? -ne 0 "Babeltrace binary not found. Skipping trace validation"

	traced=$($BABELTRACE $trace_path 2>/dev/null | grep ${event_exp} | wc -l)
	if [ "$traced" -ne 0 ]; then
		pass "Validate trace for expression '${event_exp}', $traced events"
	else
		fail "Validate trace for expression '${event_exp}'"
		diag "Found $traced occurences of '${event_exp}'"
	fi
	ret=$?
	return $ret
}

function validate_trace_only_exp()
{
	local event_exp=$1
	local trace_path=$2

	type $BABELTRACE >/dev/null
	skip $? -ne 0 "Babeltrace binary not found. Skipping trace matches"

	local count=$($BABELTRACE $trace_path | grep ${event_exp} | wc -l)
	local total=$($BABELTRACE $trace_path | wc -l)

	if [ "$count" -ne 0 ] && [ "$total" -eq "$count" ]; then
		pass "Trace match with $total for expression '${event_exp}"
	else
		fail "Trace match"
		diag "$total syscall event(s) found, only syscalls matching expression '${event_exp}' ($count occurrences) are expected"
	fi
	ret=$?
	return $ret
}

function validate_trace_empty()
{
	local trace_path=$1

	type $BABELTRACE >/dev/null
	if [ $? -ne 0 ]; then
	    skip 0 "Babeltrace binary not found. Skipping trace validation"
	fi

	traced=$($BABELTRACE $trace_path 2>/dev/null | wc -l)
	if [ "$traced" -eq 0 ]; then
		pass "Validate empty trace"
	else
		fail "Validate empty trace"
		diag "Found $traced events in trace"
	fi
	ret=$?
	return $ret
}

function metadata_regenerate ()
{
	local expected_to_fail=$1
	local sess_name=$2

	$TESTDIR/../src/bin/lttng/$LTTNG_BIN metadata regenerate -s $sess_name 1> $OUTPUT_DEST 2> $ERROR_OUTPUT_DEST
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test "$ret" -ne "0"
		ok $? "Expected fail on regenerate $sess_name"
	else
		ok $ret "Metadata regenerate $sess_name"
	fi
}

function metadata_regenerate_ok ()
{
	metadata_regenerate 0 "$@"
}

function metadata_regenerate_fail ()
{
	metadata_regenerate 1 "$@"
}

function destructive_tests_enabled ()
{
	if [ ${LTTNG_ENABLE_DESTRUCTIVE_TESTS} = "will-break-my-system" ]; then
		return 0
	else
		return 1
	fi
}
