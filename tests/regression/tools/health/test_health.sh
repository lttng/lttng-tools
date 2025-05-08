# SPDX-FileCopyrightText: 2012 Christian Babeux <christian.babeux@efficios.com>
# SPDX-FileCopyrightText: 2014 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
#
# SPDX-License-Identifier: GPL-2.0-only

TESTDIR=${CURDIR}/../../..
UST_EVENT_NAME="tp:tptest"
KERNEL_EVENT_NAME="sched_switch"
CHANNEL_NAME="testchan"
HEALTH_CHECK_BIN="health_check"
NUM_TESTS=90
SLEEP_TIME=30

source $TESTDIR/utils/utils.sh

function report_errors
{
	test_thread_error_string="$1"
	test_relayd="$2"
	err_no_relayd_match="Error querying relayd health"

	# Check for health errors
	# Include inability to contact relayd health as an expected
	# error, since this can happen whenever the relayd shutdown due
	# to an error in any thread.
	out=$(grep "${test_thread_error_string}" ${STDOUT_PATH} | wc -l)
	if [ $test_relayd -ne 0 ]; then
		outerr=$(grep "${err_no_relayd_match}" ${STDERR_PATH} | wc -l)
	else
		outerr=0
	fi
	if [ $out -eq 0 ] && [ $outerr -eq 0 ]; then
		fail "Validation failure"
		diag "Health returned:"
		diag "stdout:"
		file=${STDOUT_PATH}
		while read line ; do
		    diag "$line"
		done < ${file}

		diag "stderr:"
		file=${STDERR_PATH}
		while read line ; do
		    diag "$line"
		done < ${file}
	else
		pass "Validation OK"
	fi
}

function test_health
{
	test_suffix="$1"
	test_thread_name="$2"
	test_thread_error_string="$3"
	test_needs_root="$4"
	test_consumerd="$5"
	test_relayd="$6"

	diag "Test health problem detection with ${test_thread_name}"

	# Set the socket timeout to 5 so the health check detection
	# happens within 25 s
	export LTTNG_NETWORK_SOCKET_TIMEOUT=5
	export LTTNG_RELAYD_HEALTH="${HEALTH_PATH}/test-health"

	# Activate testpoints
	export LTTNG_TESTPOINT_ENABLE=1

	# Activate specific thread test
	export ${test_thread_name}_${test_suffix}=1

	# Spawn sessiond with preloaded testpoint override lib
	export LD_PRELOAD="$CURDIR/$SESSIOND_PRELOAD"

	diag "Start session daemon"
	start_lttng_sessiond

	if [ ${test_consumerd} -eq 1 ]; then
		create_lttng_session_no_output $SESSION_NAME

		diag "With UST consumer daemons"
		enable_ust_lttng_event_ok $SESSION_NAME $UST_EVENT_NAME $CHANNEL_NAME

		check_skip_kernel_test "1" "Skipping kernel consumer health check test." ||
		{
			diag "With kernel consumer daemon"
			lttng_enable_kernel_event $SESSION_NAME $KERNEL_EVENT_NAME $CHANNEL_NAME
		}
		start_lttng_tracing_ok $SESSION_NAME
	fi

	if [ ${test_relayd} -eq 1 ]; then
		diag "With relay daemon"
		RELAYD_ARGS="--relayd-path=${LTTNG_RELAYD_HEALTH}"

		# When starting with the error test points the "start" can fail
		# or hang waiting for the PID file which got cleaned up quickly.
		# Use the background mode with no tap to avoid the hang and failure.
		start_lttng_relayd_opt 0 "-b" "-o $TRACE_PATH"
	else
		RELAYD_ARGS=
	fi

	# Check health status, not caring about result
	$CURDIR/$HEALTH_CHECK_BIN ${RELAYD_ARGS} \
		> /dev/null

	# Wait
	diag "Check after running for ${SLEEP_TIME} seconds"
	sleep ${SLEEP_TIME}

	# Check health status
	$CURDIR/$HEALTH_CHECK_BIN ${RELAYD_ARGS} \
		> ${STDOUT_PATH} 2> ${STDERR_PATH}


	if [ ${test_needs_root} -eq 1 ]; then
		check_skip_kernel_test "1" "Skipping \"${test_thread_name}\"." ||
		{
			report_errors "${test_thread_error_string}" "${test_relayd}"
		}
	else
		report_errors "${test_thread_error_string}" "${test_relayd}"
	fi

	if [ ${test_relayd} -eq 1 ]; then
		# We may fail to stop relayd here, and this is OK, since
		# it may have been killed volountarily by testpoint.
		stop_lttng_relayd_cleanup $KILL_SIGNAL
	fi

	if [ ${test_consumerd} -eq 1 ]; then
		stop_lttng_consumerd $KILL_SIGNAL
	fi
	stop_lttng_sessiond $KILL_SIGNAL

	unset LTTNG_TESTPOINT_ENABLE
	unset ${test_thread_name}_${test_suffix}
	unset LD_PRELOAD
	unset LTTNG_NETWORK_SOCKET_TIMEOUT
	unset LTTNG_RELAYD_HEALTH
}

plan_tests $NUM_TESTS

print_test_banner "$TEST_DESC"

if [ -f "$CURDIR/$SESSIOND_PRELOAD" ]; then
	foundobj=1
else
	foundobj=0
fi

skip $foundobj "No shared object generated. Skipping all tests." $NUM_TESTS && exit 0

THREAD=(
	"LTTNG_SESSIOND_THREAD_MANAGE_CLIENTS"
	"LTTNG_SESSIOND_THREAD_MANAGE_APPS"
	"LTTNG_SESSIOND_THREAD_REG_APPS"
	"LTTNG_SESSIOND_THREAD_APP_MANAGE_NOTIFY"
	"LTTNG_SESSIOND_THREAD_APP_REG_DISPATCH"
	"LTTNG_SESSIOND_THREAD_MANAGE_KERNEL"

	"LTTNG_CONSUMERD_THREAD_CHANNEL"
	"LTTNG_CONSUMERD_THREAD_METADATA"
	"LTTNG_CONSUMERD_THREAD_METADATA_TIMER"

	"LTTNG_RELAYD_THREAD_DISPATCHER"
	"LTTNG_RELAYD_THREAD_WORKER"
	"LTTNG_RELAYD_THREAD_LISTENER"
	"LTTNG_RELAYD_THREAD_LIVE_DISPATCHER"
	"LTTNG_RELAYD_THREAD_LIVE_WORKER"
	"LTTNG_RELAYD_THREAD_LIVE_LISTENER"
)

ERROR_STRING=(
	"Thread \"Session daemon command\" is not responding in component \"sessiond\"."
	"Thread \"Session daemon application manager\" is not responding in component \"sessiond\"."
	"Thread \"Session daemon application registration\" is not responding in component \"sessiond\"."
	"Thread \"Session daemon application notification manager\" is not responding in component \"sessiond\"."
	"Thread \"Session daemon application registration dispatcher\" is not responding in component \"sessiond\"."
	"Thread \"Session daemon kernel\" is not responding in component \"sessiond\"."

	"Thread \"Consumer daemon channel\" is not responding"
	"Thread \"Consumer daemon metadata\" is not responding"
	"Thread \"Consumer daemon metadata timer\" is not responding"

	"Thread \"Relay daemon dispatcher\" is not responding in component \"relayd\"."
	"Thread \"Relay daemon worker\" is not responding in component \"relayd\"."
	"Thread \"Relay daemon listener\" is not responding in component \"relayd\"."
	"Thread \"Relay daemon live dispatcher\" is not responding in component \"relayd\"."
	"Thread \"Relay daemon live worker\" is not responding in component \"relayd\"."
	"Thread \"Relay daemon live listener\" is not responding in component \"relayd\"."
)

# TODO
# "LTTNG_SESSIOND_THREAD_MANAGE_CONSUMER"
# "Thread \"Session daemon manage consumer\" is not responding in component \"sessiond\"."

# TODO: test kernel consumerd specifically in addition to UST consumerd

# TODO: need refactoring of consumerd teardown
# "LTTNG_CONSUMERD_THREAD_SESSIOND"
# "Thread \"Consumer daemon session daemon command manager\" is not responding"

# TODO: this thread is responsible for close a file descriptor that
# triggers teardown of metadata thread. We should revisit teardown of
# consumerd.
# "LTTNG_CONSUMERD_THREAD_DATA"
# "Thread \"Consumer daemon data\" is not responding"

NEEDS_ROOT=(
	0
	0
	0
	0
	0
	1

	0
	0
	0

	0
	0
	0
	0
	0
	0
)

TEST_CONSUMERD=(
	0
	0
	0
	0
	0
	0

	1
	1
	1

	1
	1
	1
	1
	1
	1
)

TEST_RELAYD=(
	0
	0
	0
	0
	0
	0

	0
	0
	0

	1
	1
	1
	1
	1
	1
)

STDOUT_PATH=$(mktemp -t tmp.test_health_stdout_path.XXXXXX)
STDERR_PATH=$(mktemp -t tmp.test_health_stderr_path.XXXXXX)
TRACE_PATH=$(mktemp -d -t tmp.test_health_trace_path.XXXXXX)
HEALTH_PATH=$(mktemp -d -t tmp.test_health_trace_path.XXXXXX)

THREAD_COUNT=${#THREAD[@]}
i=0
while [ "$i" -lt "$THREAD_COUNT" ]; do
	test_health "${TEST_SUFFIX}" \
		"${THREAD[$i]}" \
		"${ERROR_STRING[$i]}" \
		"${NEEDS_ROOT[$i]}" \
		"${TEST_CONSUMERD[$i]}" \
		"${TEST_RELAYD[$i]}"
	let "i++"
done

rm -rf ${HEALTH_PATH}
rm -rf ${TRACE_PATH}
rm -f ${STDOUT_PATH}
rm -f ${STDERR_PATH}
