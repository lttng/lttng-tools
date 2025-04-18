#!/bin/bash
#
# SPDX-FileCopyrightText: 2020 Jonathan Rajotte-Julien <jonathan.rajotte-julien@efficios.com>
#
# SPDX-License-Identifier: LGPL-2.1-only

GENERATOR_CURDIR=$(dirname "$0")/
GENERATOR_TESTDIR=$GENERATOR_CURDIR/../../../
TESTAPP_PATH=${TESTAPP_PATH:-"$GENERATOR_TESTDIR/utils/testapp"}

SYSCALL_TESTAPP_NAME=${SYSCALL_TESTAPP_NAME:-"gen-syscall-events"}
SYSCALL_TESTAPP_BIN=${SYSCALL_TESTAPP_BIN:-"$TESTAPP_PATH/$SYSCALL_TESTAPP_NAME/$SYSCALL_TESTAPP_NAME"}

USERSPACE_PROBE_ELF_TESTAPP_NAME=${USERSPACE_PROBE_ELF_TESTAPP_NAME:-"userspace-probe-elf-binary"}
USERSPACE_PROBE_ELF_TESTAPP_BIN=${USERSPACE_PROBE_ELF_TESTAPP_BIN:-"$TESTAPP_PATH/$USERSPACE_PROBE_ELF_TESTAPP_NAME/.libs/$USERSPACE_PROBE_ELF_TESTAPP_NAME"}

# shellcheck source=../utils/utils.sh
source "$GENERATOR_TESTDIR/utils/utils.sh"

function generate_filter_events
{
	local nr=$1
	/bin/echo -n "$nr" > /proc/lttng-test-filter-event 2> /dev/null
}

function generate_syscalls
{
	local nr=$1
	shift

	for _ in $(seq 1 "$nr"); do
		# Pass /dev/null so to generate the syscall right away.
		$SYSCALL_TESTAPP_BIN /dev/null "$@"
	done
}

function userspace_probe_testapp
{
	local nr=$1
	shift 

	for _ in $(seq 1 "$nr"); do
		# This userspace probe test has to instrument the actual elf
		# binary and not the generated libtool wrapper. However, we
		# can't invoke the wrapper either since it will re-link the test
		# application binary on its first invocation, resulting in a new
		# binary with an 'lt-*' prefix under the .libs folder. The
		# relinking stage adds the .libs folder to the 'lt-*' binary's
		# rpath.
		#
		# To ensure the binary (inode) that instrumented is the same as
		# what is running, set LD_LIBRARY_PATH to find the .libs folder
		# that contains the libfoo.so library and invoke the binary
		# directly.
		LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$TESTDIR/utils/testapp/userspace-probe-elf-binary/.libs" $USERSPACE_PROBE_ELF_TESTAPP_BIN "$@"
	done
}

function ust_event_generator_toggle_state
{
	ust_event_generator_suspended=$((ust_event_generator_suspended==0))
}

function reset_generator_quit
{
	generator_quit=0
}

# Note: Only one generator can be used at a time per domain type
function ust_event_generator_run_once_per_transition
{
	# Used by the signal trap
	ust_event_generator_suspended=0
	# Used by the signal trap for SIGUSR2 to end the generator
	generator_quit=1

	local test_app=$1
	local state_file=$2
	local nr_iter=$3
	local nr_usec_wait=$4
	local run=false

	# Pass any of the remaining arguments to the generator.
	shift 4

	trap ust_event_generator_toggle_state SIGUSR1
	trap reset_generator_quit SIGUSR2

	while [ $generator_quit -ne 0  ]; do
		if [[ $ust_event_generator_suspended -eq "1" ]]; then
			touch "$state_file"
			# Reset the "run" state
			run=true
			sleep 0.5
		elif [ "$run" = true ]; then
			retry_anycpu_taskset "$test_app" -i "$nr_iter" -w "$nr_usec_wait" "$@"
			run=false;
			if [[ -f $state_file ]]; then
				rm -rf "$state_file" 2> /dev/null
			fi
		else
			# Wait for a "suspend" to reset the run state
			sleep 0.1
		fi
	done

	trap SIGUSR1
	trap SIGUSR2
}

# Note: Only one generator can be used at a time per domain type
function ust_event_generator
{
	# Used by the signal trap
	ust_event_generator_suspended=0
	# Used by the signal trap for SIGUSR2 to end the generator
	generator_quit=1

	local test_app=$1
	local state_file=$2
	local nr_iter=1000
	local nr_usec_wait=5

	# Pass any of the remaining arguments to the generator.
	shift 2

	trap ust_event_generator_toggle_state SIGUSR1
	trap reset_generator_quit SIGUSR2

	while [ $generator_quit -ne 0 ]; do
		if [[ $ust_event_generator_suspended -eq "1" ]]; then
			touch "$state_file"
			# Reset the "run" state
			sleep 0.5
		else
			retry_anycpu_taskset "$test_app" -i $nr_iter -w $nr_usec_wait "$@"
			if [[ -f $state_file ]]; then
				rm -rf "$state_file" 2> /dev/null
			fi
		fi
	done

	trap SIGUSR1
	trap SIGUSR2
}

function kernel_event_generator_toggle_state
{
	kernel_event_generator_suspended=$((kernel_event_generator_suspended==0))
}

function kernel_event_generator_run_once_per_transition
{
	# Used by the signal trap
	kernel_event_generator_suspended=0
	# Used by the signal trap for SIGUSR2 to end the generator
	generator_quit=1

	local generator=$1
	local state_file=$2
	local nr_iter=$3

	# Pass any of the remaining arguments to the generator.
	shift 3

	local run=false
	trap kernel_event_generator_toggle_state SIGUSR1
	trap reset_generator_quit SIGUSR2

	while [ $generator_quit -ne 0 ]; do
		if [[ $kernel_event_generator_suspended -eq "1" ]]; then
			touch "$state_file"
			run=true
			sleep 0.5
		elif [ "$run" = true ]; then
			$generator "$nr_iter" "$@"
			run=false
			if [[ -f $state_file ]]; then
				rm "$state_file" 2> /dev/null
			fi
		else
			# Wait for a "suspend" to reset the run state
			sleep 0.1
		fi
	done

	trap SIGUSR1
	trap SIGUSR2
}

function kernel_event_generator
{
	# Used by the signal trap
	kernel_event_generator_suspended=0
	# Used by the signal trap for SIGUSR2 to end the generator
	generator_quit=1

	local generator=$1
	local state_file=$2

	# Pass any of the remaining arguments to the generator.
	shift 2

	trap kernel_event_generator_toggle_state SIGUSR1
	trap reset_generator_quit SIGUSR2

	while [ $generator_quit -ne 0 ]; do
		if [[ $kernel_event_generator_suspended -eq "1" ]]; then
			touch "$state_file"
			sleep 0.5
		else
			$generator "10" "$@"
			if [[ -f $state_file ]]; then
				rm "$state_file" 2> /dev/null
			fi
		fi
	done

	trap SIGUSR1
	trap SIGUSR2
}
