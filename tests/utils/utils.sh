#!/bin/bash
#
# SPDX-FileCopyrightText: 2012 David Goulet <dgoulet@efficios.com>
#
# SPDX-License-Identifier: LGPL-2.1-only
#
# shellcheck disable=SC2034 # This file is sourced, unused variables are expected

# Canonicalize paths to the test and build directories
ABS_TESTDIR=$(readlink -f "$TESTDIR")
ABS_BUILDDIR=$(readlink -f "$TESTDIR/..")

SESSIOND_BIN="lttng-sessiond"
SESSIOND_MATCH=".*lttng-sess.*"
SESSIOND_PATH="$ABS_BUILDDIR/src/bin/$SESSIOND_BIN/$SESSIOND_BIN"
RUNAS_BIN="lttng-runas"
RUNAS_MATCH=".*lttng-runas.*"
CONSUMERD_BIN="lttng-consumerd"
CONSUMERD_MATCH=".*lttng-consumerd.*"
CONSUMERD_PATH="$ABS_BUILDDIR/src/bin/$CONSUMERD_BIN/$CONSUMERD_BIN"
RELAYD_BIN="lttng-relayd"
RELAYD_MATCH=".*lttng-relayd.*"
RELAYD_PATH="$ABS_BUILDDIR/src/bin/$RELAYD_BIN/$RELAYD_BIN"
LTTNG_BIN="lttng"
LTTNG_PATH="$ABS_BUILDDIR/src/bin/$LTTNG_BIN/$LTTNG_BIN"
BABELTRACE_BIN="babeltrace2"
LTTNG_TEST_LOG_DIR="${LTTNG_TEST_LOG_DIR:-}"
LTTNG_TEST_GDBSERVER_RELAYD="${LTTNG_TEST_GDBSERVER_RELAYD:-}"
LTTNG_TEST_GDBSERVER_RELAYD_PORT="${LTTNG_TEST_GDBSERVER_RELAYD_PORT:-1025}"
LTTNG_TEST_GDBSERVER_RELAYD_WAIT="${LTTNG_TEST_GDBSERVER_RELAYD_WAIT:-}"
LTTNG_TEST_GDBSERVER_SESSIOND="${LTTNG_TEST_GDBSERVER_SESSIOND:-}"
LTTNG_TEST_GDBSERVER_SESSIOND_PORT="${LTTNG_TEST_GDBSERVER_SESSIOND_PORT:-1024}"
LTTNG_TEST_GDBSERVER_SESSIOND_WAIT="${LTTNG_TEST_GDBSERVER_SESSIOND_WAIT:-}"
LTTNG_TEST_VERBOSE_BABELTRACE="${LTTNG_TEST_VERBOSE_BABELTRACE:-}"
LTTNG_TEST_BABELTRACE_VERBOSITY="${LTTNG_TEST_BABELTRACE_VERBOSITY:-I}"
LTTNG_TEST_VERBOSE_CLIENT="${LTTNG_TEST_VERBOSE_CLIENT:-}"
LTTNG_TEST_VERBOSE_RELAYD="${LTTNG_TEST_VERBOSE_RELAYD:-}"
LTTNG_TEST_VERBOSE_SESSIOND="${LTTNG_TEST_VERBOSE_SESSIOND:-}"
OUTPUT_DEST="${OUTPUT_DEST:-}"  # For 'lttng', some scripts set this to catch a command output
ERROR_OUTPUT_DEST="${ERROR_OUTPUT_DEST:-}"  # For 'lttng', some scripts set this to catch a command error output
MI_XSD_MAJOR_VERSION=4
MI_XSD_MINOR_VERSION=1
MI_XSD_PATH="$ABS_BUILDDIR/src/common/mi-lttng-${MI_XSD_MAJOR_VERSION}.${MI_XSD_MINOR_VERSION}.xsd"
MI_VALIDATE_BIN="$ABS_TESTDIR/utils/xml-utils/validate_xml"

XML_PRETTY="$ABS_TESTDIR/utils/xml-utils/pretty_xml"
XML_EXTRACT="$ABS_TESTDIR/utils/xml-utils/extract_xml"
XML_NODE_CHECK="${XML_EXTRACT} -e"

declare -a LTTNG_RELAYD_PIDS
declare -a LTTNG_SESSIOND_PIDS

# To match 20201127-175802
DATE_TIME_PATTERN="[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9][0-9][0-9]"
# The size of a long on this system
SYSTEM_LONG_BIT_SIZE=$(getconf LONG_BIT)

# Minimal kernel version supported for session daemon tests
KERNEL_MAJOR_VERSION=2
KERNEL_MINOR_VERSION=6
KERNEL_PATCHLEVEL_VERSION=27

# We set the default UST register timeout and network and app socket timeout to
# "wait forever", so that basic tests don't have to worry about hitting
# timeouts on busy systems. Specialized tests should test those corner-cases.
export LTTNG_UST_REGISTER_TIMEOUT=-1
export LTTNG_NETWORK_SOCKET_TIMEOUT=-1
export LTTNG_APP_SOCKET_TIMEOUT=-1

# We set the default lttng-sessiond path to /bin/true to prevent the spawning
# of a daemonized sessiond. This is necessary since 'lttng create' will spawn
# its own sessiond if none is running. It also ensures that 'lttng create'
# fails when no sessiond is running.
export LTTNG_SESSIOND_PATH="/bin/true"

# shellcheck source-path=SCRIPTDIR/..
source "$TESTDIR/utils/tap/tap.sh"

if [ -z ${LTTNG_TEST_TEARDOWN_TIMEOUT+x} ]; then
	LTTNG_TEST_TEARDOWN_TIMEOUT=60
fi

# Some tests use recent bash syntax, e.g. `array_var[-1]` which was introduced
# in version 4.2. Bailout with a clear error if the bash version isn't supported.
if [[ "${BASH_VERSINFO[0]}" -lt "4" ]] || [[ "${BASH_VERSINFO[0]}" == "4" && "${BASH_VERSINFO[1]}" -lt "2" ]]; then
	BAIL_OUT "Bash version '${BASH_VERSION}' is not supported by the test suite"
fi

if [[ -z "${HOSTNAME}" ]]; then
	# If bash has not set the built-in HOSTNAME variable, try using
	# hostname and uname.
	HOSTNAME="$(hostname)"
	if [[ -z "${HOSTNAME}" ]]; then
		HOSTNAME="$(uname -n)"
	fi
fi

if [[ -z "${HOSTNAME}" ]]; then
	echo "Error: HOSTNAME variable not set" >&2
	exit 1
fi

# Enable job monitor mode.
# Here we are mostly interested in the following from the monitor mode:
#    All processes run in a separate process group.
# This allows us to ensure that all subprocesses from all background tasks are
# cleaned up correctly using signal to process group id.
set -m

kill_background_jobs ()
{
	local pids
	pids=$(jobs -p)

	if [ -z "$pids" ]; then
		# Empty
		return 0
	fi

	while read -r pid;
	do
		# Use negative number to send the signal to the process group.
		# This ensure that any subprocesses receive the signal.
		# /dev/null is used since there is an acceptable race between
		# the moments the pids are listed and the moment we send a
		# signal.
		kill -SIGTERM -- "-$pid" 2>/dev/null
	done <<< "$pids"
}

function cleanup ()
{
	# Try to kill daemons gracefully
	stop_lttng_relayd_cleanup SIGTERM "$LTTNG_TEST_TEARDOWN_TIMEOUT"
	stop_lttng_sessiond_cleanup SIGTERM "$LTTNG_TEST_TEARDOWN_TIMEOUT"

	# If daemons are still present, forcibly kill them
	stop_lttng_relayd_cleanup SIGKILL "$LTTNG_TEST_TEARDOWN_TIMEOUT"
	stop_lttng_sessiond_cleanup SIGKILL "$LTTNG_TEST_TEARDOWN_TIMEOUT"
	stop_lttng_consumerd_cleanup SIGKILL "$LTTNG_TEST_TEARDOWN_TIMEOUT"

	kill_background_jobs
}

function full_cleanup ()
{
	cleanup
	exit 1
}

function LTTNG_BAIL_OUT ()
{
	cleanup
	BAIL_OUT "$@"
}

function null_pipes ()
{
	exec 0>/dev/null
	exec 1>/dev/null
	exec 2>/dev/null
}

trap full_cleanup SIGINT SIGTERM

# perl prove closes its child pipes before giving it a chance to run its
# signal trap handlers. Redirect pipes to /dev/null if SIGPIPE is caught
# to allow those trap handlers to proceed.

trap null_pipes SIGPIPE

# Check pgrep from env, default to pgrep if none
if [ -z "$PGREP" ]; then
	PGREP=pgrep
fi

# If the 'realpath' command is available, return a path relative to the top
# project directory. Otherwise, return the path as-is.
function get_path_from_top_dir() {
	if ! command -v realpath >/dev/null 2>&1; then
		echo "$1"
	fi

	realpath --relative-to="$ABS_BUILDDIR" "$1"
}

function lttng_default_rundir () {
	if [ "${UID}" == "0" ] ; then
		echo "/var/run/lttng"
	else
		echo "${LTTNG_HOME:-$HOME}/.lttng"
	fi
}

function _lttng_client_log_file ()
{
	local output_dest="${1}"
	if [[ -n "${output_dest}" ]]; then
		if [[ "${output_dest}" != "-" ]]; then
			echo "${output_dest}"
		fi
	elif [[ -n "${LTTNG_TEST_LOG_DIR}" ]]; then
		if [[ "${LTTNG_TEST_LOG_DIR}" != "-" ]]; then
			mktemp -p "${LTTNG_TEST_LOG_DIR}" -t "lttng.XXXXXX"
		fi
	else
		echo "/dev/null"
	fi
}

function lttng_client_log_file ()
{
	_lttng_client_log_file "${OUTPUT_DEST}"
}

function lttng_client_err_file ()
{
	_lttng_client_log_file "${ERROR_OUTPUT_DEST}"
}

function lttng_log_file ()
{
	local app="${1:-}"
	if [[ -z "${app}" ]] || [[ -z "${LTTNG_TEST_LOG_DIR}" ]]; then
		echo "/dev/null"
		return
	fi

	if [[ "${LTTNG_TEST_LOG_DIR}" == "-" ]]; then
		return
	fi

	mktemp -p "${LTTNG_TEST_LOG_DIR}" -t "${app}.logfile.XXXXXX"
}

# Due to the renaming of threads we need to use the full command (pgrep -f) to
# identify the pids for multiple lttng related processes. The problem with "pgrep
# -f" is that it ends up also looking at the arguments. We use a two stage
# lookup. The first one is using "pgrep -f" yielding potential candidate.
# The second on perform grep on the basename of the first field of the
# /proc/pid/cmdline of the previously identified pids. The first field
# correspond to the actual command.
function lttng_pgrep ()
{
	local pattern=$1
	local possible_pids
	local full_command_no_argument
	local command_basename

	possible_pids=$($PGREP -f "$pattern" -u "${UID}")
	if [ -z "$possible_pids" ]; then
		return 0
	fi

	while IFS= read -r pid ; do
		# /proc/pid/cmdline is null separated.
		if full_command_no_argument=$( (tr '\0' '\n' < /proc/"$pid"/cmdline) 2>/dev/null | head -n1); then
			command_basename=$(basename "$full_command_no_argument")
			if grep -q "$pattern" <<< "$command_basename"; then
				echo "$pid"
			fi
		fi
	done <<< "$possible_pids"
	return 0
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

# Print the file line by line to stdout prepended with '#'
function file_to_diag ()
{
	local file=$1

	if [ ! -f "$file" ]; then
		diag "File '$file' doesn't exist"
		return
	fi

	if [ ! -s "$file" ]; then
		diag "**EMPTY**"
		return
	fi

	while read -r line; do
		diag "$line"
	done < "$file"
}

function validate_kernel_version ()
{
	local kern_version

	# shellcheck disable=SC2207
	kern_version=($(uname -r | awk -F. '{ printf("%d\n%d\n%d\n",$1,$2,$3); }'))
	if [ "${kern_version[0]}" -gt $KERNEL_MAJOR_VERSION ]; then
		return 0
	fi
	if [ "${kern_version[1]}" -gt $KERNEL_MINOR_VERSION ]; then
		return 0
	fi
	if [ "${kern_version[2]}" -ge $KERNEL_PATCHLEVEL_VERSION ]; then
		return 0
	fi

	return 1
}

# Generate a random string
#  $1 = number of characters; defaults to 16
#  $2 = include special characters; 1 = yes, 0 = no; defaults to yes
function randstring()
{
	local len="${1:-16}"

	[ "$2" == "0" ] && CHAR="[:alnum:]" || CHAR="[:graph:]"
	# /dev/urandom isn't guaranteed to generate valid multi-byte characters.
	# Specifying the C locale eliminates the "Illegal byte sequence" error
	# that 'tr' outputs in such cases.
	LC_CTYPE=C tr -cd "$CHAR" < /dev/urandom 2>/dev/null | head -c "$len" 2>/dev/null
	echo
}

function get_pipe_max_size()
{
	if grep -q 'FreeBSD' /etc/os-release ; then
		# Kernel configuration dependant, but defaults to 64 * 1024
		# https://github.com/freebsd/freebsd-src/blob/5b0dc991093c82824f6fe566af947f64f5072264/sys/sys/pipe.h#L33
		echo 65536
	else
		cat /proc/sys/fs/pipe-max-size
	fi
}

# Return a space-separated string of online CPU IDs, based on
# /sys/devices/system/cpu/online, or from 0 to nproc - 1 otherwise.
function get_online_cpus()
{
	local cpus=()
	local range_re
	if [ -f /sys/devices/system/cpu/online ]; then
		range_re='([0-9]+)-([0-9]+)'
		while read -r range ; do
			if [[ "${range}" =~ ${range_re} ]] ; then
				mapfile -t -O "${#cpus[*]}" cpus <<< $(seq "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}")
			else
				cpus+=("${range}")
			fi
		done < <(tr ',' $'\n' < /sys/devices/system/cpu/online)
	else
		read -r -a cpus <<< $(seq 0 $(( $(conf_proc_count) - 1 )) )
	fi
	echo "${cpus[*]}"
}

# Helpers for get_possible_cpus.
function get_possible_cpus_count_from_sysfs_possible_mask()
{
	local max_possible_cpu_id

	# The Awk script extracts the highest CPU id from the possible CPU
	# mask. Assuming a numerical order, a field separator '-' and a record
	# separator ','. The last value parsed is the highest id.
	if [ -f /sys/devices/system/cpu/possible ]; then
		max_possible_cpu_id=$(awk -F '-' 'BEGIN { RS = ","} { last = $NF } END { printf("%d\n", last) }' \
				      /sys/devices/system/cpu/possible)
		echo "$((max_possible_cpu_id+1))"
	else
		echo "0"
	fi
}

# This is a fallback if the possible CPU mask is not available. This will not
# take into account unplugged CPUs.
function get_max_cpus_count_from_sysfs_cpu_directories()
{
	local max_possible_cpu_id=0
	local current_cpu_id

	for i in /sys/devices/system/cpu/cpu[0-9]*; do
		current_cpu_id="${i#/sys/devices/system/cpu/cpu}"
		if [ "$current_cpu_id" -gt "$max_possible_cpu_id" ]; then
			max_possible_cpu_id="$current_cpu_id"
		fi
	done

	echo "$((max_possible_cpu_id+1))"
}

# Return the number of possible CPUs.
function get_possible_cpus_count()
{
	local possible_cpus_count
	possible_cpus_count=$(get_possible_cpus_count_from_sysfs_possible_mask)

	if [ "$possible_cpus_count" -eq "0" ]; then
		local configured_cpus_count
		configured_cpus_count=$(getconf _NPROCESSORS_CONF)
		possible_cpus_count=$(get_max_cpus_count_from_sysfs_cpu_directories)
		possible_cpus_count=$((configured_cpus_count > possible_cpus_count \
							     ? configured_cpus_count \
							     : possible_cpus_count))
	fi

	echo "$possible_cpus_count"
}

# Return the list of exposed CPU.
#
# NOTE! Use it like so:
#
# IFS=" " read -r -a VARIABLE <<< "$(get_exposed_cpus_list)"
function get_exposed_cpus_list()
{
	local list=()

	for i in /sys/devices/system/cpu/cpu[0-9]*; do
		list+=("${i#/sys/devices/system/cpu/cpu}")
	done

	echo "${list[@]}"
}

# Print the first available CPU found to stdout. Do not make assumptions about
# the returned value, e.g. that it could be 0.
function get_any_available_cpu()
{
	for cpu in $(get_online_cpus); do
		echo "${cpu}"
		break;
	done
}

# Print the number of _configured_ CPUs to stdout.
function conf_proc_count()
{
	if ! getconf _NPROCESSORS_CONF; then
		diag "Failed to get the number of configured CPUs"
	fi
	echo
}

# Taskset that retries if the cpuset isn't available
function retry_anycpu_taskset()
{
	local err_output
	local retry=y
	local ret=0
	local c
	local taskset_options='-c'

	if [[ "${#@}" == "1" && "${1}" =~ [0-9]+ ]]; then
		taskset_options='-cp'
	fi

	err_output="$(mktemp -t "tmp.${FUNCNAME[0]}_stderr.XXXXXX")"
	while [[ -n "${retry}" ]]; do
		c="$(get_any_available_cpu)"
		taskset "${taskset_options}" "${c}" "${@}" 2> "${err_output}"
		ret=$?
		if [[ "${ret}" != "0" ]] ; then
			if grep -qE '^taskset: failed.*$' "${err_output}" ; then
				diag "'taskset ${taskset_options} ${c}' failed. Online CPUs: $(get_online_cpus)"
			else
				retry=
				diag "$(cat "${err_output}")"
			fi
		else
			# In some cases it's possible that the application started with
			# the given taskset, but the CPU chosen goes quickly offline before
			# the process finishes.
			#
			# In such a case, the processes are migrated and the CPU masks
			# updated to a default value, e.g. 0xFFFFFF such that they may
			# be scheduled anywhere.
			#
			local cpu_still_online=
			diag "Online CPUs: $(get_online_cpus)"
			while read -r -d ' ' cpu; do
				if [[ "${c}" == "${cpu}" ]]; then
					cpu_still_online=y
					break
				fi
			done <<< "$(get_online_cpus)"
			if [[ "${cpu_still_online}" == "y" ]] ; then
				retry=
			else
				diag "CPU ${c} is offline since taskset was run, retrying"
			fi
		fi
	done
	rm -f "${err_output}"
	return "${ret}"
}

function check_skip_long_regression_tests()
{
	local num_tests="${1}"
	local skip_message="LTTNG_TOOLS_RUN_TESTS_LONG_REGRESSION is not set to a non-empty value that is not '0'.${2+ }${2}"

	val="${LTTNG_TOOLS_RUN_TESTS_LONG_REGRESSION:-}"
	if [[ -n "${val}" ]] && [[ "${val}" != "0" ]]; then
		return 1
	fi

	if [[ -n "${num_tests}" ]]; then
		skip 0 "${skip_message}" "${num_tests}"
	else
		diag "${skip_message}"
	fi
	return 0
}

# Usage: is_pid_alive PID
#  Returns zero if the PID is alive
function is_pid_alive()
{
	local pid=$1

	kill -0 "$pid" >/dev/null 2>&1
}


# Usage: app_alive_wait_for_sync APP_NAME PID TIMEOUT OUTPUT_FILE SYNC_FILE
#
#  Until the timeout of TIMEOUT seconds, check that PID is alive and wait for
#  SYNC_FILE to be created on disk. On timeout, attempt to kill the app.
#
#  Returns zero on success.
#
function app_alive_wait_for_sync()
{
	local app_name=$1
	local pid=$2
	local timeout_sec=$3
	local output_file=$4
	local sync_file=$5

	local ret

	while true; do
		is_pid_alive "$pid"
		ret=$?

		if [ $ret != 0 ]; then
			fail "Testapp '$app_name' exited before sync"
			diag "Testapp output:"
			file_to_diag "$output_file"
			break
		fi

		if [ -f "${sync_file}" ]; then
			pass "Testapp '$app_name' sync"
			ret=0
			break
		fi

		if [ "$timeout_sec" -le 0 ]; then
			fail "Timeout waiting for testapp '$app_name' sync"
			diag "Killing testapp '$app_name' (pid: $pid)"
			kill -SIGKILL "$pid"
			diag "Testapp output:"
			file_to_diag "$output_file"
			ret=1
			break
		fi

		diag "Waiting for testapp '$app_name' sync... (Timeout in $timeout_sec seconds)"

		timeout_sec=$(( timeout_sec - 1 ))
		sleep 1
	done

	return "$ret"
}

# Usage: app_exit_wait_for_sync APP_NAME PID TIMEOUT OUTPUT_FILE SYNC_FILE
#
#  Until the timeout of TIMEOUT seconds, wait for PID to exit and SYNC_FILE to
#  be created on disk. On timeout, attempt to kill the app.
#
#  Returns zero on success.
#
function app_exit_wait_for_sync()
{
	local app_name=$1
	local pid=$2
	local timeout_sec=$3
	local output_file=$4
	local sync_file=$5

	local ret

	while true; do
		is_pid_alive "$pid"
		ret=$?

		# Check if the testapp has exited
		if [ $ret != 0 ]; then
			# Then check if the sync file was created
			test -f "${sync_file}"
			ret=$?
			ok "$ret" "Testapp '$app_name' created sync file and exited"
			break
		fi

		if [ "$timeout_sec" -le 0 ]; then
			fail "Timeout waiting for testapp '$app_name' to exit"
			diag "Killing testapp '$app_name' (pid: $pid)"
			kill -9 "$pid"
			ret=1
			break
		fi

		diag "Waiting for testapp '$app_name' to exit... (Timeout in $timeout_sec seconds)"

		timeout_sec=$(( timeout_sec - 1 ))
		sleep 1
	done

	if [ "$ret" != "0" ]; then
		diag "Testapp output:"
		file_to_diag "$output_file"
	fi

	return "$ret"
}

# Usage: run_testapp_ok OUTPUT_FILE TESTAPP_PATH [Options...]
function run_testapp_ok()
{
	local file_testapp_output=$1
	local testapp_path=$2
	local testapp_opts=("${@:3}")

	local ret

	diag "Run: $(get_path_from_top_dir "$testapp_path") ${testapp_opts[*]}"
	"$testapp_path" "${testapp_opts[@]}" >"${file_testapp_output}" 2>&1
	ret=$?

	ok $ret "Testapp exit with success"

	if [ "$ret" != 0 ]; then
		diag "Testapp output:"
		file_to_diag "$file_testapp_output"
	fi
}

# Usage:
# check_skip_kernel_test [NB_TESTS] [SKIP_MESSAGE]
# Return 0 if LTTNG_TOOLS_DISABLE_KERNEL_TESTS was set or the current user is not a root user
# If NB_TESTS is set, call skip() to skip number of tests.
# If NB_TESTS is empty, just output a reason with diag.
# An optional message can be added.

function check_skip_kernel_test ()
{
	local num_tests="$1"
	local skip_message="$2"

	# Check for skip test kernel flag
	if [ "$LTTNG_TOOLS_DISABLE_KERNEL_TESTS" == "1" ]; then
		if ! test -z "$num_tests"; then
			skip 0 "LTTNG_TOOLS_DISABLE_KERNEL_TESTS was set.${skip_message+ }${skip_message}" "$num_tests"
		else
			diag "LTTNG_TOOLS_DISABLE_KERNEL_TESTS was set.${skip_message+ }${skip_message}"
		fi
		return 0
	fi

	# Check if we are running as root
	if [ "$(id -u)" != "0" ]; then
		if ! test -z "$num_tests"; then
			skip 0 "Root access is needed for kernel testing.${skip_message+ }${skip_message}" "$num_tests"
		else
			diag "Root access is needed for kernel testing.${skip_message+ }${skip_message}"
		fi
		return 0
	fi

	return 1
}


function check_skip_kernel_long_regression_tests()
{
	local num_tests="$1"
	local skip_message="Kernel long regression tests disabled.${2+ }${2}"

	if check_skip_long_regression_tests "" "" || check_skip_kernel_test "" "" ; then
		if [[ -n "${num_tests}" ]]; then
			skip 0 "${skip_message}" "${num_tests}"
		else
			diag "${skip_message}"
		fi
		return 0
	fi
	return 1

}

# Check if base lttng-modules are present.
# Bail out on failure
function validate_lttng_modules_present ()
{
	# Check for loadable modules.
	if modprobe -n lttng-tracer 2>/dev/null; then
		return 0
	fi

	# Check for builtin modules.
	if ls /proc/lttng >/dev/null 2>&1; then
		return 0
	fi

	LTTNG_BAIL_OUT "LTTng modules not detected."
}

# Run the babeltrace binary
function _run_babeltrace_cmd ()
{
	local err_log
	local opts

	err_log="$(lttng_log_file babeltrace.err)"

	opts=("${@}")
	if [[ -n "${LTTNG_TEST_VERBOSE_BABELTRACE}" ]]; then
		opts=('-l' "${LTTNG_TEST_BABELTRACE_VERBOSITY}" "${opts[@]}")
	fi

	diag "${BABELTRACE_BIN} ${opts[*]}  # Error log: '${err_log:-N/A}'" >&2
	if [[ -n "${err_log}" ]]; then
		"${BABELTRACE_BIN}" "${opts[@]}" 2>"${err_log}"
	else
		"${BABELTRACE_BIN}" "${opts[@]}"
	fi
}

function _lttng_modules_loaded_opt
{
	local fail_when_present="${1}"
	local module_count
	local ret
	local message="%d LTTng modules loaded, expected count "

	check_skip_kernel_test 1 && return
	if [[ "${fail_when_present}" -eq "1" ]] ; then
		message+="= 0"
	else
		message+="> 0"
	fi

	grep -q -E '^lttng' '/proc/modules'
	ret="${?}"
	module_count="$(grep -c -E '^lttng' '/proc/modules')"

	# shellcheck disable=SC2059
	is "${ret}" "${fail_when_present}" "$(printf "${message}" "${module_count}")"
}

# Pass if any lttng modules are loaded
function lttng_modules_loaded_ok()
{
	_lttng_modules_loaded_opt 0
}

# Fail if any lttng modules are loaded
function lttng_modules_loaded_fail()
{
	_lttng_modules_loaded_opt 1
}

# Run the lttng binary.
#
# The first two arguments are stdout and stderr redirect paths, respectively.
# The rest of the arguments are forwarded to the lttng binary
function _run_lttng_cmd
{
	local stdout_dest="$1"
	local stderr_dest="$2"
	local opts=("${@:3}")

	if [[ -n "${LTTNG_TEST_MI_CLIENT}" ]] ; then
		opts=('--mi' "xml" "${opts[@]}")
	fi

	if [[ -n "${LTTNG_TEST_VERBOSE_CLIENT}" ]] ; then
		opts=('-vvv' "${opts[@]}")
	fi

	diag "Run: $(get_path_from_top_dir "$LTTNG_PATH") ${opts[*]}"
	if [[ -n "${stdout_dest}" ]] && [[ -n "${stderr_dest}" ]] ; then
		if [[ "${stdout_dest}" == "${stderr_dest}" ]] ; then
			"$LTTNG_PATH" "${opts[@]}" >"${stdout_dest}" 2>&1
		else
			"$LTTNG_PATH" "${opts[@]}" >"${stdout_dest}" 2>"${stderr_dest}"
		fi
	elif [[ -n "${stdout_dest}" ]] && [[ -z "${stderr_dest}" ]]; then
		"$LTTNG_PATH" "${opts[@]}" >"${stdout_dest}"
	elif [[ -z "${stdout_dest}" ]] && [[ -n "${stderr_dest}" ]] ; then
		"$LTTNG_PATH" "${opts[@]}" 2>"${stderr_dest}"
	else
		"$LTTNG_PATH" "${opts[@]}"
	fi
}

function lttng_mi_validate()
{
	"${MI_VALIDATE_BIN}" "${MI_XSD_PATH}" "$@"
}

function enable_kernel_lttng_event
{
	local withtap="$1"
	local expected_to_fail="$2"
	local sess_name="$3"
	local event_name="$4"
	local channel_name="$5"

	local ret

	if [ -z "$event_name" ]; then
		# Enable all event if no event name specified
		event_name="-a"
	fi

	local chan_opt=()

	# default channel if none specified
	if [ -n "$channel_name" ]; then
		chan_opt=("-c" "$channel_name")
	fi

	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" \
		enable-event "$event_name" "${chan_opt[@]}" -s "$sess_name" -k
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test $ret -ne "0"
		ret=$?
		if [ "$withtap" -eq "1" ]; then
			ok $ret "Enable kernel event '$event_name' for session '$sess_name' on channel '$channel_name' failed as expected"
		fi
	else
		if [ "$withtap" -eq "1" ]; then
			ok $ret "Enable kernel event '$event_name for session '$sess_name' on channel '$channel_name'"
		fi
	fi
}

function enable_kernel_lttng_event_ok ()
{
	enable_kernel_lttng_event 1 0 "$@"
}

function enable_kernel_lttng_event_fail ()
{
	enable_kernel_lttng_event 1 1 "$@"
}

function enable_kernel_lttng_event_notap ()
{
	enable_kernel_lttng_event 0 0 "$@"
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

	local ret

	if [ -z "$syscall_name" ]; then
		# Enable all event if no syscall name specified
		syscall_name="-a"
	fi

	local chan_opt=()

	# default channel if none specified
	if [ -n "$channel_name" ]; then
		chan_opt=("-c" "$channel_name")
	fi

	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" \
		enable-event --syscall "$syscall_name" "${chan_opt[@]}" -s "$sess_name" -k
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test $ret -ne "0"
		ok $? "Enable kernel syscall '$syscall_name' for session '$sess_name' on channel '$channel_name' fail as expected"
	else
		ok $ret "Enable kernel syscall '$syscall_name' for session '$sess_name' on channel '$channel_name'"
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

	local ret

	if [ -z "$syscall_name" ]; then
		# Enable all event if no syscall name specified
		syscall_name="-a"
	fi

	local chan_opt=()

	# default channel if none specified
	if [ -n "$channel_name" ]; then
		chan_opt=("-c" "$channel_name")
	fi

	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" \
		disable-event --syscall "$syscall_name" "${chan_opt[@]}" -s "$sess_name" -k

	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test $ret -ne "0"
		ok $? "Disable kernel syscall '$syscall_name' for session '$sess_name' on channel '$channel_name' failed as expected"
	else
		ok $ret "Disable kernel syscall '$syscall_name' for session '$sess_name' on channel '$channel_name'"
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

function lttng_enable_kernel_function_event ()
{
	local expected_to_fail="$1"
	local sess_name="$2"
	local target="$3"
	local event_name="$4"

	local ret

	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" enable-event --kernel --function="${target}" "${event_name}" -s "${sess_name}"
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test $ret -ne "0"
		ok $? "Enable kernel function '$target' event '$event_name' for session '$sess_name' failed as expected"
	else
		ok $ret "Enable kernel function '$target' event '$event_name' for session '$sess_name'"
	fi
}

function lttng_enable_kernel_function_event_ok ()
{
	lttng_enable_kernel_function_event 0 "$@"
}

function lttng_enable_kernel_userspace_probe_event ()
{
	local expected_to_fail="$1"
	local sess_name="$2"
	local target="$3"
	local event_name="$4"

	local ret

	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" enable-event \
		--kernel --userspace-probe="$target" "$event_name" --session "$sess_name"
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test $ret -ne "0"
		ok $? "Enable kernel userspace probe '$target' event '$event_name' for session '$sess_name' failed as expected"
	else
		ok $ret "Enable kernel userspace probe '$target' event '$event_name' for session '$sess_name'"
	fi
}

function lttng_enable_kernel_userspace_probe_event_fail ()
{
	lttng_enable_kernel_userspace_probe_event 1 "$@"
}

function lttng_enable_kernel_userspace_probe_event_ok ()
{
	lttng_enable_kernel_userspace_probe_event 0 "$@"
}

function disable_kernel_lttng_userspace_probe_event_ok ()
{
	local sess_name="$1"
	local event_name="$2"

	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" disable-event --kernel "${event_name}" -s "${sess_name}"
	ok $? "Disable kernel event '$event_name' for session '$sess_name'"
}

function lttng_enable_kernel_channel()
{
	local withtap=$1
	local expected_to_fail=$2
	local sess_name=$3
	local channel_name=$4
	local opts=("${@:5}")

	local ret

	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" \
		enable-channel -k "$channel_name" -s "$sess_name" "${opts[@]}"
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test "$ret" -ne "0"
		ret=$?
		if [ "$withtap" -eq "1" ]; then
			ok $ret "Enable kernel channel '$channel_name' for session '$sess_name' failed as expected"
		fi
	else
		if [ "$withtap" -eq "1" ]; then
			ok $ret "Enable kernel channel '$channel_name' for session '$sess_name'"
		fi
	fi
}

function lttng_enable_kernel_channel_ok()
{
	lttng_enable_kernel_channel 1 0 "$@"
}

function lttng_enable_kernel_channel_fail()
{
	lttng_enable_kernel_channel 1 1 "$@"
}

function lttng_enable_kernel_channel_notap()
{
	lttng_enable_kernel_channel 0 0 "$@"
}

function enable_kernel_lttng_channel_ok()
{
	lttng_enable_kernel_channel 1 0 "$@"
}

function lttng_disable_kernel_channel()
{
	local expected_to_fail=$1
	local sess_name=$2
	local channel_name=$3

	local ret

	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" \
		disable-channel -k "$channel_name" -s "$sess_name"
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test "$ret" -ne "0"
		ok $? "Disable kernel channel '$channel_name' for session '$sess_name' failed as expected"
	else
		ok $ret "Disable kernel channel '$channel_name' for session '$sess_name'"
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

# If the caller of this function sets process_mode, they must
# ensure to track the PID of the daemon somehow in order to
# not spawn multiple instances.
function start_lttng_relayd_opt()
{
	local withtap=$1
	local process_mode=$2
	local opts=("${@:3}")

	local pid_file=''
	local pid=''
	local daemon_timeout=''
	local log_file="${RELAYD_ERROR_OUTPUT_DEST:-$(lttng_log_file relayd)}"

	local ret

	if [[ -n "${LTTNG_RELAYD_PIDS[*]}" ]] ; then
		pass "lttng-relayd already started"
		return
	fi

	if [[ -n "${LTTNG_TEST_VERBOSE_RELAYD}" ]] ; then
		opts+=('-vvv')
	fi

	if [[ -n "${log_file}" ]] ; then
		diag "Relayd log file: ${log_file}"
	fi

	if [[ -n "${process_mode}" ]]; then
		opts+=("${process_mode}")
		daemon_timeout=50  # 5 seconds
	fi

	pid_file="$(mktemp -u -t "lttng_relayd_pid.XXXXXX")"
	opts+=('--pid-file' "${pid_file}" "--sig-parent")
	wait_until_ready=1
	trap 'wait_until_ready=0' SIGUSR1
	diag "Run: $(get_path_from_top_dir "$RELAYD_PATH") ${opts[*]}"
	if [[ -n "${log_file}" ]]; then
		"$RELAYD_PATH" "${opts[@]}" >"${log_file}" 2>&1 &
	else
		"$RELAYD_PATH" "${opts[@]}" &
	fi

	ret="${?}"
	if [[ "${ret}" != "0" ]] ; then
		# Something has gone wrong and receiving sigusr1 is unlikely.
		wait_until_ready=0
	fi

	# Wait for the pid file to be created. If the process mode is background or
	# daemon, this will likely hang.
	while [[ ! -f "${pid_file}" ]] && [[ "${ret}" == "0" ]]; do
		sleep 0.1
		if [[ -n "${daemon_timeout}" ]]; then
			daemon_timeout=$((daemon_timeout-1))
			if [[ "${daemon_timeout}" -lt "0" ]]; then
				diag "Timed out waiting for daemon PID file to be created"
				ret=1
				break
			fi
		fi
	done

	pid="$(cat "${pid_file}")"
	while [[ "${wait_until_ready}" -eq "1" ]] && [[ -n "${pid}" ]]; do
		sleep 0.1
		if ! ps -p "${pid}" >/dev/null ; then
			wait "${pid}"
			ret="${?}"
			break
		fi
	done

	if [[ "${ret}" == "0" ]]; then
		LTTNG_RELAYD_PIDS+=("${pid}")
	fi
	trap - SIGUSR1

	if [ "$withtap" -eq "1" ]; then
		ok $ret "Start lttng-relayd (opts: ${opts[*]})"
	fi

	if [[ -n "${LTTNG_TEST_GDBSERVER_RELAYD}" ]] && [[ -n "${pid}" ]]; then
		# The 'bash' is required since gdbserver doesn't end up running in the
		# background with '&'.
		# shellcheck disable=SC2230
		bash -c "$(which gdbserver) --attach localhost:${LTTNG_TEST_GDBSERVER_RELAYD_PORT} ${pid} | head -n 1)" >/dev/null 2>&1 &
		if [[ -n "${LTTNG_TEST_GDBSERVER_RELAYD_WAIT}" ]]; then
			read -r -p "Waiting for user input. Press 'Enter' to continue: "
		else
			# Continue blocks this, but when the next break or signal happens,
			# the process will disconnect and terminate.
			gdb --batch-silent -ex "target remote localhost:${LTTNG_TEST_GDBSERVER_RELAYD_PORT}" -ex "continue" -ex "disconnect" &
		fi
	fi
	return $ret
}

function start_lttng_relayd()
{
	start_lttng_relayd_opt 1 "" "$@"
}

function start_lttng_relayd_notap()
{
	start_lttng_relayd_opt 0 "" "$@"
}

function stop_lttng_relayd_opt()
{
	local withtap=$1
	local is_cleanup=$2
	local signal=$3
	local timeout_s=$4
	local dtimeleft_s=
	local retval=0
	local pids=()

	if [ -z "$signal" ]; then
		signal="SIGTERM"
	fi


	# Multiply time by 2 to simplify integer arithmetic
	# Multiply time by 5 to adjust for sleeping every 0.1s
	if [ -n "$timeout_s" ]; then
		dtimeleft_s=$((timeout_s * 2 * 5))
	fi


	pids=("${LTTNG_RELAYD_PIDS[@]}")
	if [ -z "${pids[*]}" ]; then
		if [ "$is_cleanup" -eq 1 ]; then
			:
		elif [ "$withtap" -eq "1" ]; then
			fail "No relay daemon to kill"
		else
			LTTNG_BAIL_OUT "No relay daemon to kill"
		fi
		return 0
	fi

	diag "Killing (signal $signal) lttng-relayd (pid: ${pids[*]})"

	if ! kill -s "$signal" "${pids[@]}"; then
		retval=1
		if [ "$withtap" -eq "1" ]; then
			fail "Kill relay daemon"
		fi
	else
		out=1
		while [ -n "$out" ]; do
			out=$(lttng_pgrep "$RELAYD_MATCH")
			if [ -n "$dtimeleft_s" ]; then
				if [ $dtimeleft_s -lt 0 ]; then
					out=
					retval=1
				fi
				dtimeleft_s=$((dtimeleft_s - 1))
			fi
			sleep 0.1
		done
		if [ "$withtap" -eq "1" ]; then
			if [ "$retval" -eq "0" ]; then
				pass "Wait after kill relay daemon"
			else
				fail "Wait after kill relay daemon"
			fi
		fi
	fi
	LTTNG_RELAYD_PIDS=()
	return $retval
}

function stop_lttng_relayd()
{
	stop_lttng_relayd_opt 1 0 "$@"
}

function stop_lttng_relayd_notap()
{
	stop_lttng_relayd_opt 0 0 "$@"
}

function stop_lttng_relayd_cleanup()
{
	stop_lttng_relayd_opt 0 1 "$@"
}

#First arg: show tap output
#Second argument: load path for automatic loading
function start_lttng_sessiond_opt()
{
	local withtap=$1
	local load_path=$2

	# The rest of the arguments will be passed directly to lttng-sessiond.
	shift 2
	local opts=("${@}")
	local log_file

	local env_vars=""
	local consumerd=""

	local long_bit_value=

	log_file="$(lttng_log_file sessiond)"
	long_bit_value=$(getconf LONG_BIT)

	if [ -n "$TEST_NO_SESSIOND" ] && [ "$TEST_NO_SESSIOND" == "1" ]; then
		# Env variable requested no session daemon
		return
	fi

	if [[ -n "${LTTNG_TEST_VERBOSE_SESSIOND}" ]]; then
		opts+=(
			'-vvv'
			'--verbose-consumer'
		)
	fi

	# Get long_bit value for 32/64 consumerd
	case "$long_bit_value" in
		32)
			consumerd="--consumerd32-path=$CONSUMERD_PATH"
			;;
		64)
			consumerd="--consumerd64-path=$CONSUMERD_PATH"
			;;
		*)
			return
			;;
	esac

	# Check for env. variable. Allow the use of LD_PRELOAD etc.
	if [[ "${LTTNG_SESSIOND_ENV_VARS}" != "" ]]; then
		env_vars="${LTTNG_SESSIOND_ENV_VARS} "
	fi
	env_vars="${env_vars}$SESSIOND_PATH"

	if ! validate_kernel_version; then
		fail "Start session daemon"
		LTTNG_BAIL_OUT "*** Kernel too old for session daemon tests ***"
	fi

	diag "export LTTNG_SESSION_CONFIG_XSD_PATH=${ABS_BUILDDIR}/src/common/"
	: "${LTTNG_SESSION_CONFIG_XSD_PATH="${ABS_BUILDDIR}/src/common/"}"
	export LTTNG_SESSION_CONFIG_XSD_PATH

	wait_until_ready=1
	trap 'wait_until_ready=0' SIGUSR1
	if [ -n "$load_path" ]; then
		diag "env $env_vars --load $load_path $consumerd ${opts[*]}"
		if [[ -n "${log_file}" ]]; then
			# shellcheck disable=SC2086
			env $env_vars --sig-parent --load "$load_path" "$consumerd" "${opts[@]}" >"${log_file}" 2>&1 &
		else
			# shellcheck disable=SC2086
			env $env_vars --sig-parent --load "$load_path" "$consumerd" "${opts[@]}" &
		fi
	else
		diag "env $env_vars $consumerd ${opts[*]}"
		if [[ -n "${log_file}" ]]; then
			# shellcheck disable=SC2086
			env $env_vars --sig-parent "$consumerd" "${opts[@]}" >"${log_file}" 2>&1 &
		else
			# shellcheck disable=SC2086
			env $env_vars --sig-parent "$consumerd" "${opts[@]}" &
		fi
	fi

	status=$?
	pid="${!}"
	if [[ "${status}" != "0" ]]; then
		wait_until_ready=0
	fi

	while [[ "${wait_until_ready}" -eq "1" ]] ; do
		sleep 0.1
		# This PID no longers exists and `--sig-parent` hasn't been received
		if ! ps -p "${pid}" >/dev/null ; then
			wait "${pid}"
			status="${?}"
			break
		fi
	done

	if [[ "${status}" == "0" ]]; then
		LTTNG_SESSIOND_PIDS+=("${pid}")
	fi

	if [ "$withtap" -eq "1" ]; then
		ok $status "Start session daemon"
	fi

	trap - SIGUSR1
	if [[ -n "${LTTNG_TEST_GDBSERVER_SESSIOND}" ]]; then
		# The 'bash' is required since gdbserver doesn't end up running in the
		# background with '&'.
		# shellcheck disable=SC2230
		bash -c "$(which gdbserver) --attach localhost:${LTTNG_TEST_GDBSERVER_SESSIOND_PORT} $(lttng_pgrep "${SESSIOND_MATCH}" | head -n 1)" >/dev/null 2>&1 &
		if [[ -n "${LTTNG_TEST_GDBSERVER_SESSIOND_WAIT}" ]]; then
			read -r -p "Waiting for user input. Press 'Enter' to continue: "
		else
			# Continue blocks this, but when the next break or signal happens,
			# the process will disconnect and terminate.
			gdb --batch-silent -ex "target remote localhost:${LTTNG_TEST_GDBSERVER_SESSIOND_PORT}" -ex "continue" -ex "disconnect" &
		fi
	fi

	return $status
}

function start_lttng_sessiond()
{
	start_lttng_sessiond_opt 1 "$@"
}

function start_lttng_sessiond_fail()
{
	start_lttng_sessiond_opt 0 "$@"
	isnt "${?}" "0" "start_lttng_sessiond_fail"
}

function start_lttng_sessiond_notap()
{
	start_lttng_sessiond_opt 0 "$@"
}

function stop_lttng_sessiond_opt()
{
	local withtap=$1
	local is_cleanup=$2
	local signal=$3
	local timeout_s=$4
	local dtimeleft_s=
	local retval=0
	local pids=()

	if [ -z "$signal" ]; then
		signal=SIGTERM
	fi

	# Multiply time by 2 to simplify integer arithmetic
	# Multiply time by 5 to adjust for sleeping every 0.1s
	if [ -n "$timeout_s" ]; then
		dtimeleft_s=$((timeout_s * 2 * 5))
	fi

	if [ -n "$TEST_NO_SESSIOND" ] && [ "$TEST_NO_SESSIOND" == "1" ]; then
		# Env variable requested no session daemon
		return 0
	fi

	pids=("${LTTNG_SESSIOND_PIDS[@]}")
	if [ -z "${pids[*]}" ]; then
		if [ "$is_cleanup" -eq 1 ]; then
			:
		elif [ "$withtap" -eq "1" ]; then
			fail "No session daemon to kill"
		else
			LTTNG_BAIL_OUT "No session daemon to kill"
		fi
		return 0
	fi

	diag "Killing (signal $signal) $SESSIOND_BIN and lt-$SESSIOND_BIN pids: ${pids[*]}"

	if ! kill -s "$signal" "${pids[@]}"; then
		retval=1
		if [ "$withtap" -eq "1" ]; then
			fail "Kill sessions daemon"
		fi
	else
		out=1
		while [ -n "$out" ]; do
			out=$(lttng_pgrep "${SESSIOND_MATCH}")
			if [ -n "$dtimeleft_s" ]; then
				if [ $dtimeleft_s -lt 0 ]; then
					out=
					retval=1
				fi
				dtimeleft_s=$((dtimeleft_s - 1))
			fi
			sleep 0.1
		done
		out=1
		while [ -n "$out" ]; do
			out=$(lttng_pgrep "$CONSUMERD_MATCH")
			if [ -n "$dtimeleft_s" ]; then
				if [ $dtimeleft_s -lt 0 ]; then
					out=
					retval=1
				fi
				dtimeleft_s=$((dtimeleft_s - 1))
			fi
			sleep 0.1
		done

		if [ "$withtap" -eq "1" ]; then
			if [ "$retval" -eq "0" ]; then
				pass "Wait after kill session daemon"
			else
				fail "Wait after kill session daemon"
			fi
		fi

		# Reset SESSIOND pids for tests that spawn the session daemon
		# multiple times.
		LTTNG_SESSIOND_PIDS=()
	fi
	if [ "$signal" = "SIGKILL" ]; then
		if [ "$(id -u)" -eq "0" ]; then
			local modules=
			modules="$(lsmod | grep ^lttng | awk '{print $1}')"

			if [ -n "$modules" ]; then
				diag "Unloading all LTTng modules"
				modprobe --remove "$modules"
			fi
		fi
	fi

	return $retval
}

function stop_lttng_sessiond()
{
	stop_lttng_sessiond_opt 1 0 "$@"
}

function stop_lttng_sessiond_notap()
{
	stop_lttng_sessiond_opt 0 0 "$@"
}

function stop_lttng_sessiond_cleanup()
{
	stop_lttng_sessiond_opt 0 1 "$@"
}

function sigstop_lttng_sessiond_opt()
{
	local withtap=$1
	local signal=SIGSTOP
	local pids=()

	if [ -n "$TEST_NO_SESSIOND" ] && [ "$TEST_NO_SESSIOND" == "1" ]; then
		# Env variable requested no session daemon
		return
	fi

	pids=("${LTTNG_SESSIOND_PIDS[@]}")

	if [ "$withtap" -eq "1" ]; then
		diag "Sending SIGSTOP to lt-$SESSIOND_BIN and $SESSIOND_BIN pids: ${pids[*]}"
	fi

	if [[ -z "${pids[*]}" ]]; then
		if [[ "${withtap}" -eq "1" ]]; then
			diag "No lttng-sessiond processes being tracked"
			skip "No lttng-sessiond to kill"
		fi
	fi

	if ! kill -s $signal "${pids[@]}"; then
		if [ "$withtap" -eq "1" ]; then
			fail "Sending ${signal} to session daemon"
		fi
	else
		out=1
		while [ $out -ne 0 ]; do
			# Wait until state becomes stopped for session
			# daemon(s).
			out=0
			for sessiond_pid in "${pids[@]}"; do
				state="$(ps -p "$sessiond_pid" -o state= )"
				if [[ -n "$state" && "$state" != "T" ]]; then
					out=1
				fi
			done
			sleep 0.5
		done
		if [ "$withtap" -eq "1" ]; then
			pass "Sending SIGSTOP to session daemon"
		fi
	fi

	if [[ "${signal}" != "SIGSTOP" ]]; then
		LTTNG_SESSIOND_PIDS=()
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
	local is_cleanup=$2
	local signal=$3
	local timeout_s=$4
	local dtimeleft_s=
	local retval=0
	local pids

	if [ -z "$signal" ]; then
		signal=SIGTERM
	fi

	# Multiply time by 2 to simplify integer arithmetic
	# Multiply time by 5 to adjust for sleeping every 0.1s
	if [ -n "$timeout_s" ]; then
		dtimeleft_s=$((timeout_s * 2 * 5))
	fi

	pids="$(lttng_pgrep "$CONSUMERD_MATCH")"

	if [ -z "$pids" ]; then
		if [ "$is_cleanup" -eq 1 ]; then
			:
		elif [ "$withtap" -eq "1" ]; then
			fail "No consumerd daemon to kill"
		else
			LTTNG_BAIL_OUT "No consumerd daemon to kill"
		fi
		return 0
	fi

	diag "Killing (signal $signal) $CONSUMERD_BIN pids: $(echo "$pids" | tr '\n' ' ')"

	# shellcheck disable=SC2086
	if ! kill -s $signal $pids; then
		retval=1
		if [ "$withtap" -eq "1" ]; then
			fail "Kill consumer daemon"
		fi
	else
		out=1
		while [ $out -ne 0 ]; do
			pids="$(lttng_pgrep "$CONSUMERD_MATCH")"

			# If consumerds are still present check their status.
			# A zombie status qualifies the consumerd as *killed*
			out=0
			for consumer_pid in $pids; do
				state="$(ps -p "$consumer_pid" -o state= )"
				if [[ -n "$state" && "$state" != "Z" ]]; then
					out=1
				fi
			done
			if [ -n "$dtimeleft_s" ]; then
				if [ $dtimeleft_s -lt 0 ]; then
					out=0
					retval=1
				fi
				dtimeleft_s=$((dtimeleft_s - 1))
			fi
			sleep 0.1
		done
		if [ "$withtap" -eq "1" ]; then
			if [ "$retval" -eq "0" ]; then
				pass "Wait after kill consumer daemon"
			else
				fail "Wait after kill consumer daemon"
			fi
		fi
	fi

	return $retval
}

function stop_lttng_consumerd()
{
	stop_lttng_consumerd_opt 1 0 "$@"
}

function stop_lttng_consumerd_notap()
{
	stop_lttng_consumerd_opt 0 0 "$@"
}

function stop_lttng_consumerd_cleanup()
{
	stop_lttng_consumerd_opt 0 1 "$@"
}

function sigstop_lttng_consumerd_opt()
{
	local withtap=$1
	local signal=SIGSTOP
	local pids

	pids="$(lttng_pgrep "$CONSUMERD_MATCH")"

	diag "Sending SIGSTOP to $CONSUMERD_BIN pids: $(echo "$pids" | tr '\n' ' ')"

	# shellcheck disable=SC2086
	kill -s $signal $pids
	retval=$?

	if [ $retval -eq 1 ]; then
		if [ "$withtap" -eq "1" ]; then
			fail "Sending SIGSTOP to consumer daemon"
		fi
		return 1
	else
		out=1
		while [ $out -ne 0 ]; do
			pids="$(lttng_pgrep "$CONSUMERD_MATCH")"

			# Wait until state becomes stopped for all
			# consumers.
			out=0
			for consumer_pid in $pids; do
				state="$(ps -p "$consumer_pid" -o state= )"
				if [[ -n "$state" && "$state" != "T" ]]; then
					out=1
				fi
			done
			sleep 0.5
		done
		if [ "$withtap" -eq "1" ]; then
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
	local withtap=$1
	local expected_to_fail=$2
	local opts=("${@:3}")

	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" \
		list "${opts[@]}"
	local ret=$?

	if [[ $expected_to_fail -eq "1" ]]; then
		test $ret -ne "0"
		ret=$?

		if [[ "$withtap" -eq "1" ]]; then
			ok $ret "List command failed as expected with options: ${opts[*]}"
		fi
	else
		if [[ "$withtap" -eq "1" ]]; then
			ok $ret "List command with options: ${opts[*]}"
		fi
	fi

	return "$ret"
}

function list_lttng_ok ()
{
	list_lttng_with_opts 1 0 "$@"
}

function list_lttng_fail ()
{
	list_lttng_with_opts 1 1 "$@"
}

function list_lttng_notap ()
{
	list_lttng_with_opts 0 0 "$@"
}

function create_lttng_session_no_output ()
{
	local sess_name=$1
	local opts=("${@:2}")

	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" \
		create "$sess_name" --no-output "${opts[@]}"
	ok $? "Create session '$sess_name' in no-output mode"
}

function create_lttng_session_uri () {
	local sess_name=$1
	local uri=$2
	local opts=("${@:3}")

	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" \
		create "$sess_name" -U "$uri" "${opts[@]}"
	ok $? "Create session '$sess_name' with uri '$uri' and options: ${opts[*]}"
}

function create_lttng_session ()
{
	local withtap=$1
	local expected_to_fail=$2
	local sess_name=$3
	local trace_path=$4
	local opts=("${@:5}")

	local output_opt=()

	# default output if none specified
	if [ -n "$trace_path" ]; then
		output_opt=("-o" "$trace_path")
	fi

	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" \
		create "$sess_name" "${output_opt[@]}" "${opts[@]}"
	ret=$?
	if [ "$expected_to_fail" -eq "1" ]; then
		test "$ret" -ne "0"
		ret=$?
		if [ "$withtap" -eq "1" ]; then
			ok $ret "Create session '$sess_name' in '$trace_path' failed as expected"
		fi
	else
		if [ "$withtap" -eq "1" ]; then
			ok $ret "Create session '$sess_name' in '$trace_path'"
		fi
	fi
	return $ret
}

function create_lttng_session_ok ()
{
	create_lttng_session 1 0 "$@"
}

function create_lttng_session_fail ()
{
	create_lttng_session 1 1 "$@"
}

function create_lttng_session_notap ()
{
	create_lttng_session 0 0 "$@"
}


function enable_ust_lttng_channel ()
{
	local withtap=$1
	local expected_to_fail=$2
	local sess_name=$3
	local channel_name=$4
	local opts=("${@:5}")

	local ret

	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" \
		enable-channel -u "$channel_name" -s "$sess_name" "${opts[@]}"
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test "$ret" -ne "0"
		ret=$?
		if [ "$withtap" -eq "1" ]; then
			ok $ret "Enable channel '$channel_name' for session '$sess_name' failed as expected"
		fi
	else
		if [ "$withtap" -eq "1" ]; then
			ok $ret "Enable channel '$channel_name' for session '$sess_name'"
		fi
	fi
	return $ret
}

function enable_ust_lttng_channel_ok ()
{
	enable_ust_lttng_channel 1 0 "$@"
}

function enable_ust_lttng_channel_fail ()
{
	enable_ust_lttng_channel 1 1 "$@"
}

function enable_ust_lttng_channel_notap ()
{
	enable_ust_lttng_channel 0 0 "$@"
}

function disable_ust_lttng_channel()
{
	local sess_name=$1
	local channel_name=$2

	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" \
		disable-channel -u "$channel_name" -s "$sess_name"
	ok $? "Disable channel '$channel_name' for session '$sess_name'"
}

function enable_lttng_mmap_overwrite_kernel_channel()
{
	local sess_name=$1
	local channel_name=$2

	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" \
		enable-channel -s "$sess_name" "$channel_name" -k --output mmap --overwrite
	ok $? "Enable channel '$channel_name' for session '$sess_name'"
}

function enable_lttng_mmap_discard_small_kernel_channel()
{
	local sess_name=$1
	local channel_name=$2

	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" \
		enable-channel -s "$sess_name" "$channel_name" -k --output mmap --discard --subbuf-size="$(getconf PAGE_SIZE)" --num-subbuf=2
	ok $? "Enable small discard channel '$channel_name' for session '$sess_name'"
}

function enable_lttng_mmap_overwrite_small_kernel_channel()
{
	local sess_name=$1
	local channel_name=$2

	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" \
		enable-channel -s "$sess_name" "$channel_name" -k --output mmap --overwrite --subbuf-size="$(getconf PAGE_SIZE)" --num-subbuf=2
	ok $? "Enable small overwrite channel '$channel_name' for session '$sess_name'"
}

function enable_lttng_mmap_overwrite_ust_channel()
{
	local sess_name=$1
	local channel_name=$2

	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" \
		enable-channel -s "$sess_name" "$channel_name" -u --output mmap --overwrite
	ok $? "Enable channel '$channel_name' for session '$sess_name'"
}

function enable_ust_lttng_event ()
{
	local withtap=$1
	local expected_to_fail=$2
	local sess_name=$3
	local event_name="$4"
	local channel_name=$5
	local opts=("${@:6}")

	local chan_opt=()

	# default channel if none specified
	if [ -n "$channel_name" ]; then
		chan_opt=("-c" "$channel_name")
	fi

	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" \
		enable-event "$event_name" "${chan_opt[@]}" -s "$sess_name" -u "${opts[@]}"
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test $ret -ne "0"
		ret=$?
		if [[ $withtap -eq "1" ]]; then
			ok $ret "Enable ust event '$event_name' for session '$sess_name' failed as expected"
		fi
	else
		if [[ $withtap -eq "1" ]]; then
			ok $ret "Enable ust event '$event_name' for session '$sess_name'"
		fi
	fi
	return $ret
}

function enable_ust_lttng_event_ok ()
{
	enable_ust_lttng_event 1 0 "$@"
}

function enable_ust_lttng_event_fail ()
{
	enable_ust_lttng_event 1 1 "$@"
}

function enable_ust_lttng_event_notap ()
{
	enable_ust_lttng_event 0 0 "$@"
}

function enable_jul_lttng_event()
{
	local sess_name=$1
	local event_name="$2"
	local channel_name=$3

	local chan_opt=()

	# default channel if none specified
	if [ -n "$channel_name" ]; then
		chan_opt=("-c" "$channel_name")
	fi

	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" \
		enable-event "$event_name" "${chan_opt[@]}" -s "$sess_name" -j
	ok $? "Enable JUL event '$event_name' for session '$sess_name'"
}

function enable_jul_lttng_event_loglevel()
{
	local sess_name=$1
	local event_name="$2"
	local loglevel=$3
	local channel_name=$4

	local chan_opt=()

	# default channel if none specified
	if [ -n "$channel_name" ]; then
		chan_opt=("-c" "$channel_name")
	fi

	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" \
		enable-event --loglevel "$loglevel" "$event_name" "${chan_opt[@]}" -s "$sess_name" -j
	ok $? "Enable JUL event '$event_name' for session '$sess_name' with loglevel '$loglevel'"
}

function enable_log4j_lttng_event()
{
	local sess_name=$1
	local event_name=$2
	local channel_name=$3

	local chan_opt=()

	# default channel if none specified
	if [ -n "$channel_name" ]; then
		chan_opt=("-c" "$channel_name")
	fi

	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" \
		enable-event "$event_name" "${chan_opt[@]}" -s "$sess_name" --log4j
	ok $? "Enable LOG4J event '$event_name' for session '$sess_name'"
}

function enable_log4j_lttng_event_filter()
{
	local sess_name=$1
	local event_name=$2
	local filter=$3

	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" \
		enable-event "$event_name" -s "$sess_name" --log4j --filter "$filter"
	ok $? "Enable LOG4J event '$event_name' with filter '$filter' for session '$sess_name'"
}

function enable_log4j_lttng_event_filter_loglevel_only()
{
	local sess_name=$1
	local event_name=$2
	local filter=$3
	local loglevel=$4

	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" \
		enable-event --loglevel-only "$loglevel" "$event_name" -s "$sess_name" -l --filter "$filter"
	ok $? "Enable LOG4J event '$event_name' with filter '$filter' and loglevel-only '$loglevel' for session '$sess_name'"
}

function enable_log4j_lttng_event_loglevel()
{
	local sess_name=$1
	local event_name=$2
	local loglevel=$3
	local channel_name=$4

	local chan_opt=()

	# default channel if none specified
	if [ -n "$channel_name" ]; then
		chan_opt=("-c" "$channel_name")
	fi

	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" \
		enable-event --loglevel "$loglevel" "$event_name" "${chan_opt[@]}" -s "$sess_name" --log4j
	ok $? "Enable LOG4J event '$event_name' for session '$sess_name' with loglevel '$loglevel'"
}

function enable_log4j_lttng_event_loglevel_only()
{
	local sess_name=$1
	local event_name=$2
	local loglevel=$3
	local channel_name=$4

	local chan_opt=()

	# default channel if none specified
	if [ -n "$channel_name" ]; then
		chan_opt=("-c" "$channel_name")
	fi

	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" \
		enable-event --loglevel-only "$loglevel" "$event_name" "${chan_opt[@]}" -s "$sess_name" --log4j
	ok $? "Enable LOG4J event '$event_name' for session '$sess_name' with loglevel-only '$loglevel'"
}

function enable_log4j2_lttng_event()
{
	local sess_name=$1
	local event_name=$2
	local channel_name=$3

	local chan_opt=()

	# default channel if none specified
	if [ -n "$channel_name" ]; then
		chan_opt=("-c" "$channel_name")
	fi

	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
		enable-event "$event_name" "${chan_opt[@]}" -s "$sess_name" --log4j2
	ok $? "Enable LOG4J2 event '$event_name' for session '$sess_name'"
}

function enable_log4j2_lttng_event_filter()
{
	local sess_name=$1
	local event_name=$2
	local filter=$3

	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
	       enable-event "$event_name" -s "$sess_name" --log4j2 --filter "$filter"
	ok $? "Enable LOG4J2 event '$event_name' with filter '$filter' for session '$sess_name'"
}

function enable_log4j2_lttng_event_filter_loglevel_only()
{
	local sess_name=$1
	local event_name=$2
	local filter=$3
	local loglevel=$4

	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
		enable-event --loglevel-only "$loglevel" "$event_name" -s "$sess_name" --log4j2 --filter "$filter"
	ok $? "Enable LOG4J2 event '$event_name' with filter '$filter' and loglevel-only '$loglevel' for session '$sess_name'"
}

function enable_log4j2_lttng_event_loglevel()
{
	local sess_name=$1
	local event_name=$2
	local loglevel=$3
	local channel_name=$4

	local chan_opt=()

	# default channel if none specified
	if [ -n "$channel_name" ]; then
		chan_opt=("-c" "$channel_name")
	fi

	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
		enable-event --loglevel "$loglevel" "$event_name" "${chan_opt[@]}" -s "$sess_name" --log4j2
	ok $? "Enable LOG4J2 event '$event_name' for session '$sess_name' with loglevel '$loglevel'"
}

function enable_log4j2_lttng_event_loglevel_only()
{
	local sess_name=$1
	local event_name=$2
	local loglevel=$3
	local channel_name=$4

	local chan_opt=()

	# default channel if none specified
	if [ -n "$channel_name" ]; then
		chan_opt=("-c" "$channel_name")
	fi

	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
		enable-event --loglevel-only "$loglevel" "$event_name" "${chan_opt[@]}" -s "$sess_name" --log4j2
	ok $? "Enable LOG4J2 event '$event_name' for session '$sess_name' with loglevel-only '$loglevel'"
}

function enable_python_lttng_event()
{
	sess_name=$1
	event_name="$2"
	channel_name=$3

	local chan_opt=()

	# default channel if none specified
	if [ -n "$channel_name" ]; then
		chan_opt=("-c" "$channel_name")
	fi

	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" \
		enable-event "$event_name" "${chan_opt[@]}" -s "$sess_name" -p
	ok $? "Enable Python event '$event_name' for session '$sess_name'"
}

function enable_python_lttng_event_loglevel()
{
	local sess_name=$1
	local event_name="$2"
	local loglevel=$3
	local channel_name=$4

	local chan_opt=()

	# default channel if none specified
	if [ -n "$channel_name" ]; then
		chan_opt=("-c" "$channel_name")
	fi

	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" \
		enable-event --loglevel "$loglevel" "$event_name" "${chan_opt[@]}" -s "$sess_name" -p
	ok $? "Enable Python event '$event_name' for session '$sess_name' with loglevel '$loglevel'"
}

function enable_ust_lttng_event_filter()
{
	local sess_name="$1"
	local event_name="$2"
	local filter="$3"
	local channel_name=$4

	local chan_opt=()

	# default channel if none specified
	if [ -n "$channel_name" ]; then
		chan_opt=("-c" "$channel_name")
	fi

	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" \
		enable-event "${chan_opt[@]}" "$event_name" -s "$sess_name" -u --filter "$filter"
	ok $? "Enable event '$event_name' for session '$sess_name' with filter '$filter'"
}

function enable_ust_lttng_event_loglevel()
{
	local sess_name="$1"
	local event_name="$2"
	local loglevel="$3"
	local channel_name="$4"

	local chan_opt=()

	# default channel if none specified
	if [ -n "$channel_name" ]; then
		chan_opt=("-c" "$channel_name")
	fi

	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" \
		enable-event "${chan_opt[@]}" "$event_name" -s "${sess_name}" -u --loglevel="${loglevel}"
	ok $? "Enable event '$event_name' for session '$sess_name' with loglevel '$loglevel'"
}

function enable_ust_lttng_event_loglevel_only()
{
	local sess_name="$1"
	local event_name="$2"
	local loglevel="$3"
	local channel_name="$4"

	local chan_opt=()

	# default channel if none specified
	if [ -n "$channel_name" ]; then
		chan_opt=("-c" "$channel_name")
	fi

	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" \
		enable-event "${chan_opt[@]}" "$event_name" -s "${sess_name}" -u --loglevel-only "${loglevel}"
	ok $? "Enable event '$event_name' for session '$sess_name' with loglevel-only '$loglevel'"
}

function disable_ust_lttng_event ()
{
	local sess_name="$1"
	local event_name="$2"
	local channel_name="$3"

	local chan_opt=()

	# default channel if none specified
	if [ -n "$channel_name" ]; then
		chan_opt=("-c" "$channel_name")
	fi

	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" \
		disable-event "$event_name" -s "$sess_name" "${chan_opt[@]}" -u
	ok $? "Disable event '$event_name' for session '$sess_name'"
}

function disable_jul_lttng_event ()
{
	local sess_name="$1"
	local event_name="$2"

	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" \
		disable-event "${event_name}" -s "${sess_name}" -j
	ok $? "Disable JUL event '$event_name' for session '$sess_name'"
}

function disable_log4j_lttng_event ()
{
	local sess_name="$1"
	local event_name="$2"

	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" \
		disable-event "$event_name" -s "$sess_name" --log4j
	ok $? "Disable LOG4J event '$event_name' for session '$sess_name'"
}

function disable_log4j2_lttng_event ()
{
	local sess_name=$1
	local event_name=$2

	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
		disable-event "$event_name" -s "$sess_name" --log4j2
	ok $? "Disable LOG4J2 event '$event_name' for session '$sess_name'"
}

function disable_python_lttng_event ()
{
	local sess_name="$1"
	local event_name="$2"

	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" \
		disable-event "$event_name" -s "$sess_name" -p
	ok $? "Disable Python event '$event_name' for session '$sess_name'"
}

function start_lttng_tracing_opt ()
{
	local withtap=$1
	local expected_to_fail=$2
	local sess_name=$3

	local opts=()
	local ret

	# Optional session name comes first
	if [ -n "$sess_name" ]; then
		opts+=("$sess_name")
	fi

	opts+=("${@:4}")

	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" \
		start "${opts[@]}"
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test "$ret" -ne "0"
		ret=$?
		if [ "$withtap" -eq "1" ]; then
			ok $ret "Start tracing for session '${sess_name:-DEFAULT}' failed as expected"
		fi
	else
		if [ "$withtap" -eq "1" ]; then
			ok $ret "Start tracing for session '${sess_name:-DEFAULT}'"
		fi
	fi
}

function start_lttng_tracing_ok ()
{
	start_lttng_tracing_opt 1 0 "$@"
}

function start_lttng_tracing_fail ()
{
	start_lttng_tracing_opt 1 1 "$@"
}

function start_lttng_tracing_notap ()
{
	start_lttng_tracing_opt 0 1 "$@"
}

function stop_lttng_tracing_opt ()
{
	local withtap=$1
	local expected_to_fail=$2
	local sess_name=$3

	local opts=()
	local ret

	# Optional session name comes first
	if [ -n "$sess_name" ]; then
		opts+=("$sess_name")
	fi

	opts+=("${@:4}")

	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" \
		stop "${opts[@]}"
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test "$ret" -ne "0"
		ret=$?
		if [ "$withtap" -eq "1" ]; then
			ok $ret "Stop lttng tracing for session '${sess_name:-DEFAULT}' failed as expected"
		fi
	else
		if [ "$withtap" -eq "1" ]; then
			ok $ret "Stop lttng tracing for session '${sess_name:-DEFAULT}'"
		fi
	fi
}

function stop_lttng_tracing_ok ()
{
	stop_lttng_tracing_opt 1 0 "$@"
}

function stop_lttng_tracing_fail ()
{
	stop_lttng_tracing_opt 1 1 "$@"
}

function stop_lttng_tracing_notap ()
{
	stop_lttng_tracing_opt 0 0 "$@"
}

function destroy_lttng_session ()
{
	local withtap=$1
	local expected_to_fail=$2
	local sess_name=$3
	local opts=("${@:4}")

	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" \
		destroy "$sess_name" "${opts[@]}"
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test "$ret" -ne "0"
		ret=$?
		if [ "$withtap" -eq "1" ]; then
			ok $ret "Destroy session '$sess_name' failed as expected"
		fi
	else
		if [ "$withtap" -eq "1" ]; then
			ok $ret "Destroy session '$sess_name'"
		fi
	fi
}

function destroy_lttng_session_ok ()
{
	destroy_lttng_session 1 0 "$@"

}

function destroy_lttng_session_fail ()
{
	destroy_lttng_session 1 1 "$@"
}

function destroy_lttng_session_notap ()
{
	destroy_lttng_session 0 0 "$@"
}

function destroy_lttng_sessions ()
{
	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" \
		destroy --all
	ok $? "Destroy all lttng sessions"
}

function lttng_snapshot_add_output ()
{
	local expected_to_fail=$1
	local sess_name=$2
	local trace_path=$3
	local opts=("${@:4}")

	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" \
		snapshot add-output -s "$sess_name" "$trace_path" "${opts[@]}"
	ret=$?
	if [[ $expected_to_fail -eq 1 ]]; then
		test "$ret" -ne "0"
		ok $? "Added snapshot output '$trace_path' failed as expected"
	else
		ok $ret "Added snapshot output '$trace_path'"
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

	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" \
		snapshot del-output -s "$sess_name" "$id"
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test "$ret" -ne "0"
		ok $? "Deleted snapshot output id '$id' failed as expected"
	else
		ok $ret "Deleted snapshot output id '$id'"
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

	local opts=()

	if [ -n "$trace_path" ]; then
		opts+=("$trace_path")
	fi

	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" \
		snapshot record -s "$sess_name" "${opts[@]}"
	ok $? "Snapshot recorded for session '$sess_name'"
}

function lttng_snapshot_list ()
{
	local sess_name=$1
	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" \
		snapshot list-output -s "$sess_name"
	ok $? "Snapshot list for session '$sess_name'"
}

function lttng_version_ok()
{
	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" version
	ok $? "Get version"
}

function lttng_save()
{
	local sess_name=$1
	local opts=()

	# Optional session name comes first
	if [ -n "$sess_name" ]; then
		opts+=("$sess_name")
	fi

	opts+=("${@:2}")

	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" \
		save "${opts[@]}"
	ok $? "Session '${sess_name:-DEFAULT}' saved"
}

function lttng_load()
{
	local expected_to_fail=$1
	local opts=("${@:2}")

	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" \
		load "${opts[@]}"
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test $ret -ne "0"
		ok $? "Load command failed as expected with opts: ${opts[*]}"
	else
		ok $ret "Load command with opts: ${opts[*]}"
	fi
}

function lttng_load_ok()
{
	lttng_load 0 "$@"
}

function lttng_load_fail()
{
	lttng_load 1 "$@"
}

function lttng_track()
{
	local expected_to_fail="$1"
	local opts=("${@:2}")

	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" \
		track "${opts[@]}"
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test $ret -ne "0"
		ok $? "Track command failed as expected with opts: ${opts[*]}"
	else
		ok $ret "Track command with opts: ${opts[*]}"
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
	local expected_to_fail="$1"
	local opts=("${@:2}")

	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" \
		untrack "${opts[@]}"
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test $ret -ne "0"
		ok $? "Untrack command failed as expected with opts: ${opts[*]}"
	else
		ok $ret "Untrack command with opts: ${opts[*]}"
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

function lttng_track_pid_ok()
{
	local pid=$1

	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" track --kernel --pid="${pid}"
	ok $? "Lttng track pid '$pid' on the kernel domain"
}

function lttng_untrack_kernel_all_ok()
{
	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" untrack --kernel --pid --all
	ok $? "Lttng untrack all pid on the kernel domain"
}

function lttng_track_ust_ok()
{
	lttng_track_ok -u "$@"
}

function lttng_track_ust_fail()
{
	lttng_track_fail -u "$@"
}

function lttng_track_kernel_ok()
{
	lttng_track_ok -k "$@"
}

function lttng_track_kernel_fail()
{
	lttng_track_fail -k "$@"
}

function lttng_untrack_ust_ok()
{
	lttng_untrack_ok -u "$@"
}

function lttng_untrack_ust_fail()
{
	lttng_untrack_fail -u "$@"
}

function lttng_untrack_kernel_ok()
{
	lttng_untrack_ok -k "$@"
}

function lttng_untrack_kernel_fail()
{
	lttng_untrack_fail -k "$@"
}

function lttng_add_context_list()
{
	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" \
		add-context --list
	ret=$?
	ok $ret "Context listing"
}

function add_context_lttng()
{
	local expected_to_fail="$1"
	local domain="$2"
	local sess_name="$3"
	local channel_name="$4"
	local type="$5"

	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" \
		add-context -s "$sess_name" -c "$channel_name" -t "$type" "$domain"
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

function wait_live_trace_ready ()
{
	local url=$1
	local zero_client_match=0

	diag "Waiting for live trace at url: $url"
	while [ "$zero_client_match" -eq 0 ]; do
		zero_client_match=$(_run_babeltrace_cmd -i lttng-live "$url" | grep -c "0 client(s) connected")
		sleep 0.1
	done
	pass "Waiting for live trace at url: $url"
}

function wait_live_viewer_connect ()
{
	local url=$1
	local one_client_match=0

	diag "Waiting for live viewers on url: $url"
	while [ "$one_client_match" -eq 0 ]; do
		one_client_match=$(_run_babeltrace_cmd -i lttng-live "$url" | grep -c "1 client(s) connected")
		sleep 0.1
	done
	pass "Waiting for live viewers on url: $url"
}

function bail_out_if_no_babeltrace()
{
	if ! command -v "$BABELTRACE_BIN" >/dev/null; then
		LTTNG_BAIL_OUT "\"$BABELTRACE_BIN\" binary not found. Skipping tests"
	fi
}

# Check that the trace metadata contains '$expected' event ids matching '$event_name'.
function validate_metadata_event()
{
	local event_name=$1
	local expected=$2
	local trace_path=$3

	local metadata_file
	local metadata_path
	local count

	metadata_file=$(find "$trace_path" -name "metadata")
	metadata_path=$(dirname "$metadata_file")

	bail_out_if_no_babeltrace

	count=$(_run_babeltrace_cmd --output-format=ctf-metadata "$metadata_path" | grep -c "$event_name")

	test "$count" -eq "$expected"
	ok $? "Found '$count / $expected' metadata event id matching '$event_name'"
}

# Check that the trace contains '$expected' events matching '$event_name', other
# events not matching '$event_name' can be present.
function trace_matches()
{
	local event_name=$1
	local expected=$2
	local trace_path=$3

	local count
	local total

	bail_out_if_no_babeltrace

	count=$(_run_babeltrace_cmd "$trace_path" | grep -c "$event_name")
	total=$(_run_babeltrace_cmd "$trace_path" | wc -l)

	test "$count" -eq "$expected"

	ok $? "Found '$count / $expected' events matching '$event_name' out of '$total' events"
}

# Check that the trace contains '$expected' events matching '$event_name' and no
# other events.
function trace_match_only()
{
	local event_name=$1
	local expected=$2
	local trace_path=$3

	local count
	local total

	bail_out_if_no_babeltrace

	count=$(_run_babeltrace_cmd "$trace_path" | grep -c "$event_name")
	total=$(_run_babeltrace_cmd "$trace_path" | wc -l)

	test "$expected" -eq "$count" && test "$total" -eq "$expected"

	ok $? "Found '$count / $expected' events matching '$event_name' amongst '$total' events"
}

# Check that the trace contains at least 1 event matching each name in the
# comma separated list '$event_names'.
function validate_trace_opt()
{
	local event_names=$1
	local trace_path=$2
	local all_events_ret=0
	local ret
	local count

	bail_out_if_no_babeltrace

	OLDIFS=$IFS
	IFS=","
	for event_name in $event_names; do
		# trace_path is unquoted since callers make use of globbing
		# shellcheck disable=SC2086
		count=$(_run_babeltrace_cmd $trace_path | grep -c "$event_name")
		test "$count" -gt 0
		ret=$?
		if [[ -n "${TAP:-}" ]]; then
			ok $ret "Found '$count' events matching '$event_name'"
		else
			diag "Found '$count' events matching '${event_name}'"
		fi
		if [[ "${ret}" != "0" ]]; then
			all_events_ret=$ret
		fi
	done
	IFS=$OLDIFS
	return $all_events_ret
}

validate_trace_notap()
{
	TAP='' validate_trace_opt "${@}"
}

validate_trace()
{
	TAP=1 validate_trace_opt "${@}"
}

function retry_validate_trace()
{
	local retries="${RETRIES:-3}"
	local sleep="${SLEEP:-1}"
	local tries=1
	local event_name="${1}"
	local path="${2}"
	local ret="1"
	local output=""

	while [[ "${tries}" -le "${retries}" ]]; do
		if ! validate_trace_notap "${event_name}" "${path}"; then
			diag "Try '${tries} / ${retries}' failed to validate event '${event_name}' at path '${path}'"
			tries=$((tries+1))
			if [[ "${tries}" -lt "${retries}" ]]; then
				sleep "${sleep}"
				continue
			fi
		else
			ret="0"
			break
		fi
	done
	ok $ret "Found events matching '${event_name}'"
}

# Check that the trace contains at least 1 event matching each name in the
# comma separated list '$event_names' and a total of '$expected' events.
function validate_trace_count()
{
	local event_names=$1
	local trace_path=$2
	local expected=$3

	local count
	local total=0

	bail_out_if_no_babeltrace

	OLDIFS=$IFS
	IFS=","
	for event_name in $event_names; do
		count=$(_run_babeltrace_cmd "$trace_path" | grep -c "$event_name")
		test "$count" -gt 0
		ok $? "Found '$count' events matching '$event_name'"
		total=$(( total + count ))
	done
	IFS=$OLDIFS
	test $total -eq "$expected"
	ok $? "Found '$total' events, expected '$expected' events"
}

# Check that the trace contains at least '$expected_min' event matching each
# name in the comma separated list '$event_names' and a total at least
# '$expected_min' and less than '$expected_max' events.
function validate_trace_count_range_incl_min_excl_max()
{
	local event_names=$1
	local trace_path=$2
	local expected_min=$3
	local expected_max=$4

	local count
	local total=0

	bail_out_if_no_babeltrace

	OLDIFS=$IFS
	IFS=","
	for event_name in $event_names; do
		count=$(_run_babeltrace_cmd "$trace_path" | grep -c "$event_name")
		test "$count" -ge "$expected_min"
		ok $? "Found '$count' events matching '$event_name', expected at least '$expected_min'"
		total=$(( total + count ))
	done
	IFS=$OLDIFS
	test $total -ge "$expected_min" && test $total -lt "$expected_max"
	ok $? "Found a total of '$total' events, expected at least '$expected_min' and less than '$expected_max'"
}

function trace_first_line()
{
	local trace_path=$1

	_run_babeltrace_cmd "$trace_path" | head -n 1
}

# Check that the trace contains at least 1 event matching the grep extended
# regexp '$event_exp'.
function validate_trace_exp()
{
	local trace_path=$1
	local event_exp=("${@:2}")

	local count

	bail_out_if_no_babeltrace

	count=$(_run_babeltrace_cmd "$trace_path" | grep -c --extended-regexp "${event_exp[@]}")
	test "$count" -gt 0
	ok $? "Found '$count' events matching expression '${event_exp[*]}'"
}

# Check that the trace contains at least 1 event matching the grep extended
# regexp '$event_exp' and zero event not matching it.
function validate_trace_only_exp()
{
	local trace_path=$1
	local event_exp=("${@:2}")

	local count
	local total

	bail_out_if_no_babeltrace

	count=$(_run_babeltrace_cmd "$trace_path" | grep -c --extended-regexp "${event_exp[@]}")
	total=$(_run_babeltrace_cmd "$trace_path" | wc -l)

	test  "$count" -gt 0 && test "$total" -eq "$count"
	ok $? "Found '$count' events matching expression '${event_exp[*]}' amongst $total events"
}

# Check that the trace is valid and contains 0 event.
function validate_trace_empty()
{
	local trace_path=$1

	local ret
	local count

	bail_out_if_no_babeltrace

	events=$(_run_babeltrace_cmd "$trace_path")
	ret=$?
	if [ $ret -ne 0 ]; then
		fail "Failed to parse trace"
		return $ret
	fi

	count=$(echo -n "$events" | wc -l)
	test "$count" -eq 0
	ok $? "Validate trace is empty, found '$count' events"
}

function validate_directory_empty ()
{
	local trace_path="$1"

	local files
	local ret
	local nb_files

	# Do not double quote `$trace_path` below as we want wildcards to be
	# expanded.
	# shellcheck disable=SC2086
	files="$(ls -A $trace_path)"
	ret=$?
	if [ $ret -ne 0 ]; then
		fail "Failed to list content of directory '$trace_path'"
		return $ret
	fi

	nb_files="$(echo -n "$files" | wc -l)"
	test "$nb_files" -eq 0
	ok $? "Directory '$trace_path' is empty"
}

function validate_trace_session_ust_empty()
{
	validate_directory_empty "$1"/ust
}

function validate_trace_session_kernel_empty()
{
	validate_trace_empty "$1"/kernel
}

function regenerate_metadata ()
{
	local expected_to_fail=$1
	local sess_name=$2

	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" \
		regenerate metadata -s "$sess_name"
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test "$ret" -ne "0"
		ok $? "Regenerate metadate for session '$sess_name' failed as expected"
	else
		ok $ret "Regenerate metadata for session '$sess_name'"
	fi
}

function regenerate_metadata_ok ()
{
	regenerate_metadata 0 "$@"
}

function regenerate_metadata_fail ()
{
	regenerate_metadata 1 "$@"
}

function regenerate_statedump ()
{
	local expected_to_fail=$1
	local sess_name=$2

	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" \
		regenerate statedump -s "$sess_name"
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test "$ret" -ne "0"
		ok $? "Regenerate statedump for session '$sess_name' failed as expected"
	else
		ok $ret "Regenerate statedump for session '$sess_name'"
	fi
}

function regenerate_statedump_ok ()
{
	regenerate_statedump 0 "$@"
}

function regenerate_statedump_fail ()
{
	regenerate_statedump 1 "$@"
}

function rotate_session ()
{
	local expected_to_fail=$1
	local sess_name=$2

	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" \
		rotate "$sess_name"
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test "$ret" -ne "0"
		ok $? "Rotation for session '$sess_name' failed as expected"
	else
		ok $ret "Rotation for session '$sess_name'"
	fi
}

function rotate_session_ok ()
{
	rotate_session 0 "$@"
}

function rotate_session_fail ()
{
	rotate_session 1 "$@"
}

function destructive_tests_enabled ()
{
	if [ "$LTTNG_ENABLE_DESTRUCTIVE_TESTS" = "will-break-my-system" ]; then
		return 0
	else
		return 1
	fi
}

function lttng_enable_rotation_timer ()
{
	local expected_to_fail=$1
	local sess_name=$2
	local period=$3

	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" \
		enable-rotation -s "$sess_name" --timer "$period"
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test "$ret" -ne "0"
		ok $? "Set periodic rotation ($period) for session '$sess_name' failed as expected"
	else
		ok $ret "Set periodic rotation ($period) for session '$sess_name'"
	fi
}

function lttng_enable_rotation_timer_ok ()
{
	lttng_enable_rotation_timer 0 "$@"
}

function lttng_enable_rotation_timer_fail ()
{
	lttng_enable_rotation_timer 1 "$@"
}

function lttng_enable_rotation_size ()
{
	local expected_to_fail=$1
	local sess_name=$2
	local size=$3

	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" \
		enable-rotation -s "$sess_name" --size "$size"
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test "$ret" -ne "0"
		ok $? "Set periodic rotation for session '$sess_name' every '$size' bytes failed as expected"
	else
		ok $ret "Set scheduled rotation for session '$sess_name' every '$size' bytes"
	fi
}

function lttng_enable_rotation_size_ok ()
{
	lttng_enable_rotation_size 0 "$@"
}

function lttng_enable_rotation_size_fail ()
{
	lttng_enable_rotation_size 1 "$@"
}

function lttng_clear_session ()
{
	local expected_to_fail=$1
	local sess_name=$2

	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" \
		clear "$sess_name"
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test "$ret" -ne "0"
		ok $? "Clear session '$sess_name' failed as expected"
	else
		ok $ret "Clear session '$sess_name'"
	fi
}

function lttng_clear_session_ok ()
{
	lttng_clear_session 0 "$@"
}

function lttng_clear_session_fail ()
{
	lttng_clear_session 1 "$@"
}

function lttng_clear_all ()
{
	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" \
		clear --all
	ok $? "Clear all lttng sessions"
}

function lttng_add_trigger()
{
	local expected_to_fail="$1"
	local trigger_name="$2"
	local opts=("${@:3}")

	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" \
		add-trigger --name "${trigger_name}" "${opts[@]}"
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test "$ret" -ne "0"
		ok $? "Add trigger '$trigger_name' failed as expected"
	else
		ok $ret "Add trigger '$trigger_name'"
	fi
}

function lttng_remove_trigger()
{
	local expected_to_fail="$1"
	local trigger_name="$2"
	local opts=("${@:3}")

	_run_lttng_cmd "$(lttng_client_log_file)" "$(lttng_client_err_file)" \
		remove-trigger "${trigger_name}" "${opts[@]}"
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test "$ret" -ne "0"
		ok $? "Remove trigger '$trigger_name' failed as expected"
	else
		ok $ret "Remove trigger '$trigger_name'"
	fi
}

function lttng_add_trigger_ok()
{
	lttng_add_trigger 0 "$@"
}

function lttng_add_trigger_fail()
{
	lttng_add_trigger 1 "$@"
}

function lttng_remove_trigger_ok()
{
	lttng_remove_trigger 0 "$@"
}

function list_triggers_matches_ok ()
{
	local test_name="$1"
	local expected_stdout_file="$2"

	local tmp_stdout
	local tmp_stderr

	tmp_stdout=$(mktemp -t "tmp.${FUNCNAME[0]}_stdout.XXXXXX")
	tmp_stderr=$(mktemp -t "tmp.${FUNCNAME[0]}_stderr.XXXXXX")

	_run_lttng_cmd "${tmp_stdout}" "${tmp_stderr}" list-triggers
	ok $? "${test_name}: exit code is 0"

	diff -u "${expected_stdout_file}" "${tmp_stdout}"
	ok $? "${test_name}: expected stdout"

	diff -u /dev/null "${tmp_stderr}"
	ok $? "${test_name}: expected stderr"

	rm -f "${tmp_stdout}"
	rm -f "${tmp_stderr}"
}

function list_triggers_matches_mi_ok ()
{
	local test_name="$1"
	local expected_stdout_file="$2"

	local tmp_stdout
	local tmp_stdout_raw
	local tmp_stderr

	tmp_stdout_raw=$(mktemp -t "tmp.${FUNCNAME[0]}_stdout_raw.XXXXXX")
	tmp_stdout=$(mktemp -t "tmp.${FUNCNAME[0]}_stdout.XXXXXX")
	tmp_stderr=$(mktemp -t "tmp.${FUNCNAME[0]}_stderr.XXXXXX")

	_run_lttng_cmd "${tmp_stdout_raw}" "${tmp_stderr}" --mi=xml list-triggers
	ok $? "${test_name}: exit code is 0"

	# Pretty-fy xml before further test.
	$XML_PRETTY < "${tmp_stdout_raw}" > "${tmp_stdout}"

	lttng_mi_validate "${tmp_stdout}"
	ok $? "list-trigger mi is valid"

	diff -u "${expected_stdout_file}" "${tmp_stdout}"
	ok $? "${test_name}: expected stdout"

	diff -u /dev/null "${tmp_stderr}"
	ok $? "${test_name}: expected stderr"

	rm -f "${tmp_stdout}"
	rm -f "${tmp_stdout_raw}"
	rm -f "${tmp_stderr}"
}

function validate_path_pattern ()
{
	local message=$1
	local pattern=$2
	# Base path is only used in error case and is used to list the content
	# of the base path.
	local base_path=$3


	# shellcheck disable=SC2086
	[ -f $pattern ]
	local ret=$?
	ok "$ret" "$message"

	if [ "$ret" -ne "0" ]; then
		diag "Path pattern expected: $pattern"
		# List the tracepath for more info. We use find as a recursive
		# directory lister.
		diag "The base path content:"
		find "$base_path" -print
	fi
}

function validate_trace_path_ust_uid ()
{
	local trace_path=$1
	local sess_name=$2
	local uid=$UID
	local pattern="$trace_path/$sess_name-$DATE_TIME_PATTERN/ust/uid/$uid/$SYSTEM_LONG_BIT_SIZE-bit/metadata"

	validate_path_pattern "UST per-uid trace path is valid" "$pattern" "$trace_path"
}

function validate_trace_path_ust_uid_network ()
{
	local trace_path=$1
	local sess_name=$2
	local base_path=$3
	local uid=$UID
	local hostname=$HOSTNAME
	local pattern
	local ret

	# If the session was given a network base path (e.g
	# 127.0.0.1/my/custom/path on creation, there is no session name
	# component to the path on the relayd side. Caller can simply not pass a
	# session name for this scenario.
	if [ -n "$sess_name" ]; then
		sess_name="$sess_name-$DATE_TIME_PATTERN"
		if [ -n "$base_path" ]; then
			fail "Session name and base path are mutually exclusive"
			return
		fi
	fi

	pattern="$trace_path/$hostname/$base_path/$sess_name/ust/uid/$uid/$SYSTEM_LONG_BIT_SIZE-bit/metadata"

	validate_path_pattern "UST per-uid network trace path is valid" "$pattern" "$trace_path"
}

function validate_trace_path_ust_uid_snapshot_network ()
{
	local trace_path=$1
	local sess_name=$2
	local snapshot_name=$3
	local snapshot_number=$4
	local base_path=$5
	local hostname=$HOSTNAME
	local uid=$UID
	local pattern
	local ret

	# If the session/output was given a network base path (e.g
	# 127.0.0.1/my/custom/path on creation, there is no session name
	# component to the path on the relayd side. Caller can simply not pass a
	# session name for this scenario.
	if [ -n "$sess_name" ]; then
		sess_name="$sess_name-$DATE_TIME_PATTERN"
		if [ -n "$base_path" ]; then
			fail "Session name and base path are mutually exclusive"
			return
		fi
	fi

	pattern="$trace_path/$hostname/$base_path/$sess_name/$snapshot_name-$DATE_TIME_PATTERN-$snapshot_number/ust/uid/$uid/$SYSTEM_LONG_BIT_SIZE-bit/metadata"

	validate_path_pattern "UST per-uid network snapshot trace path is valid" "$pattern" "$trace_path"
}

function validate_trace_path_ust_uid_snapshot ()
{
	local trace_path=$1
	local sess_name=$2
	local snapshot_name=$3
	local snapshot_number=$4
	local base_path=$5
	local uid=$UID
	local pattern
	local ret

	# If the session/output was given a network base path (e.g
	# 127.0.0.1/my/custom/path) on creation, there is no session name
	# component to the path on the relayd side. Caller can simply not pass a
	# session name for this scenario.
	if [ -n "$sess_name" ]; then
		sess_name="$sess_name-$DATE_TIME_PATTERN"
		if [ -n "$base_path" ]; then
			fail "Session name and base path are mutually exclusive"
			return
		fi
	fi

	pattern="$trace_path/$base_path/$sess_name/$snapshot_name-$DATE_TIME_PATTERN-$snapshot_number/ust/uid/$uid/$SYSTEM_LONG_BIT_SIZE-bit/metadata"

	validate_path_pattern "UST per-uid snapshot trace path is valid" "$pattern" "$trace_path"
}

function validate_trace_path_ust_pid ()
{
	local trace_path=$1
	local sess_name=$2
	local app_string=$3
	local pid=$4
	local pattern
	local ret

	# If the session was given a trace path on creation, there is no session
	# name component to the path. Caller can simply not pass a session name
	# for this scenario.
	if [ -n "$sess_name" ]; then
		sess_name="$sess_name-$DATE_TIME_PATTERN"
	fi

	pattern="$trace_path/$sess_name/ust/pid/$pid/$app_string-*-$DATE_TIME_PATTERN/metadata"

	validate_path_pattern "UST per-pid trace path is valid" "$pattern" "$trace_path"
}

function validate_trace_path_kernel ()
{
	local trace_path=$1
	local sess_name=$2
	local pattern

	# If the session was given a trace path on creation, there is no session
	# name component to the path. Caller can simply not pass a session name
	# for this scenario.
	if [ -n "$sess_name" ]; then
		sess_name="$sess_name-$DATE_TIME_PATTERN"
	fi

	pattern="$trace_path/$sess_name/kernel/metadata"

	validate_path_pattern "Kernel trace path is valid" "$pattern" "$trace_path"
}

function validate_trace_path_kernel_network ()
{
	local trace_path=$1
	local sess_name=$2

	local pattern="$trace_path/$HOSTNAME/$sess_name-$DATE_TIME_PATTERN/kernel/metadata"

	validate_path_pattern "Kernel network trace path is valid" "$pattern" "$trace_path"
}

function validate_trace_path_kernel_snapshot ()
{
	local trace_path=$1
	local sess_name=$2
	local snapshot_name=$3
	local snapshot_number=$4
	local base_path=$5

	local pattern

	# If the session/output was given a network base path (e.g
	# 127.0.0.1/my/custom/path on creation, there is no session name
	# component to the path on the relayd side. Caller can simply not pass a
	# session name for this scenario.
	if [ -n "$sess_name" ]; then
		sess_name="$sess_name-$DATE_TIME_PATTERN"
		if [ -n "$base_path" ]; then
			fail "Session name and base path are mutually exclusive"
			return
		fi
	fi

	pattern="$trace_path/$base_path/$sess_name/$snapshot_name-$DATE_TIME_PATTERN-$snapshot_number/kernel/metadata"

	validate_path_pattern "Kernel snapshot trace path is valid" "$pattern" "$trace_path"
}

function validate_trace_path_kernel_snapshot_network ()
{
	local trace_path=$1
	local sess_name=$2
	local snapshot_name=$3
	local snapshot_number=$4
	local base_path=$5

	local pattern

	# If the session/output was given a network base path (e.g
	# 127.0.0.1/my/custom/path on creation, there is no session name
	# component to the path on the relayd side. Caller can simply not pass a
	# session name for this scenario.
	if [ -n "$sess_name" ]; then
		sess_name="$sess_name-$DATE_TIME_PATTERN"
		if [ -n "$base_path" ]; then
			fail "Session name and base path are mutually exclusive"
			return
		fi
	fi

	pattern="$trace_path/$HOSTNAME/$base_path/$sess_name/$snapshot_name-$DATE_TIME_PATTERN-$snapshot_number/kernel/metadata"

	validate_path_pattern "Kernel network snapshot trace path is valid" "$pattern" "$trace_path"
}
