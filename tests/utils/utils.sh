# Copyright (C) 2012 David Goulet <dgoulet@efficios.com>
#
# SPDX-License-Identifier: LGPL-2.1-only
#

SESSIOND_BIN="lttng-sessiond"
SESSIOND_MATCH=".*lttng-sess.*"
RUNAS_BIN="lttng-runas"
RUNAS_MATCH=".*lttng-runas.*"
CONSUMERD_BIN="lttng-consumerd"
CONSUMERD_MATCH=".*lttng-consumerd.*"
RELAYD_BIN="lttng-relayd"
RELAYD_MATCH=".*lttng-relayd.*"
LTTNG_BIN="lttng"
BABELTRACE_BIN="babeltrace2"
OUTPUT_DEST=/dev/null
ERROR_OUTPUT_DEST=/dev/null
MI_XSD_MAJOR_VERSION=4
MI_XSD_MINOR_VERSION=1
MI_XSD_PATH="$TESTDIR/../src/common/mi-lttng-${MI_XSD_MAJOR_VERSION}.${MI_XSD_MINOR_VERSION}.xsd"
MI_VALIDATE="$TESTDIR/utils/xml-utils/validate_xml ${MI_XSD_PATH}"

XML_PRETTY="$TESTDIR/utils/xml-utils/pretty_xml"
XML_EXTRACT="$TESTDIR/utils/xml-utils/extract_xml"
XML_NODE_CHECK="${XML_EXTRACT} -e"

# To match 20201127-175802
date_time_pattern="[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9][0-9][0-9]"
# The size of a long on this system
system_long_bit_size=$(getconf LONG_BIT)

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

source $TESTDIR/utils/tap/tap.sh

if [ -z ${LTTNG_TEST_TEARDOWN_TIMEOUT+x} ]; then
	LTTNG_TEST_TEARDOWN_TIMEOUT=60
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
	stop_lttng_relayd_cleanup SIGTERM $LTTNG_TEST_TEARDOWN_TIMEOUT
	stop_lttng_sessiond_cleanup SIGTERM $LTTNG_TEST_TEARDOWN_TIMEOUT

	# If daemons are still present, forcibly kill them
	stop_lttng_relayd_cleanup SIGKILL $LTTNG_TEST_TEARDOWN_TIMEOUT
	stop_lttng_sessiond_cleanup SIGKILL $LTTNG_TEST_TEARDOWN_TIMEOUT
	stop_lttng_consumerd_cleanup SIGKILL $LTTNG_TEST_TEARDOWN_TIMEOUT

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

	possible_pids=$($PGREP -f "$pattern")
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
	local len="${1:-16}"

	[ "$2" == "0" ] && CHAR="[:alnum:]" || CHAR="[:graph:]"
	# /dev/urandom isn't guaranteed to generate valid multi-byte characters.
	# Specifying the C locale eliminates the "Illegal byte sequence" error
	# that 'tr' outputs in such cases.
	LC_CTYPE=C tr -cd "$CHAR" < /dev/urandom 2>/dev/null | head -c "$len" 2>/dev/null
	echo
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

# Return any available CPU found. Do not make assumption about the returned
# value, e.g. that it could be 0.
function get_any_available_cpu()
{
	for cpu in $(get_online_cpus); do
		echo "${cpu}"
		break;
	done
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

# Check if base lttng-modules are present.
# Bail out on failure
function validate_lttng_modules_present ()
{
	# Check for loadable modules.
	modprobe -n lttng-tracer 2>/dev/null
	if [ $? -eq 0 ]; then
		return 0
	fi

	# Check for builtin modules.
	ls /proc/lttng > /dev/null 2>&1
	if [ $? -eq 0 ]; then
		return 0
	fi

	LTTNG_BAIL_OUT "LTTng modules not detected."
}

# Run the lttng binary.
#
# The first two arguments are stdout and stderr redirect paths, respectively.
# The rest of the arguments are forwarded to the lttng binary
function _run_lttng_cmd
{
	local stdout_dest="$1"
	local stderr_dest="$2"
	shift 2

	diag "$TESTDIR/../src/bin/lttng/$LTTNG_BIN $*"
	$TESTDIR/../src/bin/lttng/$LTTNG_BIN "$@" 1> "$stdout_dest" 2> "$stderr_dest"
}

function enable_kernel_lttng_event
{
	local withtap="$1"
	local expected_to_fail="$2"
	local sess_name="$3"
	local event_name="$4"
	local channel_name="$5"

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

	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
		enable-event "$event_name" $chan -s $sess_name -k
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test $ret -ne "0"
		ret=$?
		if [ $withtap -eq "1" ]; then
			ok $ret "Enable kernel event $event_name for session $session_name on channel $channel_name failed as expected"
		fi
	else
		if [ $withtap -eq "1" ]; then
			ok $ret "Enable kernel event $event_name for session $sess_name"
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

	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
		enable-event --syscall "$syscall_name" $chan -s $sess_name -k
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

	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
		disable-event --syscall "$syscall_name" $chan -s $sess_name -k

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

function lttng_enable_kernel_function_event ()
{
	local expected_to_fail="$1"
	local sess_name="$2"
	local target="$3"
	local event_name="$4"

	"$TESTDIR/../src/bin/lttng/$LTTNG_BIN" enable-event --kernel --function="$target" "$event_name" -s "$sess_name" > "$OUTPUT_DEST" 2> "$ERROR_OUTPUT_DEST"
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test $ret -ne "0"
		ok $? "Enable kernel function event for session $sess_name failed as expected"
	else
		ok $ret "Enable kernel function event for session $sess_name"
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

	"$TESTDIR/../src/bin/lttng/$LTTNG_BIN" enable-event --kernel --userspace-probe="$target" "$event_name" -s "$sess_name" > "$OUTPUT_DEST" 2> "$ERROR_OUTPUT_DEST"
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test $ret -ne "0"
		ok $? "Enable kernel userspace probe event for session $sess_name failed as expected"
	else
		ok $ret "Enable kernel userspace probe event for session $sess_name"
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

	"$TESTDIR/../src/bin/lttng/$LTTNG_BIN" disable-event --kernel "$event_name" -s "$sess_name" > "$OUTPUT_DEST" 2> "$ERROR_OUTPUT_DEST"
	ok $? "Disable kernel event $target for session $sess_name"
}
function lttng_enable_kernel_channel()
{
	local withtap=$1
	local expected_to_fail=$2
	local sess_name=$3
	local channel_name=$4
	local opts="${@:5}"

	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
		enable-channel -k $channel_name -s $sess_name $opts
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test "$ret" -ne "0"
		ret=$?
		if [ $withtap -eq "1" ]; then
			ok $ret "Enable channel $channel_name for session $sess_name failed as expected"
		fi
	else
		if [ $withtap -eq "1" ]; then
			ok $ret "Enable channel $channel_name for session $sess_name"
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

	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
		disable-channel -k $channel_name -s $sess_name
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
	local withtap=$1
	local process_mode=$2
	local opt=$3

	DIR=$(readlink -f "$TESTDIR")

	if [ -z $(lttng_pgrep "$RELAYD_MATCH") ]; then
		# shellcheck disable=SC2086
		$DIR/../src/bin/lttng-relayd/$RELAYD_BIN $process_mode $opt 1> $OUTPUT_DEST 2> $ERROR_OUTPUT_DEST
		#$DIR/../src/bin/lttng-relayd/$RELAYD_BIN $opt -vvv >>/tmp/relayd.log 2>&1 &
		if [ $? -eq 1 ]; then
			if [ $withtap -eq "1" ]; then
				fail "Start lttng-relayd (process mode: $process_mode opt: $opt)"
			fi
			return 1
		else
			if [ $withtap -eq "1" ]; then
				pass "Start lttng-relayd (process mode: $process_mode opt: $opt)"
			fi
		fi
	else
		pass "Start lttng-relayd (opt: $opt)"
	fi
}

function start_lttng_relayd()
{
	start_lttng_relayd_opt 1 "-b" "$@"
}

function start_lttng_relayd_notap()
{
	start_lttng_relayd_opt 0 "-b" "$@"
}

function stop_lttng_relayd_opt()
{
	local withtap=$1
	local is_cleanup=$2
	local signal=$3
	local timeout_s=$4
	local dtimeleft_s=
	local retval=0
	local pids

	if [ -z "$signal" ]; then
		signal="SIGTERM"
	fi


	# Multiply time by 2 to simplify integer arithmetic
	if [ -n "$timeout_s" ]; then
		dtimeleft_s=$((timeout_s * 2))
	fi


	pids=$(lttng_pgrep "$RELAYD_MATCH")
	if [ -z "$pids" ]; then
		if [ "$is_cleanup" -eq 1 ]; then
			:
		elif [ "$withtap" -eq "1" ]; then
			fail "No relay daemon to kill"
		else
			LTTNG_BAIL_OUT "No relay daemon to kill"
		fi
		return 0
	fi

	diag "Killing (signal $signal) lttng-relayd (pid: $pids)"

	# shellcheck disable=SC2086
	if ! kill -s $signal $pids 1> $OUTPUT_DEST 2> $ERROR_OUTPUT_DEST; then
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
			sleep 0.5
		done
		if [ "$withtap" -eq "1" ]; then
			if [ "$retval" -eq "0" ]; then
				pass "Wait after kill relay daemon"
			else
				fail "Wait after kill relay daemon"
			fi
		fi
	fi
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

	local env_vars=""
	local consumerd=""

	local long_bit_value=
	long_bit_value=$(getconf LONG_BIT)

	if [ -n "$TEST_NO_SESSIOND" ] && [ "$TEST_NO_SESSIOND" == "1" ]; then
		# Env variable requested no session daemon
		return
	fi

	DIR=$(readlink -f "$TESTDIR")

	# Get long_bit value for 32/64 consumerd
	case "$long_bit_value" in
		32)
			consumerd="--consumerd32-path=$DIR/../src/bin/lttng-consumerd/lttng-consumerd"
			;;
		64)
			consumerd="--consumerd64-path=$DIR/../src/bin/lttng-consumerd/lttng-consumerd"
			;;
		*)
			return
			;;
	esac

	# Check for env. variable. Allow the use of LD_PRELOAD etc.
	if [[ "x${LTTNG_SESSIOND_ENV_VARS}" != "x" ]]; then
		env_vars="${LTTNG_SESSIOND_ENV_VARS} "
	fi
	env_vars="${env_vars}$DIR/../src/bin/lttng-sessiond/$SESSIOND_BIN"

	if ! validate_kernel_version; then
	    fail "Start session daemon"
	    LTTNG_BAIL_OUT "*** Kernel too old for session daemon tests ***"
	fi

	diag "export LTTNG_SESSION_CONFIG_XSD_PATH=${DIR}/../src/common/"
	: "${LTTNG_SESSION_CONFIG_XSD_PATH="${DIR}/../src/common/"}"
	export LTTNG_SESSION_CONFIG_XSD_PATH

	if [ -z "$(lttng_pgrep "${SESSIOND_MATCH}")" ]; then
		# Have a load path ?
		if [ -n "$load_path" ]; then
			diag "env $env_vars --load $load_path --background $consumerd $@"
			# shellcheck disable=SC2086
			env $env_vars --load "$load_path" --background "$consumerd" "$@"
		else
			diag "env $env_vars --background $consumerd $@"
			# shellcheck disable=SC2086
			env $env_vars --background "$consumerd" "$@"
		fi
		#$DIR/../src/bin/lttng-sessiond/$SESSIOND_BIN --background --consumerd32-path="$DIR/../src/bin/lttng-consumerd/lttng-consumerd" --consumerd64-path="$DIR/../src/bin/lttng-consumerd/lttng-consumerd" --verbose-consumer >>/tmp/sessiond.log 2>&1
		status=$?
		if [ "$withtap" -eq "1" ]; then
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
	local is_cleanup=$2
	local signal=$3
	local timeout_s=$4
	local dtimeleft_s=
	local retval=0
	local runas_pids
	local pids

	if [ -z "$signal" ]; then
		signal=SIGTERM
	fi

	# Multiply time by 2 to simplify integer arithmetic
	if [ -n "$timeout_s" ]; then
		dtimeleft_s=$((timeout_s * 2))
	fi

	if [ -n "$TEST_NO_SESSIOND" ] && [ "$TEST_NO_SESSIOND" == "1" ]; then
		# Env variable requested no session daemon
		return 0
	fi

	runas_pids=$(lttng_pgrep "$RUNAS_MATCH")
	pids=$(lttng_pgrep "$SESSIOND_MATCH")

	if [ -n "$runas_pids" ]; then
		pids="$pids $runas_pids"
	fi

	if [ -z "$pids" ]; then
		if [ "$is_cleanup" -eq 1 ]; then
			:
		elif [ "$withtap" -eq "1" ]; then
			fail "No session daemon to kill"
		else
			LTTNG_BAIL_OUT "No session daemon to kill"
		fi
		return 0
	fi

	diag "Killing (signal $signal) $SESSIOND_BIN and lt-$SESSIOND_BIN pids: $(echo "$pids" | tr '\n' ' ')"

	# shellcheck disable=SC2086
	if ! kill -s $signal $pids 1> $OUTPUT_DEST 2> $ERROR_OUTPUT_DEST; then
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
			sleep 0.5
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
			sleep 0.5
		done

		if [ "$withtap" -eq "1" ]; then
			if [ "$retval" -eq "0" ]; then
				pass "Wait after kill session daemon"
			else
				fail "Wait after kill session daemon"
			fi
		fi
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
	local pids

	if [ -n "$TEST_NO_SESSIOND" ] && [ "$TEST_NO_SESSIOND" == "1" ]; then
		# Env variable requested no session daemon
		return
	fi

	pids="$(lttng_pgrep "${SESSIOND_MATCH}") $(lttng_pgrep "$RUNAS_MATCH")"

	if [ "$withtap" -eq "1" ]; then
		diag "Sending SIGSTOP to lt-$SESSIOND_BIN and $SESSIOND_BIN pids: $(echo "$pids" | tr '\n' ' ')"
	fi

	# shellcheck disable=SC2086
	if ! kill -s $signal $pids 1> $OUTPUT_DEST 2> $ERROR_OUTPUT_DEST; then
		if [ "$withtap" -eq "1" ]; then
			fail "Sending SIGSTOP to session daemon"
		fi
	else
		out=1
		while [ $out -ne 0 ]; do
			pids="$(lttng_pgrep "$SESSIOND_MATCH")"

			# Wait until state becomes stopped for session
			# daemon(s).
			out=0
			for sessiond_pid in $pids; do
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
	if [ -n "$timeout_s" ]; then
		dtimeleft_s=$((timeout_s * 2))
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
	if ! kill -s $signal $pids 1> $OUTPUT_DEST 2> $ERROR_OUTPUT_DEST; then
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
			sleep 0.5
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
	kill -s $signal $pids 1> $OUTPUT_DEST 2> $ERROR_OUTPUT_DEST
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
	local ret
	local withtap=$1
	shift
	local opts=$1
	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
		list $opts
	ret=$?
	if [ $withtap -eq "1" ]; then
		ok $ret "Lttng-tool list command with option $opts"
	fi
}

function list_lttng_ok ()
{
	list_lttng_with_opts 1 "$@"
}

function list_lttng_notap ()
{
	list_lttng_with_opts 0 "$@"
}

function create_lttng_session_no_output ()
{
	local sess_name=$1
	local opts="${@:2}"

	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
		create $sess_name --no-output $opts
	ok $? "Create session $sess_name in no-output mode"
}

function create_lttng_session_uri () {
	local sess_name=$1
	local uri=$2
	local opts="${@:3}"

	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
		create $sess_name -U $uri $opts
	ok $? "Create session $sess_name with uri:$uri and opts: $opts"
}

function create_lttng_session ()
{
	local withtap=$1
	local expected_to_fail=$2
	local sess_name=$3
	local trace_path=$4
	local opt=$5

	if [ -z "$trace_path" ]; then
		# Use lttng-sessiond default output.
		trace_path=""
	else
		trace_path="-o $trace_path"
	fi

	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
		create "$sess_name" $trace_path $opt
	ret=$?
	if [ $expected_to_fail -eq "1" ]; then
		test "$ret" -ne "0"
		ret=$?
		if [ $withtap -eq "1" ]; then
			ok $ret "Create session $sess_name in $trace_path failed as expected"
		fi
	else
		if [ $withtap -eq "1" ]; then
			ok $ret "Create session $sess_name in $trace_path"
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
	local opts="${@:5}"

	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
		enable-channel -u $channel_name -s $sess_name $opts
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test "$ret" -ne "0"
		ret=$?
		if [ $withtap -eq "1" ]; then
			ok $ret "Enable channel $channel_name for session $sess_name failed as expected"
		fi
	else
		if [ $withtap -eq "1" ]; then
			ok $ret "Enable channel $channel_name for session $sess_name"
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

	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
		disable-channel -u $channel_name -s $sess_name
	ok $? "Disable channel $channel_name for session $sess_name"
}

function enable_lttng_mmap_overwrite_kernel_channel()
{
	local sess_name=$1
	local channel_name=$2

	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
		enable-channel -s $sess_name $channel_name -k --output mmap --overwrite
	ok $? "Enable channel $channel_name for session $sess_name"
}

function enable_lttng_mmap_discard_small_kernel_channel()
{
	local sess_name=$1
	local channel_name=$2

	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
		enable-channel -s $sess_name $channel_name -k --output mmap --discard --subbuf-size=$(getconf PAGE_SIZE) --num-subbuf=2
	ok $? "Enable small discard channel $channel_name for session $sess_name"
}

function enable_lttng_mmap_overwrite_small_kernel_channel()
{
	local sess_name=$1
	local channel_name=$2

	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
		enable-channel -s $sess_name $channel_name -k --output mmap --overwrite --subbuf-size=$(getconf PAGE_SIZE) --num-subbuf=2
	ok $? "Enable small discard channel $channel_name for session $sess_name"
}

function enable_lttng_mmap_overwrite_ust_channel()
{
	local sess_name=$1
	local channel_name=$2

	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
		enable-channel -s $sess_name $channel_name -u --output mmap --overwrite
	ok $? "Enable channel $channel_name for session $sess_name"
}

function enable_ust_lttng_event ()
{
	local withtap=$1
	local expected_to_fail=$2
	local sess_name=$3
	local event_name="$4"
	local channel_name=$5

	if [ -z $channel_name ]; then
		# default channel if none specified
		chan=""
	else
		chan="-c $channel_name"
	fi

	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
		enable-event "$event_name" $chan -s "$sess_name" -u
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test $ret -ne "0"
		ret=$?
		if [[ $withtap -eq "1" ]]; then
			ok $ret "Enable ust event $event_name for session $session_name failed as expected"
		fi
	else
		if [[ $withtap -eq "1" ]]; then
			ok $ret "Enable ust event $event_name for session $sess_name"
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
	sess_name=$1
	event_name="$2"
	channel_name=$3

	if [ -z $channel_name ]; then
		# default channel if none specified
		chan=""
	else
		chan="-c $channel_name"
	fi

	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
		enable-event "$event_name" $chan -s $sess_name -j
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

	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
		enable-event --loglevel $loglevel "$event_name" $chan -s $sess_name -j
	ok $? "Enable JUL event $event_name for session $sess_name with loglevel $loglevel"
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

	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
		enable-event "$event_name" "${chan_opt[@]}" -s "$sess_name" --log4j
	ok $? "Enable LOG4J event '$event_name' for session '$sess_name'"
}

function enable_log4j_lttng_event_filter()
{
	local sess_name=$1
	local event_name=$2
	local filter=$3

	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
		enable-event "$event_name" -s "$sess_name" --log4j --filter "$filter"
	ok $? "Enable LOG4J event '$event_name' with filter '$filter' for session '$sess_name'"
}

function enable_log4j_lttng_event_filter_loglevel_only()
{
	local sess_name=$1
	local event_name=$2
	local filter=$3
	local loglevel=$4

	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
		enable-event --loglevel-only "$loglevel" "$event_name" -s "$sess_name" -l --filter "$filter"
	ok $? "Enable LOG4J event '$event_name' with filter '$filter' and loglevel-only '$loglevel' for session '$sess_name'"
}

function enable_log4j_lttng_event_loglevel()
{
	local sess_name=$1
	local event_name=$2
	local loglevel=$3
	local channel_name=$4


	# default channel if none specified
	if [ -n "$channel_name" ]; then
		chan_opt=("-c" "$channel_name")
	fi

	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
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

	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
		enable-event --loglevel-only "$loglevel" "$event_name" "${chan_opt[@]}" -s "$sess_name" --log4j
	ok $? "Enable LOG4J event '$event_name' for session '$sess_name' with loglevel-only '$loglevel'"
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

	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
		enable-event "$event_name" $chan -s $sess_name -p
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

	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
		enable-event --loglevel $loglevel "$event_name" $chan -s $sess_name -p
	ok $? "Enable Python event $event_name for session $sess_name with loglevel $loglevel"
}

function enable_ust_lttng_event_filter()
{
	local sess_name="$1"
	local event_name="$2"
	local filter="$3"
	local channel_name=$4

	if [ -z $channel_name ]; then
		# default channel if none specified
		chan=""
	else
		chan="-c $channel_name"
	fi

	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
		enable-event $chan "$event_name" -s $sess_name -u --filter "$filter"
	ok $? "Enable event $event_name with filtering for session $sess_name"
}

function enable_ust_lttng_event_loglevel()
{
	local sess_name="$1"
	local event_name="$2"
	local loglevel="$3"
	local channel_name="$4"
	local chan=()
	if [ -n "${channel_name}" ] ; then
		chan=('-c' "${channel_name}")
	fi

	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
		enable-event "${chan[@]}" "$event_name" -s "${sess_name}" -u --loglevel="${loglevel}"
	ok $? "Enable event $event_name with loglevel $loglevel"
}

function enable_ust_lttng_event_loglevel_only()
{
	local sess_name="$1"
	local event_name="$2"
	local loglevel="$3"
	local channel_name="$4"
	local chan=()
	if [ -n "${channel_name}" ] ; then
		chan=('-c' "${channel_name}")
	fi

	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
		enable-event "${chan[@]}" "$event_name" -s "${sess_name}" -u --loglevel-only "${loglevel}"
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

	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
		disable-event "$event_name" -s $sess_name $chan -u
	ok $? "Disable event $event_name for session $sess_name"
}

function disable_jul_lttng_event ()
{
	local sess_name="$1"
	local event_name="$2"

	$TESTDIR/../src/bin/lttng/$LTTNG_BIN disable-event "$event_name" -s $sess_name -j >/dev/null 2>&1
	ok $? "Disable JUL event $event_name for session $sess_name"
}

function disable_log4j_lttng_event ()
{
	local sess_name="$1"
	local event_name="$2"

	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
		disable-event "$event_name" -s "$sess_name" --log4j
	ok $? "Disable LOG4J event '$event_name' for session '$sess_name'"
}

function disable_python_lttng_event ()
{
	local sess_name="$1"
	local event_name="$2"

	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
		disable-event "$event_name" -s $sess_name -p
	ok $? "Disable Python event $event_name for session $sess_name"
}

function start_lttng_tracing_opt ()
{
	local withtap=$1
	local expected_to_fail=$2
	local sess_name=$3

	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
		start $sess_name
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test "$ret" -ne "0"
		ret=$?
		if [ $withtap -eq "1" ]; then
			ok $? "Start tracing for session $sess_name failed as expected"
		fi
	else
		if [ $withtap -eq "1" ]; then
			ok $ret "Start tracing for session $sess_name"
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

	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
		stop $sess_name
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test "$ret" -ne "0"
		ret=$?
		if [ $withtap -eq "1" ]; then
			ok $? "Stop lttng tracing for session $sess_name failed as expected"
		fi
	else
		if [ $withtap -eq "1" ]; then
			ok $ret "Stop lttng tracing for session $sess_name"
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

	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
		destroy $sess_name
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test "$ret" -ne "0"
		ret=$?
		if [ $withtap -eq "1" ]; then
			ok $ret "Destroy session $sess_name failed as expected"
		fi
	else
		if [ $withtap -eq "1" ]; then
			ok $ret "Destroy session $sess_name"
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
	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
		destroy --all
	ok $? "Destroy all lttng sessions"
}

function lttng_snapshot_add_output ()
{
	local expected_to_fail=$1
	local sess_name=$2
	local trace_path=$3
	local opts=$4

	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
		snapshot add-output -s $sess_name $trace_path $opts
	ret=$?
	if [[ $expected_to_fail -eq 1 ]]; then
		test "$ret" -ne "0"
		ok $? "Added snapshot output $trace_path failed as expected"
	else
		ok $ret "Added snapshot output $trace_path"
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

	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
		snapshot del-output -s $sess_name $id
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

	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
		snapshot record -s "$sess_name" "$trace_path"
	ok $? "Snapshot recorded"
}

function lttng_snapshot_list ()
{
	local sess_name=$1
	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
		snapshot list-output -s $sess_name
	ok $? "Snapshot list"
}

function lttng_save()
{
	local sess_name=$1
	local opts=$2

	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
		save $sess_name $opts
	ok $? "Session saved"
}

function lttng_load()
{
	local expected_to_fail=$1
	local opts=$2

	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
		load $opts
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test $ret -ne "0"
		ok $? "Load command failed as expected with opts: $opts"
	else
		ok $ret "Load command with opts: $opts"
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
	shift 1
	local opts="$@"
	$TESTDIR/../src/bin/lttng/$LTTNG_BIN track $opts >$OUTPUT_DEST
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
	local expected_to_fail="$1"
	shift 1
	local opts="$@"
	$TESTDIR/../src/bin/lttng/$LTTNG_BIN untrack $opts >$OUTPUT_DEST
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

function lttng_track_pid_ok()
{
	PID=$1
	"$TESTDIR/../src/bin/lttng/$LTTNG_BIN" track --kernel --pid=$PID 1> $OUTPUT_DEST 2> $ERROR_OUTPUT_DEST
	ok $? "Lttng track pid on the kernel domain"
}

function lttng_untrack_kernel_all_ok()
{
	"$TESTDIR/../src/bin/lttng/$LTTNG_BIN" untrack --kernel --pid --all 1> $OUTPUT_DEST 2> $ERROR_OUTPUT_DEST
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
	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
		add-context --list
	ret=$?
	ok $ret "Context listing"
}

function add_context_lttng()
{
	local expected_to_fail="$1"
	local domain="$2"
	local session_name="$3"
	local channel_name="$4"
	local type="$5"

	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
		add-context -s $session_name -c $channel_name -t $type $domain 
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
	while [ $zero_client_match -eq 0 ]; do
		zero_client_match=$($BABELTRACE_BIN -i lttng-live $url | grep "0 client(s) connected" | wc -l)
		sleep 0.5
	done
	pass "Waiting for live trace at url: $url"
}

function wait_live_viewer_connect ()
{
	local url=$1
	local one_client_match=0

	diag "Waiting for live viewers on url: $url"
	while [ $one_client_match -eq 0 ]; do
		one_client_match=$($BABELTRACE_BIN -i lttng-live $url | grep "1 client(s) connected" | wc -l)
		sleep 0.5
	done
	pass "Waiting for live viewers on url: $url"
}

function bail_out_if_no_babeltrace()
{
	which "$BABELTRACE_BIN" >/dev/null
	if [ $? -ne 0 ]; then
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

	count=$($BABELTRACE_BIN --output-format=ctf-metadata "$metadata_path" | grep -c "$event_name")

	test "$count" -eq "$expected"
	ok $? "Found $count / $expected metadata event id matching '$event_name'"
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

	count=$($BABELTRACE_BIN "$trace_path" | grep -c "$event_name")
	total=$($BABELTRACE_BIN "$trace_path" | wc -l)

	test "$count" -eq "$expected"

	ok $? "Found $count / $expected events matching '$event_name' out of $total events"
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

	count=$($BABELTRACE_BIN "$trace_path" | grep -c "$event_name")
	total=$($BABELTRACE_BIN "$trace_path" | wc -l)

	test "$expected" -eq "$count" && test "$total" -eq "$expected"

	ok $? "Found $count / $expected events matching '$event_name' amongst $total events"
}

# Check that the trace contains at least 1 event matching each name in the
# comma separated list '$event_names'.
function validate_trace()
{
	local event_names=$1
	local trace_path=$2

	local count

	bail_out_if_no_babeltrace

	OLDIFS=$IFS
	IFS=","
	for event_name in $event_names; do
		# trace_path is unquoted since callers make use of globbing
		count=$($BABELTRACE_BIN $trace_path | grep -c "$event_name")
		test "$count" -gt 0
		ok $? "Found $count events matching '$event_name'"
	done
	IFS=$OLDIFS
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
		count=$($BABELTRACE_BIN "$trace_path" | grep -c "$event_name")
		test "$count" -gt 0
		ok $? "Found '$count' events matching '$event_name'"
		total=$(( total + count ))
	done
	IFS=$OLDIFS
	test $total -eq "$expected"
	ok $? "Found $total events, expected $expected events"
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
		count=$($BABELTRACE_BIN "$trace_path" | grep -c "$event_name")
		test "$count" -ge "$expected_min"
		ok $? "Found $count events matching '$event_name', expected at least $expected_min"
		total=$(( total + count ))
	done
	IFS=$OLDIFS
	test $total -ge "$expected_min" && test $total -lt "$expected_max"
	ok $? "Found a total of $total events, expected at least $expected_min and less than $expected_max"
}

function trace_first_line()
{
	local trace_path=$1

	$BABELTRACE_BIN "$trace_path" | head -n 1
}

# Check that the trace contains at least 1 event matching the grep extended
# regexp '$event_exp'.
function validate_trace_exp()
{
	local event_exp=$1
	local trace_path=$2

	local count

	bail_out_if_no_babeltrace

	# event_exp is unquoted since it contains multiple grep arguments
	count=$($BABELTRACE_BIN "$trace_path" | grep -c --extended-regexp $event_exp)
	test "$count" -gt 0
	ok $? "Found $count events matching expression '$event_exp'"
}

# Check that the trace contains at least 1 event matching the grep extended
# regexp '$event_exp' and zero event not matching it.
function validate_trace_only_exp()
{
	local event_exp=$1
	local trace_path=$2

	local count
	local total

	bail_out_if_no_babeltrace

	# event_exp is unquoted since it contains multiple grep arguments
	count=$($BABELTRACE_BIN "$trace_path" | grep -c --extended-regexp $event_exp)
	total=$($BABELTRACE_BIN "$trace_path" | wc -l)

	test  "$count" -gt 0 && test "$total" -eq "$count"
	ok $? "Found $count events matching expression '$event_exp' amongst $total events"
}

# Check that the trace is valid and contains 0 event.
function validate_trace_empty()
{
	local trace_path=$1

	local ret
	local count

	bail_out_if_no_babeltrace

	events=$($BABELTRACE_BIN "$trace_path")
	ret=$?
	if [ $ret -ne 0 ]; then
		fail "Failed to parse trace"
		return $ret
	fi

	count=$(echo -n "$events" | wc -l)
	test "$count" -eq 0
	ok $? "Validate trace is empty, found $count events"
}

function validate_directory_empty ()
{
	local trace_path="$1"

	local files
	local ret
	local nb_files

	# Do not double quote `$trace_path` below as we want wildcards to be
	# expanded.
	files="$(ls -A $trace_path)"
	ret=$?
	if [ $ret -ne 0 ]; then
		fail "Failed to list content of directory \"$trace_path\""
		return $ret
	fi

	nb_files="$(echo -n "$files" | wc -l)"
	test "$nb_files" -eq 0
	ok $? "Directory \"$trace_path\" is empty"
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

	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
		regenerate metadata -s $sess_name
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test "$ret" -ne "0"
		ok $? "Expected fail on regenerate metadata $sess_name"
	else
		ok $ret "Metadata regenerate $sess_name"
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

	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
		regenerate statedump -s $sess_name
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test "$ret" -ne "0"
		ok $? "Expected fail on regenerate statedump $sess_name"
	else
		ok $ret "Statedump regenerate $sess_name"
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

	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
		rotate $sess_name
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test "$ret" -ne "0"
		ok $? "Expected fail on rotate session $sess_name"
	else
		ok $ret "Rotate session $sess_name"
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

	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
		enable-rotation -s $sess_name --timer $period
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test "$ret" -ne "0"
		ok $? "Expected fail when setting periodic rotation ($period) of session $sess_name"
	else
		ok $ret "Set periodic rotation ($period) of session $sess_name"
	fi
}

function lttng_enable_rotation_timer_ok ()
{
	lttng_enable_rotation_timer 0 $@
}

function lttng_enable_rotation_timer_fail ()
{
	lttng_enable_rotation_timer 1 $@
}

function lttng_enable_rotation_size ()
{
	local expected_to_fail=$1
	local sess_name=$2
	local size=$3

	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
		enable-rotation -s $sess_name --size $size
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test "$ret" -ne "0"
		ok $? "Expected to fail to set a periodic rotation of session $sess_name" "every " $size " bytes"
	else
		ok $ret "Set a scheduled rotation of session $sess_name" "every " $size " bytes"
	fi
}

function lttng_enable_rotation_size_ok ()
{
	lttng_enable_rotation_size 0 $@
}

function lttng_enable_rotation_size_fail ()
{
	lttng_enable_rotation_size 1 $@
}

function lttng_clear_session ()
{
	local expected_to_fail=$1
	local sess_name=$2

	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
		clear $sess_name
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test "$ret" -ne "0"
		ok $? "Expected fail on clear session $sess_name"
	else
		ok $ret "Clear session $sess_name"
	fi
}

function lttng_clear_session_ok ()
{
	lttng_clear_session 0 $@
}

function lttng_clear_session_fail ()
{
	lttng_clear_session 1 $@
}

function lttng_clear_all ()
{
	_run_lttng_cmd "$OUTPUT_DEST" "$ERROR_OUTPUT_DEST" \
		clear --all
	ok $? "Clear all lttng sessions"
}

function lttng_add_trigger()
{
	local expected_to_fail="$1"
	local trigger_name="$2"
	shift 2
	local args=("$@")

	diag "$TESTDIR/../src/bin/lttng/$LTTNG_BIN add-trigger --name $trigger_name ${args[*]}"
	$TESTDIR/../src/bin/lttng/$LTTNG_BIN add-trigger --name "$trigger_name" "${args[@]}" 1> /dev/null 2> /dev/null
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test "$ret" -ne "0"
		ok $? "Add trigger $trigger_name failed as expected"
	else
		ok $ret "Add trigger $trigger_name"
	fi
}

function lttng_remove_trigger()
{
	local expected_to_fail="$1"
	local trigger_name="$2"
	shift 2

	diag "$TESTDIR/../src/bin/lttng/$LTTNG_BIN remove-trigger $trigger_name $*"
	"$TESTDIR/../src/bin/lttng/$LTTNG_BIN" remove-trigger "$trigger_name" "$@" 1> /dev/null 2> /dev/null
	ret=$?
	if [[ $expected_to_fail -eq "1" ]]; then
		test "$ret" -ne "0"
		ok $? "Remove trigger $trigger_name failed as expected"
	else
		ok $ret "Remove trigger $trigger_name"
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
	local tmp_stdout=$(mktemp -t "tmp.${FUNCNAME[0]}_stdout.XXXXXX")
	local tmp_stderr=$(mktemp -t "tmp.${FUNCNAME[0]}_stderr.XXXXXX")

	local test_name="$1"
	local expected_stdout_file="$2"

	diag "$TESTDIR/../src/bin/lttng/$LTTNG_BIN list-triggers"

	"$TESTDIR/../src/bin/lttng/$LTTNG_BIN" list-triggers > "${tmp_stdout}" 2> "${tmp_stderr}"
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
	local tmp_stdout
	local tmp_stdout_raw
	local tmp_stderr

	local test_name="$1"
	local expected_stdout_file="$2"

	tmp_stdout_raw=$(mktemp -t "tmp.${FUNCNAME[0]}_stdout.XXXXXX")
	tmp_stdout=$(mktemp -t "tmp.${FUNCNAME[0]}_stdout.XXXXXX")
	tmp_stderr=$(mktemp -t "tmp.${FUNCNAME[0]}_stderr.XXXXXX")

	diag "$TESTDIR/../src/bin/lttng/$LTTNG_BIN --mi xml list-triggers"

	"$TESTDIR/../src/bin/lttng/$LTTNG_BIN" --mi=xml list-triggers > "${tmp_stdout_raw}" 2> "${tmp_stderr}"
	ok $? "${test_name}: exit code is 0"

	# Pretty-fy xml before further test.
	$XML_PRETTY < "${tmp_stdout_raw}" > "${tmp_stdout}"

	$MI_VALIDATE "${tmp_stdout}"
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


	[ -f $pattern ]
	ret=$?
	ok $ret "$message"

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
	local session_name=$2
	local uid=$UID
	local pattern="$trace_path/$session_name-$date_time_pattern/ust/uid/$uid/${system_long_bit_size}-bit/metadata"

	validate_path_pattern "UST per-uid trace path is valid" "$pattern" "$trace_path"
}

function validate_trace_path_ust_uid_network ()
{
	local trace_path=$1
	local session_name=$2
	local base_path=$3
	local uid=$UID
	local hostname=$HOSTNAME
	local pattern
	local ret

	# If the session was given a network base path (e.g
	# 127.0.0.1/my/custom/path on creation, there is no session name
	# component to the path on the relayd side. Caller can simply not pass a
	# session name for this scenario.
	if [ -n "$session_name" ]; then
		session_name="$session_name-$date_time_pattern"
		if [ -n "$base_path" ]; then
			fail "Session name and base path are mutually exclusive"
			return
		fi
	fi

	pattern="$trace_path/$hostname/$base_path/$session_name/ust/uid/$uid/${system_long_bit_size}-bit/metadata"

	validate_path_pattern "UST per-uid network trace path is valid" "$pattern" "$trace_path"
}

function validate_trace_path_ust_uid_snapshot_network ()
{
	local trace_path=$1
	local session_name=$2
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
	if [ -n "$session_name" ]; then
		session_name="$session_name-$date_time_pattern"
		if [ -n "$base_path" ]; then
			fail "Session name and base path are mutually exclusive"
			return
		fi
	fi

	pattern="$trace_path/$hostname/$base_path/$session_name/$snapshot_name-$date_time_pattern-$snapshot_number/ust/uid/$uid/${system_long_bit_size}-bit/metadata"

	validate_path_pattern "UST per-uid network snapshot trace path is valid" "$pattern" "$trace_path"
}

function validate_trace_path_ust_uid_snapshot ()
{
	local trace_path=$1
	local session_name=$2
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
	if [ -n "$session_name" ]; then
		session_name="$session_name-$date_time_pattern"
		if [ -n "$base_path" ]; then
			fail "Session name and base path are mutually exclusive"
			return
		fi
	fi

	pattern="$trace_path/$base_path/$session_name/$snapshot_name-$date_time_pattern-$snapshot_number/ust/uid/$uid/${system_long_bit_size}-bit/metadata"

	validate_path_pattern "UST per-uid snapshot trace path is valid" "$pattern" "$trace_path"
}

function validate_trace_path_ust_pid ()
{
	local trace_path=$1
	local session_name=$2
	local app_string=$3
	local pid=$4
	local pattern
	local ret

	# If the session was given a trace path on creation, there is no session
	# name component to the path. Caller can simply not pass a session name
	# for this scenario.
	if [ -n "$session_name" ]; then
		session_name="$session_name-$date_time_pattern"
	fi

	pattern="$trace_path/$session_name/ust/pid/$pid/$app_string-*-$date_time_pattern/metadata"

	validate_path_pattern "UST per-pid trace path is valid" "$pattern" "$trace_path"
}

function validate_trace_path_kernel ()
{
	local trace_path=$1
	local session_name=$2
	local pattern

	# If the session was given a trace path on creation, there is no session
	# name component to the path. Caller can simply not pass a session name
	# for this scenario.
	if [ -n "$session_name" ]; then
		session_name="$session_name-$date_time_pattern"
	fi

	pattern="$trace_path/$session_name/kernel/metadata"

	validate_path_pattern "Kernel trace path is valid" "$pattern" "$trace_path"
}

function validate_trace_path_kernel_network ()
{
	local trace_path=$1
	local session_name=$2
	local hostname=$HOSTNAME
	local pattern="$trace_path/$hostname/$session_name-$date_time_pattern/kernel/metadata"

	validate_path_pattern "Kernel network trace path is valid" "$pattern" "$trace_path"
}

function validate_trace_path_kernel_snapshot ()
{
	local trace_path=$1
	local session_name=$2
	local snapshot_name=$3
	local snapshot_number=$4
	local base_path=$5
	local pattern
	local ret

	# If the session/output was given a network base path (e.g
	# 127.0.0.1/my/custom/path on creation, there is no session name
	# component to the path on the relayd side. Caller can simply not pass a
	# session name for this scenario.
	if [ -n "$session_name" ]; then
		session_name="$session_name-$date_time_pattern"
		if [ -n "$base_path" ]; then
			fail "Session name and base path are mutually exclusive"
			return
		fi
	fi

	pattern="$trace_path/$base_path/$session_name/$snapshot_name-$date_time_pattern-$snapshot_number/kernel/metadata"

	validate_path_pattern "Kernel snapshot trace path is valid" "$pattern" "$trace_path"
}

function validate_trace_path_kernel_snapshot_network ()
{
	local trace_path=$1
	local session_name=$2
	local snapshot_name=$3
	local snapshot_number=$4
	local base_path=$5
	local hostname=$HOSTNAME
	local pattern
	local ret

	# If the session/output was given a network base path (e.g
	# 127.0.0.1/my/custom/path on creation, there is no session name
	# component to the path on the relayd side. Caller can simply not pass a
	# session name for this scenario.
	if [ -n "$session_name" ]; then
		session_name="$session_name-$date_time_pattern"
		if [ -n "$base_path" ]; then
			fail "Session name and base path are mutually exclusive"
			return
		fi
	fi

	pattern="$trace_path/$hostname/$base_path/$session_name/$snapshot_name-$date_time_pattern-$snapshot_number/kernel/metadata"

	validate_path_pattern "Kernel network snapshot trace path is valid" "$pattern" "$trace_path"
}
