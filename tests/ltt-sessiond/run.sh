#!/bin/bash
#
# Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#

PWD=$(dirname $0)

SESSIOND_CLIENT_SOCK_PATH="/tmp/.test-sessiond-client"
SESSIOND_APPS_SOCK_PATH="/tmp/.test-sessiond-apps"
SESSIOND_BIN="$PWD/../../ltt-sessiond/ltt-sessiond"
LTTNG_BIN="$PWD/../../lttng/lttng"
#SESSIOND_ARGS="-c $SESSIOND_CLIENT_SOCK_PATH -a $SESSIOND_APPS_SOCK_PATH"
SESSIOND_ARGS=""
SESSION_ID_REGEX="[[:alnum:]]{8}-[[:alnum:]]{4}-[[:alnum:]]{4}-[[:alnum:]]{4}-[[:alnum:]]{12}"

function clean_exit()
{
	echo "[+] Shuting down session daemon..."
	kill -s SIGTERM $pid
	exit $1
}

# Exec $1, check error code.
# If 0, return output, else, stop execution
# and return and error.
function check_ret_code()
{
	if [ $1 -ne 0 ]; then
		printf "\n!STOPPING!\n"
		clean_exit 1
	fi
}

# Create session with $1 and return output.
function lttng_create_session()
{
	local command="$LTTNG_BIN -c $1"
	local ret=$($command)
	LTTNG_RET_CODE=$?

	# Extract session UUID
	if [[ "$ret" =~ $SESSION_ID_REGEX ]]; then
		LTTNG_SESSION_ID="$BASH_REMATCH"
	fi
}

# List sessions and return output.
function lttng_list_session()
{
	local command="$LTTNG_BIN --list-sessions"
	local ret=$(lttng_command "$command")

	if [[ "$result" =~ $session_id ]]; then
		printf "SUCCESS!\n"
	else
		printf "FAIL!\n"
		printf "Missing $session_id!\n"
		exit 1
	fi
	echo "$ret"
}

function test_destroy_session()
{
	local command="$LTTNG_BIN -d $LTTNG_SESSION_ID"
	local ret=$($command)
	check_ret_code $LTTNG_RET_CODE
	echo "[+] Destroy session: PASSED!"
}

function test_one_session()
{
	lttng_create_session "test1"
	check_ret_code $LTTNG_RET_CODE
	echo "[+] Session creation: PASSED!"
}

function test_session_same_name()
{
	lttng_create_session "test-same"
	lttng_create_session "test-same"
	if [ $LTTNG_RET_CODE -ne 0 ]; then
		echo "[-] Session with the same name: FAILED!"
		printf "Two session having the same name NOT ALLOWED\n"
		clean_exit 1
	fi
	echo "[+] Session with the same name: PASSED!"
}

if [ ! -x $SESSIOND_BIN ]; then
	echo "Please use make before test execution"
	exit 1
fi

# Daemonized by the -d
./$SESSIOND_BIN $SESSIOND_ARGS -d
echo "[+] Session daemon started"

pid=$(pidof lt-ltt-sessiond)
if [ -z "$pid" ]; then
	echo "[-] Can't found session daemon"
	./$SESSIOND_BIN $SESSIOND_ARGS
	exit 1
fi
echo "[+] Got the session daemon pid $pid"

printf "=== Starting tests ===\n"

test_one_session

test_destroy_session

test_session_same_name

clean_exit 0

