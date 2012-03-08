#!/bin/bash
#
# Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; only version 2
# of the License.
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

SESSIOND_BIN="lttng-sessiond"
RESULTS_PATH="/tmp/lttng-bench-results.txt"
BASEDIR=`dirname $0`

echo "Starting session daemon"

BENCH_BOOT_PROCESS=1 $BASEDIR/../src/bin/lttng-sessiond/$SESSIOND_BIN -v >/dev/null 2>&1 &

PID_SESSIOND=$!
if [ -z $PID_SESSIOND ]; then
	echo -e '\e[1;31mFAILED\e[0m'
	exit 1
else
	echo -e "\e[1;32mOK\e[0m"
	echo "PID session daemon: $PID_SESSIOND"
fi

# Wait for the benchmark to run
echo -n "Waiting."
sleep 1
echo -n "."
sleep 1
echo "."
sleep 1

kill $PID_SESSIOND

wait $PID_SESSIOND

echo "Benchmarks done in $RESULTS_PATH"

exit 0
