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

echo "Session daemon boot"
#BENCH_COMMANDS=1 $BASEDIR/../src/bin/lttng-sessiond/$SESSIOND_BIN -v >/dev/null 2>&1 &

#PID_SESSIOND=$!
#if [ -z $PID_SESSIOND ]; then
#	echo -e '\e[1;31mFAILED\e[0m'
#	exit 1
#else
#	echo -e "\e[1;32mOK\e[0m"
#	echo "PID session daemon: $PID_SESSIOND"
#fi

# Session daemon need to boot up and run benchmark
echo -n "Waiting."
sleep 1
echo -n "."
sleep 1
echo "."
sleep 1

# Start libust instrumented application to register.
for i in `seq 100`; do
	echo -n "."
	./$BASEDIR/hello &
done
echo ""

echo "Input when ready"
read -n 1

# We measure these commands
lttng create test1
lttng create test2
lttng create test3
lttng create test4
lttng enable-channel chan1 -u -s test1
lttng enable-channel chan1 -u -s test2
lttng enable-channel chan1 -u -s test3
lttng enable-channel chan1 -u -s test4
lttng enable-channel chan2 -u -s test1
lttng enable-channel chan2 -u -s test2
lttng enable-channel chan2 -u -s test3
lttng enable-channel chan2 -u -s test4
lttng enable-channel chan3 -u -s test1
lttng enable-channel chan3 -u -s test2
lttng enable-channel chan3 -u -s test3
lttng enable-channel chan3 -u -s test4
lttng enable-channel chan4 -u -s test1
lttng enable-channel chan4 -u -s test2
lttng enable-channel chan4 -u -s test3
lttng enable-channel chan4 -u -s test4
lttng enable-event -a -u -c chan1 -s test1
lttng enable-event -a -u -c chan1 -s test2
lttng enable-event -a -u -c chan1 -s test3
lttng enable-event -a -u -c chan1 -s test4
lttng start test1
lttng start test2
lttng start test3
lttng start test4

#kill $PID_SESSIOND
#wait $PID_SESSIOND

killall hello

echo "Benchmarks done in $RESULTS_PATH"

exit 0
