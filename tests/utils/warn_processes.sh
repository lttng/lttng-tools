#!/bin/bash
#
# SPDX-FileCopyrightText: 2016 Michael Jeanson <mjeanson@efficios.com>
#
# SPDX-License-Identifier: GPL-2.0-only
#

if [ -z $PGREP ]; then
	PGREP=pgrep
fi

if [ x$LTTNG_TOOLS_TESTS_DISABLE_WARN_LTTNG_PROCESSES == x1 ]; then
	exit
fi

color_error='\E[1;91m'
color_reset='\E[0m'
color_bold='\E[1m'

lttng_processes="$("$PGREP" -l 'lttng|gen-ust-.+')"

if [ $? -eq 0 ]; then
	pids="$(cut -d ' ' -f 1 <<< "$lttng_processes" | tr '\n' ' ')"

	echo -e "${color_error}Error: the following LTTng processes were detected running on the system:$color_reset"
	echo
	echo "$lttng_processes"
	echo
	echo -e "Here's how to kill them: ${color_bold}kill -9 $pids$color_reset"
	echo
	echo "The test suite will not run in the presence of those processes since its result may not be reliable."
	echo
	exit 1
fi
