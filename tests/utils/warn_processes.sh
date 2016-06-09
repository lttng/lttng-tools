#!/bin/bash

PGREP="$1"

if [ x$LTTNG_TOOLS_TESTS_DISABLE_WARN_LTTNG_PROCESSES == x1 ]; then
	exit
fi

color_warn='\E[1;33m'
color_reset='\E[0m'
color_bold='\E[1m'

lttng_processes="$("$PGREP" -l 'lttng|gen-ust-.+')"

if [ $? -eq 0 ]; then
	pids="$(cut -d ' ' -f 1 <<< "$lttng_processes" | tr '\n' ' ')"

	echo -e "${color_warn}Warning: the following LTTng processes were detected running on the system:$color_reset"
	echo
	echo "$lttng_processes"
	echo
	echo -e "Here's how to kill them: ${color_bold}kill -9 $pids$color_reset"
	echo -e "${color_warn}If you leave them alive, some tests could fail.$color_reset"
	echo
fi
