#!/bin/sh
#
# SPDX-FileCopyrightText: 2013 Christian Babeux <christian.babeux@efficios.com>
#
# SPDX-License-Identifier: GPL-2.0-only
#

CORE_PATTERN_PATH="/proc/sys/kernel/core_pattern"
CORE_HANDLER_PATH="$(dirname $(readlink -e $0))/handler.sh"
CORE_PATTERN="$(cat ${CORE_PATTERN_PATH})"

echo ${CORE_PATTERN} > core_pattern.bkp

echo "Backup current core_pattern in core_pattern.bkp."

echo "|$CORE_HANDLER_PATH %p %u %g %s %t %h %e %E %c" > ${CORE_PATTERN_PATH}

if [ $? -eq 0 ]
then
	echo "Successfully installed core_pattern."
else
	echo "Installation of core_pattern failed."
	exit 1
fi
