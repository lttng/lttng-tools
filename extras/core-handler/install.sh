#!/bin/sh
#
# Copyright (C) 2013 - Christian Babeux <christian.babeux@efficios.com>
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
