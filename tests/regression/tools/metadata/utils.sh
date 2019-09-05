#!/bin/bash
#
# Copyright (C) - 2019 Jonathan Rajotte-Julien <jonathan.rajotte-julien@efficios.com>
#
# This library is free software; you can redistribute it and/or modify it under
# the terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; version 2.1 of the License.
#
# This library is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this library; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA

function get_env_value ()
{
	local env_file=$1
	local key=$2
	local result
	local ret

	result=$(grep "$key" < "$env_file")
	ret=$?
	if [ $ret -eq 1 ]; then
		echo "invalid_value_extraction"
		return 1
	else
		# Strip the key using bash substring removal.
		# This remove all leading chars until the actual value.
		result=${result#* = }

		# Remove the trailing ';'
		result=${result:0:-1}

		# Remove enclosing '"' if present
		if [ "${result:0:1}" == '"' ]; then
			result=${result:1:-1}
		fi

		echo "$result"
		return 0
	fi
}

function iso8601_to_lttng_dir_datetime ()
{
	local result=$1

	result=${result/T/-}

	# Remove trailing timezone information including the '-'.
	result=${result:0:-5}

	echo "$result"
	return 0
}
