#!/bin/bash
#
# Copyright (C) 2019 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
#
# SPDX-License-Identifier: LGPL-2.1-only

function get_env_value ()
{
	local env_file=$1
	local key=$2
	local result
	local ret

	result=$(grep "$key =" < "$env_file")
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
