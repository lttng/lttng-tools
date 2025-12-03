#!/bin/bash
#
# SPDX-FileCopyrightText: 2019 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
#
# SPDX-License-Identifier: LGPL-2.1-only

function get_env_value_ctf2 ()
{
	local metadata_file=$1
	local key=$2

	"$TESTDIR/utils/extract_ctf_2_prop.py" "$metadata_file" trace-class "environment/$key"
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
