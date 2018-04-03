#!/bin/bash
#
# Copyright (C) - 2017 Julien Desfossez <jdesfossez@efficios.com>
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

# Clean everything under directory but keep directory
function clean_path ()
{
	local path=$1
	# Use -u from bash top prevent empty expansion of variable yielding a
	# list of current directory from find.
	set -u
	find $path -mindepth 1 -maxdepth 1 -exec rm -rf '{}' \;
	set +u
}

function set_chunk_pattern ()
{
	# Need to call this function after $today has been set.

	# YYYYMMDDTHHMMSS[+-]HHMM-YYYYMMDDTHHMMSS[+-]HHMM
	export chunk_pattern="${today}T[0-9][0-9][0-9][0-9][0-9][0-9][+-][0-9][0-9][0-9][0-9]-${today}T[0-9][0-9][0-9][0-9][0-9][0-9][+-][0-9][0-9][0-9][0-9]"
}

function validate_test_chunks ()
{
	local_path=$1
	today=$2
	app_path=$3
	domain=$4
	per_pid=$5

	set_chunk_pattern
	local path=

	# Validate that only 3 chunks are present
	nb_chunk=$(ls -A $local_path | wc -l)
	test $nb_chunk -eq 3
	ok $? "${local_path} contains 3 chunks only"

	# Check if the first and second chunk folders exist and they contain a ${app_path}/metadata file.
	for chunk in $(seq 1 2); do
		path=$(ls $local_path/${chunk_pattern}-${chunk}/${app_path}/metadata)
		ok $? "Chunk ${chunk} exists based on path $path"
	done

	# In per-pid the last chunk (3) must be empty.
	if [ "${per_pid}" -eq "1" ]; then
		test -z "$(ls -A $local_path/${chunk_pattern}-3/${domain})"
		ok $? "Chunk 3 is empty per-pid mode"
	else
		path=$(ls $local_path/${chunk_pattern}-3/${app_path}/metadata)
		ok $? "Chunk 3 exists based on path $path"
	fi

	# Make sure we don't have anything else in the first 2 chunk directories
	# besides the kernel folder.
	for chunk in $(seq 1 2); do
		nr_stale=$(ls -A $local_path/${chunk_pattern}-${chunk} | grep -v $domain | wc -l)
		ok $nr_stale "No stale folders in chunk ${chunk} directory"
	done

	# We expect a complete session of 30 events
	validate_trace_count $EVENT_NAME $local_path 30

	# Chunk 1: 10 events
	validate_trace_count $EVENT_NAME $local_path/${chunk_pattern}-1 10

	# Chunk 2: 20 events
	validate_trace_count $EVENT_NAME $local_path/${chunk_pattern}-2 20

	# Chunk 3: 0 event
	# Trace for chunk number 3 can only be read in per-uid mode since in
	# per-pid mode it is empty (no metadata or stream files).
	if test $per_pid = 0; then
		validate_trace_empty $local_path/${chunk_pattern}-3
	fi
}

function rotate_timer_test ()
{
	local_path=$1
	per_pid=$2

	today=$(date +%Y%m%d)
	nr=0
	nr_iter=0
	expected_chunks=3

	# Wait for $expected_chunks to be generated, timeout after
	# 3 * $expected_chunks * 0.5s.
	# On a laptop with an empty session, a local rotation takes about 200ms,
	# and a remote rotation takes about 600ms.
	# We currently set the timeout to 6 seconds for 3 rotations, if we get
	# errors, we can bump this value.

	until [ $nr -ge $expected_chunks ] || [ $nr_iter -ge $(($expected_chunks * 2 )) ]; do
		nr=$(ls $local_path | wc -l)
		nr_iter=$(($nr_iter+1))
		sleep 1
	done
	test $nr -ge $expected_chunks
	ok $? "Generated $nr chunks in $(($nr_iter))s"
	stop_lttng_tracing_ok $SESSION_NAME
	destroy_lttng_session_ok $SESSION_NAME

	now=$(date +%Y%m%d)
	test $today = $now
	ok $? "Date did not change during the test"

	# Make sure the 10 first chunks are valid empty traces
	i=1
	set_chunk_pattern

	# In a per-pid setup, only the first chunk is a valid trace, the other
	# chunks should be empty folders
	if test $per_pid = 1; then
		validate_trace_empty $local_path/${chunk_pattern}-1
		nr=$(ls $local_path/${chunk_pattern}-2/ust | wc -l)
		test $nr = 0
		ok $? "Chunk 2 is empty"
		nr=$(ls $local_path/${chunk_pattern}-3/ust | wc -l)
		test $nr = 0
		ok $? "Chunk 3 is empty"
	else
		while [ $i -le $expected_chunks ]; do
			validate_trace_empty $local_path/${chunk_pattern}-$i
			i=$(($i+1))
		done
	fi
}
