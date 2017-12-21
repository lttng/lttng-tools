function set_chunk_pattern ()
{
	# Need to call this function after $today has been set.

	# YYYYMMDD-HHMMSS-YYYYMMDD-HHMMSS
	export chunk_pattern="${today}-[0-9][0-9][0-9][0-9][0-9][0-9]-${today}-[0-9][0-9][0-9][0-9][0-9][0-9]"
}

function validate_test_chunks ()
{
	local_path=$1
	today=$2
	app_path=$3
	domain=$4
	per_pid=$5

	set_chunk_pattern

	# Check if the 3 chunk folders exist and they contain a ${app_path}/metadata file.
	ls $local_path/${chunk_pattern}-1/${app_path}/metadata >/dev/null
	ok $? "Chunk 1 exists"
	ls $local_path/${chunk_pattern}-2/${app_path}/metadata >/dev/null
	ok $? "Chunk 2 exists"
	ls $local_path/${chunk_pattern}-3/${domain} >/dev/null
	ok $? "Chunk 3 exists"

	# Make sure we don't have anything else in the first 2 chunk directories
	# besides the kernel folder.
	nr_stale=$(\ls $local_path/${chunk_pattern}-1 | grep -v $domain | wc -l)
	ok $nr_stale "No stale folders in chunk 1 directory"
	nr_stale=$(\ls $local_path/${chunk_pattern}-2 | grep -v $domain | wc -l)
	ok $nr_stale "No stale folders in chunk 2 directory"

	# We expect a session of 30 events
	validate_trace_count $EVENT_NAME $local_path 30

	# Chunk 1: 10 events
	validate_trace_count $EVENT_NAME $local_path/${chunk_pattern}-1 10
	if [ $? -eq 0 ]; then
		# Only delete if successful
		rm -rf $local_path/${chunk_pattern}-1
	fi

	# Chunk 2: 20 events
	validate_trace_count $EVENT_NAME $local_path/${chunk_pattern}-2 20
	if [ $? -eq 0 ]; then
		# Only delete if successful
		rm -rf $local_path/${chunk_pattern}-2
	fi

	# Chunk 3: 0 event
	# Do not check in per-pid, because the folder is really empty, no metadata
	# or stream files.
	if test $per_pid = 1; then
		rm -rf $local_path/${chunk_pattern}-3
	else
		validate_trace_empty $local_path/${chunk_pattern}-3
		if [ $? -eq 0 ]; then
			# Only delete if successful
			rm -rf $local_path/${chunk_pattern}-3
		fi
	fi

	# The session folder after all chunks have been removed is empty
	test -z "$(\ls -A $local_path)"
	empty=$?
	ok $empty "Trace folder is now empty"
	if [ $empty -eq 0 ]; then
	# Only delete if successful
		rm -rf $local_path/
	else
		find $local_path
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

	rm -rf $local_path
}
