#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2025 Kienan Stewart <kstewart@efficios.com>
# SPDX-License-Identifier: GPL-2.1-only
#

"""
Validate that under heaving tracing load the sum of the recorded and dropped
events matches the expected output of the traced applications
"""

import os
import pathlib
import sys
import multiprocessing

test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.append(str(test_utils_import_path))

import bt2
import lttngtest
import tempfile


def count_events_worker(args):
    trace_path = args
    received = 0
    discarded = 0
    for msg in bt2.TraceCollectionMessageIterator(str(trace_path)):
        if type(msg) is bt2._EventMessageConst:
            received += 1
            continue

        if type(msg) is bt2._DiscardedEventsMessageConst:
            discarded += msg.count

    return (received, discarded)


def parallel_count_events(trace_path, test_env):
    """
    Count the number of events in a trace using parallel processing.
    This is a workaround for the performance issues with bt2 bindings.
    """
    streams_path = None
    for root, dirs, files in os.walk(str(trace_path)):
        if "metadata" in files:
            streams_path = pathlib.Path(root)
            break

    if streams_path is None:
        raise RuntimeError("No metadata found in trace path: {}".format(trace_path))

    metadata_path = streams_path / "metadata"
    stream_dirs = []

    for file in streams_path.iterdir():
        if file.name == "metadata":
            continue

        temp_dir_path = test_env.create_temporary_directory()

        # Symlink to the stream file
        stream_link = temp_dir_path / file.name
        stream_link.symlink_to(file)
        # Symlink to the metadata file
        metadata_link = temp_dir_path / "metadata"
        metadata_link.symlink_to(metadata_path)

        stream_dirs.append(temp_dir_path)

    received = 0
    discarded = 0

    with multiprocessing.Pool() as pool:
        results = pool.map(count_events_worker, stream_dirs)

    for this_received, this_discarded in results:
        received += this_received
        discarded += this_discarded

    return received, discarded


def test_high_throughput(
    tap, test_env, app_count=len(lttngtest.online_cpus()) * 2, events_per_app=1000000
):
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    output_path = test_env.create_temporary_directory()
    output = lttngtest.LocalSessionOutputLocation(trace_path=output_path)
    session = client.create_session(output=output)
    channel = session.add_channel(lttngtest.lttngctl.TracingDomain.User)
    channel.add_recording_rule(lttngtest.lttngctl.UserTracepointEventRule("tp:tptest"))
    session.start()

    app_group = lttngtest.WaitTraceTestApplicationGroup(
        test_env, app_count, events_per_app, wait_before_exit=True
    )
    app_group.trace()
    app_group.exit()
    session.stop()

    expected = app_count * events_per_app
    received, discarded = parallel_count_events(output_path, test_env)

    total = received + discarded
    tap.diagnostic("Trace output path: {}".format(str(output_path)))
    tap.diagnostic(
        "received={}, dropped={}, total={}, expected={}".format(
            received, discarded, total, expected
        )
    )
    tap.test(
        total == expected,
        "Total events {} match expected total {}".format(total, expected),
    )


if __name__ == "__main__":
    tap = lttngtest.TapGenerator(1)
    with lttngtest.test_environment(log=tap.diagnostic, with_sessiond=True) as test_env:
        test_high_throughput(tap, test_env)
    sys.exit(0 if tap.is_successful else 1)
