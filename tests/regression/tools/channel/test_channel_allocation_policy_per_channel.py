#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2025 Olivier Dion <odion@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only

import os
import pathlib
import random
import sys

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.append(str(test_utils_import_path))

import bt2
import lttngtest

"""
This test suite validates the following properties of the option
`--buffer-allocation=per-channel' of the `enable-channel' command:

  - Only a single file stream is generated in the trace output

  - By default, no CPU ID is provided as a context

  - When adding the `cpu_id' context, the correct CPU ID is added to the context
    of each events

  - Kernel domains cannot use the per-channel allocation

These tests are ran against 3 variants:

  - Normal session

  - Snapshot session

  - Live session
"""


def make_ust_per_channel_buffers_or_fail(session):
    """
    Make a channel in the UST domain with per-channel buffers allocation for SESSION.
    """
    try:
        return session.add_channel(
            lttngtest.TracingDomain.User,
            buffer_allocation_policy=lttngtest.BufferAllocationPolicy.PerChannel,
        )
    except Exception as e:
        tap.fail("Could not create UST channel with per-channel buffers")
        raise e


def trace_stream_count(channel_name, trace_location):
    """
    Return the number of stream from CHANNEL_NAME in TRACE_LOCATION.
    """

    count = 0

    for _, _, filenames in os.walk(trace_location):
        for filename in filenames:
            if filename.startswith(channel_name) and not filename.endswith(".idx"):
                count += 1
    return count


def trace_stream_all_context_values(context_name, events):
    """
    List all values seen for context named CONTEXT_NAME in TRACE_LOCATION.
    """

    values = set()

    for event in events:
        if event.common_context_field and context_name in event.common_context_field:
            values.add(event.common_context_field[context_name])
        elif (
            event.specific_context_field
            and context_name in event.specific_context_field
        ):
            values.add(event.specific_context_field[context_name])

    return values


def test_per_channel_buffers_ust_single_stream(tap, client, session, get_events):
    """
    Ensure that only a single stream is in the trace for
    channels with the per-channel allocation policy.
    """

    channel = make_ust_per_channel_buffers_or_fail(session)
    channel.add_recording_rule(lttngtest.UserTracepointEventRule())
    get_events()

    if isinstance(session.output, lttngtest.LocalSessionOutputLocation):
        tap.test(
            1 == trace_stream_count(channel.name, str(session.output.path)),
            "Only a single stream is created for per-channel buffers",
        )
    else:
        # The way to determine the output path of a streamed session is
        # convoluted.
        #
        # The output path format used by the relayd is "ABI", so we can rely on
        # it. By default, it follows the pattern:
        #   $LTTNG_HOME/lttng-traces/hostname/SESSION_NAME-CREATION_TIMESTAMP/"
        #
        # Unfortunately, the session's creation timestamp is not available from
        # the CLI; it is only exposed by liblttng-ctl's API (see lttng_session_get_creation_time()).
        # The following assumes that the session name is unique enough to be
        # used as a unique identifier.
        host_output_path = (
            test_env.lttng_home_location / "lttng-traces" / os.uname().nodename
        )
        # Choose the first path that matches the session name.
        session_output_path = next(
            p for p in host_output_path.iterdir() if p.name.startswith(session.name)
        )
        tap.test(
            1 == trace_stream_count(channel.name, str(session_output_path)),
            "Only a single stream is create for per-channel buffers",
        )


def test_per_channel_buffers_no_cpu_id_by_default(tap, client, session, get_events):
    """
    Ensure that by default, when creating a channel with
    per-channel buffers, no `cpu_id' context is added to events
    of the trace.
    """

    channel = make_ust_per_channel_buffers_or_fail(session)
    channel.add_recording_rule(lttngtest.UserTracepointEventRule())
    events = get_events()
    cpu_ids_seen = trace_stream_all_context_values("cpu_id", events)
    tap.test(len(cpu_ids_seen) == 0, "No cpu_id context field found in the trace")


def test_per_channel_buffers_correct_cpu_id_context(tap, client, session, get_events):
    """
    Ensure that `cpu_id' context is added to event when enabled.

    The test works by selecting a random CPU part of the current
    process affinity.  The tracee created inherit this affinity
    and will only produce events for that CPU.  It is expected
    that in the trace, only the ID of the selected CPU is emitted.
    """

    channel = make_ust_per_channel_buffers_or_fail(session)
    channel.add_context(lttngtest.CPUidContextType())
    channel.add_recording_rule(lttngtest.UserTracepointEventRule())

    # Before starting the tracee. Change the CPU affinity of this process to a
    # single CPU randomly selected from the current CPU affinity.
    saved_cpu_affinity = os.sched_getaffinity(0)

    try:
        online_cpus = lttngtest.online_cpus()
    except Exception as e:
        tap.skip("Could not get list of online CPUS: {}".format(e), 1)
        return

    try:
        new_affinity = {random.choice(list(saved_cpu_affinity.union(online_cpus)))}
        os.sched_setaffinity(0, new_affinity)
        events = get_events()
        cpu_id_seen = trace_stream_all_context_values("cpu_id", events)
        tap.test(cpu_id_seen == new_affinity, "Only desired cpu_id in the trace")
    finally:
        # Restore the CPU affinity of the process in any case.
        os.sched_setaffinity(0, saved_cpu_affinity)


def test_per_channel_buffers_kernel(tap, client, session, get_events):
    """
    Ensure that per-channel bufffers cannot be used with kernel domain channels.
    """

    try:
        session.add_channel(
            lttngtest.TracingDomain.Kernel,
            buffer_allocation_policy=lttngtest.BufferAllocationPolicy.PerChannel,
        )
        tap.fail("Kernel channel was created with per-channel buffers")
    except lttngtest.LTTngClientError as exn:
        tap.test(
            "Buffer allocation not supported for the kernel domain" in exn._output,
            "Cannot enable a channel with per-channel allocation policy in the kernel domain",
        )
    except Exception as e:
        tap.fail("Unknown exception thrown while adding 'cpu_id' context: {}".format(e))


def run_test(test, tap, client, snapshot=False, live=False):
    try:
        if live:
            session_output_location = lttngtest.NetworkSessionOutputLocation(
                "net://localhost:{}:{}/".format(
                    test_env.lttng_relayd_control_port, test_env.lttng_relayd_data_port
                )
            )
        else:
            session_output_location = lttngtest.LocalSessionOutputLocation(
                test_env.create_temporary_directory("trace")
            )

        session = client.create_session(
            output=session_output_location, snapshot=snapshot, live=live
        )

        if live:

            def prepare_consumer():
                viewer = test_env.launch_live_viewer(session.name)
                viewer.wait_until_connected()
                return viewer

            def drain_consumer(viewer):
                viewer.wait()
                return [msg.event for msg in viewer.messages]

        else:

            def prepare_consumer():
                return str(session.output.path)

            def drain_consumer(trace_location):
                return [
                    msg.event
                    for msg in bt2.TraceCollectionMessageIterator(trace_location)
                    if type(msg) is bt2._EventMessageConst
                ]

        # Launch a test application, and start a session.
        #
        # Prepare the consumer (either live viewer or simple trace location).
        #
        # Run the test application and wait for it to terminate.
        #
        # If the session is in snapshot mode, ask for a snapshot record.
        #
        # Stop the session and ask the consumer to drain all events from the
        # trace.
        def get_events():
            test_app = test_env.launch_wait_trace_test_application(50)
            session.start()
            consumer = prepare_consumer()
            test_app.trace()
            test_app.wait_for_exit()
            if snapshot:
                session.snapshot_record()
            session.stop()
            return drain_consumer(consumer)

        test(tap, client, session, get_events)
    finally:
        session.destroy()


ust_domain_tests = (
    test_per_channel_buffers_ust_single_stream,
    test_per_channel_buffers_no_cpu_id_by_default,
    test_per_channel_buffers_correct_cpu_id_context,
)

kernel_domain_tests = (test_per_channel_buffers_kernel,)

variants = (
    {},
    {"snapshot": True},
    {"live": True},
)

tap = lttngtest.TapGenerator(
    len(variants) * (len(ust_domain_tests) + len(kernel_domain_tests))
)

with lttngtest.test_environment(
    with_sessiond=True, with_relayd=True, log=tap.diagnostic
) as test_env:
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)

    for variant in variants:
        tap.diagnostic("Running variant: {}".format(variant))

        for test in ust_domain_tests:
            run_test(test, tap, client, **variant)

        for test in kernel_domain_tests:
            if test_env.run_kernel_tests():
                run_test(test, tap, client, **variant)
            else:
                tap.skip(
                    "'{}' test require root to create kernel domain buffers".format(
                        test.__name__
                    ),
                    1,
                )


sys.exit(0 if tap.is_successful else 1)
