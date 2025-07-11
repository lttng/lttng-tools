#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2025 Kienan Stewart <kstewart@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#
"""
Validates the behaviour of the lttng clear in various conditions.
"""

import itertools
import os
import pathlib
import sys
import time

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.append(str(test_utils_import_path))

import lttngtest
import bt2


def compare_expected_event_count_tuples(counts, expected):
    ok = True
    msg = ""
    i = 0
    for count, expected in zip(counts, expected):
        description = ""
        if len(expected) == 3:
            description = expected[2] + " "

        description += "{} received and {} discarded events, expected {} received and {} discarded events; ".format(
            count[0], count[1], expected[0], expected[1]
        )
        msg += description
        if count != expected[0:2]:
            ok = False

    return (ok, msg.strip("; "))


def do_clear(
    session, clear_twice, rotate_before, rotate_after, stop_session_before_clear
):
    if stop_session_before_clear:
        session.stop()

    if rotate_before:
        session.rotate()

    session.clear()
    if clear_twice:
        session.clear()

    if rotate_after:
        try:
            session.rotate()
        except RuntimeError as e:
            # rotate twice should fail
            if not stop_session_before_clear:
                raise e

    if stop_session_before_clear:
        session.start()


def test_ust_streaming(
    client,
    test_env,
    tap,
    buffer_sharing_policy,
    clear_twice=False,
    rotate_before=False,
    rotate_after=False,
    stop_session_before_clear=False,
):
    """
    Test UST streaming with clear
    """
    session_output_location = lttngtest.NetworkSessionOutputLocation(
        "net://localhost:{}:{}/".format(
            test_env.lttng_relayd_control_port, test_env.lttng_relayd_data_port
        )
    )
    session = client.create_session(output=session_output_location)
    relayd_output_path = pathlib.Path(
        os.path.join(test_env.lttng_relayd_output_path, session.name)
    )
    channel = session.add_channel(
        lttngtest.lttngctl.TracingDomain.User,
        buffer_sharing_policy=buffer_sharing_policy,
    )
    channel.add_recording_rule(lttngtest.lttngctl.UserTracepointEventRule("tp:tptest"))
    session.start()
    app = test_env.launch_wait_trace_test_application(10)
    app.trace()
    app.wait_for_exit()
    do_clear(
        session, clear_twice, rotate_before, rotate_after, stop_session_before_clear
    )
    session.stop()

    expected_count = 10 if rotate_before else 0
    relayd_output_path = pathlib.Path(test_env.lttng_relayd_output_path)
    received, discarded = lttngtest.count_events(
        relayd_output_path.glob("{}*".format(session.name)),
        buffer_sharing_policy == lttngtest.lttngctl.BufferSharingPolicy.PerPID,
    )
    session.destroy(wait=False)
    tap.test(
        received == expected_count,
        "Received {} events, expected {}".format(received, expected_count),
    )


def test_ust_streaming_rotate_clear(
    client,
    test_env,
    tap,
    buffer_sharing_policy,
    clear_twice=False,
    rotate_before=False,
    rotate_after=False,
    stop_session_before_clear=False,
):
    """
    Test UST streaming with rotate then clear
    """
    session_output_location = lttngtest.NetworkSessionOutputLocation(
        "net://localhost:{}:{}/".format(
            test_env.lttng_relayd_control_port, test_env.lttng_relayd_data_port
        )
    )
    session = client.create_session(output=session_output_location)
    relayd_output_path = pathlib.Path(
        os.path.join(test_env.lttng_relayd_output_path, session.name)
    )
    channel = session.add_channel(
        lttngtest.lttngctl.TracingDomain.User,
        buffer_sharing_policy=buffer_sharing_policy,
    )
    channel.add_recording_rule(lttngtest.lttngctl.UserTracepointEventRule("tp:tptest"))
    session.start()
    app = test_env.launch_wait_trace_test_application(1)
    app.trace()
    app.wait_for_exit()
    session.rotate()
    app = test_env.launch_wait_trace_test_application(2)
    app.trace()
    app.wait_for_exit()
    do_clear(
        session, clear_twice, rotate_before, rotate_after, stop_session_before_clear
    )
    app = test_env.launch_wait_trace_test_application(3)
    app.trace()
    app.wait_for_exit()
    session.stop()

    expected_count = 6 if rotate_before else 4
    relayd_output_path = pathlib.Path(test_env.lttng_relayd_output_path)
    received, discarded = lttngtest.count_events(
        relayd_output_path.glob("{}*".format(session.name))
    )
    session.destroy(wait=False)
    tap.test(
        received == expected_count,
        "Received {} events, expected {}".format(received, expected_count),
    )


def test_ust_streaming_clear_rotate(
    client,
    test_env,
    tap,
    buffer_sharing_policy,
    clear_twice=False,
    rotate_before=False,
    rotate_after=False,
    stop_session_before_clear=False,
):
    """
    Test UST streaming with clear then rotate
    """
    session_output_location = lttngtest.NetworkSessionOutputLocation(
        "net://localhost:{}:{}/".format(
            test_env.lttng_relayd_control_port, test_env.lttng_relayd_data_port
        )
    )
    session = client.create_session(output=session_output_location)
    relayd_output_path = pathlib.Path(
        os.path.join(test_env.lttng_relayd_output_path, session.name)
    )
    channel = session.add_channel(
        lttngtest.lttngctl.TracingDomain.User,
        buffer_sharing_policy=buffer_sharing_policy,
    )
    channel.add_recording_rule(lttngtest.lttngctl.UserTracepointEventRule("tp:tptest"))
    session.start()
    app = test_env.launch_wait_trace_test_application(1)
    app.trace()
    app.wait_for_exit()
    do_clear(
        session, clear_twice, rotate_before, rotate_after, stop_session_before_clear
    )
    app = test_env.launch_wait_trace_test_application(2)
    app.trace()
    app.wait_for_exit()
    session.rotate()
    app = test_env.launch_wait_trace_test_application(3)
    app.trace()
    app.wait_for_exit()
    session.stop()

    expected_count = 6 if rotate_before else 5
    relayd_output_path = pathlib.Path(test_env.lttng_relayd_output_path)
    received, discarded = lttngtest.count_events(
        relayd_output_path.glob("{}*".format(session.name))
    )
    session.destroy(wait=False)
    tap.test(
        received == expected_count,
        "Received {} events, expected {}".format(received, expected_count),
    )


def test_ust_streaming_tracefile_rotation(
    client,
    test_env,
    tap,
    buffer_sharing_policy,
    clear_twice=False,
    rotate_before=False,
    rotate_after=False,
    stop_session_before_clear=False,
):
    """
    Test UST streaming clear with tracefile rotation

    With 1 byte per event (as strict minimum), generating 200000 events
    guarantees filling up 2 files of 64k in size, which is the maximum
    page size known on Linux
    """
    session_output_location = lttngtest.NetworkSessionOutputLocation(
        "net://localhost:{}:{}/".format(
            test_env.lttng_relayd_control_port, test_env.lttng_relayd_data_port
        )
    )
    session = client.create_session(output=session_output_location)
    relayd_output_path = pathlib.Path(
        os.path.join(test_env.lttng_relayd_output_path, session.name)
    )
    channel = session.add_channel(
        lttngtest.lttngctl.TracingDomain.User,
        buffer_sharing_policy=buffer_sharing_policy,
        subbuf_size=lttngtest.getconf("PAGESIZE"),
        tracefile_count=2,
        tracefile_size=lttngtest.getconf("PAGESIZE"),
    )
    channel.add_recording_rule(lttngtest.lttngctl.UserTracepointEventRule("tp:tptest"))
    session.start()
    app = test_env.launch_wait_trace_test_application(10)
    # Taskset to a specific CPU in order to ensure that the events are written
    # to a single channel, thus guaranteeing an overwrite.
    app.taskset_anycpu()
    app.trace()
    app.wait_for_exit()
    do_clear(
        session, clear_twice, rotate_before, rotate_after, stop_session_before_clear
    )
    session.stop()
    expected_counts = [(10 if rotate_before else 0, 0, "After first app")]
    counts = []
    relayd_output_path = pathlib.Path(test_env.lttng_relayd_output_path)
    counts.append(
        lttngtest.count_events(
            relayd_output_path.glob("{}*".format(session.name)),
            buffer_sharing_policy == lttngtest.lttngctl.BufferSharingPolicy.PerPID,
        )
    )

    session.start()
    app = test_env.launch_wait_trace_test_application(20)
    # Taskset to a specific CPU in order to ensure that the events are written
    # to a single channel, thus guaranteeing an overwrite.
    app.taskset_anycpu()
    app.trace()
    app.wait_for_exit()
    session.stop()
    expected_counts.append((30 if rotate_before else 20, 0, "After second app"))
    counts.append(
        lttngtest.count_events(relayd_output_path.glob("{}*".format(session.name)))
    )
    session.destroy(wait=False)
    tap.test(*compare_expected_event_count_tuples(counts, expected_counts))


def test_ust_streaming_tracefile_rotation_overwrite_files(
    client,
    test_env,
    tap,
    buffer_sharing_policy,
    clear_twice=False,
    rotate_before=False,
    rotate_after=False,
    stop_session_before_clear=False,
):
    """
    Test UST streaming clear with tracefile rotation and overwriting files

    With 1 byte per event (as strict minimum), generating 200000 events
    guarantees filling up 2 files of 64k in size, which is the maximum
    page size known on Linux
    """
    session_output_location = lttngtest.NetworkSessionOutputLocation(
        "net://localhost:{}:{}/".format(
            test_env.lttng_relayd_control_port, test_env.lttng_relayd_data_port
        )
    )
    session = client.create_session(output=session_output_location)
    relayd_output_path = pathlib.Path(
        os.path.join(test_env.lttng_relayd_output_path, session.name)
    )
    channel = session.add_channel(
        lttngtest.lttngctl.TracingDomain.User,
        buffer_sharing_policy=buffer_sharing_policy,
        subbuf_size=lttngtest.getconf("PAGESIZE"),
        tracefile_count=2,
        tracefile_size=lttngtest.getconf("PAGESIZE"),
    )
    channel.add_recording_rule(lttngtest.lttngctl.UserTracepointEventRule("tp:tptest"))
    session.start()
    app = test_env.launch_wait_trace_test_application(200000)
    # Taskset to a specific CPU in order to ensure that the events are written
    # to a single channel, thus guaranteeing an overwrite.
    app.taskset_anycpu()
    app.trace()
    app.wait_for_exit()
    do_clear(
        session, clear_twice, rotate_before, rotate_after, stop_session_before_clear
    )
    session.stop()
    relayd_output_path = pathlib.Path(test_env.lttng_relayd_output_path)
    received, discarded = lttngtest.count_events(
        relayd_output_path.glob("{}*".format(session.name)),
        buffer_sharing_policy == lttngtest.lttngctl.BufferSharingPolicy.PerPID,
    )
    # Expect between 1 and 199999 if rotate_before
    first_test_pass = (
        received > 0 and received < 200000 if rotate_before else received == 0
    )

    session.start()
    app = test_env.launch_wait_trace_test_application(400000)
    # Taskset to a specific CPU in order to ensure that the events are written
    # to a single channel, thus guaranteeing an overwrite.
    app.taskset_anycpu()
    app.trace()
    app.wait_for_exit()
    session.stop()
    # Expected between 1 and 599999 if rotate_before else 1 and 199999
    received_2, discarded_2 = lttngtest.count_events(
        relayd_output_path.glob("{}*".format(session.name))
    )
    second_test_pass = (
        received_2 > 0 and received_2 < 600000
        if rotate_before
        else received_2 > 0 and received_2 < 200000
    )

    session.destroy(wait=False)
    tap.test(
        first_test_pass and second_test_pass,
        "First application received {} events; Second application received {} events".format(
            received, received_2
        ),
    )


def test_ust_streaming_no_event(
    client,
    test_env,
    tap,
    buffer_sharing_policy,
    clear_twice=False,
    rotate_before=False,
    rotate_after=False,
    stop_session_before_clear=False,
):
    """
    Test UST streaming with no events
    """
    session_output_location = lttngtest.NetworkSessionOutputLocation(
        "net://localhost:{}:{}/".format(
            test_env.lttng_relayd_control_port, test_env.lttng_relayd_data_port
        )
    )
    session = client.create_session(output=session_output_location)
    relayd_output_path = pathlib.Path(
        os.path.join(test_env.lttng_relayd_output_path, session.name)
    )
    channel = session.add_channel(
        lttngtest.lttngctl.TracingDomain.User,
        buffer_sharing_policy=buffer_sharing_policy,
    )
    channel.add_recording_rule(lttngtest.lttngctl.UserTracepointEventRule("tp:tptest"))
    session.start()
    app = test_env.launch_wait_trace_test_application(10)
    app.trace()
    app.wait_for_exit()
    do_clear(
        session, clear_twice, rotate_before, rotate_after, stop_session_before_clear
    )
    session.stop()

    expected_count = 10 if rotate_before else 0
    relayd_output_path = pathlib.Path(test_env.lttng_relayd_output_path)
    received, discarded = lttngtest.count_events(
        relayd_output_path.glob("{}*".format(session.name)),
        buffer_sharing_policy == lttngtest.lttngctl.BufferSharingPolicy.PerPID,
    )

    session.destroy(wait=False)
    tap.test(
        received == expected_count,
        "Received {} events, expected {}".format(received, expected_count),
    )


def test_ust_streaming_live(
    client,
    buffer_sharing_policy,
    test_env,
    tap,
    clear_twice=False,
    rotate_before=False,
    rotate_after=False,
    stop_session_before_clear=False,
):
    """
    Test UST streaming live with no viewer
    """
    if rotate_before or rotate_after:
        tap.skip(
            "test_ust_streaming_live does not run with the rotate_before or rotate_after options"
        )
        return

    session_output_location = lttngtest.NetworkSessionOutputLocation(
        "net://localhost:{}:{}/".format(
            test_env.lttng_relayd_control_port, test_env.lttng_relayd_data_port
        )
    )
    session = client.create_session(output=session_output_location, live=True)
    relayd_output_path = pathlib.Path(
        os.path.join(test_env.lttng_relayd_output_path, session.name)
    )
    channel = session.add_channel(
        lttngtest.lttngctl.TracingDomain.User,
        buffer_sharing_policy=buffer_sharing_policy,
    )
    channel.add_recording_rule(lttngtest.lttngctl.UserTracepointEventRule("tp:tptest"))
    session.start()
    app = test_env.launch_wait_trace_test_application(10)
    app.trace()
    app.wait_for_exit()
    do_clear(session, clear_twice, False, False, stop_session_before_clear)
    session.stop()

    # If the buffer sharing policy is PerUID, there should be a valid but empty trace
    # If the buffer sharing policy is PerPID, there should be not valid trace
    relayd_output_path = pathlib.Path(test_env.lttng_relayd_output_path)
    received, discarded = lttngtest.count_events(
        relayd_output_path.glob("{}*".format(session.name)),
        buffer_sharing_policy == lttngtest.lttngctl.BufferSharingPolicy.PerPID,
    )
    session.destroy()
    tap.test(received == 0, "Trace is empty")


def test_ust_basic_streaming_live_viewer(
    client,
    test_env,
    tap,
    buffer_sharing_policy,
    clear_twice=False,
    rotate_before=False,
    rotate_after=False,
    stop_session_before_clear=False,
):
    """
    Test UST basic streaming live with attached viewer.
    """
    if clear_twice or rotate_before or rotate_after:
        tap.skip(
            "test_ust_streaming_live does not run with clear_twice, rotate_before, or rotate_after options"
        )
        return

    session_output_location = lttngtest.NetworkSessionOutputLocation(
        "net://localhost:{}:{}/".format(
            test_env.lttng_relayd_control_port, test_env.lttng_relayd_data_port
        )
    )
    session = client.create_session(output=session_output_location, live=True)
    channel = session.add_channel(
        lttngtest.lttngctl.TracingDomain.User,
        buffer_sharing_policy=buffer_sharing_policy,
    )
    channel.add_recording_rule(lttngtest.lttngctl.UserTracepointEventRule("tp:tptest"))
    session.start()

    expected = 10
    viewer = test_env.launch_live_viewer(session.name)
    viewer.wait_until_connected(10)
    app = test_env.launch_wait_trace_test_application(expected)
    app.trace()
    app.wait_for_exit()
    # With PerPID buffer sharing policy, BT keeps checking for new streams rather than hanging up
    while len(viewer.messages) < expected:
        viewer.wait(timeout=1, close_iterator=False)
    session.stop()
    session.destroy()
    connected = viewer.wait_until_disconnected(timeout=10)
    tap.test(
        len(viewer.messages) == expected and not connected,
        "Received {} events, expected {}, connected_after={}".format(
            len(viewer.messages),
            expected,
            connected,
        ),
    )


def test_ust_streaming_live_viewer(
    client,
    test_env,
    tap,
    buffer_sharing_policy,
    clear_twice=False,
    rotate_before=False,
    rotate_after=False,
    stop_session_before_clear=False,
):
    """
    Test UST streaming live clear with viewer
    """
    if rotate_before or rotate_after:
        tap.skip(
            "test_ust_streaming_live does not run with rotate_before, or rotate_after options"
        )
        return

    session_output_location = lttngtest.NetworkSessionOutputLocation(
        "net://localhost:{}:{}/".format(
            test_env.lttng_relayd_control_port, test_env.lttng_relayd_data_port
        )
    )
    session = client.create_session(output=session_output_location, live=True)
    channel = session.add_channel(
        lttngtest.lttngctl.TracingDomain.User,
        buffer_sharing_policy=buffer_sharing_policy,
    )
    channel.add_recording_rule(lttngtest.lttngctl.UserTracepointEventRule("tp:tptest"))
    session.start()

    expected = 0
    viewer = test_env.launch_live_viewer(session.name)
    viewer.wait_until_connected(10)
    app = test_env.launch_wait_trace_test_application(10)
    app.trace()
    app.wait_for_exit()
    do_clear(
        session, clear_twice, rotate_before, rotate_after, stop_session_before_clear
    )
    session.stop()
    session.destroy()
    viewer.wait()
    connected = viewer.wait_until_disconnected(timeout=10)
    tap.test(
        len(viewer.messages) == expected and not connected,
        "Received {} events, expected {}, connected_after={}".format(
            len(viewer.messages),
            expected,
            connected,
        ),
    )


def test_ust_streaming_live_viewer_new_metadata_after_clear(
    client,
    test_env,
    tap,
    buffer_sharing_policy,
    clear_twice=False,
    rotate_before=False,
    rotate_after=False,
    stop_session_before_clear=False,
):
    """
    Test UST streaming live clear with viewer with new metadata after clear
    """
    if rotate_before or rotate_after:
        tap.skip(
            "test_ust_streaming_live does not run with clear_twice, rotate_before, or rotate_after options"
        )
        return

    session_output_location = lttngtest.NetworkSessionOutputLocation(
        "net://localhost:{}:{}/".format(
            test_env.lttng_relayd_control_port, test_env.lttng_relayd_data_port
        )
    )
    session = client.create_session(output=session_output_location, live=True)
    channel = session.add_channel(
        lttngtest.lttngctl.TracingDomain.User,
        buffer_sharing_policy=buffer_sharing_policy,
    )
    channel.add_context(lttngtest.VpidContextType())
    channel.add_recording_rule(lttngtest.lttngctl.UserTracepointEventRule("tp:tptest"))
    session.start()

    expected = 12
    viewer = test_env.launch_live_viewer(session.name)
    viewer.wait_until_connected(10)
    app = test_env.launch_wait_trace_test_application(expected, wait_before_exit=True)
    app.trace()
    # With PerPID buffer sharing policy, BT keeps checking for new streams rather than hanging up
    while len(viewer.messages) < 10:
        viewer.wait(timeout=1, close_iterator=False)

    do_clear(
        session, clear_twice, rotate_before, rotate_after, stop_session_before_clear
    )

    # Enable new events which will add their descriptions to the metadata
    # file. This validates that, following a clear, the relay daemon rotates
    # the metadata viewer stream to the new metadata file.
    channel.add_recording_rule(
        lttngtest.lttngctl.UserTracepointEventRule(
            "lttng_ust_statedump:start",
            filter_expression="'$ctx.vpid == {}'".format(app.vpid),
        )
    )
    channel.add_recording_rule(
        lttngtest.lttngctl.UserTracepointEventRule(
            "lttng_ust_statedump:end",
            filter_expression="'$ctx.vpid == {}'".format(app.vpid),
        )
    )
    session.regenerate(lttngtest.lttngctl.SessionRegenerateTarget.Statedump)

    # With PerPID buffer sharing policy, BT keeps checking for new streams rather than hanging up
    while len(viewer.messages) < expected:
        viewer.wait(timeout=1, close_iterator=False)

    app.touch_exit_file()
    app.wait_for_exit()
    session.stop()
    session.destroy()
    connected = viewer.wait_until_disconnected(timeout=10)
    tap.test(
        len(viewer.messages) == expected and not connected,
        "Received {} events, expected {}, connected_after={}".format(
            len(viewer.messages),
            expected,
            connected,
        ),
    )


def test_ust_local(
    client,
    test_env,
    tap,
    buffer_sharing_policy,
    clear_twice=False,
    rotate_before=False,
    rotate_after=False,
    stop_session_before_clear=False,
):
    """
    Test UST local
    """
    session_output_location = lttngtest.LocalSessionOutputLocation(
        test_env.create_temporary_directory("trace")
    )
    session = client.create_session(output=session_output_location)
    channel = session.add_channel(
        lttngtest.lttngctl.TracingDomain.User,
        buffer_sharing_policy=buffer_sharing_policy,
    )
    channel.add_recording_rule(lttngtest.lttngctl.UserTracepointEventRule("tp:tptest"))
    session.start()
    app = test_env.launch_wait_trace_test_application(10)
    app.trace()
    app.wait_for_exit()
    do_clear(
        session, clear_twice, rotate_before, rotate_after, stop_session_before_clear
    )
    session.stop()

    expected_count = 10 if rotate_before else 0
    received = 0
    discarded = 0
    try:
        received, discarded = lttngtest.count_events(session_output_location.path)
    except RuntimeError as e:
        # When using per-PID buffer, there's no metadata so a run-time error is OK.
        if buffer_sharing_policy != lttngtest.lttngctl.BufferSharingPolicy.PerPID:
            raise e

    tap.test(
        received == expected_count and discarded == 0,
        "{} received and {} discarded events. Excepted {} received and {} discarded events".format(
            received, discarded, expected_count, 0
        ),
    )

    session.destroy(wait=False)


def test_ust_local_rotate_clear(
    client,
    test_env,
    tap,
    buffer_sharing_policy,
    clear_twice=False,
    rotate_before=False,
    rotate_after=False,
    stop_session_before_clear=False,
):
    """
    Test UST local with rotate then clear
    """
    session_output_location = lttngtest.LocalSessionOutputLocation(
        test_env.create_temporary_directory("trace")
    )
    session = client.create_session(output=session_output_location)
    channel = session.add_channel(
        lttngtest.lttngctl.TracingDomain.User,
        buffer_sharing_policy=buffer_sharing_policy,
    )
    channel.add_recording_rule(lttngtest.lttngctl.UserTracepointEventRule("tp:tptest"))
    session.start()

    app = test_env.launch_wait_trace_test_application(1)
    app.trace()
    app.wait_for_exit()
    session.rotate()
    app = test_env.launch_wait_trace_test_application(2)
    app.trace()
    app.wait_for_exit()
    do_clear(
        session, clear_twice, rotate_before, rotate_after, stop_session_before_clear
    )
    app = test_env.launch_wait_trace_test_application(3)
    app.trace()
    app.wait_for_exit()
    session.stop()

    expected_count = 6 if rotate_before else 4
    received, discarded = lttngtest.count_events(session_output_location.path)
    tap.test(
        received == expected_count and discarded == 0,
        "{} received and {} discarded events. Expected {} received and {} discarded events".format(
            received, discarded, expected_count, 0
        ),
    )

    session.destroy(wait=False)


def test_ust_local_clear_rotate(
    client,
    test_env,
    tap,
    buffer_sharing_policy,
    clear_twice=False,
    rotate_before=False,
    rotate_after=False,
    stop_session_before_clear=False,
):
    """
    Test UST local with clear then rotate
    """
    session_output_location = lttngtest.LocalSessionOutputLocation(
        test_env.create_temporary_directory("trace")
    )
    session = client.create_session(output=session_output_location)
    channel = session.add_channel(
        lttngtest.lttngctl.TracingDomain.User,
        buffer_sharing_policy=buffer_sharing_policy,
    )
    channel.add_recording_rule(lttngtest.lttngctl.UserTracepointEventRule("tp:tptest"))
    session.start()

    app = test_env.launch_wait_trace_test_application(1)
    app.trace()
    app.wait_for_exit()
    do_clear(
        session, clear_twice, rotate_before, rotate_after, stop_session_before_clear
    )
    app = test_env.launch_wait_trace_test_application(2)
    app.trace()
    app.wait_for_exit()
    session.rotate()
    app = test_env.launch_wait_trace_test_application(3)
    app.trace()
    app.wait_for_exit()
    session.stop()

    expected_count = 6 if rotate_before else 5
    received, discarded = lttngtest.count_events(session_output_location.path)
    tap.test(
        received == expected_count and discarded == 0,
        "{} received and {} discarded events. Excepted {} received and {} discarded events".format(
            received, discarded, expected_count, 0
        ),
    )

    session.destroy(wait=False)


def test_ust_local_no_event(
    client,
    test_env,
    tap,
    buffer_sharing_policy,
    clear_twice=False,
    rotate_before=False,
    rotate_after=False,
    stop_session_before_clear=False,
):
    """
    Test UST local with no events
    """
    # Ignore rotation tests
    if rotate_before or rotate_after:
        tap.skip("Disabled for tests with rotate_before or rotate_after")
        return

    session_output_location = lttngtest.LocalSessionOutputLocation(
        test_env.create_temporary_directory("trace")
    )
    session = client.create_session(output=session_output_location)
    channel = session.add_channel(
        lttngtest.lttngctl.TracingDomain.User,
        buffer_sharing_policy=buffer_sharing_policy,
    )
    channel.add_recording_rule(lttngtest.lttngctl.UserTracepointEventRule("tp:tptest"))
    session.start()
    do_clear(
        session, clear_twice, rotate_before, rotate_after, stop_session_before_clear
    )
    session.stop()
    try:
        received, discarded = lttngtest.count_events(session_output_location.path)
        tap.fail(
            "No trace should be available at `{}`. Found {} receive and {} discarded events.".format(
                session_output_location.path, received, discarded
            )
        )
    except RuntimeError as e:
        tap.ok("No trace available at `{}`".format(session_output_location.path))

    # The trace directory should be empty
    tap.test
    session.destroy(wait=False)


def test_ust_streaming_snapshot(
    client,
    test_env,
    tap,
    buffer_sharing_policy,
    clear_twice=False,
    rotate_before=False,
    rotate_after=False,
    stop_session_before_clear=False,
):
    """
    Test UST streaming with snapshot
    """
    if buffer_sharing_policy != lttngtest.lttngctl.BufferSharingPolicy.PerUID:
        tap.skip(
            "test_ust_streaming_snapshot does not run with buffer_sharing_policy=`{}`".format(
                buffer_sharing_policy
            )
        )
        return

    if rotate_before or rotate_after:
        tap.skip("Disabled for tests with rotate_before or rotate_after")
        return

    snapshot_location = lttngtest.LocalSessionOutputLocation(
        test_env.create_temporary_directory("trace_snapshot")
    )
    session_output_location = lttngtest.NetworkSessionOutputLocation(
        "net://localhost:{}:{}/".format(
            test_env.lttng_relayd_control_port, test_env.lttng_relayd_data_port
        )
    )
    session = client.create_session(output=session_output_location, snapshot=True)
    channel = session.add_channel(
        lttngtest.lttngctl.TracingDomain.User,
        buffer_sharing_policy=buffer_sharing_policy,
    )
    channel.add_recording_rule(lttngtest.lttngctl.UserTracepointEventRule("tp:tptest"))
    session.start()
    app = test_env.launch_wait_trace_test_application(10)
    app.trace()
    app.wait_for_exit()

    expected_count = 10
    session.record_snapshot(snapshot_location)
    session.stop()
    received, discarded = lttngtest.count_events(snapshot_location.path)

    # Confirm that snapshot after clear is empty
    snapshot_dir = lttngtest.TemporaryDirectory("snapshot2")
    session.start()
    do_clear(session, clear_twice, False, False, stop_session_before_clear)
    session.record_snapshot(lttngtest.LocalSessionOutputLocation(snapshot_dir.path))
    session.stop()
    received_empty, discarded_empty = lttngtest.count_events(snapshot_dir.path)

    # Confirm that events are generated in a subsequent snapshot
    snapshot_dir = lttngtest.TemporaryDirectory("snapshot3")
    session.start()
    app = test_env.launch_wait_trace_test_application(10)
    app.trace()
    app.wait_for_exit()
    session.record_snapshot(lttngtest.LocalSessionOutputLocation(snapshot_dir.path))
    session.stop()
    received_again, discarded_again = lttngtest.count_events(snapshot_dir.path)
    tap.test(
        received == expected_count
        and received_empty == 0
        and received_again == expected_count,
        "Snapshot 1: {} events, expected {}; Snapshot empty: {} events, expected {}; Snapshot 2: {} events, expected {}".format(
            received, expected_count, received_empty, 0, received_again, expected_count
        ),
    )
    session.destroy(wait=False)


def test_ust_local_snapshot(
    client,
    test_env,
    tap,
    buffer_sharing_policy,
    clear_twice=False,
    rotate_before=False,
    rotate_after=False,
    stop_session_before_clear=False,
):
    """
    Test UST local with snapshot
    """
    if buffer_sharing_policy != lttngtest.lttngctl.BufferSharingPolicy.PerUID:
        tap.skip(
            "test_ust_local_snapshot does not run with buffer_sharing_policy=`{}`".format(
                buffer_sharing_policy
            )
        )
        return

    if rotate_before or rotate_after:
        tap.skip("Disabled for tests with rotate_before or rotate_after")
        return

    session_output_location = lttngtest.LocalSessionOutputLocation(
        test_env.create_temporary_directory("trace")
    )
    session = client.create_session(output=session_output_location, snapshot=True)
    channel = session.add_channel(
        lttngtest.lttngctl.TracingDomain.User,
        buffer_sharing_policy=buffer_sharing_policy,
    )
    channel.add_recording_rule(lttngtest.lttngctl.UserTracepointEventRule("tp:tptest"))
    session.start()
    app = test_env.launch_wait_trace_test_application(10)
    app.trace()
    app.wait_for_exit()

    expected_count = 10
    session.record_snapshot()
    session.stop()
    received, discarded = lttngtest.count_events(session_output_location.path)

    # Confirm that a new snapshot is empty
    snapshot_dir = lttngtest.TemporaryDirectory("snapshot2")
    session.start()
    do_clear(session, clear_twice, False, False, stop_session_before_clear)
    session.record_snapshot(lttngtest.LocalSessionOutputLocation(snapshot_dir.path))
    session.stop()
    received_empty, discarded_empty = lttngtest.count_events(snapshot_dir.path)

    # Confirm that events are generated in a new snapshot
    snapshot_dir = lttngtest.TemporaryDirectory("snapshot3")
    session.start()
    app = test_env.launch_wait_trace_test_application(10)
    app.trace()
    app.wait_for_exit()
    session.record_snapshot(lttngtest.LocalSessionOutputLocation(snapshot_dir.path))
    session.stop()
    received_again, discarded_again = lttngtest.count_events(snapshot_dir.path)

    tap.test(
        received == expected_count
        and received_empty == 0
        and received_again == expected_count,
        "Snapshot 1: {} events, expected {}; Snapshot empty: {} events, expected {}; Snapshot 2: {} events, expected {}".format(
            received, expected_count, received_empty, 0, received_again, expected_count
        ),
    )
    session.destroy(wait=False)


def test_ust_local_snapshot_per_pid(
    client,
    test_env,
    tap,
    buffer_sharing_policy,
    clear_twice=False,
    rotate_before=False,
    rotate_after=False,
    stop_session_before_clear=False,
):
    """
    Test UST local snapshot with per-pid buffer sharing policy
    """
    if buffer_sharing_policy != lttngtest.lttngctl.BufferSharingPolicy.PerPID:
        tap.skip(
            "test_ust_local_snapshot_per_pid does not run with buffer sharing policy=`{}`".format(
                buffer_sharing_policy
            )
        )
        return

    if rotate_before or rotate_after:
        tap.skip("test_ust_local_snapshot_per_pid does not run with rotations enabled")
        return

    session_output_location = lttngtest.LocalSessionOutputLocation(
        test_env.create_temporary_directory("trace")
    )
    session = client.create_session(output=session_output_location, snapshot=True)
    channel = session.add_channel(
        lttngtest.lttngctl.TracingDomain.User,
        buffer_sharing_policy=buffer_sharing_policy,
    )
    channel.add_recording_rule(lttngtest.lttngctl.UserTracepointEventRule("tp:tptest"))
    session.start()

    # Gen 9 of 10 events
    expected_count = 9
    expected_empty = 0
    expected_final = 1
    app = test_env.launch_wait_trace_test_application(
        10, wait_before_exit=True, wait_before_last_event=True
    )
    app.trace()
    app.wait_for_before_last_event()
    session.record_snapshot()
    session.stop()
    received, discarded = lttngtest.count_events(session_output_location.path)

    # Make sure the next snapshot is empty and valid
    snapshot_dir = lttngtest.TemporaryDirectory("snapshot2")
    session.start()
    do_clear(session, clear_twice, False, False, stop_session_before_clear)
    session.record_snapshot(lttngtest.LocalSessionOutputLocation(snapshot_dir.path))
    session.stop()
    received_empty, discarded_empty = lttngtest.count_events(snapshot_dir.path)

    # Continue with the last event
    snapshot_dir = lttngtest.TemporaryDirectory("snapshot3")
    session.start()
    app.touch_last_event_file()
    # Keep the traced application alive until after the snapshot
    app.wait_for_tracing_done()
    session.record_snapshot(lttngtest.LocalSessionOutputLocation(snapshot_dir.path))
    session.stop()
    app.touch_exit_file()
    app.wait_for_exit()
    received_final, discarded_final = lttngtest.count_events(snapshot_dir.path)

    tap.test(
        received == expected_count
        and received_empty == expected_empty
        and received_final == expected_final,
        "First snapshot received {} events, expected {}; Empty snapshot received {} events, expected {}; Final snapshot received {} events, expected {}".format(
            received,
            expected_count,
            received_empty,
            expected_empty,
            received_final,
            expected_final,
        ),
    )


if __name__ == "__main__":
    tests = {
        "streaming": [
            test_ust_streaming,
            test_ust_streaming_rotate_clear,
            test_ust_streaming_clear_rotate,
            test_ust_streaming_tracefile_rotation,
            test_ust_streaming_tracefile_rotation_overwrite_files,
            test_ust_streaming_no_event,
        ],
        "live": [
            test_ust_streaming_live,
            test_ust_basic_streaming_live_viewer,
            test_ust_streaming_live_viewer,
            test_ust_streaming_live_viewer_new_metadata_after_clear,
        ],
        "local": [
            test_ust_local,
            test_ust_local_rotate_clear,
            test_ust_local_clear_rotate,
            test_ust_local_no_event,
        ],
        "snapshot": [
            test_ust_streaming_snapshot,  # uid
            test_ust_local_snapshot,  # uid
            test_ust_local_snapshot_per_pid,  # pid
        ],
    }

    test_args_buffer_sharing_policy = [
        {"buffer_sharing_policy": lttngtest.lttngctl.BufferSharingPolicy.PerUID},
        {"buffer_sharing_policy": lttngtest.lttngctl.BufferSharingPolicy.PerPID},
    ]
    test_args_stop_session_before_clear = [
        {"stop_session_before_clear": True},
        {"stop_session_before_clear": False},
    ]
    test_args = [
        {
            # defaults to all False (just clear once)
        },
        {"clear_twice": True},
        {
            # Only applies to streaming and local tests
            "rotate_before": True
        },
        {
            # Only applies to streaming and local tests
            "rotate_after": True
        },
    ]

    # Build a list of test arguments based on [BufferSharingPolicies], [TracingActiveOrNot],
    # and test_procedure_args
    tests_with_args = []
    for argument_dict in itertools.product(
        test_args_buffer_sharing_policy, test_args, test_args_stop_session_before_clear
    ):
        args = dict()
        for x in argument_dict:
            args.update(x)
        for category, test_functions in tests.items():
            for test_function in test_functions:
                tests_with_args.append({"function": test_function, "args": args})

    tap = lttngtest.TapGenerator(len(tests_with_args))
    with lttngtest.test_environment(
        with_sessiond=True, log=tap.diagnostic, with_relayd=True
    ) as test_env:
        client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
        for test in tests_with_args:
            tap.diagnostic(
                "Test '{}' with args: {}".format(
                    test["function"].__name__, test["args"]
                )
            )
            test["function"](client=client, test_env=test_env, tap=tap, **test["args"])
    sys.exit(0 if tap.is_successful else 1)
