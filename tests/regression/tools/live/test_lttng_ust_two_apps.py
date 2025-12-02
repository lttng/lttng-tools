#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2025 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
# SPDX-License-Identifier: LGPL-2.1-only
#

"""
Test that live works as expected when first connecting a viewer to a
live session, and then running two traced applications consecutively
while reading the events from the live viewer between the execution
of the two applications.
The viewer should not crash, and should observe all events.
"""

import os
import pathlib
import subprocess
import sys
import time

test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.append(str(test_utils_import_path))

import lttngtest


def test_lttng_ust_two_apps(tap, test_env, buffer_sharing_policy):
    tap.diagnostic(
        "test_lttng_ust_two_apps with buffer sharing policy {}".format(
            buffer_sharing_policy
        )
    )

    user = None
    if buffer_sharing_policy == lttngtest.lttngctl.BufferSharingPolicy.PerUID:
        if os.getuid() != 0 or not test_env.allows_destructive():
            tap.skip(
                "Need to run PerUID test as root and have `LTTNG_ENABLE_DESTRUCTIVE_TESTS` set properly to create a dummy user",
                2,
            )
            return
        (uid, user) = test_env.create_dummy_user()

    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    output = lttngtest.NetworkSessionOutputLocation(
        "net://localhost:{}:{}/".format(
            test_env.lttng_relayd_control_port, test_env.lttng_relayd_data_port
        )
    )

    session = client.create_session(output=output, live=True)
    channel = session.add_channel(
        lttngtest.lttngctl.TracingDomain.User,
        buffer_sharing_policy=buffer_sharing_policy,
    )
    channel.add_recording_rule(lttngtest.lttngctl.UserTracepointEventRule("tp:tptest"))
    session.start()

    # Connect live viewer
    viewer = test_env.launch_live_viewer(session.name)
    viewer.wait_until_connected()

    # Run first app
    first_app = test_env.launch_wait_trace_test_application(
        10,
        wait_before_exit=True,
        run_as=user,
    )
    first_app.trace()
    first_app.wait_for_tracing_done()

    while len(viewer.messages) < 10:
        viewer.wait(timeout=1, close_iterator=False)
        time.sleep(0.1)

    # Run second app
    second_app = test_env.launch_wait_trace_test_application(
        10,
        wait_before_exit=True,
        run_as=user,
    )
    second_app.trace()
    second_app.wait_for_tracing_done()

    # Wait for the viewer to receive at least the expected number of events.
    # A loop is needed since the viewer's iterator may see an "inactive" state,
    # which doesn't mean all events have been received yet. The "inactive"
    # state may be seen if the viewer checks for new data before the second
    # app's recorded events have been flushed to the relayd.
    while len(viewer.messages) < 20:
        viewer.wait(timeout=1, close_iterator=False)
        time.sleep(0.1)

    session.stop()
    session.destroy()

    # The viewer should be disconnected then the session is destroyed
    viewer.wait_until_disconnected()
    tap.test(
        not viewer.is_connected(),
        "Live viewer exited gracefully",
    )
    tap.test(
        len(viewer.messages) == 20,
        "Live viewer got {} / 20 expected events".format(len(viewer.messages)),
    )
    first_app.touch_exit_file()
    first_app.wait_for_exit()
    second_app.touch_exit_file()
    second_app.wait_for_exit()


tap = lttngtest.TapGenerator(4)
for buffer_sharing_policy in [
    lttngtest.lttngctl.BufferSharingPolicy.PerUID,
    lttngtest.lttngctl.BufferSharingPolicy.PerPID,
]:
    with lttngtest.test_environment(
        log=tap.diagnostic, with_relayd=True, with_sessiond=True
    ) as test_env:
        test_lttng_ust_two_apps(tap, test_env, buffer_sharing_policy)

sys.exit(0 if tap.is_successful else 1)
