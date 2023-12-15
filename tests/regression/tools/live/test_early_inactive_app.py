#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2024 Kienan Stewart <kstewart@efficios.com>
# SPDX-LicenseIdentifier: LGPL-2.1-only
#

"""
Test that live doesn't hang when a traced UST application started before the
session if the application doesn't produce any further events.
"""

import os
import pathlib
import subprocess
import sys
import time

test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.append(str(test_utils_import_path))

import lttngtest


def test_early_ust_app(tap, test_env, buffer_sharing_policy):
    tap.diagnostic(
        "test_early_inactive_app with buffer sharing policy {}".format(
            buffer_sharing_policy
        )
    )

    uid = None
    user = None
    if buffer_sharing_policy == lttngtest.lttngctl.BufferSharingPolicy.PerUID:
        if os.getuid() != 0 or not test_env.allows_destructive():
            tap.skip(
                "Need to run PerUID test as root and have `LTTNG_ENABLE_DESTRUCTIVE_TESTS` set properly to create a dummy user",
                2,
            )
            return
        (uid, user) = test_env.create_dummy_user()

    # Run early app
    early_app = test_env.launch_wait_trace_test_application(
        10,
        wait_before_exit=True,
        run_as=user,
    )
    early_app.trace()
    early_app.wait_for_tracing_done()

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

    # Run second test app
    late_app = test_env.launch_wait_trace_test_application(
        10, wait_before_exit=True, run_as=user
    )
    late_app.trace()
    late_app.wait_for_tracing_done()

    # Wait for the viewer to receive at least the expected number of events.
    # If the session is stopped and destroyed immediately, there is a small
    # window where new streams with per-PID buffers may not be sent to the
    # live client.
    while len(viewer.messages) < 10:
        viewer.wait()
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
        len(viewer.messages) == 10,
        "Live viewer got {} / 10 expected events".format(len(viewer.messages)),
    )

    early_app.touch_exit_file()
    early_app.wait_for_exit()
    late_app.touch_exit_file()
    late_app.wait_for_exit()


tap = lttngtest.TapGenerator(4)
for buffer_sharing_policy in [
    lttngtest.lttngctl.BufferSharingPolicy.PerUID,
    lttngtest.lttngctl.BufferSharingPolicy.PerPID,
]:
    with lttngtest.test_environment(
        log=tap.diagnostic, with_relayd=True, with_sessiond=True
    ) as test_env:
        test_early_ust_app(tap, test_env, buffer_sharing_policy)

sys.exit(0 if tap.is_successful else 1)
