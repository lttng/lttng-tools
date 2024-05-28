#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2024 Kienan Stewart <kstewart@efficios.com>
# SPDX-LicenseIdentifier: LGPL-2.1-only
#
"""
Test that an attached live viewer doesn't miss streams created for a short lived
application which ends before the live viewer sees the new streams.

This test tries to mimic the race between destruction and a live viewer's
GET_NEW_METADATA + GET_NEW_STREAMS commands by immediately destroying the session
after the traced application terminates.

This is more likely with per-PID buffer allocation, but the underlying mechanism
also affects per-UID buffers if a new user is created and a short lived application
run quickly.

When the relayd/live connection isn't working properly, this test will fail only
occasionally as the underlying mechanism is timing dependant. When working properly,
the test should always pass when run in a loop.
"""

import os
import pathlib
import subprocess
import sys

test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.append(str(test_utils_import_path))
import lttngtest


def test_short_lived_ust_app(tap, test_env, buffer_sharing_policy):
    tap.diagnostic(
        "test_short_lived_ust_app with buffer sharing policy `{}`".format(
            buffer_sharing_policy
        )
    )

    uid = None
    user = None
    if buffer_sharing_policy == lttngtest.lttngctl.BufferSharingPolicy.PerUID:
        if not (os.getuid() == 0 and test_env.allows_destructive()):
            tap.skip(
                "Need to run PerUID test as root with `LTTNG_ENABLE_DESTRUCTIVE_TESTS` properly set to create a dummy user",
                1,
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

    late_app = test_env.launch_wait_trace_test_application(
        10, wait_before_exit=False, run_as=user
    )
    late_app.trace()
    late_app.wait_for_tracing_done()
    late_app.wait_for_exit()

    session.stop()
    session.destroy()
    viewer.wait()

    tap.test(
        len(viewer.messages) == 10,
        "Live viewer got {} / 10 expected events add exited gracefully".format(
            len(viewer.messages)
        ),
    )


tap = lttngtest.TapGenerator(2)
for buffer_sharing_policy in [
    lttngtest.lttngctl.BufferSharingPolicy.PerUID,
    lttngtest.lttngctl.BufferSharingPolicy.PerPID,
]:
    with lttngtest.test_environment(
        log=tap.diagnostic, with_relayd=True, with_sessiond=True
    ) as test_env:
        test_short_lived_ust_app(tap, test_env, buffer_sharing_policy)
sys.exit(0 if tap.is_successful else 1)
