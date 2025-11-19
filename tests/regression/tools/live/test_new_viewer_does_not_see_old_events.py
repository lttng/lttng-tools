#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2025 Kienan Stewart <kstewart@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#

"""
Test that a newly attached live viewer doesn't see old events.
"""

import pathlib
import re
import socket
import subprocess
import sys
import tempfile
import time

test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.append(str(test_utils_import_path))

import lttngtest
import bt2


def test_with_babeltrace_bindings(
    tap,
    test_env,
    viewer_delay_seconds=None,
    live_timer_us=None,
    expected_pre=0,
    expected_post=15,
):
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    output = lttngtest.NetworkSessionOutputLocation(
        "net://localhost:{}:{}/".format(
            test_env.lttng_relayd_control_port, test_env.lttng_relayd_data_port
        )
    )
    session = client.create_session(
        output=output, live=live_timer_us if live_timer_us is not None else True
    )
    channel = session.add_channel(
        lttngtest.lttngctl.TracingDomain.User,
        buffer_sharing_policy=lttngtest.lttngctl.BufferSharingPolicy.PerUID,
    )
    channel.add_context(lttngtest.lttngctl.VpidContextType())
    channel.add_recording_rule(lttngtest.lttngctl.UserTracepointEventRule("tp:tptest"))
    session.start()

    # Run a first application, before the live viewer connects
    app = test_env.launch_wait_trace_test_application(10)
    pre_attach_pid = app.vpid
    app.trace()
    app.wait_for_exit()

    if viewer_delay_seconds:
        time.sleep(viewer_delay_seconds)

    # Connect live viewer
    viewer = test_env.launch_live_viewer(session.name)
    viewer.wait_until_connected()
    # Get all available events without disconnecting
    viewer._drain()

    # Run second test app
    app = test_env.launch_wait_trace_test_application(15)
    app.trace()
    app.wait_for_exit()
    post_attach_pid = app.vpid

    # Get all available events without disconnecting
    viewer.wait(close_iterator=False)
    session.stop()
    session.destroy()

    # The viewer should be disconnected when the session is destroyed
    tap.diagnostic("Waiting for live viewer to disconnect")
    # Drain iterator, the loop is to catch events
    # if it takes a little longer for them to become available.
    while len(viewer.messages) < 15:
        viewer.wait(close_iterator=False)
        time.sleep(0.1)

    viewer.wait()
    viewer.wait_until_disconnected()
    tap.diagnostic(
        "Testing with delay {}s, live_timer_us={}".format(
            viewer_delay_seconds, live_timer_us if live_timer_us else "default"
        )
    )
    tap.test(
        not viewer.is_connected(),
        "Live viewer exited gracefully",
    )

    messages = viewer.messages
    message_count = len(messages)
    messages_by_pid = {
        pre_attach_pid: 0,
        post_attach_pid: 0,
    }

    for message in messages:
        if type(message) is bt2._EventMessageConst:
            pid = message.event["vpid"]
            messages_by_pid[pid] = (
                (messages_by_pid[pid] + 1) if pid in messages_by_pid else 1
            )

    for pid, message_count_by_pid in messages_by_pid.items():
        pid_desc = "unknown"
        if pid == pre_attach_pid:
            pid_desc = "pre-attach"
        elif pid == post_attach_pid:
            pid_desc = "post-attach"

        tap.diagnostic(
            "{} messages from {} PID {}".format(message_count_by_pid, pid_desc, pid)
        )

    tap.test(
        messages_by_pid[pre_attach_pid] == expected_pre,
        "Live viewer got {} / {} expected events from pre-attach PID {}".format(
            messages_by_pid[pre_attach_pid], expected_pre, pre_attach_pid
        ),
    )
    tap.test(
        messages_by_pid[post_attach_pid] == expected_post,
        "Live viewer got {} / {} expected events from post-attach PID {}".format(
            messages_by_pid[post_attach_pid], expected_post, post_attach_pid
        ),
    )


def test_with_babeltrace_bin(
    tap,
    test_env,
    viewer_delay_seconds=None,
    live_timer_us=None,
    expected_pre=0,
    expected_post=15,
):
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    output = lttngtest.NetworkSessionOutputLocation(
        "net://localhost:{}:{}/".format(
            test_env.lttng_relayd_control_port, test_env.lttng_relayd_data_port
        )
    )
    session = client.create_session(
        output=output, live=live_timer_us if live_timer_us is not None else True
    )
    channel = session.add_channel(
        lttngtest.lttngctl.TracingDomain.User,
        buffer_sharing_policy=lttngtest.lttngctl.BufferSharingPolicy.PerUID,
    )
    channel.add_context(lttngtest.lttngctl.VpidContextType())
    channel.add_recording_rule(lttngtest.lttngctl.UserTracepointEventRule("tp:tptest"))
    session.start()

    # Run a first application, before the live viewer connects
    app = test_env.launch_wait_trace_test_application(10)
    pre_attach_pid = app.vpid
    app.trace()

    if viewer_delay_seconds:
        time.sleep(viewer_delay_seconds)

    live_url = "net://localhost:{}/host/{}/{}".format(
        test_env.lttng_relayd_live_port, socket.gethostname(), session.name
    )
    viewer_output = tempfile.NamedTemporaryFile(
        prefix="babeltrace2_", dir=test_env.lttng_log_dir, delete=False
    )
    viewer = subprocess.Popen(
        [
            "babeltrace2",
            "-i",
            "lttng-live",
            live_url,
        ],
        stdout=viewer_output.file,
    )

    pattern = re.compile("(?P<client_count>[0-9]+) client\\(s\\) connected")
    bt2_err_output = tempfile.NamedTemporaryFile(
        prefix="babeltrace2_", dir=test_env.lttng_log_dir, delete=False
    )
    # Wait until the viewer is fully connected
    while True:
        p = subprocess.Popen(
            [
                "babeltrace2",
                "-i",
                "lttng-live",
                "net://localhost:{}".format(test_env.lttng_relayd_live_port),
            ],
            stdout=subprocess.PIPE,
            stderr=bt2_err_output.file,
        )
        p.wait()
        x = pattern.search(p.stdout.read().decode("utf-8"))
        if x and int(x.group("client_count")) >= 1:
            break
        time.sleep(0.1)

    # Wait for exit afterwards: possible race between app teardown and
    # live viewer starting when there are a lot of streams.
    app.wait_for_exit()

    # Run second test app
    app = test_env.launch_wait_trace_test_application(15)
    app.trace()
    app.wait_for_exit()
    post_attach_pid = app.vpid

    session.stop()
    session.destroy()

    # The viewer should be disconnected when the session is destroyed
    tap.diagnostic("Waiting for live viewer to disconnect")
    viewer.wait()
    tap.diagnostic(
        "Testing with delay {}s, live_timer_us={}".format(
            viewer_delay_seconds, live_timer_us if live_timer_us else "default"
        )
    )
    tap.test(
        viewer.returncode == 0,
        "Live viewer exited gracefully",
    )

    with open(viewer_output.name, "r") as f:
        messages = f.readlines()

    messages_by_pid = {
        pre_attach_pid: 0,
        post_attach_pid: 0,
    }
    re_vpid = re.compile("{ vpid = (?P<vpid>[0-9]+) }")
    for message in messages:
        x = re_vpid.search(message)
        if x:
            pid = int(x.group("vpid"))
            messages_by_pid[pid] = (
                (messages_by_pid[pid] + 1) if pid in messages_by_pid else 1
            )

    for pid, message_count_by_pid in messages_by_pid.items():
        pid_desc = "unknown"
        if pid == pre_attach_pid:
            pid_desc = "pre-attach"
        elif pid == post_attach_pid:
            pid_desc = "post-attach"

        tap.diagnostic(
            "{} messages from {} PID {}".format(message_count_by_pid, pid_desc, pid)
        )

    tap.test(
        messages_by_pid[pre_attach_pid] == expected_pre,
        "Live viewer got {} / {} expected events from pre-attach PID {}".format(
            messages_by_pid[pre_attach_pid], expected_pre, pre_attach_pid
        ),
    )
    tap.test(
        messages_by_pid[post_attach_pid] == expected_post,
        "Live viewer got {} / {} expected events from post-attach PID {}".format(
            messages_by_pid[post_attach_pid], expected_post, post_attach_pid
        ),
    )


if __name__ == "__main__":
    tests = [
        test_with_babeltrace_bindings,
        test_with_babeltrace_bin,
    ]

    # What we're interested in testing are two cases relative to when the live
    # timer fires after the first application is traced and when the live
    # viewer is connected.
    #
    # If the timer fires before the viewer connects, the events from the first
    # instrumented application shouldn't be visible.
    #
    # If the timer fires after the viewer connects, the events from the first
    # instrumented application should be visible.
    #
    # By setting the live timer to a long value we should be able to safely test
    # the former case, and by using a delay >> live_timer_us, the latter case
    # can be exercised.
    #
    configurations = [
        # Live timer fires after first instrumented application and before viewer connects
        # only events from the second instrumented application should be visible.
        {"viewer_delay_seconds": 5.0, "expected_pre": 0, "expected_post": 15},
        # Live timer fires after the 2nd instrumented application is run.
        {"live_timer_us": 1000000 * 5, "expected_pre": 10, "expected_post": 15},
    ]
    tap = lttngtest.TapGenerator(len(tests) * len(configurations) * 3)
    for test in tests:
        for conf in configurations:
            with lttngtest.test_environment(
                log=tap.diagnostic, with_relayd=True, with_sessiond=True
            ) as test_env:
                tap.diagnostic(
                    "Starting test '{}' with parameters: {}".format(test.__name__, conf)
                )
                test(tap, test_env, **conf)

    sys.exit(0 if tap.is_successful else 1)
