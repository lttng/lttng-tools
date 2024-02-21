#!/usr/bin/env python3
#
# Copyright (C) 2024 Kienan Stewart <kstewart@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#

"""
Test for https://review.lttng.org/c/lttng-tools/+/11819

A live client shouldn't hang around after a session with no data has
been destroyed
"""

import pathlib
import socket
import subprocess
import sys
import time

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.append(str(test_utils_import_path))

import lttngtest
import bt2

tap = lttngtest.TapGenerator(1)


def test_live_hang(tap, test_env):
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)

    # lttng create --live
    output = lttngtest.NetworkSessionOutputLocation(
        "net://localhost:{}:{}/".format(
            test_env.lttng_relayd_control_port, test_env.lttng_relayd_data_port
        )
    )
    session = client.create_session(output=output, live=True)

    # lttng enable-event --userspace --all
    channel = session.add_channel(lttngtest.lttngctl.TracingDomain.User)
    channel.add_recording_rule(lttngtest.lttngctl.UserTracepointEventRule())

    session.start()
    test_app = test_env.launch_wait_trace_test_application(100)
    session.stop()
    session.clear()

    ctf_live_cc = bt2.find_plugin("ctf").source_component_classes["lttng-live"]
    query_executor = bt2.QueryExecutor(
        ctf_live_cc,
        "sessions",
        params={"url": "net://localhost:{}".format(test_env.lttng_relayd_live_port)},
    )

    # wait until 'ready'
    ready = False
    query_result = None
    while not ready:
        try:
            query_result = query_executor.query()
        except bt2._Error:
            time.sleep(0.1)
            continue

        for live_session in query_result:
            if live_session["session-name"] == session.name:
                ready = True
                break
        time.sleep(0.1)

    # start live viewer
    bt2_args = [
        "babeltrace2",
        "-i",
        "lttng-live",
        "net://localhost:{}/host/{}/{}".format(
            test_env.lttng_relayd_live_port, socket.gethostname(), session.name
        ),
        "--params=session-not-found-action=end",
    ]
    tap.diagnostic("Running bt2: {}".format(bt2_args))
    bt2_proc = subprocess.Popen(bt2_args)

    # wait until one client is connected
    ready = False
    while not ready:
        try:
            query_result = query_executor.query()
        except bt2._Error:
            time.sleep(0.1)
            continue
        for live_session in query_result:
            if (
                live_session["session-name"] == session.name
                and live_session["client-count"] == 1
            ):
                ready = True
                break
        time.sleep(0.1)

    session.destroy()

    # assert live viewer has exited
    stopped = False
    try:
        bt2_proc.wait(5)
        stopped = True
    except subprocess.TimeoutExpired as e:
        tap.diagnostic("Timed out (5s) waiting for babeltrace2 to return")
    tap.test(
        stopped and bt2_proc.returncode == 0, "BT2 live viewer exited successfully"
    )
    if not stopped:
        bt2_proc.terminate()


with lttngtest.test_environment(
    with_sessiond=True, log=tap.diagnostic, with_relayd=True
) as test_env:
    test_live_hang(tap, test_env)

sys.exit(0 if tap.is_successful else 1)
