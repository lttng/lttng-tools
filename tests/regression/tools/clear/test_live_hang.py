#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2024 Kienan Stewart <kstewart@efficios.com>
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

    viewer = test_env.launch_live_viewer(session.name)
    viewer.wait_until_connected()

    session.destroy()

    viewer.wait()
    tap.test(
        True,
        "BT2 live viewer exited successfully",
    )


with lttngtest.test_environment(
    with_sessiond=True, log=tap.diagnostic, with_relayd=True
) as test_env:
    test_live_hang(tap, test_env)

sys.exit(0 if tap.is_successful else 1)
