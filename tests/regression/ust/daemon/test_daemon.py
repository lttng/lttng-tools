#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2013 Jérémie Galarneau <jeremie.galarneau@efficios.com>
# SPDX-FileCopyrightText: 2025 Kienan Stewart <kstewart@efficios.com>
#
# SPDX-License-Identifier: GPL-2.0-only

import os
import pathlib
import subprocess
import sys

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.append(str(test_utils_import_path))

import lttngtest
import bt2


def test(tap, test_env):
    expected_events = [
        "ust_tests_daemon:before_daemon",
        "ust_tests_daemon:after_daemon_child",
    ]
    test_path = os.path.dirname(os.path.abspath(__file__))
    output_path = test_env.create_temporary_directory("trace")
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(output_path)
    )
    channel = session.add_channel(lttngtest.lttngctl.TracingDomain.User)
    channel.add_recording_rule(lttngtest.lttngctl.UserTracepointEventRule("*"))
    session.start()

    parent_pid = None
    daemon_pid = None
    daemon_process = test_env.launch_test_application(
        os.path.join(test_path, "daemon"), stdout=subprocess.PIPE
    )
    daemon_process.wait_for_exit()
    for line in daemon_process._process.stdout:
        name, pid = line.decode("utf-8").split()
        if name == "child_pid":
            daemon_pid = pid
        if name == "parent_pid":
            parent_pid = pid

    tap.diagnostic("Parent pid: {}, daemon pid: {}".format(parent_pid, daemon_pid))
    session.stop()
    received_events_parent = {x: 0 for x in expected_events}
    received_events_daemon = {x: 0 for x in expected_events}
    for msg in bt2.TraceCollectionMessageIterator(str(output_path)):
        if type(msg) is bt2._EventMessageConst:
            if "pid" not in msg.event.payload_field:
                continue

            pid = str(msg.event.payload_field["pid"])
            if pid == parent_pid and msg.event.name in expected_events:
                received_events_parent[msg.event.name] += 1

            if pid == daemon_pid and msg.event.name in expected_events:
                received_events_daemon[msg.event.name] += 1

    tap.test(
        received_events_parent["ust_tests_daemon:before_daemon"] == 1,
        "Received before_daemon event from parent pid {}".format(parent_pid),
    )
    tap.test(
        received_events_parent["ust_tests_daemon:after_daemon_child"] == 0,
        "Did not receive after_daemon_child event from parent pid {}".format(
            parent_pid
        ),
    )
    tap.test(
        received_events_daemon["ust_tests_daemon:before_daemon"] == 0,
        "Did not received before_daemon event from daemon pid {}".format(daemon_pid),
    )
    tap.test(
        received_events_daemon["ust_tests_daemon:after_daemon_child"] == 1,
        "Received after_daemon_child event from daemon pid {}".format(daemon_pid),
    )


if __name__ == "__main__":
    tap = lttngtest.TapGenerator(4)
    with lttngtest.test_environment(with_sessiond=True, log=tap.diagnostic) as test_env:
        test(tap, test_env)

    sys.exit(0 if tap.is_successful else 1)
