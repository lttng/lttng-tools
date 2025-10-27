#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2013 Jérémie Galarneau <jeremie.galarneau@efficios.com>
# SPDX-FileCopyrightText: 2025 Kienan Stewart <kstewart@efficios.com>
#
# SPDX-License-Identifier: GPL-2.0-only

import os
import pathlib
import re
import subprocess
import shutil
import sys

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.append(str(test_utils_import_path))

import lttngtest
import bt2


def test(tap, test_env):
    expected_events_parent = [
        "ust_tests_fork:before_fork",
        "ust_tests_fork:after_fork_parent",
    ]
    expected_events_child = [
        "ust_tests_fork:after_fork_child",
        "ust_tests_fork:after_exec",
    ]
    test_path = os.path.dirname(os.path.abspath(__file__)) + "/"
    output_path = test_env.create_temporary_directory("trace")
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(output_path)
    )
    channel = session.add_channel(lttngtest.lttngctl.TracingDomain.User)
    channel.add_recording_rule(lttngtest.lttngctl.UserTracepointEventRule("*"))
    session.start()

    fork_process = test_env.launch_test_application(
        [os.path.join(test_path, "fork"), os.path.join(test_path, "fork2")],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    parent_pid = -1
    child_pid = -1
    fork_process.wait_for_exit()
    for line in fork_process._process.stdout:
        line = line.decode("utf-8").replace("\n", "")
        match = re.search(r"child_pid (\d+)", line)
        if match:
            child_pid = match.group(1)

        match = re.search(r"parent_pid (\d+)", line)
        if match:
            parent_pid = match.group(1)

    tap.diagnostic("Parent pid: {}, child pid: {}".format(parent_pid, child_pid))
    session.stop()
    received_events_parent = {x: 0 for x in expected_events_parent}
    received_events_child = {x: 0 for x in expected_events_child}
    for msg in bt2.TraceCollectionMessageIterator(str(output_path)):
        if type(msg) is bt2._EventMessageConst:
            if "pid" not in msg.event.payload_field:
                continue

            pid = str(msg.event.payload_field["pid"])
            if pid == parent_pid and msg.event.name in expected_events_parent:
                received_events_parent[msg.event.name] += 1

            if pid == child_pid and msg.event.name in expected_events_child:
                received_events_child[msg.event.name] += 1

    for event, count in received_events_parent.items():
        tap.test(
            count > 0,
            "Event '{}' has at least 1 event in parent pid {}".format(
                event, parent_pid
            ),
        )

    for event, count in received_events_child.items():
        tap.test(
            count > 0,
            "Event '{}' has at least 1 event in child pid {}".format(event, child_pid),
        )


if __name__ == "__main__":
    tap = lttngtest.TapGenerator(4)
    with lttngtest.test_environment(with_sessiond=True, log=tap.diagnostic) as test_env:
        test(tap, test_env)

    sys.exit(0 if tap.is_successful else 1)
