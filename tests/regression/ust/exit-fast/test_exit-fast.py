#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2013 Jérémie Galarneau <jeremie.galarneau@efficios.com>
# SPDX-FileCopyrightText: 2025 Kienan Stewart <kstewart@efficios.com>
#
# SPDX-License-Identifier: GPL-2.0-only

import os
import pathlib
import shutil
import subprocess
import sys

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.append(str(test_utils_import_path))

import lttngtest
import bt2


def test(tap, test_env):
    normal_exit_message = "exit-fast tracepoint normal exit"
    suicide_exit_message = "exit-fast tracepoint suicide"
    test_path = os.path.dirname(os.path.abspath(__file__)) + "/"
    output_path = test_env.create_temporary_directory("trace")
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(output_path)
    )
    channel = session.add_channel(lttngtest.lttngctl.TracingDomain.User)
    channel.add_recording_rule(
        lttngtest.lttngctl.UserTracepointEventRule("ust_tests_exitfast*")
    )
    session.start()

    exit_fast_process = test_env.launch_test_application(
        os.path.join(test_path, "exit-fast"),
    )
    exit_fast_process.wait_for_exit()

    exit_fast_process = test_env.launch_test_application(
        [os.path.join(test_path, "exit-fast"), "suicide"],
    )
    try:
        exit_fast_process.wait_for_exit()
    except RuntimeError as e:
        # This invocation should die with non-zero exit code
        pass
    session.stop()

    received_events = []
    for msg in bt2.TraceCollectionMessageIterator(str(output_path)):
        if type(msg) is bt2._EventMessageConst:
            received_events.append(msg.event)

    tap.test(len(received_events) == 2, "Found 2 expected events")
    tap.test(
        received_events[0].payload_field["message"] == normal_exit_message,
        "Event '{}' message '{}' matches expected value '{}'".format(
            received_events[0].name,
            received_events[0].payload_field["message"],
            normal_exit_message,
        ),
    )
    tap.test(
        received_events[1].payload_field["message"] == suicide_exit_message,
        "Event '{}' message '{}' matches expected value '{}'".format(
            received_events[1].name,
            received_events[1].payload_field["message"],
            normal_exit_message,
        ),
    )


if __name__ == "__main__":
    tap = lttngtest.TapGenerator(3)
    with lttngtest.test_environment(with_sessiond=True, log=tap.diagnostic) as test_env:
        test(tap, test_env)

    sys.exit(0 if tap.is_successful else 1)
