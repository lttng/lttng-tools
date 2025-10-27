#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2013 Jérémie Galarneau <jeremie.galarneau@efficios.com>
# SPDX-FileCopyrightText: 2025 Kienan Stewart <kstewart@efficios.com>
#
# SPDX-License-Identifier: GPL-2.0-only

import os
import pathlib
import sys

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.append(str(test_utils_import_path))

import lttngtest
import bt2


def test(tap, test_env):
    expected_events = [
        "lttng_ust_libc:malloc",
        "lttng_ust_libc:free",
    ]
    test_path = os.path.dirname(os.path.abspath(__file__)) + "/"
    output_path = test_env.create_temporary_directory("trace")
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(output_path)
    )
    channel = session.add_channel(lttngtest.lttngctl.TracingDomain.User)
    channel.add_recording_rule(
        lttngtest.lttngctl.UserTracepointEventRule("lttng_ust_libc*")
    )
    session.start()

    malloc_process = test_env.launch_test_application(os.path.join(test_path, "prog"))
    malloc_process.wait_for_exit()
    session.stop()

    received_events = {x: 0 for x in expected_events}
    for msg in bt2.TraceCollectionMessageIterator(str(output_path)):
        if type(msg) is bt2._EventMessageConst:
            if msg.event.name in received_events:
                received_events[msg.event.name] += 1

    tap.test(
        received_events["lttng_ust_libc:malloc"] > 0,
        "Received at least one malloc event",
    )
    tap.test(
        received_events["lttng_ust_libc:free"] > 0, "Received at least one free event"
    )


if __name__ == "__main__":
    tap = lttngtest.TapGenerator(2)
    with lttngtest.test_environment(with_sessiond=True, log=tap.diagnostic) as test_env:
        test(tap, test_env)

    sys.exit(0 if tap.is_successful else 1)
