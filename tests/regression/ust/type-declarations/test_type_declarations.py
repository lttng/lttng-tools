#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2014 Geneviève Bastien <gbastien@versatic.net>
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
    test_path = os.path.dirname(os.path.abspath(__file__)) + "/"
    output_path = test_env.create_temporary_directory("trace")
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(output_path)
    )
    channel = session.add_channel(lttngtest.lttngctl.TracingDomain.User)
    channel.add_recording_rule(
        lttngtest.lttngctl.UserTracepointEventRule("ust_tests_td*")
    )
    session.start()
    td_process = test_env.launch_test_application(
        os.path.join(test_path, "type-declarations"),
    )
    td_process.wait_for_exit()
    session.stop()
    expected = 5
    received = 0
    events = []
    for msg in bt2.TraceCollectionMessageIterator(str(output_path)):
        if type(msg) is bt2._EventMessageConst:
            received += 1
            events.append(msg.event)

    tap.test(received == expected, "Receive the expected number of events in trace")
    tap.test(
        events[0].name == "ust_tests_td:tptest", "First event is ust_tests_td:tptest"
    )
    tap.test(
        "(zero)" in str(events[0]["enumfield"]),
        "First event's enumfield maps to '(zero)': `{}`".format(events[0]["enumfield"]),
    )
    tap.test(
        "(one)" in str(events[0]["enumfield_bis"]),
        "First event's enumfield_bis maps to '(one)': `{}`".format(
            events[0]["enumfield_bis"]
        ),
    )

    tap.test(
        events[1].name == "ust_tests_td:tptest_bis",
        "Second event is ust_tests_td:tptest_bis",
    )
    tap.test(
        "(zero)" in str(events[1]["enumfield"]),
        "Second event's enumfield maps to '(zero)': `{}`".format(
            events[1]["enumfield"]
        ),
    )

    tap.test(
        "(one)" in str(events[2]["enumfield"]),
        "Third event's enumfield maps to '(one)': `{}`".format(events[2]["enumfield"]),
    )

    event = events[4]
    tap.test(
        "(zero)" in str(event["zero"])
        and "(two)" in str(event["two"])
        and "(three)" in str(event["three"])
        and "(ten_to_twenty)" in str(event["fifteen"])
        and "(twenty_one)" in str(event["twenty_one"]),
        "Auto-incrementing enum values are correct. zero=`{}`, two=`{}`, three=`{}`, fifteen=`{}`, twenty_one=`{}`".format(
            event["zero"],
            event["two"],
            event["three"],
            event["fifteen"],
            event["twenty_one"],
        ),
    )
    del events


if __name__ == "__main__":
    tap = lttngtest.TapGenerator(8)
    with lttngtest.test_environment(with_sessiond=True, log=tap.diagnostic) as test_env:
        test(tap, test_env)

    sys.exit(0 if tap.is_successful else 1)
