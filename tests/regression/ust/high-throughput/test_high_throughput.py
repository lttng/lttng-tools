#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2025 Kienan Stewart <kstewart@efficios.com>
# SPDX-License-Identifier: GPL-2.1-only
#

"""
Validate that under heaving tracing load the sum of the recorded and dropped
events matches the expected output of the traced applications
"""

import os
import pathlib
import subprocess
import sys
import time

test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.append(str(test_utils_import_path))

import bt2
import lttngtest


def test_high_throughput(tap, test_env, app_count=20, events_per_app=1000000):
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    output_path = test_env.create_temporary_directory()
    output = lttngtest.LocalSessionOutputLocation(trace_path=output_path)
    session = client.create_session(output=output)
    channel = session.add_channel(lttngtest.lttngctl.TracingDomain.User)
    channel.add_recording_rule(lttngtest.lttngctl.UserTracepointEventRule("tp:tptest"))
    session.start()

    app_group = lttngtest.WaitTraceTestApplicationGroup(
        test_env, app_count, events_per_app, wait_before_exit=True
    )
    app_group.trace()
    app_group.exit()
    session.stop()

    expected = app_count * events_per_app
    received = 0
    discarded = 0
    for msg in bt2.TraceCollectionMessageIterator(str(output_path)):
        if type(msg) is bt2._EventMessageConst:
            received += 1
            continue

        if type(msg) is bt2._DiscardedEventsMessageConst:
            discarded += msg.count

    total = received + discarded
    tap.diagnostic("Trace output path: {}".format(str(output_path)))
    tap.diagnostic(
        "received={}, dropped={}, total={}, expected={}".format(
            received, discarded, total, expected
        )
    )
    tap.test(
        total == expected,
        "Total events {} match expected total {}".format(total, expected),
    )


if __name__ == "__main__":
    tap = lttngtest.TapGenerator(1)
    with lttngtest.test_environment(log=tap.diagnostic, with_sessiond=True) as test_env:
        test_high_throughput(tap, test_env)
    sys.exit(0 if tap.is_successful else 1)
