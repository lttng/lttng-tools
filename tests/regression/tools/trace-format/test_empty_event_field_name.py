#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Kienan Stewart <kstewart@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#
"""
Validate that a tracepoint event that contains a field with an empty identifier
is handled in both CTF 1.8 and CTF 2.0.
"""

import pathlib
import sys

# Import in-tree test utils
# Modify this depending on where the test file is in the tree
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.append(str(test_utils_import_path))

import lttngtest
import bt2


def test_event_empty_identifier(
    tap, test_env, trace_format=lttngtest.lttngctl.TraceFormat.CTF_2
):
    tap.diagnostic("Testing with traceformat: {}".format(trace_format))

    output_path = test_env.create_temporary_directory("trace")
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(output_path),
        trace_format=trace_format,
    )
    channel = session.add_channel(lttngtest.lttngctl.TracingDomain.User)
    channel.add_recording_rule(
        lttngtest.lttngctl.UserTracepointEventRule("tp:tptest_empty")
    )

    session.start()
    app = test_env.launch_wait_trace_test_application(
        1000, emit_event_with_empty_field_name=True
    )
    app.trace()
    app.wait_for_tracing_done()
    app.wait_for_exit()
    session.regenerate(lttngtest.lttngctl.SessionRegenerateTarget.Metadata)
    session.rotate()
    session.stop()
    session.destroy()

    received, discarded = lttngtest.count_events(output_path)
    tap.test(received == 1 and discarded == 0, "Got expected events")


if __name__ == "__main__":
    tests = [
        {
            "test": test_event_empty_identifier,
            "kwargs": {
                "trace_format": lttngtest.lttngctl.TraceFormat.CTF_1_8,
            },
        },
        {
            "test": test_event_empty_identifier,
            "kwargs": {
                "trace_format": lttngtest.lttngctl.TraceFormat.CTF_2,
            },
        },
    ]

    tap = lttngtest.TapGenerator(len(tests))
    for test_definition in tests:
        with lttngtest.test_environment(
            with_sessiond=True, log=tap.diagnostic
        ) as test_env:
            test_definition["test"](tap, test_env, **test_definition["kwargs"])

    sys.exit(0 if tap.is_successful else 1)
