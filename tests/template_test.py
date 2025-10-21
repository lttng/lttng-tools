#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: XXXX Name <email@example.com>
# SPDX-License-Identifier: GPL-2.0-only
#
"""
Describe what the test is validating.
"""

import pathlib
import sys

# Import in-tree test utils
# Modify this depending on where the test file is in the tree
test_utils_import_path = pathlib.Path(__file__).absolute().parents[0] / "utils"
sys.path.append(str(test_utils_import_path))

import lttngtest
import bt2


def test_example(tap, test_env):
    output_path = test_env.create_temporary_directory("trace")

    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(output_path)
    )
    channel = session.add_channel(lttngtest.lttngctl.TracingDomain.User)
    channel.add_recording_rule(lttngtest.lttngctl.UserTracepointEventRule("tp:tptest"))

    session.start()
    app = test_env.launch_wait_trace_test_application(1000)
    app.trace()
    app.wait_for_tracing_done()
    app.wait_for_exit()
    session.stop()
    session.destroy()

    received, discarded = lttngtest.count_events(output_path)
    tap.test(received == 1000 and discarded == 0, "Got expected events")


if __name__ == "__main__":
    tests = [
        test_example,
    ]
    tap = lttngtest.TapGenerator(len(tests))

    # Check for platform requirements, if necessary
    has_platform_requirements = True
    if not has_platform_requirements:
        # This function will exit either with skipping or with a bailout,
        # depending on the the environment configuration.
        tap.missing_platform_requirements("Need XXX")

    for test in tests:
        with lttngtest.test_environment(
            with_sessiond=True, log=tap.diagnostic
        ) as test_env:
            test(tap, test_env)

    sys.exit(0 if tap.is_successful else 1)
