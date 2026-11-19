#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#
"""
Validate that the string values of the CTF 1.8 trace environment are
escaped. A session name containing double quotes and backslashes must be
read back unchanged as the `trace_name` environment entry.
"""

import pathlib
import sys

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest
import bt2


def read_trace_name(trace_path):
    # type: (pathlib.Path) -> str
    for msg in bt2.TraceCollectionMessageIterator(str(trace_path)):
        if type(msg) is bt2._StreamBeginningMessageConst:
            return str(msg.stream.trace.environment["trace_name"])

    raise LookupError("No stream found in the trace")


def test_env_string_escaping(tap, test_env):
    session_name = 'quote"back\\slash\\"end'
    output_path = test_env.create_temporary_directory("trace")
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session = client.create_session(
        name=session_name,
        output=lttngtest.LocalSessionOutputLocation(output_path),
        trace_format=lttngtest.lttngctl.TraceFormat.CTF_1_8,
    )
    channel = session.add_channel(lttngtest.lttngctl.TracingDomain.User)
    channel.add_recording_rule(lttngtest.lttngctl.UserTracepointEventRule("tp:tptest"))

    session.start()
    app = test_env.launch_wait_trace_test_application(1)
    app.trace()
    app.wait_for_exit()
    session.stop()
    session.destroy()

    with tap.case("Trace environment `trace_name` matches the session name"):
        trace_name = read_trace_name(output_path)
        if trace_name != session_name:
            raise AssertionError(
                "Expected `{}`, got `{}`".format(session_name, trace_name)
            )


if __name__ == "__main__":
    tap = lttngtest.TapGenerator(1)
    with lttngtest.test_environment(with_sessiond=True, log=tap.diagnostic) as test_env:
        test_env_string_escaping(tap, test_env)

    sys.exit(0 if tap.is_successful else 1)
