#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2025 Philippe Proulx <eeppeliteloop@gmail.com>
# SPDX-License-Identifier: GPL-2.0-only

import pathlib
import json
import sys

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.append(str(test_utils_import_path))

import lttngtest
import bt2
from extract_ctf_2_prop import extract_prop

from trace_format_helpers import get_metadata_directory


def _is_ctf2_trace(trace_path):
    try:
        versions = extract_prop(
            str(get_metadata_directory(trace_path) / "metadata"), "preamble", "version"
        )
    except json.JSONDecodeError:
        return False

    return len(versions) == 1 and versions[0] == 2


def _capture_trace(test_env, tap, trace_format=None):
    session_output_location = lttngtest.LocalSessionOutputLocation(
        test_env.create_temporary_directory("trace")
    )
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session = client.create_session(
        output=session_output_location, trace_format=trace_format
    )
    channel = session.add_channel(lttngtest.TracingDomain.User)
    test_app = test_env.launch_wait_trace_test_application(10)
    test_app.taskset_anycpu()
    session.user_vpid_process_attribute_tracker.track(test_app.vpid)
    channel.add_recording_rule(lttngtest.UserTracepointEventRule("tp:tptest"))
    session.start()
    test_app.trace()
    test_app.wait_for_exit()
    session.stop()
    session.destroy()
    return session_output_location.path


tap = lttngtest.TapGenerator(0)
tap.diagnostic(
    "Test `--default-trace-format` option and `LTTNG_SESSIOND_DEFAULT_TRACE_FORMAT` environment variable of `lttng-sessiond`"
)

if tuple(map(int, bt2.__version__.split(".")[:2])) < (2, 1):
    tap.missing_platform_requirement("Babeltrace 2.1.0 or later is required")
    sys.exit(0)

sys.exit(0 if tap.is_successful else 1)
