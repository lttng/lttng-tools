#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2025 Olivier Dion <odion@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only

import os
import pathlib
import sys

import bt2

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest

"""
This test suite validates the robustness of the ust-ctl protocol. By
pre-loading the `liblttng-ust-ctl-fuzz.so` library in the session daemon, some
LTTng ust-ctl functions are overloaded with fuzzed variants.

The variants simply call `lttng_ust_ctl_unknown_command` and assert that it
returns 0, before calling the real functions.

The `lttng_ust_ctl_unknown_command` is a special command that is not understood
by the client (the user application). It sends a payload and a file-descriptor
to the application. It then verifies that the client returns `LTTNG_UST_ERR_NOSYS`
(command not supported) and that the sent file descriptor was closed.

In the end, pre-loading the fuzz library will inject the unknown command before
every command sent to clients. The test suite passes if they were no errors on
the sessiond, consumerd and client sides and that the final trace is valid.
"""


def test_simple(tap, test_env, session):
    "All user events enabled with some contexts"

    channel = session.add_channel(
        lttngtest.TracingDomain.User,
    )

    channel.add_context(
        lttngtest.VpidContextType(),
    )

    channel.add_context(
        lttngtest.VuidContextType(),
    )

    channel.add_recording_rule(lttngtest.UserTracepointEventRule(name_pattern="*"))

    app = test_env.launch_wait_trace_test_application(100)

    # This is just for sending more messages to the application.
    session.start()
    session.stop()
    session.start()

    app.trace()
    app.wait_for_exit()

    session.rotate()

    lttngtest.validate_trace(str(session.output.path))


if __name__ == "__main__":

    tests = (test_simple,)

    tap = lttngtest.TapGenerator(len(tests))

    path_to_fuzz_lib = (
        pathlib.Path(__file__).absolute().parents[1] / ".libs/liblttng-ust-ctl-fuzz.so"
    )

    if not os.path.exists(str(path_to_fuzz_lib)):
        tap.bail_out(
            "Path to LTTng ust-ctl fuzz does not exists: {}".format(path_to_fuzz_lib)
        )

    os.environ["LTTNG_SESSIOND_ENV_VARS"] = "LD_PRELOAD={}".format(
        str(path_to_fuzz_lib)
    )

    with lttngtest.test_environment(with_sessiond=True, log=tap.diagnostic) as test_env:

        client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)

        for test in tests:
            tap.diagnostic(test.__doc__)
            try:
                session = client.create_session(
                    output=lttngtest.LocalSessionOutputLocation(
                        test_env.create_temporary_directory("trace")
                    )
                )
                test(tap, test_env, session)
                tap.ok(test.__name__)
            except Exception as exn:
                tap.fail("{} - Exception: {}".format(test.__name__, exn))
            finally:
                session.destroy()

    sys.exit(0 if tap.is_successful else 1)
