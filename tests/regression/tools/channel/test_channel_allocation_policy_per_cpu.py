#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2025 Olivier Dion <odion@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only

import pathlib
import sys

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.append(str(test_utils_import_path))

import lttngtest

"""
This test suite validates the following properties of the option
`--buffer-allocation=per-cpu' of the `enable-channel' command:

  - The `cpu_id' context is implicitly added to the channel.
"""


def make_ust_per_cpu_buffers_or_fail(session):
    """
    Make a channel in the UST domain with per-cpu buffers allocation for SESSION.
    """
    try:
        return session.add_channel(
            lttngtest.TracingDomain.User,
            buffer_allocation_policy=lttngtest.BufferAllocationPolicy.PerCPU,
        )
    except Exception as e:
        tap.fail("Could not create UST channel with per-cpu buffers")
        raise e


def test_per_cpu_buffers_ust_implicit_cpu_id_context(tap, client, session):
    """
    Ensure that the `cpu_id' context is implicitly added to channels with the
    per-cpu buffer allocation policy.
    """

    channel = make_ust_per_cpu_buffers_or_fail(session)

    try:
        channel.add_context(lttngtest.CPUidContextType())
        tap.fail(
            "Successfully added 'cpu_id' context when the channel allocation policy is 'per-cpu'."
        )
    except lttngtest.LTTngClientError as exn:
        tap.test(
            "User space tracing context already exists" in exn._output,
            "Cannot add `cpu_id' context when channel allocation policy is 'per-cpu'",
        )
    except Exception as e:
        tap.fail("Unknown exception thrown while adding 'cpu_id' context: {}".format(e))


def run_test(test, tap, client):
    try:
        session_output_location = lttngtest.LocalSessionOutputLocation(
            test_env.create_temporary_directory("trace")
        )

        session = client.create_session(
            output=session_output_location,
        )

        test(tap, client, session)
    finally:
        session.destroy()


ust_domain_tests = (test_per_cpu_buffers_ust_implicit_cpu_id_context,)

tap = lttngtest.TapGenerator(len(ust_domain_tests))

with lttngtest.test_environment(with_sessiond=True, log=tap.diagnostic) as test_env:
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)

    for test in ust_domain_tests:
        run_test(test, tap, client)

sys.exit(0 if tap.is_successful else 1)
