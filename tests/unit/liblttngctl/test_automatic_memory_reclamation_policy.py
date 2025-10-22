#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: Kienan Stewart <kstewart@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#
"""
Tests lttng_channel_(get|set)_automatic_memory_reclamation_policy
"""

import ctypes
import os
import pathlib
import sys

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[2] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest


def test_get_automatic_memory_reclamation_policy_no_channel(tap, test_env):
    ret = lttng.lttng_channel_get_automatic_memory_reclamation_policy(
        None, ctypes.pointer(ctypes.c_uint64(0))
    )
    tap.test(
        ret != lttng.LTTNG_CHANNEL_STATUS_OK,
        "'lttng_channel_get_automatic_memory_reclamation_policy' rejects NULL channel",
    )


def test_set_automatic_memory_reclamation_policy_no_channel(tap, test_env):
    ret = lttng.lttng_channel_set_automatic_memory_reclamation_policy(
        None, ctypes.c_uint64(0)
    )
    tap.test(
        ret != lttng.LTTNG_CHANNEL_STATUS_OK,
        "'lttng_channel_set_automatic_memory_reclamation_policy' rejects NULL channel",
    )


def test_get_automatic_memory_reclamation_policy_no_channel_ext(tap, test_env):
    ret = lttng.lttng_channel_get_automatic_memory_reclamation_policy(
        ctypes.pointer(lttng.struct_lttng_channel()),
        ctypes.pointer(ctypes.c_uint64(0)),
    )
    tap.test(
        ret != lttng.LTTNG_CHANNEL_STATUS_OK,
        "'lttng_channel_get_automatic_memory_reclamation_policy' refuses channel with NULL extended attribute",
    )


def test_set_automatic_memory_reclamation_policy_no_channel_ext(tap, test_env):
    ret = lttng.lttng_channel_set_automatic_memory_reclamation_policy(
        ctypes.pointer(lttng.struct_lttng_channel()), ctypes.c_uint64(0)
    )
    tap.test(
        ret != lttng.LTTNG_CHANNEL_STATUS_OK,
        "'lttng_channel_set_automatic_memory_reclamation_policy' refuses channel with NULL extended attribute",
    )


def test_get_automatic_memory_reclamation_policy_no_policy(tap, test_env):
    ret = lttng.lttng_channel_get_automatic_memory_reclamation_policy(
        common.get_channel_instance(), None
    )
    tap.test(
        ret != lttng.LTTNG_CHANNEL_STATUS_OK,
        "'lttng_channel_get_automatic_memory_reclamation_policy' refuses NULL destination poitner",
    )


def test_automatic_memory_reclamation_policy_mock(tap, test_env):
    expected_value = 126253
    attribute = ctypes.c_uint64(0)
    channel_instance = common.get_channel_instance()
    set_ret = lttng.lttng_channel_set_automatic_memory_reclamation_policy(
        channel_instance, ctypes.c_uint64(expected_value)
    )
    get_ret = lttng.lttng_channel_get_automatic_memory_reclamation_policy(
        channel_instance, ctypes.pointer(attribute)
    )
    tap.test(
        set_ret == lttng.LTTNG_CHANNEL_STATUS_OK
        and get_ret == lttng.LTTNG_CHANNEL_STATUS_OK
        and attribute.value == expected_value,
        "'lttng_channel_get_automatic_memory_reclamation_policy' mock, set_ret=`{}`, get_ret=`{}`, value=`{}`, expected=`{}`".format(
            set_ret, get_ret, attribute.value, expected_value
        ),
    )


def test_automatic_memory_reclamation_policy_with_session(tap, test_env):
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session = client.create_session()
    channel_obj = session.add_channel(lttngtest.TracingDomain.User)

    # Setup to get channel

    session_name = session.name.encode()
    domain_array_head = ctypes.cast(
        ctypes.c_void_p(None), ctypes.POINTER(lttng.struct_lttng_domain)
    )
    domain_count = lttng.lttng_list_domains(
        session_name, ctypes.pointer(domain_array_head)
    )
    tap.diagnostic("Domains for session '{}': {}".format(session_name, domain_count))
    if domain_count <= 0:
        domain_array_head = None

    handle_instance = lttng.lttng_create_handle(
        session_name,
        (domain_array_head if domain_array_head else None),
    )
    channel_array_head = ctypes.cast(
        ctypes.c_void_p(None), ctypes.POINTER(lttng.struct_lttng_channel)
    )
    channel_count = lttng.lttng_list_channels(
        handle_instance,
        ctypes.pointer(channel_array_head),
    )
    if channel_count <= 0:
        # Error or no channels
        tap.fail(
            "Error or no channels: lttng_list_channels.ret=`{}`".format(channel_count)
        )
        return

    # If there's only one result, we can just use the first channel...
    assert channel_count == 1
    attribute = ctypes.c_uint64()

    res = lttng.lttng_channel_get_automatic_memory_reclamation_policy(
        channel_array_head, ctypes.pointer(attribute)
    )

    test_pass = True
    if res != lttng.LTTNG_CHANNEL_STATUS_UNSET or attribute.value != 0:
        tap.diagnostic(
            "Failed to validate automatic memory reclamation policy: value={}, res={}".format(
                attribute.value, res
            )
        )
        test_pass = False

    tap.test(
        test_pass,
        "lttng_channel_get/set_automatic_memory_reclamation_policy with sessiond",
    )


if __name__ == "__main__":
    tests = [
        test_get_automatic_memory_reclamation_policy_no_channel,
        test_set_automatic_memory_reclamation_policy_no_channel,
        test_get_automatic_memory_reclamation_policy_no_channel_ext,
        test_set_automatic_memory_reclamation_policy_no_channel_ext,
        test_get_automatic_memory_reclamation_policy_no_policy,
        test_automatic_memory_reclamation_policy_mock,
        test_automatic_memory_reclamation_policy_with_session,  # simple integration test
    ]
    tap = lttngtest.TapGenerator(len(tests))

    headers_dir = pathlib.Path(__file__).absolute().parents[0] / "lttngctl"
    sys.path.insert(0, str(headers_dir))
    import common
    import lttng

    with lttngtest.test_environment(with_sessiond=True, log=tap.diagnostic) as test_env:
        # Set LTTNG_RUNDIR for the tests
        rundir = (
            test_env.lttng_rundir
            if test_env.lttng_rundir
            else test_env.lttng_home_location / ".lttng"
        )
        tap.diagnostic("Setting LTTNG_RUNDIR: {}".format(rundir))
        os.environ["LTTNG_RUNDIR"] = str(rundir)
        try:
            for test in tests:
                tap.diagnostic("Running test `{}`".format(test.__name__))
                test(tap, test_env)
        finally:
            del os.environ["LTTNG_RUNDIR"]

    sys.exit(0 if tap.is_successful else 1)
