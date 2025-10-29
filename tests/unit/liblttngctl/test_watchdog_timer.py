#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: Kienan Stewart <kstewart@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#
"""
Tests lttng_channel_(get|set)_watchdog_timer_interval
"""

import ctypes
import os
import pathlib
import sys

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[2] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest


def test_get_watchdog_timer_no_channel(tap, test_env):
    ret = lttng.lttng_channel_get_watchdog_timer_interval(
        None, ctypes.pointer(ctypes.c_uint64(0))
    )
    tap.test(
        ret != lttng.LTTNG_CHANNEL_STATUS_OK,
        "'lttng_channel_get_watchdog_timer_interval' rejects NULL channel",
    )


def test_set_watchdog_timer_no_channel(tap, test_env):
    ret = lttng.lttng_channel_set_watchdog_timer_interval(None, ctypes.c_uint64(0))
    tap.test(
        ret != lttng.LTTNG_CHANNEL_STATUS_OK,
        "'lttng_channel_set_watchdog_timer_interval' rejects NULL channel",
    )


def test_get_watchdog_timer_no_channel_ext(tap, test_env):
    ret = lttng.lttng_channel_get_watchdog_timer_interval(
        ctypes.pointer(lttng.struct_lttng_channel()),
        ctypes.pointer(ctypes.c_uint64(0)),
    )
    tap.test(
        ret != lttng.LTTNG_CHANNEL_STATUS_OK,
        "'lttng_channel_get_watchdog_timer_interval' rejects channel with NULL extended attribute",
    )


def test_set_watchdog_timer_no_channel_ext(tap, test_env):
    ret = lttng.lttng_channel_set_watchdog_timer_interval(
        ctypes.pointer(lttng.struct_lttng_channel()), ctypes.c_uint64(0)
    )
    tap.test(
        ret != lttng.LTTNG_CHANNEL_STATUS_OK,
        "'lttng_channel_set_watchdog_timer_interval' rejects channel with NULL extended attribute",
    )


def test_get_watchdog_timer_no_timer_set(tap, test_env):
    # Currently the kernel domain doesn't have support for the watchdog timer,
    # and if that changes this test will no longer work as expected.
    domain_instance = lttng.struct_lttng_domain()
    lttng.type = lttng.LTTNG_DOMAIN_KERNEL
    domain_instance.buf_type = lttng.LTTNG_BUFFER_PER_UID
    channel_instance = common.get_channel_instance(domain_instance)
    ret = lttng.lttng_channel_get_watchdog_timer_interval(
        channel_instance, ctypes.pointer(ctypes.c_uint64(0))
    )
    tap.test(
        ret != lttng.LTTNG_CHANNEL_STATUS_OK,
        "lttng_channel_get_watchdog_timer_interval with no timer set returns an error",
    )


def test_get_watchdog_timer_no_timer_interval(tap, test_env):
    channel_instance = common.get_channel_instance()
    ret = lttng.lttng_channel_get_watchdog_timer_interval(channel_instance, None)
    tap.test(
        ret != lttng.LTTNG_CHANNEL_STATUS_OK,
        "'lttng_channel-get_watchdog_timer_interval' rejects a NULL destination pointer",
    )


def test_watchdog_timer_mock(tap, test_env):
    expected_value = 126253
    channel_instance = common.get_channel_instance()
    attribute = ctypes.c_uint64()
    set_ret = lttng.lttng_channel_set_watchdog_timer_interval(
        channel_instance, expected_value
    )
    get_ret = lttng.lttng_channel_get_watchdog_timer_interval(
        channel_instance, ctypes.pointer(attribute)
    )
    tap.test(
        set_ret == lttng.LTTNG_CHANNEL_STATUS_OK
        and get_ret == lttng.LTTNG_CHANNEL_STATUS_OK
        and attribute.value == expected_value,
        "'lttng_channel_get_watchdog_timer_interval' mock, set_ret=`{}`, get_ret=`{}`, value=`{}`, expected=`{}`".format(
            set_ret, get_ret, attribute.value, expected_value
        ),
    )


def test_watchdog_timer_interval_with_session(tap, test_env):
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session = client.create_session()
    channel_obj = session.add_channel(lttngtest.TracingDomain.User)

    # Setup to get channel
    session_name = session.name.encode()
    domain_array_head = ctypes.cast(
        ctypes.c_void_p(None),
        ctypes.POINTER(lttng.struct_lttng_domain),
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
        ctypes.c_void_p(None),
        ctypes.POINTER(lttng.struct_lttng_channel),
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

    assert channel_count == 1
    timer_interval = ctypes.c_uint64(0)
    res = lttng.lttng_channel_get_watchdog_timer_interval(
        channel_array_head, ctypes.pointer(timer_interval)
    )

    test_pass = True
    if res != lttng.LTTNG_CHANNEL_STATUS_OK or timer_interval.value != 2000000:
        tap.diagnostic(
            "Failed to validate timer interval: timer_interval={}, res={}".format(
                timer_interval.value, res
            )
        )
        test_pass = False

    tap.test(test_pass, "lttng_channel_get/set_watchdog_timer_interval")


if __name__ == "__main__":
    tests = [
        test_get_watchdog_timer_no_channel,
        test_get_watchdog_timer_no_channel_ext,
        test_get_watchdog_timer_no_timer_interval,
        test_get_watchdog_timer_no_timer_set,
        test_set_watchdog_timer_no_channel,
        test_set_watchdog_timer_no_channel_ext,
        test_watchdog_timer_mock,
        test_watchdog_timer_interval_with_session,  # simple integration test
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
