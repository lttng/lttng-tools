#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: Kienan Stewart <kstewart@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#
"""
Test the liblttngctl `lttng_channel_get_data_stream_info_sets` interface
"""

import ctypes
import importlib
import os
import pathlib
import sys

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[2] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest


def test_channel_get_data_stream_info_sets_no_session_string(
    session_name, channel_name, tap, test_env
):
    sets = ctypes.cast(
        ctypes.c_void_p(None),
        ctypes.POINTER(lttng.struct_lttng_data_stream_info_sets),
    )
    ret = lttng.lttng_channel_get_data_stream_info_sets(
        None,
        channel_name.encode(),
        lttng.LTTNG_DOMAIN_UST,
        ctypes.pointer(sets),
    )
    tap.test(
        ret != lttng.LTTNG_CHANNEL_GET_DATA_STREAM_INFO_SETS_STATUS_OK,
        "lttng_channel_get_data_stream_info_sets_status fails with no session string",
    )


def test_channel_get_data_stream_info_sets_no_channel_string(
    session_name, channel_name, tap, test_env
):
    sets = ctypes.cast(
        ctypes.c_void_p(None),
        ctypes.POINTER(lttng.struct_lttng_data_stream_info_sets),
    )
    ret = lttng.lttng_channel_get_data_stream_info_sets(
        session_name.encode(),
        None,
        lttng.LTTNG_DOMAIN_UST,
        ctypes.pointer(sets),
    )
    tap.test(
        ret != lttng.LTTNG_CHANNEL_GET_DATA_STREAM_INFO_SETS_STATUS_OK,
        "lttng_channel_get_data_stream_info_sets_status fails with no channel string",
    )


def test_channel_get_data_stream_info_sets_no_sets(
    session_name, channel_name, tap, test_env
):
    ret = lttng.lttng_channel_get_data_stream_info_sets(
        session_name.encode(),
        channel_name.encode(),
        lttng.LTTNG_DOMAIN_UST,
        None,
    )
    tap.test(
        ret != lttng.LTTNG_CHANNEL_GET_DATA_STREAM_INFO_SETS_STATUS_OK,
        "lttng_channel_get_data_stream_info_sets_status fails with no sets parameter",
    )


def test_channel_get_data_stream_info_sets_no_sessiond(
    session_name, channel_name, tap, test_env
):
    sets = ctypes.cast(
        ctypes.c_void_p(None),
        ctypes.POINTER(lttng.struct_lttng_data_stream_info_sets),
    )
    # Set a fake directory to force the connection to fail
    old_rundir = os.environ["LTTNG_RUNDIR"]
    os.environ["LTTNG_RUNDIR"] = "/fake"
    try:
        ret = lttng.lttng_channel_get_data_stream_info_sets(
            session_name.encode(),
            channel_name.encode(),
            lttng.LTTNG_DOMAIN_UST,
            ctypes.pointer(sets),
        )
    finally:
        os.environ["LTTNG_RUNDIR"] = old_rundir

    tap.test(
        ret != lttng.LTTNG_CHANNEL_GET_DATA_STREAM_INFO_SETS_STATUS_OK,
        "lttng_channel_get_data_stream_info_sets_status fails with no sessiond",
    )


def test_channel_get_data_stream_info_sets_invalid_domain_value(
    session_name, channel_name, tap, test_env
):
    sets = ctypes.cast(
        ctypes.c_void_p(None),
        ctypes.POINTER(lttng.struct_lttng_data_stream_info_sets),
    )
    ret = lttng.lttng_channel_get_data_stream_info_sets(
        session_name.encode(),
        channel_name.encode(),
        lttng.LTTNG_DOMAIN_NR + 1,
        ctypes.pointer(sets),
    )
    tap.test(
        ret != lttng.LTTNG_CHANNEL_GET_DATA_STREAM_INFO_SETS_STATUS_OK,
        "lttng_channel_get_data_stream_info_sets_status fails with invalid domain",
    )


def test_channel_get_data_stream_info_sets_with_sessiond(
    session_name, channel_name, tap, test_env
):
    sets = ctypes.cast(
        ctypes.c_void_p(None),
        ctypes.POINTER(lttng.struct_lttng_data_stream_info_sets),
    )
    ret = lttng.lttng_channel_get_data_stream_info_sets(
        session_name.encode(),
        channel_name.encode(),
        lttng.LTTNG_DOMAIN_UST,
        ctypes.pointer(sets),
    )
    tap.test(
        ret == lttng.LTTNG_CHANNEL_GET_DATA_STREAM_INFO_SETS_STATUS_OK,
        "lttng_channel_get_data_stream_info_sets_status passes: ret=`{}`, sets=`{}`".format(
            ret, str(sets[0])
        ),
    )


if __name__ == "__main__":
    tests = [
        test_channel_get_data_stream_info_sets_no_session_string,
        test_channel_get_data_stream_info_sets_no_channel_string,
        test_channel_get_data_stream_info_sets_no_sets,
        test_channel_get_data_stream_info_sets_no_sessiond,
        test_channel_get_data_stream_info_sets_invalid_domain_value,
        test_channel_get_data_stream_info_sets_with_sessiond,  # simple integration test
    ]
    tap = lttngtest.TapGenerator(len(tests))

    headers_dir = pathlib.Path(__file__).absolute().parents[0] / "lttngctl"
    sys.path.insert(0, str(headers_dir))
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
        client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
        session = client.create_session()
        channel_obj = session.add_channel(lttngtest.TracingDomain.User)
        try:
            for test in tests:
                tap.diagnostic("Running test `{}`".format(test.__name__))
                test(session.name, channel_obj.name, tap, test_env)
        finally:
            del os.environ["LTTNG_RUNDIR"]

    sys.exit(0 if tap.is_successful else 1)
