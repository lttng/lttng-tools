#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: Kienan Stewart <kstewart@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#
"""
Test the liblttngctl `lttng_reclaim_channel_memory` interface
"""

import ctypes
import os
import pathlib
import sys

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[2] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest


def test_reclaim_channel_memory_no_session_string(
    session_name, channel_name, tap, test_env
):
    handle = ctypes.POINTER(lttng.struct_lttng_reclaim_handle)()
    ret = lttng.lttng_reclaim_channel_memory(
        None,
        ctypes.cast(
            channel_name.encode(), lttng.lttng_reclaim_channel_memory.argtypes[1]
        ),
        lttng.LTTNG_DOMAIN_UST,
        ctypes.c_uint64(0),
        ctypes.pointer(handle),
    )
    tap.test(
        ret != lttng.LTTNG_RECLAIM_CHANNEL_MEMORY_STATUS_OK,
        "lttng_reclaim_channel_memory_status fails with no session string",
    )
    if handle:
        lttng.lttng_reclaim_handle_destroy(handle)


def test_reclaim_channel_memory_no_channel_string(
    session_name, channel_name, tap, test_env
):
    handle = ctypes.POINTER(lttng.struct_lttng_reclaim_handle)()
    ret = lttng.lttng_reclaim_channel_memory(
        ctypes.cast(
            session_name.encode(), lttng.lttng_reclaim_channel_memory.argtypes[0]
        ),
        None,
        lttng.LTTNG_DOMAIN_UST,
        ctypes.c_uint64(0),
        ctypes.pointer(handle),
    )
    tap.test(
        ret != lttng.LTTNG_RECLAIM_CHANNEL_MEMORY_STATUS_OK,
        "lttng_reclaim_channel_memory_status fails with no channel string",
    )
    if handle:
        lttng.lttng_reclaim_handle_destroy(handle)


def test_reclaim_channel_memory_no_handle(session_name, channel_name, tap, test_env):
    session_name_enc = session_name.encode()
    channel_name_enc = channel_name.encode()
    ret = lttng.lttng_reclaim_channel_memory(
        ctypes.cast(session_name_enc, lttng.lttng_reclaim_channel_memory.argtypes[0]),
        ctypes.cast(channel_name_enc, lttng.lttng_reclaim_channel_memory.argtypes[1]),
        lttng.LTTNG_DOMAIN_UST,
        ctypes.c_uint64(0),
        None,
    )
    tap.test(
        ret != lttng.LTTNG_RECLAIM_CHANNEL_MEMORY_STATUS_OK,
        "lttng_reclaim_channel_memory_status fails with no handle parameter",
    )


def test_reclaim_channel_memory_no_sessiond(session_name, channel_name, tap, test_env):
    handle = ctypes.POINTER(lttng.struct_lttng_reclaim_handle)()
    session_name_enc = session_name.encode()
    channel_name_enc = channel_name.encode()
    # Set a fake directory to force the connection to fail
    old_rundir = os.environ["LTTNG_RUNDIR"]
    os.environ["LTTNG_RUNDIR"] = "/fake"
    try:
        ret = lttng.lttng_reclaim_channel_memory(
            ctypes.cast(
                session_name_enc, lttng.lttng_reclaim_channel_memory.argtypes[0]
            ),
            ctypes.cast(
                channel_name_enc, lttng.lttng_reclaim_channel_memory.argtypes[1]
            ),
            lttng.LTTNG_DOMAIN_UST,
            ctypes.c_uint64(0),
            ctypes.pointer(handle),
        )
    finally:
        os.environ["LTTNG_RUNDIR"] = old_rundir

    tap.test(
        ret != lttng.LTTNG_RECLAIM_CHANNEL_MEMORY_STATUS_OK,
        "lttng_reclaim_channel_memory_status fails with no sessiond",
    )
    if handle:
        lttng.lttng_reclaim_handle_destroy(handle)


def test_reclaim_channel_memory_invalid_domain_value(
    session_name, channel_name, tap, test_env
):
    handle = ctypes.POINTER(lttng.struct_lttng_reclaim_handle)()
    session_name_enc = session_name.encode()
    channel_name_enc = channel_name.encode()
    ret = lttng.lttng_reclaim_channel_memory(
        ctypes.cast(session_name_enc, lttng.lttng_reclaim_channel_memory.argtypes[0]),
        ctypes.cast(channel_name_enc, lttng.lttng_reclaim_channel_memory.argtypes[1]),
        lttng.LTTNG_DOMAIN_NR + 1,
        ctypes.c_uint64(0),
        ctypes.pointer(handle),
    )
    tap.test(
        ret != lttng.LTTNG_RECLAIM_CHANNEL_MEMORY_STATUS_OK,
        "lttng_reclaim_channel_memory_status fails with invalid domain",
    )
    if handle:
        lttng.lttng_reclaim_handle_destroy(handle)


def test_reclaim_channel_memory_with_sessiond(
    session_name, channel_name, tap, test_env
):
    handle = ctypes.POINTER(lttng.struct_lttng_reclaim_handle)()
    session_name_enc = session_name.encode()
    channel_name_enc = channel_name.encode()
    ret = lttng.lttng_reclaim_channel_memory(
        ctypes.cast(session_name_enc, lttng.lttng_reclaim_channel_memory.argtypes[0]),
        ctypes.cast(channel_name_enc, lttng.lttng_reclaim_channel_memory.argtypes[1]),
        lttng.LTTNG_DOMAIN_UST,
        ctypes.c_uint64(0),
        ctypes.pointer(handle),
    )

    reclaimed_memory_size_bytes = ctypes.c_uint64(0)
    if ret == lttng.LTTNG_RECLAIM_CHANNEL_MEMORY_STATUS_OK and handle:
        lttng.lttng_reclaim_handle_get_reclaimed_memory_size_bytes(
            handle, ctypes.pointer(reclaimed_memory_size_bytes)
        )
        lttng.lttng_reclaim_handle_destroy(handle)

    tap.test(
        ret == lttng.LTTNG_RECLAIM_CHANNEL_MEMORY_STATUS_OK,
        "lttng_reclaim_channel_memory_status passes: ret=`{}`, reclaimed_memory_size_bytes=`{}`".format(
            ret, reclaimed_memory_size_bytes.value
        ),
    )


if __name__ == "__main__":
    tests = [
        test_reclaim_channel_memory_no_session_string,
        test_reclaim_channel_memory_no_channel_string,
        test_reclaim_channel_memory_no_handle,
        test_reclaim_channel_memory_no_sessiond,
        test_reclaim_channel_memory_invalid_domain_value,
        test_reclaim_channel_memory_with_sessiond,  # simple integration test
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
