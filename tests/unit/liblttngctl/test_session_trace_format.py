#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: Kienan Stewart <kstewart@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#
"""
Tests lttngctl trace format functions.
"""

import ctypes
import ctypes.util
import os
import pathlib
import sys

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[2] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest


def test_get_session_trace_format_null_session(tap, test_env):
    trace_format = lttng.lttng_trace_format(lttng.LTTNG_TRACE_FORMAT_DEFAULT)
    ret = lttng.lttng_get_session_trace_format(None, ctypes.pointer(trace_format))
    tap.test(
        ret != lttng.LTTNG_GET_SESSION_TRACE_FORMAT_STATUS_OK,
        "lttng_get_session_trace_format fails with null session, ret={}".format(ret),
    )


def test_get_session_trace_format_null_format(tap, test_env):
    session_descriptor = lttng.lttng_session_descriptor_create(None)
    ret = lttng.lttng_create_session_ext(session_descriptor)
    tap.diagnostic("Session creation, ret={}".format(ret))
    session_list = ctypes.cast(
        ctypes.c_void_p(None), ctypes.POINTER(lttng.struct_lttng_session)
    )
    ret = lttng.lttng_list_sessions(ctypes.pointer(session_list))
    tap.diagnostic("Session list, ret={}".format(ret))
    ret = lttng.lttng_get_session_trace_format(session_list[0], None)
    tap.test(
        ret != lttng.LTTNG_GET_SESSION_TRACE_FORMAT_STATUS_OK,
        "lttng_get_session_trace_format fails with null trace format, ret={}".format(
            ret
        ),
    )
    ret = lttng.lttng_destroy_session(
        ctypes.cast(session_list[0].name, lttng.lttng_destroy_session.argtypes[0])
    )
    tap.diagnostic("Session destroy, ret={}".format(ret))
    free(session_list)


def test_get_session_trace_format_default_format(tap, test_env):
    session_descriptor = lttng.lttng_session_descriptor_create(None)
    trace_format = lttng.lttng_trace_format(lttng.LTTNG_TRACE_FORMAT_DEFAULT)
    ret = lttng.lttng_create_session_ext(session_descriptor)
    tap.diagnostic("Session creation, ret={}".format(ret))
    session_list = ctypes.cast(
        ctypes.c_void_p(None), ctypes.POINTER(lttng.struct_lttng_session)
    )
    ret = lttng.lttng_list_sessions(ctypes.pointer(session_list))
    tap.diagnostic("Session list, ret={}".format(ret))
    ret = lttng.lttng_get_session_trace_format(
        session_list[0], ctypes.pointer(trace_format)
    )
    tap.test(
        ret == lttng.LTTNG_GET_SESSION_TRACE_FORMAT_STATUS_OK,
        "lttng_get_session_trace_format with default format succeeds, ret={}, trace_format={}".format(
            ret, trace_format.value
        ),
    )
    ret = lttng.lttng_destroy_session(
        ctypes.cast(session_list[0].name, lttng.lttng_destroy_session.argtypes[0])
    )
    tap.diagnostic("Session destroy, ret={}".format(ret))
    free(session_list)


def _test_get_session_trace_format(tap, test_env, trace_format):
    session_descriptor = lttng.lttng_session_descriptor_create(None)
    ret = lttng.lttng_session_descriptor_set_trace_format(
        session_descriptor, trace_format
    )
    ret = lttng.lttng_create_session_ext(session_descriptor)
    tap.diagnostic("Session creation, ret={}".format(ret))
    session_list = ctypes.cast(
        ctypes.c_void_p(None), ctypes.POINTER(lttng.struct_lttng_session)
    )
    ret = lttng.lttng_list_sessions(ctypes.pointer(session_list))
    tap.diagnostic("Session list, ret={}".format(ret))
    ret_trace_format = lttng.lttng_trace_format(lttng.LTTNG_TRACE_FORMAT_DEFAULT)
    ret = lttng.lttng_get_session_trace_format(
        session_list[0], ctypes.pointer(ret_trace_format)
    )
    tap.test(
        ret == lttng.LTTNG_GET_SESSION_TRACE_FORMAT_STATUS_OK
        and ret_trace_format.value == trace_format.value,
        "lttng_get_session_trace_format with format {} succeeds, ret={}, trace_format={}".format(
            trace_format.value, ret, ret_trace_format.value
        ),
    )
    ret = lttng.lttng_destroy_session(
        ctypes.cast(session_list[0].name, lttng.lttng_destroy_session.argtypes[0])
    )
    tap.diagnostic("Session destroy, ret={}".format(ret))
    free(session_list)


def test_get_session_trace_format_ctf1_8(tap, test_env):
    trace_format = lttng.lttng_trace_format(lttng.LTTNG_TRACE_FORMAT_CTF_1_8)
    _test_get_session_trace_format(tap, test_env, trace_format)


def test_get_session_trace_format_ctf2(tap, test_env):
    trace_format = lttng.lttng_trace_format(lttng.LTTNG_TRACE_FORMAT_CTF_2)
    _test_get_session_trace_format(tap, test_env, trace_format)


def test_lttng_session_descriptor_set_trace_format_null_descriptor(tap, test_env):
    ret = lttng.lttng_session_descriptor_set_trace_format(
        None, lttng.lttng_trace_format(lttng.LTTNG_TRACE_FORMAT_DEFAULT)
    )
    tap.test(
        ret != lttng.LTTNG_SESSION_DESCRIPTOR_STATUS_OK,
        "lttng_session_descriptor_set_trace_format fails with null descriptor, ret={}".format(
            ret
        ),
    )


def test_lttng_session_descriptor_set_trace_format_invalid_format(tap, test_env):
    session_descriptor = lttng.lttng_session_descriptor_create(None)
    ret = lttng.lttng_session_descriptor_set_trace_format(
        session_descriptor, lttng.lttng_trace_format(-1)
    )
    tap.test(
        ret != lttng.LTTNG_SESSION_DESCRIPTOR_STATUS_OK,
        "lttng_session_descriptor_set_trace_format fails with invalid format, ret={}".format(
            ret
        ),
    )


if __name__ == "__main__":
    tests = [
        test_get_session_trace_format_null_session,
        test_get_session_trace_format_null_format,
        test_get_session_trace_format_default_format,
        test_get_session_trace_format_ctf1_8,
        test_get_session_trace_format_ctf2,
        test_lttng_session_descriptor_set_trace_format_null_descriptor,
        test_lttng_session_descriptor_set_trace_format_invalid_format,
        # test_lttng_session_descriptor_set_trace_format,
    ]
    tap = lttngtest.TapGenerator(len(tests))

    free = ctypes.CDLL(ctypes.util.find_library("libc")).free
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
