#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: Kienan Stewart <kstewart@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#
"""
Test the liblttngctl data stream info interface (stream-info.h)
"""

import ctypes
import os
import pathlib
import struct
import sys

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[2] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest


def get_interpreter_bitness():
    """Return the bitness of the Python interpreter (32 or 64)."""
    return struct.calcsize("P") * 8


# Global variables to track current policies for tests that need them
current_buffer_sharing_policy = None
current_buffer_allocation_policy = None


def get_sets(session_name, channel_name, tap, test_name):
    """
    Get a valid sets object. Returns sets on success, None on failure.
    Caller must call lttng_data_stream_info_sets_destroy(sets) when done.
    """
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
    if ret != lttng.LTTNG_CHANNEL_GET_DATA_STREAM_INFO_SETS_STATUS_OK:
        tap.fail("{}: failed to get sets, ret=`{}`".format(test_name, ret))
        return None
    return sets


def get_set_ptr(session_name, channel_name, tap, test_name):
    """
    Get a valid sets and set_ptr. Returns (sets, set_ptr) on success, (None, None) on failure.
    Caller must call lttng_data_stream_info_sets_destroy(sets) when done.
    """
    sets = get_sets(session_name, channel_name, tap, test_name)
    if sets is None:
        return None, None

    set_ptr = ctypes.cast(
        ctypes.c_void_p(None),
        ctypes.POINTER(lttng.struct_lttng_data_stream_info_set),
    )
    ret = lttng.lttng_data_stream_info_sets_get_at_index(
        sets, 0, ctypes.pointer(set_ptr)
    )
    if ret != lttng.LTTNG_DATA_STREAM_INFO_STATUS_OK:
        lttng.lttng_data_stream_info_sets_destroy(sets)
        tap.fail("{}: failed to get set, ret=`{}`".format(test_name, ret))
        return None, None
    return sets, set_ptr


def get_stream_info(session_name, channel_name, tap, test_name):
    """
    Get valid sets, set_ptr, and stream_info_ptr.
    Returns (sets, set_ptr, stream_info_ptr) on success, (None, None, None) on failure.
    Caller must call lttng_data_stream_info_sets_destroy(sets) when done.
    """
    sets, set_ptr = get_set_ptr(session_name, channel_name, tap, test_name)
    if sets is None:
        return None, None, None

    stream_info_ptr = ctypes.cast(
        ctypes.c_void_p(None),
        ctypes.POINTER(lttng.struct_lttng_data_stream_info),
    )
    ret = lttng.lttng_data_stream_info_set_get_at_index(
        set_ptr, 0, ctypes.pointer(stream_info_ptr)
    )
    if ret != lttng.LTTNG_DATA_STREAM_INFO_STATUS_OK:
        lttng.lttng_data_stream_info_sets_destroy(sets)
        tap.fail("{}: failed to get stream_info, ret=`{}`".format(test_name, ret))
        return None, None, None
    return sets, set_ptr, stream_info_ptr


# Tests for lttng_channel_get_data_stream_info_sets
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
        "lttng_channel_get_data_stream_info_sets fails with no session string",
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
        "lttng_channel_get_data_stream_info_sets fails with no channel string",
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
        "lttng_channel_get_data_stream_info_sets fails with no sets parameter",
    )


def test_channel_get_data_stream_info_sets_no_sessiond(
    session_name, channel_name, tap, test_env
):
    sets = ctypes.cast(
        ctypes.c_void_p(None),
        ctypes.POINTER(lttng.struct_lttng_data_stream_info_sets),
    )
    # Set fake directories to force the connection to fail
    old_rundir = os.environ.get("LTTNG_RUNDIR")
    old_lttng_home = os.environ.get("LTTNG_HOME")
    os.environ["LTTNG_RUNDIR"] = "/fake"
    os.environ["LTTNG_HOME"] = "/fake"
    try:
        ret = lttng.lttng_channel_get_data_stream_info_sets(
            session_name.encode(),
            channel_name.encode(),
            lttng.LTTNG_DOMAIN_UST,
            ctypes.pointer(sets),
        )
    finally:
        if old_rundir is not None:
            os.environ["LTTNG_RUNDIR"] = old_rundir
        else:
            del os.environ["LTTNG_RUNDIR"]
        if old_lttng_home is not None:
            os.environ["LTTNG_HOME"] = old_lttng_home
        else:
            del os.environ["LTTNG_HOME"]

    tap.test(
        ret != lttng.LTTNG_CHANNEL_GET_DATA_STREAM_INFO_SETS_STATUS_OK,
        "lttng_channel_get_data_stream_info_sets fails with no sessiond",
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
        "lttng_channel_get_data_stream_info_sets fails with invalid domain",
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
        "lttng_channel_get_data_stream_info_sets passes: ret=`{}`".format(ret),
    )


# Tests for lttng_data_stream_info_sets_get_count
def test_data_stream_info_sets_get_count_no_sets(
    session_name, channel_name, tap, test_env
):
    count = ctypes.c_uint(0)
    ret = lttng.lttng_data_stream_info_sets_get_count(None, ctypes.pointer(count))
    tap.test(
        ret != lttng.LTTNG_DATA_STREAM_INFO_STATUS_OK,
        "lttng_data_stream_info_sets_get_count rejects NULL sets",
    )


def test_data_stream_info_sets_get_count_no_count(
    session_name, channel_name, tap, test_env
):
    sets = get_sets(session_name, channel_name, tap, "sets_get_count_no_count")
    if sets is None:
        return

    ret = lttng.lttng_data_stream_info_sets_get_count(sets, None)
    lttng.lttng_data_stream_info_sets_destroy(sets)
    tap.test(
        ret != lttng.LTTNG_DATA_STREAM_INFO_STATUS_OK,
        "lttng_data_stream_info_sets_get_count rejects NULL count",
    )


def test_data_stream_info_sets_get_count_valid(
    session_name, channel_name, tap, test_env
):
    sets = get_sets(session_name, channel_name, tap, "sets_get_count_valid")
    if sets is None:
        return

    count = ctypes.c_uint(0)
    ret = lttng.lttng_data_stream_info_sets_get_count(sets, ctypes.pointer(count))
    lttng.lttng_data_stream_info_sets_destroy(sets)
    tap.test(
        ret == lttng.LTTNG_DATA_STREAM_INFO_STATUS_OK and count.value >= 1,
        "lttng_data_stream_info_sets_get_count returns count >= 1: ret=`{}`, count=`{}`".format(
            ret, count.value
        ),
    )


# Tests for lttng_data_stream_info_sets_get_at_index
def test_data_stream_info_sets_get_at_index_no_sets(
    session_name, channel_name, tap, test_env
):
    set_ptr = ctypes.cast(
        ctypes.c_void_p(None),
        ctypes.POINTER(lttng.struct_lttng_data_stream_info_set),
    )
    ret = lttng.lttng_data_stream_info_sets_get_at_index(
        None, 0, ctypes.pointer(set_ptr)
    )
    tap.test(
        ret != lttng.LTTNG_DATA_STREAM_INFO_STATUS_OK,
        "lttng_data_stream_info_sets_get_at_index rejects NULL sets",
    )


def test_data_stream_info_sets_get_at_index_no_set(
    session_name, channel_name, tap, test_env
):
    sets = get_sets(session_name, channel_name, tap, "sets_get_at_index_no_set")
    if sets is None:
        return

    ret = lttng.lttng_data_stream_info_sets_get_at_index(sets, 0, None)
    lttng.lttng_data_stream_info_sets_destroy(sets)
    tap.test(
        ret != lttng.LTTNG_DATA_STREAM_INFO_STATUS_OK,
        "lttng_data_stream_info_sets_get_at_index rejects NULL set output",
    )


def test_data_stream_info_sets_get_at_index_invalid_index(
    session_name, channel_name, tap, test_env
):
    sets = get_sets(session_name, channel_name, tap, "sets_get_at_index_invalid_index")
    if sets is None:
        return

    set_ptr = ctypes.cast(
        ctypes.c_void_p(None),
        ctypes.POINTER(lttng.struct_lttng_data_stream_info_set),
    )
    # Use a very large index that should be invalid
    ret = lttng.lttng_data_stream_info_sets_get_at_index(
        sets, 999999, ctypes.pointer(set_ptr)
    )
    lttng.lttng_data_stream_info_sets_destroy(sets)
    tap.test(
        ret != lttng.LTTNG_DATA_STREAM_INFO_STATUS_OK,
        "lttng_data_stream_info_sets_get_at_index rejects invalid index",
    )


def test_data_stream_info_sets_get_at_index_valid(
    session_name, channel_name, tap, test_env
):
    sets = get_sets(session_name, channel_name, tap, "sets_get_at_index_valid")
    if sets is None:
        return

    set_ptr = ctypes.cast(
        ctypes.c_void_p(None),
        ctypes.POINTER(lttng.struct_lttng_data_stream_info_set),
    )
    ret = lttng.lttng_data_stream_info_sets_get_at_index(
        sets, 0, ctypes.pointer(set_ptr)
    )
    lttng.lttng_data_stream_info_sets_destroy(sets)
    tap.test(
        ret == lttng.LTTNG_DATA_STREAM_INFO_STATUS_OK and bool(set_ptr),
        "lttng_data_stream_info_sets_get_at_index returns valid set: ret=`{}`".format(
            ret
        ),
    )


# Tests for lttng_data_stream_info_sets_destroy
def test_data_stream_info_sets_destroy_null(session_name, channel_name, tap, test_env):
    # Should not crash when passed NULL
    lttng.lttng_data_stream_info_sets_destroy(None)
    tap.test(True, "lttng_data_stream_info_sets_destroy accepts NULL without crash")


# Tests for lttng_data_stream_info_set_get_count
def test_data_stream_info_set_get_count_no_set(
    session_name, channel_name, tap, test_env
):
    count = ctypes.c_uint(0)
    ret = lttng.lttng_data_stream_info_set_get_count(None, ctypes.pointer(count))
    tap.test(
        ret != lttng.LTTNG_DATA_STREAM_INFO_STATUS_OK,
        "lttng_data_stream_info_set_get_count rejects NULL set",
    )


def test_data_stream_info_set_get_count_no_count(
    session_name, channel_name, tap, test_env
):
    sets, set_ptr = get_set_ptr(
        session_name, channel_name, tap, "set_get_count_no_count"
    )
    if sets is None:
        return

    ret = lttng.lttng_data_stream_info_set_get_count(set_ptr, None)
    lttng.lttng_data_stream_info_sets_destroy(sets)
    tap.test(
        ret != lttng.LTTNG_DATA_STREAM_INFO_STATUS_OK,
        "lttng_data_stream_info_set_get_count rejects NULL count",
    )


def test_data_stream_info_set_get_count_valid(
    session_name, channel_name, tap, test_env
):
    sets, set_ptr = get_set_ptr(session_name, channel_name, tap, "set_get_count_valid")
    if sets is None:
        return

    count = ctypes.c_uint(0)
    ret = lttng.lttng_data_stream_info_set_get_count(set_ptr, ctypes.pointer(count))
    lttng.lttng_data_stream_info_sets_destroy(sets)
    tap.test(
        ret == lttng.LTTNG_DATA_STREAM_INFO_STATUS_OK and count.value >= 1,
        "lttng_data_stream_info_set_get_count returns count >= 1: ret=`{}`, count=`{}`".format(
            ret, count.value
        ),
    )


# Tests for lttng_data_stream_info_set_get_at_index
def test_data_stream_info_set_get_at_index_no_set(
    session_name, channel_name, tap, test_env
):
    stream_info_ptr = ctypes.cast(
        ctypes.c_void_p(None),
        ctypes.POINTER(lttng.struct_lttng_data_stream_info),
    )
    ret = lttng.lttng_data_stream_info_set_get_at_index(
        None, 0, ctypes.pointer(stream_info_ptr)
    )
    tap.test(
        ret != lttng.LTTNG_DATA_STREAM_INFO_STATUS_OK,
        "lttng_data_stream_info_set_get_at_index rejects NULL set",
    )


def test_data_stream_info_set_get_at_index_no_stream_info(
    session_name, channel_name, tap, test_env
):
    sets, set_ptr = get_set_ptr(
        session_name, channel_name, tap, "set_get_at_index_no_stream_info"
    )
    if sets is None:
        return

    ret = lttng.lttng_data_stream_info_set_get_at_index(set_ptr, 0, None)
    lttng.lttng_data_stream_info_sets_destroy(sets)
    tap.test(
        ret != lttng.LTTNG_DATA_STREAM_INFO_STATUS_OK,
        "lttng_data_stream_info_set_get_at_index rejects NULL stream_info output",
    )


def test_data_stream_info_set_get_at_index_invalid_index(
    session_name, channel_name, tap, test_env
):
    sets, set_ptr = get_set_ptr(
        session_name, channel_name, tap, "set_get_at_index_invalid_index"
    )
    if sets is None:
        return

    stream_info_ptr = ctypes.cast(
        ctypes.c_void_p(None),
        ctypes.POINTER(lttng.struct_lttng_data_stream_info),
    )
    ret = lttng.lttng_data_stream_info_set_get_at_index(
        set_ptr, 999999, ctypes.pointer(stream_info_ptr)
    )
    lttng.lttng_data_stream_info_sets_destroy(sets)
    tap.test(
        ret != lttng.LTTNG_DATA_STREAM_INFO_STATUS_OK,
        "lttng_data_stream_info_set_get_at_index rejects invalid index",
    )


def test_data_stream_info_set_get_at_index_valid(
    session_name, channel_name, tap, test_env
):
    sets, set_ptr = get_set_ptr(
        session_name, channel_name, tap, "set_get_at_index_valid"
    )
    if sets is None:
        return

    stream_info_ptr = ctypes.cast(
        ctypes.c_void_p(None),
        ctypes.POINTER(lttng.struct_lttng_data_stream_info),
    )
    ret = lttng.lttng_data_stream_info_set_get_at_index(
        set_ptr, 0, ctypes.pointer(stream_info_ptr)
    )
    lttng.lttng_data_stream_info_sets_destroy(sets)
    tap.test(
        ret == lttng.LTTNG_DATA_STREAM_INFO_STATUS_OK and bool(stream_info_ptr),
        "lttng_data_stream_info_set_get_at_index returns valid stream_info: ret=`{}`".format(
            ret
        ),
    )


# Tests for lttng_data_stream_info_set_get_uid
def test_data_stream_info_set_get_uid_no_set(session_name, channel_name, tap, test_env):
    uid = lttng.uid_t(0)
    ret = lttng.lttng_data_stream_info_set_get_uid(None, ctypes.pointer(uid))
    tap.test(
        ret != lttng.LTTNG_DATA_STREAM_INFO_STATUS_OK,
        "lttng_data_stream_info_set_get_uid rejects NULL set",
    )


def test_data_stream_info_set_get_uid_no_uid(session_name, channel_name, tap, test_env):
    sets, set_ptr = get_set_ptr(session_name, channel_name, tap, "set_get_uid_no_uid")
    if sets is None:
        return

    ret = lttng.lttng_data_stream_info_set_get_uid(set_ptr, None)
    lttng.lttng_data_stream_info_sets_destroy(sets)
    tap.test(
        ret != lttng.LTTNG_DATA_STREAM_INFO_STATUS_OK,
        "lttng_data_stream_info_set_get_uid rejects NULL uid",
    )


def test_data_stream_info_set_get_uid_valid(session_name, channel_name, tap, test_env):
    sets, set_ptr = get_set_ptr(session_name, channel_name, tap, "set_get_uid_valid")
    if sets is None:
        return

    uid = lttng.uid_t(0)
    ret = lttng.lttng_data_stream_info_set_get_uid(set_ptr, ctypes.pointer(uid))
    lttng.lttng_data_stream_info_sets_destroy(sets)

    # Enforce expected behavior based on buffer sharing policy
    if current_buffer_sharing_policy == lttngtest.lttngctl.BufferSharingPolicy.PerUID:
        tap.test(
            ret == lttng.LTTNG_DATA_STREAM_INFO_STATUS_OK,
            "lttng_data_stream_info_set_get_uid returns OK for per-UID buffers: ret=`{}`, uid=`{}`".format(
                ret, uid.value
            ),
        )
    else:  # PerPID
        tap.test(
            ret == lttng.LTTNG_DATA_STREAM_INFO_STATUS_NONE,
            "lttng_data_stream_info_set_get_uid returns NONE for per-PID buffers: ret=`{}`".format(
                ret
            ),
        )


# Tests for lttng_data_stream_info_set_get_pid
def test_data_stream_info_set_get_pid_no_set(session_name, channel_name, tap, test_env):
    pid = lttng.pid_t(0)
    ret = lttng.lttng_data_stream_info_set_get_pid(None, ctypes.pointer(pid))
    tap.test(
        ret != lttng.LTTNG_DATA_STREAM_INFO_STATUS_OK,
        "lttng_data_stream_info_set_get_pid rejects NULL set",
    )


def test_data_stream_info_set_get_pid_no_pid(session_name, channel_name, tap, test_env):
    sets, set_ptr = get_set_ptr(session_name, channel_name, tap, "set_get_pid_no_pid")
    if sets is None:
        return

    ret = lttng.lttng_data_stream_info_set_get_pid(set_ptr, None)
    lttng.lttng_data_stream_info_sets_destroy(sets)
    tap.test(
        ret != lttng.LTTNG_DATA_STREAM_INFO_STATUS_OK,
        "lttng_data_stream_info_set_get_pid rejects NULL pid",
    )


def test_data_stream_info_set_get_pid_valid(session_name, channel_name, tap, test_env):
    sets, set_ptr = get_set_ptr(session_name, channel_name, tap, "set_get_pid_valid")
    if sets is None:
        return

    pid = lttng.pid_t(0)
    ret = lttng.lttng_data_stream_info_set_get_pid(set_ptr, ctypes.pointer(pid))
    lttng.lttng_data_stream_info_sets_destroy(sets)

    # Enforce expected behavior based on buffer sharing policy
    if current_buffer_sharing_policy == lttngtest.lttngctl.BufferSharingPolicy.PerPID:
        tap.test(
            ret == lttng.LTTNG_DATA_STREAM_INFO_STATUS_OK,
            "lttng_data_stream_info_set_get_pid returns OK for per-PID buffers: ret=`{}`, pid=`{}`".format(
                ret, pid.value
            ),
        )
    else:  # PerUID
        tap.test(
            ret == lttng.LTTNG_DATA_STREAM_INFO_STATUS_NONE,
            "lttng_data_stream_info_set_get_pid returns NONE for per-UID buffers: ret=`{}`".format(
                ret
            ),
        )


# Tests for lttng_data_stream_info_set_get_app_bitness
def test_data_stream_info_set_get_app_bitness_no_set(
    session_name, channel_name, tap, test_env
):
    bitness = lttng.lttng_app_bitness(0)
    ret = lttng.lttng_data_stream_info_set_get_app_bitness(
        None, ctypes.pointer(bitness)
    )
    tap.test(
        ret != lttng.LTTNG_DATA_STREAM_INFO_STATUS_OK,
        "lttng_data_stream_info_set_get_app_bitness rejects NULL set",
    )


def test_data_stream_info_set_get_app_bitness_no_bitness(
    session_name, channel_name, tap, test_env
):
    sets, set_ptr = get_set_ptr(
        session_name, channel_name, tap, "set_get_app_bitness_no_bitness"
    )
    if sets is None:
        return

    ret = lttng.lttng_data_stream_info_set_get_app_bitness(set_ptr, None)
    lttng.lttng_data_stream_info_sets_destroy(sets)
    tap.test(
        ret != lttng.LTTNG_DATA_STREAM_INFO_STATUS_OK,
        "lttng_data_stream_info_set_get_app_bitness rejects NULL bitness",
    )


def test_data_stream_info_set_get_app_bitness_valid(
    session_name, channel_name, tap, test_env
):
    sets, set_ptr = get_set_ptr(
        session_name, channel_name, tap, "set_get_app_bitness_valid"
    )
    if sets is None:
        return

    bitness = lttng.lttng_app_bitness(0)
    ret = lttng.lttng_data_stream_info_set_get_app_bitness(
        set_ptr, ctypes.pointer(bitness)
    )
    lttng.lttng_data_stream_info_sets_destroy(sets)

    # Both per-UID and per-PID buffers have a bitness set
    # Validate that it matches the interpreter's bitness
    interpreter_bitness = get_interpreter_bitness()
    if interpreter_bitness == 64:
        expected_bitness = lttng.LTTNG_APP_BITNESS_64
    else:
        expected_bitness = lttng.LTTNG_APP_BITNESS_32

    tap.test(
        ret == lttng.LTTNG_DATA_STREAM_INFO_STATUS_OK
        and bitness.value == expected_bitness,
        "lttng_data_stream_info_set_get_app_bitness returns OK with correct bitness: ret=`{}`, bitness=`{}`, expected=`{}` ({}bit)".format(
            ret, bitness.value, expected_bitness, interpreter_bitness
        ),
    )


# Tests for lttng_data_stream_info_get_cpu_id
def test_data_stream_info_get_cpu_id_no_stream_info(
    session_name, channel_name, tap, test_env
):
    cpu_id = ctypes.c_uint(0)
    ret = lttng.lttng_data_stream_info_get_cpu_id(None, ctypes.pointer(cpu_id))
    tap.test(
        ret != lttng.LTTNG_DATA_STREAM_INFO_STATUS_OK,
        "lttng_data_stream_info_get_cpu_id rejects NULL stream_info",
    )


def test_data_stream_info_get_cpu_id_no_cpu_id(
    session_name, channel_name, tap, test_env
):
    sets, _, stream_info_ptr = get_stream_info(
        session_name, channel_name, tap, "get_cpu_id_no_cpu_id"
    )
    if sets is None:
        return

    ret = lttng.lttng_data_stream_info_get_cpu_id(stream_info_ptr, None)
    lttng.lttng_data_stream_info_sets_destroy(sets)
    tap.test(
        ret != lttng.LTTNG_DATA_STREAM_INFO_STATUS_OK,
        "lttng_data_stream_info_get_cpu_id rejects NULL cpu_id",
    )


def test_data_stream_info_get_cpu_id_valid(session_name, channel_name, tap, test_env):
    sets, _, stream_info_ptr = get_stream_info(
        session_name, channel_name, tap, "get_cpu_id_valid"
    )
    if sets is None:
        return

    cpu_id = ctypes.c_uint(0)
    ret = lttng.lttng_data_stream_info_get_cpu_id(
        stream_info_ptr, ctypes.pointer(cpu_id)
    )
    lttng.lttng_data_stream_info_sets_destroy(sets)

    # Enforce expected behavior based on buffer allocation policy
    if (
        current_buffer_allocation_policy
        == lttngtest.lttngctl.BufferAllocationPolicy.PerCPU
    ):
        tap.test(
            ret == lttng.LTTNG_DATA_STREAM_INFO_STATUS_OK,
            "lttng_data_stream_info_get_cpu_id returns OK for per-CPU buffers: ret=`{}`, cpu_id=`{}`".format(
                ret, cpu_id.value
            ),
        )
    else:  # PerChannel
        tap.test(
            ret == lttng.LTTNG_DATA_STREAM_INFO_STATUS_NONE,
            "lttng_data_stream_info_get_cpu_id returns NONE for per-channel buffers: ret=`{}`".format(
                ret
            ),
        )


# Tests for lttng_data_stream_info_get_memory_usage
def test_data_stream_info_get_memory_usage_no_stream_info(
    session_name, channel_name, tap, test_env
):
    value = ctypes.c_uint64(0)
    ret = lttng.lttng_data_stream_info_get_memory_usage(None, ctypes.pointer(value))
    tap.test(
        ret != lttng.LTTNG_DATA_STREAM_INFO_STATUS_OK,
        "lttng_data_stream_info_get_memory_usage rejects NULL stream_info",
    )


def test_data_stream_info_get_memory_usage_no_value(
    session_name, channel_name, tap, test_env
):
    sets, _, stream_info_ptr = get_stream_info(
        session_name, channel_name, tap, "get_memory_usage_no_value"
    )
    if sets is None:
        return

    ret = lttng.lttng_data_stream_info_get_memory_usage(stream_info_ptr, None)
    lttng.lttng_data_stream_info_sets_destroy(sets)
    tap.test(
        ret != lttng.LTTNG_DATA_STREAM_INFO_STATUS_OK,
        "lttng_data_stream_info_get_memory_usage rejects NULL value",
    )


def test_data_stream_info_get_memory_usage_valid(
    session_name, channel_name, tap, test_env
):
    sets, _, stream_info_ptr = get_stream_info(
        session_name, channel_name, tap, "get_memory_usage_valid"
    )
    if sets is None:
        return

    value = ctypes.c_uint64(0)
    ret = lttng.lttng_data_stream_info_get_memory_usage(
        stream_info_ptr, ctypes.pointer(value)
    )
    lttng.lttng_data_stream_info_sets_destroy(sets)
    tap.test(
        ret == lttng.LTTNG_DATA_STREAM_INFO_STATUS_OK,
        "lttng_data_stream_info_get_memory_usage returns OK: ret=`{}`, value=`{}`".format(
            ret, value.value
        ),
    )


# Tests for lttng_data_stream_info_get_max_memory_usage
def test_data_stream_info_get_max_memory_usage_no_stream_info(
    session_name, channel_name, tap, test_env
):
    value = ctypes.c_uint64(0)
    ret = lttng.lttng_data_stream_info_get_max_memory_usage(None, ctypes.pointer(value))
    tap.test(
        ret != lttng.LTTNG_DATA_STREAM_INFO_STATUS_OK,
        "lttng_data_stream_info_get_max_memory_usage rejects NULL stream_info",
    )


def test_data_stream_info_get_max_memory_usage_no_value(
    session_name, channel_name, tap, test_env
):
    sets, _, stream_info_ptr = get_stream_info(
        session_name, channel_name, tap, "get_max_memory_usage_no_value"
    )
    if sets is None:
        return

    ret = lttng.lttng_data_stream_info_get_max_memory_usage(stream_info_ptr, None)
    lttng.lttng_data_stream_info_sets_destroy(sets)
    tap.test(
        ret != lttng.LTTNG_DATA_STREAM_INFO_STATUS_OK,
        "lttng_data_stream_info_get_max_memory_usage rejects NULL value",
    )


def test_data_stream_info_get_max_memory_usage_valid(
    session_name, channel_name, tap, test_env
):
    sets, _, stream_info_ptr = get_stream_info(
        session_name, channel_name, tap, "get_max_memory_usage_valid"
    )
    if sets is None:
        return

    value = ctypes.c_uint64(0)
    ret = lttng.lttng_data_stream_info_get_max_memory_usage(
        stream_info_ptr, ctypes.pointer(value)
    )
    lttng.lttng_data_stream_info_sets_destroy(sets)
    tap.test(
        ret == lttng.LTTNG_DATA_STREAM_INFO_STATUS_OK,
        "lttng_data_stream_info_get_max_memory_usage returns OK: ret=`{}`, value=`{}`".format(
            ret, value.value
        ),
    )


if __name__ == "__main__":
    tests = [
        # lttng_channel_get_data_stream_info_sets tests
        test_channel_get_data_stream_info_sets_no_session_string,
        test_channel_get_data_stream_info_sets_no_channel_string,
        test_channel_get_data_stream_info_sets_no_sets,
        test_channel_get_data_stream_info_sets_no_sessiond,
        test_channel_get_data_stream_info_sets_invalid_domain_value,
        test_channel_get_data_stream_info_sets_with_sessiond,
        # lttng_data_stream_info_sets_get_count tests
        test_data_stream_info_sets_get_count_no_sets,
        test_data_stream_info_sets_get_count_no_count,
        test_data_stream_info_sets_get_count_valid,
        # lttng_data_stream_info_sets_get_at_index tests
        test_data_stream_info_sets_get_at_index_no_sets,
        test_data_stream_info_sets_get_at_index_no_set,
        test_data_stream_info_sets_get_at_index_invalid_index,
        test_data_stream_info_sets_get_at_index_valid,
        # lttng_data_stream_info_sets_destroy tests
        test_data_stream_info_sets_destroy_null,
        # lttng_data_stream_info_set_get_count tests
        test_data_stream_info_set_get_count_no_set,
        test_data_stream_info_set_get_count_no_count,
        test_data_stream_info_set_get_count_valid,
        # lttng_data_stream_info_set_get_at_index tests
        test_data_stream_info_set_get_at_index_no_set,
        test_data_stream_info_set_get_at_index_no_stream_info,
        test_data_stream_info_set_get_at_index_invalid_index,
        test_data_stream_info_set_get_at_index_valid,
        # lttng_data_stream_info_set_get_uid tests
        test_data_stream_info_set_get_uid_no_set,
        test_data_stream_info_set_get_uid_no_uid,
        test_data_stream_info_set_get_uid_valid,
        # lttng_data_stream_info_set_get_pid tests
        test_data_stream_info_set_get_pid_no_set,
        test_data_stream_info_set_get_pid_no_pid,
        test_data_stream_info_set_get_pid_valid,
        # lttng_data_stream_info_set_get_app_bitness tests
        test_data_stream_info_set_get_app_bitness_no_set,
        test_data_stream_info_set_get_app_bitness_no_bitness,
        test_data_stream_info_set_get_app_bitness_valid,
        # lttng_data_stream_info_get_cpu_id tests
        test_data_stream_info_get_cpu_id_no_stream_info,
        test_data_stream_info_get_cpu_id_no_cpu_id,
        test_data_stream_info_get_cpu_id_valid,
        # lttng_data_stream_info_get_memory_usage tests
        test_data_stream_info_get_memory_usage_no_stream_info,
        test_data_stream_info_get_memory_usage_no_value,
        test_data_stream_info_get_memory_usage_valid,
        # lttng_data_stream_info_get_max_memory_usage tests
        test_data_stream_info_get_max_memory_usage_no_stream_info,
        test_data_stream_info_get_max_memory_usage_no_value,
        test_data_stream_info_get_max_memory_usage_valid,
    ]

    # Run tests with all combinations of buffer sharing and allocation policies
    buffer_sharing_policies = [
        lttngtest.lttngctl.BufferSharingPolicy.PerUID,
        lttngtest.lttngctl.BufferSharingPolicy.PerPID,
    ]
    buffer_allocation_policies = [
        lttngtest.lttngctl.BufferAllocationPolicy.PerCPU,
        lttngtest.lttngctl.BufferAllocationPolicy.PerChannel,
    ]

    # Total tests = tests * sharing policies * allocation policies
    tap = lttngtest.TapGenerator(
        len(tests) * len(buffer_sharing_policies) * len(buffer_allocation_policies)
    )

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

        try:
            for buffer_sharing_policy in buffer_sharing_policies:
                for buffer_allocation_policy in buffer_allocation_policies:
                    current_buffer_sharing_policy = buffer_sharing_policy
                    current_buffer_allocation_policy = buffer_allocation_policy
                    tap.diagnostic(
                        "=== Running tests with {}, {} ===".format(
                            buffer_sharing_policy.value, buffer_allocation_policy.value
                        )
                    )

                    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
                    session = client.create_session()
                    channel_obj = session.add_channel(
                        lttngtest.TracingDomain.User,
                        buffer_sharing_policy=buffer_sharing_policy,
                        buffer_allocation_policy=buffer_allocation_policy,
                    )
                    session.start()

                    # Launch an app to force the allocation of streams. The app
                    # will wait until we tell it to exit so that per-PID buffers
                    # remain allocated during the test.
                    app = test_env.launch_wait_trace_test_application(
                        1000, wait_before_exit=True
                    )
                    app.trace()
                    app.wait_for_tracing_done()

                    for test in tests:
                        tap.diagnostic("Running test `{}`".format(test.__name__))
                        test(session.name, channel_obj.name, tap, test_env)

                    app.touch_exit_file()
                    app.wait_for_exit()
                    session.stop()
                    session.destroy()
        finally:
            del os.environ["LTTNG_RUNDIR"]

    sys.exit(0 if tap.is_successful else 1)
