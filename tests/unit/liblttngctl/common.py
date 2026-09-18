#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: Kienan Stewart <kstewart@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#
"""
Common helper functions for liblttng-ctl
"""

import contextlib
import ctypes
import logging
import pathlib
import platform
import sys

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[2] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest

headers_dir = pathlib.Path(__file__).absolute().parents[0] / "lttngctl"

# Imports required for the tests
sys.path.insert(0, str(headers_dir))
import lttng
import defaults as lttng_native_defaults

free = None


def get_liblttngctl_free():
    global free

    if free is None:
        # Normally, ctypes expects the free() from the memory allocator used by a given
        # library to match the allocator that did the initial allocation.
        # From the python side we don't know what allocator was used, so we return the
        # symbol 'free' from the liblttng-ctl CDLL.
        # This way, we don't have to try to guess at which libc was loaded by liblttng-ctl.
        for k, v in lttng._libraries.items():
            if k.startswith("liblttng-ctl."):
                logging.debug("Setting free to {} from {}".format(v.free, v))
                free = v.free
                break

    return free


def get_channel_instance(domain_instance=None):
    if domain_instance is None:
        domain_instance = lttng.struct_lttng_domain()
        domain_instance.type = lttng.LTTNG_DOMAIN_UST
        domain_instance.buf_type = lttng.LTTNG_BUFFER_PER_UID
    return lttng.lttng_channel_create(domain_instance)


def test_enable_channel_create(
    tap,
    test_env,
    enabled: bool = True,
    domain: lttngtest.lttngctl.TracingDomain = lttngtest.lttngctl.TracingDomain.User,
):
    session_name = lttngtest.lttngctl.Session._generate_name()
    channel_name = lttngtest.lttngctl.Channel._generate_name()
    free = get_liblttngctl_free()

    with contextlib.ExitStack() as exit_stack:
        # For i386, armhf
        session_name_buffer = ctypes.create_string_buffer(session_name.encode())
        session_descriptor = lttng.lttng_session_descriptor_create(session_name_buffer)
        assert session_descriptor is not None
        exit_stack.callback(lttng.lttng_session_descriptor_destroy, session_descriptor)

        err = lttng.lttng_create_session_ext(session_descriptor)
        assert err == lttng.LTTNG_OK

        lookup_domain_val = None
        if domain == lttngtest.lttngctl.TracingDomain.User:
            domain_val = lttng.LTTNG_DOMAIN_UST
        elif domain == lttngtest.lttngctl.TracingDomain.Kernel:
            domain_val = lttng.LTTNG_DOMAIN_KERNEL
        elif domain == lttngtest.lttngctl.TracingDomain.Log4j:
            domain_val = lttng.LTTNG_DOMAIN_LOG4J
            channel_name = lttng_native_defaults.DEFAULT_LOG4J_CHANNEL_NAME
            lookup_domain_val = lttng.LTTNG_DOMAIN_UST
        elif domain == lttngtest.lttngctl.TracingDomain.Log4j2:
            domain_val = lttng.LTTNG_DOMAIN_LOG4J2
            channel_name = lttng_native_defaults.DEFAULT_LOG4J2_CHANNEL_NAME
            lookup_domain_val = lttng.LTTNG_DOMAIN_UST
        elif domain == lttngtest.lttngctl.TracingDomain.JUL:
            domain_val = lttng.LTTNG_DOMAIN_JUL
            channel_name = lttng_native_defaults.DEFAULT_JUL_CHANNEL_NAME
            lookup_domain_val = lttng.LTTNG_DOMAIN_UST
        elif domain == lttngtest.lttngctl.TracingDomain.Python:
            domain_val = lttng.LTTNG_DOMAIN_PYTHON
            channel_name = lttng_native_defaults.DEFAULT_PYTHON_CHANNEL_NAME
            lookup_domain_val = lttng.LTTNG_DOMAIN_UST
        else:
            raise Exception("Unhandled domain: {}".format(domain))

        domain_instance = lttng.struct_lttng_domain()
        domain_instance.buf_type = lttng.LTTNG_BUFFER_PER_UID
        domain_instance.type = domain_val
        handle = lttng.lttng_create_handle(
            session_name_buffer,
            ctypes.pointer(domain_instance),
        )
        assert handle is not None
        exit_stack.callback(lttng.lttng_destroy_handle, handle)

        channel_instance = lttng.struct_lttng_channel()
        lttng.lttng_channel_set_default_attr(
            ctypes.pointer(domain_instance), channel_instance.attr
        )

        channel_instance.name = channel_name.encode()
        channel_instance.enabled = 1 if enabled else 0
        err = lttng.lttng_enable_channel(handle, ctypes.pointer(channel_instance))
        assert err == 0, "Channel creation failed: {} (err={})".format(
            (ctypes.cast(lttng.lttng_strerror(-err), ctypes.c_char_p).value).decode(
                "utf-8"
            ),
            err,
        )

        # List the session's channels to confirm their state.
        channels_head = ctypes.cast(
            ctypes.c_void_p(None), ctypes.POINTER(lttng.struct_lttng_channel)
        )

        # Some of the domains lookups use domains that aren't the creation domain.
        if lookup_domain_val is not None and lookup_domain_val != domain_val:
            domain_instance.type = lookup_domain_val
            handle = lttng.lttng_create_handle(
                session_name_buffer,
                ctypes.pointer(domain_instance),
            )
            exit_stack.callback(lttng.lttng_destroy_handle, handle)

        channel_count = lttng.lttng_list_channels(handle, ctypes.pointer(channels_head))
        exit_stack.callback(free, channels_head)

        # We expect only one channel to exist
        assert channel_count == 1
        assert channels_head[0].enabled == (1 if enabled else 0)

    tap.ok(
        "test_enable_channel_create enabled={}, domain={} passed".format(
            enabled, domain
        )
    )
