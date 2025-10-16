#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: Kienan Stewart <kstewart@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#
"""
Common helper functions for liblttng-ctl
"""

import ctypes
import pathlib
import platform
import sys

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[2] / "utils"
sys.path.append(str(test_utils_import_path))

import lttngtest

headers_dir = pathlib.Path(__file__).absolute().parents[0] / "lttngctl"

# Imports required for the tests
sys.path.insert(0, str(headers_dir))
import lttng


def get_channel_instance(domain_instance=None):
    if domain_instance is None:
        domain_instance = lttng.struct_lttng_domain()
        domain_instance.type = lttng.LTTNG_DOMAIN_UST
        domain_instance.buf_type = lttng.LTTNG_BUFFER_PER_UID
    return lttng.lttng_channel_create(domain_instance)
