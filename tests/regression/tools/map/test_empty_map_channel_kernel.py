#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Philippe Proulx <pproulx@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#

"""
A Linux kernel map channel that holds no allocated keys (an empty map).

This is the kernel counterpart of test_empty_map_channel_ust.py: it
repeats the no-trigger shape on a kernel map channel to confirm an empty
kernel map channel is described the same way as an empty user space one.

A map channel allocates a counter key lazily, on the first increment of
that key. With no trigger targeting the channel, nothing ever increments
it, so it must appear in the `channels` table while its `keys`,
`entries`, and `vmap` relations stay empty, and reading any key back
yields `None` rather than zero (see lttng-export-maps(1)).

The kernel case needs `root` and the `lttng-test` module
(see _Environment.run_kernel_tests()).
"""

import pathlib
import sys

# Import in-tree test utils.
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest
import common

from empty_map_channel_utils import check_empty


def test_kernel_no_trigger(
    test_env,  # type: lttngtest._Environment
    tap,  # type: lttngtest.TapGenerator
):
    # type: (...) -> None
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session = common._create_recording_session(test_env, client)
    channel = session.add_kernel_map_channel(channel_name="untouched-kernel")
    session.start()

    check_empty(tap, session, channel.name, "kernel", "kernel no trigger")

    session.stop()
    session.destroy()


tap = lttngtest.TapGenerator(3)

# The kernel case needs `root` and the `lttng-test` module; skip its
# three tests otherwise.
common.run_kernel_test(
    tap,
    test_kernel_no_trigger,
    skip_reason="empty kernel map channel requires `root` and the `lttng-test` module",
)

sys.exit(0 if tap.is_successful else 1)
