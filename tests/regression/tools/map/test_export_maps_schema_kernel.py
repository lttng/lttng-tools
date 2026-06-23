#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Philippe Proulx <pproulx@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#

"""
Public SQL schema of `lttng export-maps` (see lttng-export-maps(1)),
Linux kernel case.

This is the kernel counterpart of test_export_maps_schema_ust.py. It
covers the one owner shape that only a kernel channel produces: a
`kernel-global` group, whose counters are ownerless and system-wide.

A kernel map channel of an explicit value type is driven through the
`lttng-test` module (an "increment map value" trigger on
`lttng_test_filter_event`, then a write to /proc/lttng-test-filter-event)
and read back with `export-maps`; the `kernel-global` rows must be
ownerless, carry the kernel channel type, and sum to the event count
across partitions.

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

from export_maps_schema_utils import VAL_TYPE, select, sum_values

# Kernel counter driving.
KERNEL_EVENT_COUNT = 10
KERNEL_KEY = "kernel-events"


def test_kernel_global(
    test_env,  # type: lttngtest._Environment
    tap,  # type: lttngtest.TapGenerator
):
    # type: (...) -> None
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session = common._create_recording_session(test_env, client)
    channel = session.add_kernel_map_channel(value_type=VAL_TYPE)

    common.add_kernel_event_count_trigger(client, session, channel.name, KERNEL_KEY)
    session.start()
    common.fire_kernel_test_events(KERNEL_EVENT_COUNT)

    rows = common.read_map_rows(session)
    kernel = select(rows, group_type="kernel-global", key=KERNEL_KEY)

    tap.test(
        len(kernel) > 0
        and all(row["channel_type"] == "kernel" for row in kernel)
        and all(row["owner_id"] is None for row in kernel)
        and all(row["owner_name"] is None for row in kernel)
        and all(
            row["value_type"] in ("signed-int-32", "signed-int-64") for row in kernel
        )
        and all(row["has_overflow"] == 0 for row in kernel),
        "the kernel map group rows are ownerless with a kernel map channel type",
    )
    tap.test(
        sum_values(kernel) == KERNEL_EVENT_COUNT,
        "the kernel counter sums to {} across partitions (got {})".format(
            KERNEL_EVENT_COUNT, sum_values(kernel)
        ),
    )

    session.stop()
    session.destroy()


tap = lttngtest.TapGenerator(2)

# The kernel rows need `root` access and the `lttng-test` module,
# therefore run their two tests only when the kernel prerequisites
# are met.
common.run_kernel_test(
    tap,
    test_kernel_global,
    skip_reason="kernel rows require `root` and the `lttng-test` module",
)

sys.exit(0 if tap.is_successful else 1)
