#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Philippe Proulx <pproulx@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#

"""
Shared helper for the empty map channel tests
(test_empty_map_channel_ust.py and test_empty_map_channel_kernel.py).
"""

import pathlib
import sys

# Import in-tree test utils.
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest
import common


# Asserts that the map channel named `channel_name` of `session` is
# present but empty: it appears in `channels`, yet no key, entry, or
# `vmap` row exists, and reading an arbitrary key yields `None`.
def check_empty(
    tap,  # type: lttngtest.TapGenerator
    session,  # type: lttngtest.Session
    channel_name,  # type: str
    channel_type,  # type: str
    label,  # type: str
):
    # type: (...) -> None
    conn = session.export_maps()

    try:
        channel_rows = [
            dict(row)
            for row in conn.execute(
                "SELECT name, type FROM channels WHERE name = ?", (channel_name,)
            )
        ]
        key_count = conn.execute("SELECT COUNT(*) AS c FROM keys").fetchone()["c"]
        entry_count = conn.execute("SELECT COUNT(*) AS c FROM entries").fetchone()["c"]
        vmap_count = conn.execute("SELECT COUNT(*) AS c FROM vmap").fetchone()["c"]
    finally:
        conn.close()

    tap.test(
        len(channel_rows) == 1 and channel_rows[0]["type"] == channel_type,
        "{}: the empty map channel `{}` is present with type `{}`".format(
            label, channel_name, channel_type
        ),
    )
    tap.test(
        key_count == 0 and entry_count == 0 and vmap_count == 0,
        "{}: no key, entry, or `vmap` row exists (got {}, {}, {})".format(
            label, key_count, entry_count, vmap_count
        ),
    )
    tap.test(
        common.read_map_value(session, "count/{}".format(common.UST_TRACEPOINT_NAME))
        is None,
        "{}: reading an unallocated key yields `None`".format(label),
    )
