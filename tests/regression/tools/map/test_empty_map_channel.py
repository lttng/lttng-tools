#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Philippe Proulx <pproulx@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#

"""
A map channel that holds no allocated keys (an empty map).

A map channel allocates a counter key lazily, on the first increment of
that key. Until then the channel exists but carries no keys, and a tool
must still describe it gracefully rather than fail or invent rows.

This test covers two ways a channel ends up empty:

• No trigger at all targets the channel, so nothing ever increments it.

• A trigger targets the channel but its "event rule matches" condition
  never fires (the test runs no application), so no key is allocated.

For each case it asserts, through `lttng export-maps` (see
lttng-export-maps(1)), that:

• The channel itself is present in the `channels` table (an empty map is
  still a map).

• The `keys`, `entries`, and `vmap` relations are empty for that channel
  (no key was allocated, hence no per-key rows).

• Reading any key back yields `None` rather than zero, distinguishing a
  never-allocated key from one allocated and holding zero.

The Linux kernel case (`root` only) repeats the no-trigger shape to
confirm an empty kernel map channel behaves the same way.
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
def _check_empty(
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


def test_no_trigger(
    test_env,  # type: lttngtest._Environment
    tap,  # type: lttngtest.TapGenerator
):
    # type: (...) -> None

    # A map channel that no trigger targets: it can never allocate a key
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session = common._create_recording_session(test_env, client)
    channel = session.add_user_map_channel(channel_name="untouched")
    session.start()

    _check_empty(tap, session, channel.name, "user", "no trigger")

    session.destroy()


def test_trigger_never_fires(
    test_env,  # type: lttngtest._Environment
    tap,  # type: lttngtest.TapGenerator
):
    # type: (...) -> None

    # A map channel with an event-driven trigger, but no application
    # runs, so the condition never fires and no key is ever allocated.
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session = common._create_recording_session(test_env, client)
    channel = session.add_user_map_channel(channel_name="armed-but-idle")
    common.add_user_event_count_trigger(client, session, channel.name)
    session.start()

    _check_empty(tap, session, channel.name, "user", "trigger never fires")

    session.destroy()


def test_kernel_no_trigger(
    test_env,  # type: lttngtest._Environment
    tap,  # type: lttngtest.TapGenerator
):
    # type: (...) -> None
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session = common._create_recording_session(test_env, client)
    channel = session.add_kernel_map_channel(channel_name="untouched-kernel")
    session.start()

    _check_empty(tap, session, channel.name, "kernel", "kernel no trigger")

    session.stop()
    session.destroy()


tap = lttngtest.TapGenerator(9)

with lttngtest.test_environment(
    with_sessiond=True, log=tap.diagnostic, enable_kernel_domain=False
) as test_env:
    test_no_trigger(test_env, tap)
    test_trigger_never_fires(test_env, tap)

# The kernel case needs `root` and the `lttng-test` module; skip its
# three tests otherwise.
common.run_kernel_test(
    tap,
    test_kernel_no_trigger,
    skip_count=3,
    skip_reason="empty kernel map channel requires `root` and the `lttng-test` module",
)

sys.exit(0 if tap.is_successful else 1)
