#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Philippe Proulx <pproulx@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#

"""
Public SQL schema of `lttng export-maps` (see lttng-export-maps(1)),
user space cases.

The other map tests read counters through the `vmap` convenience view
but only ever project its `key` and `value` columns.

This test instead asserts the _whole_ documented schema: every `vmap`
column (`channel_name`, `channel_type`, `group_type`, `owner_id`,
`owner_name`, `value_type`, `part_id`, `key`, `value`, `has_overflow`)
and the referential integrity of the four underlying tables (`channels`,
`groups`, `keys`, `entries`).

It covers the two user space owner shapes the schema distinguishes:

• A per-user user space channel, whose counters split between a
  `user-per-user` owner group (Unix user ID) and the channel-wide
  `shared` group (no owner).

• A per-process user space channel, whose counters live in a
  `user-per-process` owner group (process ID).

The Linux kernel case (the ownerless `kernel-global` group) lives in
test_export_maps_schema_kernel.py.

The `sqlite` format quotes names with SQLite string literals (double the
single quote; the backslash is ordinary). To exercise that quoting, the
user space channel and counter names deliberately contain a single quote
and a backslash; a round trip through `sqlite3` that reads the exact
same strings back proves the escaping is correct.
"""

import os
import pathlib
import sqlite3
import sys

# Import in-tree test utils.
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest
import common

from export_maps_schema_utils import VAL_TYPE, VAL_TYPE_SQL, select, sum_values

# A single quote and a backslash live in every user space name below to
# exercise the SQLite string-literal quoting of `export-maps`.
CHANNEL_NAME = "ch'an\\nel"
EVENT_KEY = "ev'ent\\key"
SHARED_KEY = "sha'red\\key"


# Returns the number of rows of `view` whose foreign key columns
# `fk_columns` have no match in `parent`; zero means the references
# are intact.
def _orphan_count(
    conn,  # type: sqlite3.Connection
    view,  # type: str
    fk_column,  # type: str
    parent,  # type: str
):
    # type: (...) -> int
    return conn.execute(
        "SELECT COUNT(*) AS c FROM {view} v "
        "LEFT JOIN {parent} p ON v.{fk} = p.id "
        "WHERE p.id IS NULL".format(view=view, fk=fk_column, parent=parent)
    ).fetchone()["c"]


def test_per_user_and_shared(
    test_env,  # type: lttngtest._Environment
    tap,  # type: lttngtest.TapGenerator
):
    # type: (...) -> None

    # A per-user channel with an event-driven counter (per-user owner
    # map group) and a rotation-driven counter (channel-wide
    # shared group).
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session = common._create_recording_session(test_env, client)
    channel = session.add_user_map_channel(
        channel_name=CHANNEL_NAME,
        value_type=VAL_TYPE,
        buffer_sharing_policy=lttngtest.lttngctl.BufferSharingPolicy.PerUID,
    )

    common.add_user_event_count_trigger(client, session, channel.name, key=EVENT_KEY)
    common.add_rotation_count_trigger(client, session, channel.name, key=SHARED_KEY)
    session.start()

    for _ in range(common.DEFAULT_ROTATION_COUNT):
        session.rotate(wait=True)

    # Pin the application to a single CPU so the whole event count lands
    # on one partition (the sum across partitions is what gets checked,
    # so the specific CPU does not matter).
    app = test_env.launch_wait_trace_test_application(common.DEFAULT_EVENT_COUNT)
    app.taskset_anycpu()
    app.trace()
    app.wait_for_tracing_done()
    app.wait_for_exit()

    # Referential integrity of the four base tables: every entry points
    # at a real group and key, and every group at a real channel.
    #
    # This also confirms the names with quotes and backslashes survived
    # the SQLite quoting (a broken escape would derail the script load
    # and `export_maps()` would have raised).
    conn = session.export_maps()

    try:
        channel_rows = conn.execute("SELECT name, type FROM channels").fetchall()
        orphans = (
            _orphan_count(conn, "entries", "group_id", "groups")
            + _orphan_count(conn, "entries", "key_id", "keys")
            + _orphan_count(conn, "groups", "channel_id", "channels")
        )
        key_names = {
            row["name"] for row in conn.execute("SELECT name FROM keys").fetchall()
        }
    finally:
        conn.close()

    tap.test(
        len(channel_rows) == 1
        and channel_rows[0]["name"] == CHANNEL_NAME
        and channel_rows[0]["type"] == "user",
        "`channels` has the exact (quoted) map channel name with type `user`",
    )
    tap.test(orphans == 0, "every foreign key resolves (no orphan rows)")
    tap.test(
        key_names == {EVENT_KEY, SHARED_KEY},
        "`keys` holds the exact (quoted) counter keys (got {})".format(key_names),
    )

    rows = common.read_map_rows(session)

    # The per-user owner group: the event counter, owned by the current
    # user, broken down per CPU, summing to the event count.
    user_event = select(rows, group_type="user-per-user", key=EVENT_KEY)
    tap.test(
        len(user_event) > 0
        and all(row["channel_name"] == CHANNEL_NAME for row in user_event)
        and all(row["channel_type"] == "user" for row in user_event)
        and all(row["owner_id"] == os.getuid() for row in user_event)
        and all(row["owner_name"] is not None for row in user_event)
        and all(row["value_type"] == VAL_TYPE_SQL for row in user_event)
        and all(isinstance(row["part_id"], int) for row in user_event)
        and all(row["has_overflow"] == 0 for row in user_event),
        "the per-user map group rows carry the full owner/partition/metadata columns",
    )
    tap.test(
        sum_values(user_event) == common.DEFAULT_EVENT_COUNT,
        "the per-user event counter sums to {} across partitions (got {})".format(
            common.DEFAULT_EVENT_COUNT, sum_values(user_event)
        ),
    )

    # The shared group: the rotation counter, ownerless, with no
    # per-partition decomposition (a single NULL `part_id` row).
    #
    # Its `value_type` column is the accumulator width of the daemon,
    # not the configured value type of the map channel (the daemon, not
    # a tracer, owns these counters), therefore the test only checks it
    # against the value domain of the schema rather than
    # against `VAL_TYPE_SQL`.
    shared = select(rows, group_type="shared", key=SHARED_KEY)
    tap.test(
        len(shared) == 1
        and shared[0]["owner_id"] is None
        and shared[0]["owner_name"] is None
        and shared[0]["part_id"] is None
        and shared[0]["value_type"] in ("signed-int-32", "signed-int-64")
        and shared[0]["value"] == common.DEFAULT_ROTATION_COUNT
        and shared[0]["has_overflow"] == 0,
        "the shared map group row is ownerless, partition-less, and holds {}".format(
            common.DEFAULT_ROTATION_COUNT
        ),
    )

    # The key registry is channel-wide: each key also appears in the
    # other map group, holding zero there.
    tap.test(
        sum_values(select(rows, group_type="shared", key=EVENT_KEY)) == 0
        and sum_values(select(rows, group_type="user-per-user", key=SHARED_KEY)) == 0,
        "each key appears in both map groups, holding zero in the map group that didn't increment it",
    )

    session.destroy()


def test_per_process(
    test_env,  # type: lttngtest._Environment
    tap,  # type: lttngtest.TapGenerator
):
    # type: (...) -> None

    # A process ID identifies the owner group of a per-process channel,
    # and that group exists only while the process is alive: keep the
    # application running while reading the counters.
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session = common._create_recording_session(test_env, client)
    channel = session.add_user_map_channel(
        channel_name=CHANNEL_NAME,
        value_type=VAL_TYPE,
        buffer_sharing_policy=lttngtest.lttngctl.BufferSharingPolicy.PerPID,
        dead_process_policy=lttngtest.lttngctl.MapChannelDeadProcessPolicy.Drop,
    )

    common.add_user_event_count_trigger(client, session, channel.name, key=EVENT_KEY)
    session.start()

    app = test_env.launch_wait_trace_test_application(
        common.DEFAULT_EVENT_COUNT, wait_before_exit=True
    )
    app.trace()
    app.wait_for_tracing_done()

    rows = common.read_map_rows(session)
    process = select(rows, group_type="user-per-process", key=EVENT_KEY)

    tap.test(
        len(process) > 0
        and all(row["owner_id"] == app.vpid for row in process)
        and all(row["owner_name"] is not None for row in process),
        "the per-process map group is owned by the application PID {}".format(app.vpid),
    )
    tap.test(
        len(process) > 0
        and all(row["channel_type"] == "user" for row in process)
        and all(row["value_type"] == VAL_TYPE_SQL for row in process)
        and all(row["has_overflow"] == 0 for row in process)
        and sum_values(process) == common.DEFAULT_EVENT_COUNT,
        "the per-process event counter sums to {} (got {})".format(
            common.DEFAULT_EVENT_COUNT, sum_values(process)
        ),
    )

    app.touch_exit_file()
    app.wait_for_exit()
    session.destroy()


tap = lttngtest.TapGenerator(9)

with lttngtest.test_environment(
    with_sessiond=True, log=tap.diagnostic, enable_kernel_domain=False
) as test_env:
    test_per_user_and_shared(test_env, tap)
    test_per_process(test_env, tap)

sys.exit(0 if tap.is_successful else 1)
