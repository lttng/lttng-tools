#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Philippe Proulx <pproulx@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#

"""
Shared helpers for the map channel and "increment map value" trigger
action regression tests.
"""

import collections
import os
import pathlib
import sys
from typing import Callable, Dict, List, Optional, Type

# Import in-tree test utils.
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest

# Name of the user space tracepoint that the `gen-ust-events` test
# application emits; only that application emits it, therefore a trigger
# counting it yields a deterministic value.
UST_TRACEPOINT_NAME = "tp:tptest"

# Name of the Linux kernel tracepoint that the `lttng-test` kernel
# module emits, on demand, through fire_kernel_test_events().
KERNEL_TRACEPOINT_NAME = "lttng_test_filter_event"

# Default number of events the test application emits, and therefore the
# expected counter value of a per-event user space map channel.
DEFAULT_EVENT_COUNT = 100

# Default number of manual rotations performed by the rotation-based
# populate helper, and therefore the expected counter value.
DEFAULT_ROTATION_COUNT = 3


# Returns whether or not the current process runs as root.
def is_root():
    # type: () -> bool
    return os.getuid() == 0


# Fixture returned by the populate_*() helpers of this module: a map
# channel created and driven to known counter values, bundled with
# everything a test needs to inspect it and verify its counter.
#
# Attributes:
#
# `client`:
#     The `LTTngClient` that owns the recording session.
#
# `session`:
#     The recording session containing the map channel, which a test
#     reads, rotates, and ultimately destroys.
#
# `channel`:
#     The created `MapChannel` (a `UserMapChannel` or
#     a `KernelMapChannel`).
#
# `channel_type`:
#     The concrete class of `channel`, suitable for filtering
#     with `Session.map_channels()`.
#
# `key`:
#     The single counter key that the trigger incremented.
#
# `expected_val`:
#     The value that `key` is expected to hold.
PopulatedMap = collections.namedtuple(
    "PopulatedMap",
    ["client", "session", "channel", "channel_type", "key", "expected_val"],
)


# Returns the current counter values of the map channels of `session` as
# a (key, value) dictionary, which `lttng export-maps` reads.
#
# When the same key appears in more than one map channel, the returned
# value is the sum of the per-channel counters, which is sufficient for
# the single-channel recording sessions that this module builds.
def read_map_values(
    session,  # type: lttngtest.Session
):
    # type: (...) -> Dict[str, int]
    conn = session.export_maps()

    try:
        return {
            row["key"]: row["value"]
            for row in conn.execute(
                "SELECT key, SUM(value) AS value FROM vmap GROUP BY key"
            )
        }
    finally:
        conn.close()


# Returns the current value of counter `key` of the map channels of
# `session`, or `None` when the key is absent.
#
# Like read_map_values(), the value sums the per-channel counters when
# `key` appears in more than one map channel.
def read_map_value(
    session,  # type: lttngtest.Session
    key,  # type: str
):
    # type: (...) -> Optional[int]
    conn = session.export_maps()

    try:
        # SUM() over no matching row yields `NULL`, so an absent key
        # naturally reads back as `None`.
        return conn.execute(
            "SELECT SUM(value) AS value FROM vmap WHERE key = ?", (key,)
        ).fetchone()["value"]
    finally:
        conn.close()


# Returns every `vmap` row of the map channels of `session` as a list of
# dictionaries (one per row), each carrying the full public schema of
# `lttng export-maps` (see lttng-export-maps(1)): `channel_name`,
# `channel_type`, `group_type`, `owner_id`, `owner_name`, `value_type`,
# `part_id`, `key`, `value`, and `has_overflow`.
#
# Unlike read_map_values(), this performs no aggregation, so that a
# caller can inspect the per-group, per-partition, and metadata
# columns directly.
def read_map_rows(
    session,  # type: lttngtest.Session
):
    # type: (...) -> List[Dict[str, object]]
    conn = session.export_maps()

    try:
        return [dict(row) for row in conn.execute("SELECT * FROM vmap")]
    finally:
        conn.close()


# Sums the `value` of counter `key` across the `vmap` rows of `session`
# whose `group_type` column equals `group_type` (`shared`,
# `user-per-user`, `user-per-process`, `kernel-global`), or returns
# `None` when no such row exists.
#
# A returned `None` therefore distinguishes a vanished or never-created
# map group from one that survives holding zero.
def sum_map_value_in_group_type(
    session,  # type: lttngtest.Session
    group_type,  # type: str
    key,  # type: str
):
    # type: (...) -> Optional[int]
    total = None  # type: Optional[int]

    for row in read_map_rows(session):
        if row["group_type"] == group_type and row["key"] == key:
            total = (total or 0) + int(row["value"])  # type: ignore[arg-type]

    return total


# Create a recording session with a local output.
#
# The returned recording session has _no channel_; callers add a map
# channel. That alone lets the recording session start, and
# therefore rotate.
def _create_recording_session(
    test_env,  # type: lttngtest._Environment
    client,  # type: lttngtest.LTTngClient
):
    # type: (...) -> lttngtest.Session
    return client.create_session(
        output=lttngtest.LocalSessionOutputLocation(
            test_env.create_temporary_directory("map-trace")
        )
    )


# Registers an "increment map value" trigger on `client`: whenever
# `cond` is met, the trigger increments the counter `key` of the map
# channel named `channel_name` (of type `channel_type`) in recording
# session `session`.
#
# `key` is a key template, so it may carry placeholders such as
# `{event_name}` when `cond` is an "event rule matches" condition.
def _add_increment_map_value_trigger(
    client,  # type: lttngtest.LTTngClient
    cond,  # type: lttngtest.lttngctl.Condition
    session,  # type: lttngtest.Session
    channel_name,  # type: str
    channel_type,  # type: Type[lttngtest.lttngctl.MapChannel]
    key,  # type: str
):
    # type: (...) -> None
    client.add_trigger(
        cond,
        [
            lttngtest.lttngctl.IncrementMapValueTriggerAction(
                session_name=session.name,
                channel_name=channel_name,
                channel_type=channel_type,
                key_template=key,
            )
        ],
    )


# Registers an "increment map value" trigger driven by an "event rule
# matches" condition on the user space tracepoint `UST_TRACEPOINT_NAME`,
# incrementing the counter `key` of the user space map channel named
# `channel_name` in recording session `session`.
#
# This helper takes `channel_name` by name (not as a `UserMapChannel`
# object) so that a caller can register the trigger before the channel
# exists, to exercise late binding.
def add_user_event_count_trigger(
    client,  # type: lttngtest.LTTngClient
    session,  # type: lttngtest.Session
    channel_name,  # type: str
    key="count/{event_name}",  # type: str
):
    # type: (...) -> None
    _add_increment_map_value_trigger(
        client,
        lttngtest.lttngctl.EventRuleMatchesCondition(
            lttngtest.lttngctl.UserTracepointEventRule(UST_TRACEPOINT_NAME)
        ),
        session,
        channel_name,
        lttngtest.lttngctl.UserMapChannel,
        key,
    )


# Registers an "increment map value" trigger driven by an "event rule
# matches" condition on the Linux kernel tracepoint
# `KERNEL_TRACEPOINT_NAME`, incrementing the counter `key` of the kernel
# map channel named `channel_name` in recording session `session`.
def add_kernel_event_count_trigger(
    client,  # type: lttngtest.LTTngClient
    session,  # type: lttngtest.Session
    channel_name,  # type: str
    key,  # type: str
):
    # type: (...) -> None
    _add_increment_map_value_trigger(
        client,
        lttngtest.lttngctl.EventRuleMatchesCondition(
            lttngtest.lttngctl.KernelTracepointEventRule(KERNEL_TRACEPOINT_NAME)
        ),
        session,
        channel_name,
        lttngtest.lttngctl.KernelMapChannel,
        key,
    )


# Registers an "increment map value" trigger driven by a "recording
# session rotation finishes" condition, incrementing the literal counter
# `key` of the map channel named `channel_name` (of type `channel_type`)
# in recording session `session`.
#
# Because the condition is not an "event rule matches" condition, `key`
# is a literal counter name rather than a template.
def add_rotation_count_trigger(
    client,  # type: lttngtest.LTTngClient
    session,  # type: lttngtest.Session
    channel_name,  # type: str
    channel_type=lttngtest.lttngctl.UserMapChannel,  # type: Type[lttngtest.lttngctl.MapChannel]
    key="rotations",  # type: str
):
    # type: (...) -> None
    _add_increment_map_value_trigger(
        client,
        lttngtest.lttngctl.SessionRotationCompletedCondition(session.name),
        session,
        channel_name,
        channel_type,
        key,
    )


# Creates a recording session with a user space map channel and an
# "increment map value" trigger driven by an "event rule matches"
# condition, and then runs the user space test application to fire the
# trigger `event_count` times.
#
# The trigger uses the `count/{event_name}` key template, therefore the
# resulting counter key is `count/tp:tptest`. With the default
# (per-event) update policy, its expected integral value
# is `event_count`.
#
# Returns a `PopulatedMap` describing the result. This helper leaves the
# session started so that a caller can read its counters with
# `lttng export-maps`.
def populate_user_map_from_events(
    test_env,  # type: lttngtest._Environment
    tap,  # type: lttngtest.TapGenerator
    client=None,  # type: Optional[lttngtest.LTTngClient]
    val_type=None,  # type: Optional[lttngtest.lttngctl.MapChannelValueType]
    max_key_count=None,  # type: Optional[int]
    update_policy=None,  # type: Optional[lttngtest.lttngctl.MapChannelUpdatePolicy]
    buffer_sharing_policy=None,  # type: Optional[lttngtest.lttngctl.BufferSharingPolicy]
    dead_process_policy=None,  # type: Optional[lttngtest.lttngctl.MapChannelDeadProcessPolicy]
    event_count=DEFAULT_EVENT_COUNT,  # type: int
):
    # type: (...) -> PopulatedMap
    client = client or lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session = _create_recording_session(test_env, client)
    channel = session.add_user_map_channel(
        value_type=val_type,
        max_key_count=max_key_count,
        update_policy=update_policy,
        buffer_sharing_policy=buffer_sharing_policy,
        dead_process_policy=dead_process_policy,
    )

    add_user_event_count_trigger(client, session, channel.name)
    session.start()

    app = test_env.launch_wait_trace_test_application(event_count)
    app.trace()
    app.wait_for_tracing_done()
    app.wait_for_exit()

    return PopulatedMap(
        client,
        session,
        channel,
        lttngtest.lttngctl.UserMapChannel,
        "count/{}".format(UST_TRACEPOINT_NAME),
        event_count,
    )


# Creates a recording session with a map channel of the given type
# (`lttngtest.lttngctl.UserMapChannel` or
# `lttngtest.lttngctl.KernelMapChannel`) and an "increment map value"
# trigger driven by a "recording session rotation finishes" condition,
# then performs `rotation_count` manual rotations to fire the trigger.
#
# Because the condition is not an "event rule matches" condition, the
# trigger uses a literal `key` (not a template). Each rotation
# increments the counter by one, therefore its expected value
# is `rotation_count`.
#
# This helper leaves the recording session started so that a caller can
# read its counters with `lttng export-maps`.
#
# Requires root access for a `KernelMapChannel`.
def populate_map_from_rotations(
    test_env,  # type: lttngtest._Environment
    tap,  # type: lttngtest.TapGenerator
    channel_type,  # type: Type[lttngtest.lttngctl.MapChannel]
    client=None,  # type: Optional[lttngtest.LTTngClient]
    val_type=None,  # type: Optional[lttngtest.lttngctl.MapChannelValueType]
    max_key_count=None,  # type: Optional[int]
    update_policy=None,  # type: Optional[lttngtest.lttngctl.MapChannelUpdatePolicy]
    buffer_sharing_policy=None,  # type: Optional[lttngtest.lttngctl.BufferSharingPolicy]
    dead_process_policy=None,  # type: Optional[lttngtest.lttngctl.MapChannelDeadProcessPolicy]
    rotation_count=DEFAULT_ROTATION_COUNT,  # type: int
    key="rotations",  # type: str
):
    # type: (...) -> PopulatedMap
    client = client or lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session = _create_recording_session(test_env, client)

    if channel_type == lttngtest.lttngctl.KernelMapChannel:
        channel = session.add_kernel_map_channel(
            value_type=val_type,
            max_key_count=max_key_count,
            update_policy=update_policy,
        )
    else:
        channel = session.add_user_map_channel(
            value_type=val_type,
            max_key_count=max_key_count,
            update_policy=update_policy,
            buffer_sharing_policy=buffer_sharing_policy,
            dead_process_policy=dead_process_policy,
        )

    add_rotation_count_trigger(client, session, channel.name, channel_type, key)
    session.start()

    for _ in range(rotation_count):
        session.rotate(wait=True)

    return PopulatedMap(client, session, channel, channel_type, key, rotation_count)


# Default explanation a test reports when it skips a kernel map channel
# case for lack of the kernel testing prerequisites.
KERNEL_SKIP_REASON = (
    "kernel map channel tests require `root` and the `lttng-test` module"
)


# Asks the loaded `lttng-test` kernel module to emit `count`
# `KERNEL_TRACEPOINT_NAME` events by writing to its procfs control file.
#
# Requires the `lttng-test` module to be loaded, which
# run_kernel_test() arranges.
def fire_kernel_test_events(
    count,  # type: int
):
    # type: (...) -> None
    with open("/proc/lttng-test-filter-event", "w") as proc:
        proc.write(str(count))


# Runs
#
#     test_func(test_env, tap)
#
# inside a test environment that has the Linux kernel domain enabled and
# the `lttng-test` kernel module loaded, which together are what a
# kernel map channel test needs.
#
# When the kernel testing prerequisites are missing (see
# `_Environment.run_kernel_tests()`, which needs `root` and an unset
# `LTTNG_TOOLS_DISABLE_KERNEL_TESTS`), `test_func` does not run and this
# helper skips the affected tests instead: the whole remaining plan when
# `skip_count` is `None`, or `skip_count` individual tests otherwise
# (for a plan whose kernel tests are only a part).
def run_kernel_test(
    tap,  # type: lttngtest.TapGenerator
    test_func,  # type: Callable[[lttngtest._Environment, lttngtest.TapGenerator], None]
    skip_count=None,  # type: Optional[int]
    skip_reason=KERNEL_SKIP_REASON,  # type: str
):
    # type: (...) -> None
    if not lttngtest._Environment.run_kernel_tests():
        if skip_count is None:
            tap.skip_all_remaining(skip_reason)
        else:
            tap.skip(skip_reason, skip_count)

        return

    with (
        lttngtest.kernel_module("lttng-test"),
        lttngtest.test_environment(
            with_sessiond=True, log=tap.diagnostic, enable_kernel_domain=True
        ) as test_env,
    ):
        test_func(test_env, tap)
