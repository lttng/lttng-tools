#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Philippe Proulx <pproulx@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#

"""
`lttng clear` on a recording session must reset the counter values of
its map channels to zero while preserving the keys: a cleared counter is
still listed, but now holding zero.

A map channel clears its counters through two distinct paths: it resets
the channel-wide shared map group wholesale, while it clears the
tracer-backed (per-user/per-process) map groups one element at a time.
test_clear_shared_and_tracer_counters() drives a counter into each path
so that it exercises `clear` on both.
"""

import pathlib
import sys

# Import in-tree test utils.
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest
import common


def test_clear_preserves_keys(
    test_env,  # type: lttngtest._Environment
    tap,  # type: lttngtest.TapGenerator
):
    # type: (...) -> None
    populated = common.populate_user_map_from_events(test_env, tap)
    session = populated.session
    key = populated.key

    tap.test(
        common.read_map_value(session, key) == populated.expected_val,
        "counter `{}` is {} before clear".format(key, populated.expected_val),
    )

    session.clear()
    vals_after = common.read_map_values(session)

    tap.test(
        key in vals_after,
        "key `{}` is still listed after clear".format(key),
    )
    tap.test(
        vals_after.get(key) == 0,
        "counter `{}` is reset to 0 after clear (got {})".format(
            key, vals_after.get(key)
        ),
    )

    session.destroy()


def test_clear_shared_and_tracer_counters(
    test_env,  # type: lttngtest._Environment
    tap,  # type: lttngtest.TapGenerator
):
    # type: (...) -> None

    # Build a single channel holding two counters that clear through
    # different paths:
    #
    # • An event-driven counter, `count/tp:tptest`, lives in a
    #   tracer-backed per-user group (cleared element by element).
    #
    # • A rotation-driven counter, `rotations`, lives in the
    #   channel-wide shared group (reset wholesale).
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session = common._create_recording_session(test_env, client)
    channel = session.add_user_map_channel(
        buffer_sharing_policy=lttngtest.lttngctl.BufferSharingPolicy.PerUID,
    )

    event_key = "count/{}".format(common.UST_TRACEPOINT_NAME)
    shared_key = "rotations"

    common.add_user_event_count_trigger(client, session, channel.name)
    common.add_rotation_count_trigger(client, session, channel.name, key=shared_key)
    session.start()

    app = test_env.launch_wait_trace_test_application(common.DEFAULT_EVENT_COUNT)
    app.trace()
    app.wait_for_tracing_done()
    app.wait_for_exit()

    for _ in range(common.DEFAULT_ROTATION_COUNT):
        session.rotate(wait=True)

    # Each trigger populates its counter, in the expected group,
    # before clear.
    tap.test(
        common.sum_map_value_in_group_type(session, "user-per-user", event_key)
        == common.DEFAULT_EVENT_COUNT,
        "event-driven counter `{}` is {} in the per-user group before clear".format(
            event_key, common.DEFAULT_EVENT_COUNT
        ),
    )
    tap.test(
        common.sum_map_value_in_group_type(session, "shared", shared_key)
        == common.DEFAULT_ROTATION_COUNT,
        "rotation-driven counter `{}` is {} in the shared group before clear".format(
            shared_key, common.DEFAULT_ROTATION_COUNT
        ),
    )

    session.clear()

    # Both keys remain listed, now holding zero, in their groups
    tap.test(
        common.sum_map_value_in_group_type(session, "user-per-user", event_key) == 0,
        "tracer-backed counter `{}` is reset to 0 after clear (got {})".format(
            event_key,
            common.sum_map_value_in_group_type(session, "user-per-user", event_key),
        ),
    )
    tap.test(
        common.sum_map_value_in_group_type(session, "shared", shared_key) == 0,
        "shared counter `{}` is reset to 0 after clear (got {})".format(
            shared_key,
            common.sum_map_value_in_group_type(session, "shared", shared_key),
        ),
    )

    session.destroy()


tap = lttngtest.TapGenerator(7)

with lttngtest.test_environment(
    with_sessiond=True, log=tap.diagnostic, enable_kernel_domain=False
) as test_env:
    test_clear_preserves_keys(test_env, tap)
    test_clear_shared_and_tracer_counters(test_env, tap)

sys.exit(0 if tap.is_successful else 1)
