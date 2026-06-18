#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Philippe Proulx <pproulx@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#

"""
Test the human-readable output
of `lttng list SESSION --map-channel=CHANNEL`.

The `--map-channel` filter renders the configuration of a single map
channel as a human-readable tree.

This test creates user space map channels with explicit attributes and
asserts that the emitted strings reflect the configured value type,
update policy, buffer sharing policy, and dead process policy.
"""

import pathlib
import shlex
import sys

# Import in-tree test utils.
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest
import common


# Returns the human-readable output
# of `lttng list SESSION --map-channel=CHANNEL`.
def _list_map_channel(
    client,  # type: lttngtest.LTTngClient
    session,  # type: lttngtest.Session
    channel,  # type: lttngtest.lttngctl.MapChannel
):
    # type: (...) -> str
    return client._run_cmd(
        "list {} --map-channel={}".format(
            shlex.quote(session.name), shlex.quote(channel.name)
        ),
        lttngtest.LTTngClient.CommandOutputFormat.HUMAN,
    )[0]


def test_per_user(
    test_env,  # type: lttngtest._Environment
    tap,  # type: lttngtest.TapGenerator
    client,  # type: lttngtest.LTTngClient
):
    # type: (...) -> None
    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(
            test_env.create_temporary_directory("map-list")
        )
    )
    channel = session.add_user_map_channel(
        value_type=lttngtest.lttngctl.MapChannelValueType.SignedIntMax,
        max_key_count=64,
        update_policy=lttngtest.lttngctl.MapChannelUpdatePolicy.PerEvent,
        buffer_sharing_policy=lttngtest.lttngctl.BufferSharingPolicy.PerUID,
    )

    out = _list_map_channel(client, session, channel)

    tap.test("Map channel" in out, "per-user output has a map channel header")
    tap.test(channel.name in out, "per-user output includes the channel name")
    tap.test("String" in out, "per-user output reports the String key type")
    tap.test(
        "Widest signed integer" in out,
        "per-user output reports the widest signed integer value type",
    )
    tap.test("Max. key count" in out, "per-user output reports the max. key count")
    tap.test(
        "Per matching event" in out,
        "per-user output reports the per-event update policy",
    )
    tap.test(
        "per Unix user" in out,
        "per-user output reports the per-Unix user buffer configuration",
    )
    tap.test(
        "Dead process policy" not in out,
        "per-user output has no dead process policy line",
    )

    session.destroy()


def test_per_process(
    test_env,  # type: lttngtest._Environment
    tap,  # type: lttngtest.TapGenerator
    client,  # type: lttngtest.LTTngClient
):
    # type: (...) -> None
    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(
            test_env.create_temporary_directory("map-list")
        )
    )
    channel = session.add_user_map_channel(
        value_type=lttngtest.lttngctl.MapChannelValueType.SignedIntMax,
        max_key_count=64,
        update_policy=lttngtest.lttngctl.MapChannelUpdatePolicy.PerRuleMatch,
        buffer_sharing_policy=lttngtest.lttngctl.BufferSharingPolicy.PerPID,
        dead_process_policy=lttngtest.lttngctl.MapChannelDeadProcessPolicy.Drop,
    )

    out = _list_map_channel(client, session, channel)

    tap.test(
        "per process" in out,
        "per-process output reports the per-process buffer configuration",
    )
    tap.test(
        "Per event rule match" in out,
        "per-process output reports the per-rule match update policy",
    )
    tap.test(
        "Dead process policy" in out,
        "per-process output reports a dead process policy line",
    )

    session.destroy()


def test_val_types(
    test_env,  # type: lttngtest._Environment
    tap,  # type: lttngtest.TapGenerator
    client,  # type: lttngtest.LTTngClient
):
    # type: (...) -> None
    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(
            test_env.create_temporary_directory("map-list")
        )
    )
    channel = session.add_user_map_channel(
        value_type=lttngtest.lttngctl.MapChannelValueType.SignedInt32,
        max_key_count=64,
        update_policy=lttngtest.lttngctl.MapChannelUpdatePolicy.PerEvent,
        buffer_sharing_policy=lttngtest.lttngctl.BufferSharingPolicy.PerUID,
    )

    tap.test(
        "32-bit signed integer" in _list_map_channel(client, session, channel),
        "output reports the 32-bit signed integer value type",
    )

    session.destroy()

    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(
            test_env.create_temporary_directory("map-list")
        )
    )
    channel = session.add_user_map_channel(
        value_type=lttngtest.lttngctl.MapChannelValueType.SignedIntMax,
        max_key_count=64,
        update_policy=lttngtest.lttngctl.MapChannelUpdatePolicy.PerEvent,
        buffer_sharing_policy=lttngtest.lttngctl.BufferSharingPolicy.PerUID,
    )

    tap.test(
        "Widest signed integer" in _list_map_channel(client, session, channel),
        "output reports the widest signed integer value type",
    )

    session.destroy()


tap = lttngtest.TapGenerator(13)

with lttngtest.test_environment(
    with_sessiond=True, log=tap.diagnostic, enable_kernel_domain=False
) as test_env:
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    test_per_user(test_env, tap, client)
    test_per_process(test_env, tap, client)
    test_val_types(test_env, tap, client)

sys.exit(0 if tap.is_successful else 1)
