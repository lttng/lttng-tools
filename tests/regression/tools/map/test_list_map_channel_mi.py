#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Philippe Proulx <pproulx@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#

"""
Test the machine interface (MI) output of `lttng list SESSION` for user
space map channels.

Create a single recording session with two user space map channels (one
per-user, one per-process with a "sum into shared" dead process policy),
and then drive `lttng --mi=xml list SESSION` and assert the text of the
`<map_channels>/<map_channel>` subtree elements against the contract.

The _run_cmd() method of the client automatically validates the MI
output against the LTTng MI XSD; this test additionally asserts the
value of specific child elements.
"""

import pathlib
import sys
import xml.etree.ElementTree as xml
from typing import Dict, Optional

# Import in-tree test utils.
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest
import common


# Builds and returns a (channel name, `<map_channel>` MI element)
# dictionary from the `<map_channels>` elements of every `<domain>` of
# the session.
def _map_channels_by_name(
    client,  # type: lttngtest.LTTngClient
    session_name,  # type: str
):
    # type: (...) -> Dict[str, xml.Element]
    session_elem = client.list_session_raw(session_name)
    map_channel_elems = []

    for domain_elem in lttngtest.LTTngClient._mi_get_in_element(
        session_elem, "domains"
    ):
        mc = lttngtest.LTTngClient._mi_find_in_element(domain_elem, "map_channels")

        if mc is not None:
            map_channel_elems.extend(list(mc))

    result = {}  # type: Dict[str, xml.Element]

    for e in map_channel_elems:
        name = lttngtest.LTTngClient._mi_get_in_element(e, "name").text
        assert name is not None
        result[name] = e

    return result


# Assert that the `child_name` child element of `channel_elem` is
# present and has the text `expected`.
def _check_child_text(
    tap,  # type: lttngtest.TapGenerator
    channel_elem,  # type: Optional[xml.Element]
    child_name,  # type: str
    expected,  # type: str
    description,  # type: str
):
    # type: (...) -> None
    if channel_elem is None:
        tap.test(False, "{} (map channel element is missing)".format(description))
        return

    child = lttngtest.LTTngClient._mi_find_in_element(channel_elem, child_name)

    if child is None:
        tap.test(
            False,
            "{} (`{}` element is missing)".format(description, child_name),
        )
        return

    tap.test(
        child.text == expected,
        "{} (got `{}`, expected `{}`)".format(description, child.text, expected),
    )


def test_list_map_channel_mi(
    test_env,  # type: lttngtest._Environment
    tap,  # type: lttngtest.TapGenerator
):
    # type: (...) -> None
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(
            test_env.create_temporary_directory("map-list-mi")
        )
    )

    channel_per_user = session.add_user_map_channel(
        value_type=lttngtest.lttngctl.MapChannelValueType.SignedInt32,
        max_key_count=10,
        update_policy=lttngtest.lttngctl.MapChannelUpdatePolicy.PerEvent,
        buffer_sharing_policy=lttngtest.lttngctl.BufferSharingPolicy.PerUID,
    )
    channel_per_process = session.add_user_map_channel(
        value_type=lttngtest.lttngctl.MapChannelValueType.SignedIntMax,
        max_key_count=20,
        update_policy=lttngtest.lttngctl.MapChannelUpdatePolicy.PerRuleMatch,
        buffer_sharing_policy=lttngtest.lttngctl.BufferSharingPolicy.PerPID,
        dead_process_policy=lttngtest.lttngctl.MapChannelDeadProcessPolicy.SumIntoShared,
    )

    by_name = _map_channels_by_name(client, session.name)

    # Per-UID channel.
    uid_elem = by_name.get(channel_per_user.name)
    tap.test(uid_elem is not None, "per-user map channel is listed in the MI output")
    _check_child_text(
        tap, uid_elem, "enabled", "true", "per-user map channel is enabled"
    )
    _check_child_text(
        tap,
        uid_elem,
        "value_type",
        "signed-int-32",
        "per-user map channel value type",
    )
    _check_child_text(
        tap,
        uid_elem,
        "max_key_count",
        "10",
        "per-user map channel max key count",
    )
    _check_child_text(
        tap,
        uid_elem,
        "update_policy",
        "per-event",
        "per-user map channel update policy",
    )
    _check_child_text(
        tap,
        uid_elem,
        "buffer_ownership",
        "per-uid",
        "per-user map channel buffer ownership",
    )

    if uid_elem is not None:
        dead_group_policy = lttngtest.LTTngClient._mi_find_in_element(
            uid_elem, "dead_group_policy"
        )
        tap.test(
            dead_group_policy is None,
            "per-user map channel has no dead group policy",
        )
    else:
        tap.test(
            False,
            "per-user map channel has no dead group policy (map channel element is missing)",
        )

    # Per-PID channel.
    pid_elem = by_name.get(channel_per_process.name)
    tap.test(pid_elem is not None, "per-process map channel is listed in the MI output")
    _check_child_text(
        tap,
        pid_elem,
        "value_type",
        "signed-int-max",
        "per-process map channel value type",
    )
    _check_child_text(
        tap,
        pid_elem,
        "max_key_count",
        "20",
        "per-process map channel max key count",
    )
    _check_child_text(
        tap,
        pid_elem,
        "update_policy",
        "per-rule-match",
        "per-process map channel update policy",
    )
    _check_child_text(
        tap,
        pid_elem,
        "buffer_ownership",
        "per-pid",
        "per-process map channel buffer ownership",
    )
    _check_child_text(
        tap,
        pid_elem,
        "dead_group_policy",
        "sum-into-shared",
        "per-process map channel dead group policy",
    )

    session.destroy()


tap = lttngtest.TapGenerator(13)

with lttngtest.test_environment(
    with_sessiond=True, log=tap.diagnostic, enable_kernel_domain=False
) as test_env:
    test_list_map_channel_mi(test_env, tap)

sys.exit(0 if tap.is_successful else 1)
