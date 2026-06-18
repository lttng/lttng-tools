#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Philippe Proulx <pproulx@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#

"""
Output test of every `lttng show-maps` option.

This test exercises the four option groups that lttng-show-maps(1)
documents: aggregation (--per), selection (--channel, --type, the owner
axis, --part-id/--cpu-id, --key/--key-glob, and --non-init-values),
sorting (--sort-by, --sort-order), and display (--limit).

For each option case, the test verifies _both_ output formats at once:

• Human-readable output: the test asserts it byte for byte against the
  complete, expected literal string (UTF-8 box-drawing borders).

• Machine interface (MI) XML output: the client auto-validates it
  against `mi-lttng-4.2.xsd`, then the test cross-checks it against the
  very same expected human string.

  The test parses both outputs into the same normalized list of tables
  (each carrying its group type, optional CPU, and ordered
  `(key, value, overflow)` rows) and compares them, so the expected
  human literal stays the single source of truth for the data of a case.

To make every case deterministic, including the per-CPU breakdown, the
test builds a single user space map channel and populates it to
known values:

• An event-driven counter `count/tp:tptest` whose value is 100.

  The test pins the traced application to a single CPU (`taskset`) so
  that the whole count lands on one known CPU. This counter belongs to
  the per-user owner group.

• Three rotation-driven counters, `mango` (3), `apple` (2), and
  `zebra` (1).

  The session daemon increments these on each session rotation, so they
  belong to the channel-wide _shared_ group. Distinct values come from
  registering each trigger before a different number of
  remaining rotations.

The key set (`apple`, `count/tp:tptest`, `mango`, `zebra`) and the split
between the per-user and shared groups together cover every selection,
aggregation, sorting, and limiting behaviour. A second, per-process
channel covers the process ID ownership options (--pid, --all-pids).

The expectations are full literal strings; the test substitutes only the
host-dependent scalars (session and channel names, owner ID/name,
effective value type). `LTTNG_TERM_COLOR=never` disables the header
styling escape codes. Every case runs with the default UTF-8 borders; a
single dedicated case checks the ASCII fallback since it only swaps the
box glyphs.
"""

import collections
import enum
import pathlib
import re
import shlex
import sys
import xml.etree.ElementTree as xml
from typing import Dict, List, Tuple

# Import in-tree test utils.
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest
import common

# Normalized table model and parsers.
#
# Both the human and MI outputs carry the same logical data: an ordered
# list of tables, each with a group type, an optional CPU (partition)
# ID, and ordered `(key, value, overflow)` rows.
#
# Parsing both into this common form lets each option case assert the
# human output exactly while cross-checking the MI output against that
# very same expected string.
#
# `group_type` is a `_GroupType`: `CHANNEL` is the folded per-channel
# table, with no single owner context.
#
# `part_id` is the CPU ID of a per-CPU table or `None`.
#
# `rows` is a list of (key, value, has overflow) tuples in
# display order.
_Table = collections.namedtuple("_Table", ["group_type", "part_id", "rows"])


# Normalized map group type shared by the human and MI parsers.
class _GroupType(enum.Enum):
    CHANNEL = "channel"
    USER = "user-per-user"
    PROCESS = "user-per-process"
    SHARED = "shared"
    KERNEL = "kernel"


# MI text of `<type>` of `<map_group>` to normalized group type.
_MI_GROUP_TYPE = {
    "user-per-user": _GroupType.USER,
    "user-per-process": _GroupType.PROCESS,
    "shared": _GroupType.SHARED,
    "kernel-global": _GroupType.KERNEL,
}


# Returns the group type that the channel title `channel_line` implies.
def _human_group_type(
    channel_line,  # type: str
):
    # type: (...) -> _GroupType
    if ", shared counters" in channel_line:
        return _GroupType.SHARED
    elif "user ID" in channel_line:
        return _GroupType.USER
    elif "process ID" in channel_line:
        return _GroupType.PROCESS
    else:
        return _GroupType.CHANNEL


NOTHING_TO_SHOW = "Nothing to show!\n"


# Parses human-readable `show-maps` output into a list of `_Table`.
def _parse_human(
    text,  # type: str
):
    # type: (...) -> List[_Table]
    if text == NOTHING_TO_SHOW:
        return []

    # Each entry is a mutable (channel line, rows) pair
    blocks = []
    expect_channel = False

    for line in text.splitlines():
        if line.startswith("Recording session "):
            blocks.append([None, []])
            expect_channel = True
        elif expect_channel:
            blocks[-1][0] = line
            expect_channel = False
        elif line.startswith("┃"):
            # A header or data row: strip the outer borders, then split
            # on the inner column separator.
            cells = [cell.strip() for cell in line.strip("┃").split("│")]

            if cells[:3] == ["Key", "Value", "Overflow?"]:
                continue

            blocks[-1][1].append((cells[0], int(cells[1]), cells[2] == "✔"))

    tables = []

    for channel_line, rows in blocks:
        cpu = re.search(r", CPU (\d+)", channel_line)
        tables.append(
            _Table(
                _human_group_type(channel_line),
                int(cpu.group(1)) if cpu else None,
                rows,
            )
        )

    return tables


# Required text of an MI element (which is never empty in practice).
def _text(
    element,  # type: xml.Element
):
    # type: (...) -> str
    assert element.text is not None
    return element.text


# The (key, value, has overflow) rows of an MI map table element.
def _mi_rows(
    table_elem,  # type: xml.Element
):
    # type: (...) -> List[Tuple[str, int, bool]]
    rows_elem = lttngtest.LTTngClient._mi_get_in_element(table_elem, "rows")
    rows = []

    for row in lttngtest.LTTngClient._mi_findall_in_element(rows_elem, "row"):
        value = lttngtest.LTTngClient._mi_get_in_element(row, "value")
        rows.append(
            (
                _text(lttngtest.LTTngClient._mi_get_in_element(row, "key")),
                int(_text(value)),
                value.get("has_overflow") == "true",
            )
        )

    return rows


# Normalized group type of a grouped (per-owner/per-partition) MI table.
def _mi_group_type(
    table_elem,  # type: xml.Element
):
    # type: (...) -> _GroupType
    return _MI_GROUP_TYPE[
        _text(
            lttngtest.LTTngClient._mi_get_in_element(
                lttngtest.LTTngClient._mi_get_in_element(table_elem, "map_group"),
                "type",
            )
        )
    ]


# Parse a `<show-maps>` MI element into a list of `_Table`.
def _parse_mi(
    show_maps_elem,  # type: xml.Element
):
    # type: (...) -> List[_Table]
    tables = []

    for table in list(show_maps_elem):
        # Strip the MI namespace from the element tag.
        tag = table.tag.split("}", 1)[-1]

        if tag == "per_channel_map_table":
            tables.append(_Table(_GroupType.CHANNEL, None, _mi_rows(table)))
        elif tag == "per_owner_map_table":
            tables.append(_Table(_mi_group_type(table), None, _mi_rows(table)))
        elif tag == "per_part_map_table":
            part_id = int(
                _text(lttngtest.LTTngClient._mi_get_in_element(table, "part_id"))
            )
            tables.append(_Table(_mi_group_type(table), part_id, _mi_rows(table)))

    return tables


# Client whose locale forces UTF-8 or ASCII borders, with colors off.
def _make_client(
    test_env,  # type: lttngtest._Environment
    tap,  # type: lttngtest.TapGenerator
    with_utf_8=True,  # type: bool
):
    # type: (...) -> lttngtest.LTTngClient
    env_vars = {"LTTNG_TERM_COLOR": "never"}

    if with_utf_8:
        env_vars["LANG"] = "C.UTF-8"
    else:
        env_vars["LTTNG_NO_UTF_8"] = "1"

    return lttngtest.LTTngClient(test_env, log=tap.diagnostic, extra_env_vars=env_vars)


# Returns the single non-shared (per-user or per-process) group.
def _owner_group(
    channel,  # type: lttngtest.lttngctl.UserMapChannel
):
    # type: (...) -> lttngtest.lttngctl.MapGroup
    return next(
        group
        for group in channel.groups()
        if group.type != lttngtest.lttngctl.MapGroupType.Shared
    )


# Counter value width (the number that the human output shows) of an
# effective value type.
_VALUE_TYPE_WIDTH = {
    lttngtest.lttngctl.MapChannelValueType.SignedInt32: 32,
    lttngtest.lttngctl.MapChannelValueType.SignedInt64: 64,
}


# The substitution scalars for the expected-output literals.
def _owner_fmt(
    session,  # type: lttngtest.Session
    channel,  # type: lttngtest.lttngctl.UserMapChannel
):
    # type: (...) -> Dict[str, object]
    owner = _owner_group(channel)

    return {
        "session": session.name,
        "channel": channel.name,
        "owner_id": owner.owner_id,
        "owner_name": owner.owner_name,
        "value_type": _VALUE_TYPE_WIDTH[owner.effective_value_type],
    }


def _add_increment_trigger(
    client,  # type: lttngtest.LTTngClient
    session,  # type: lttngtest.Session
    channel,  # type: lttngtest.lttngctl.UserMapChannel
    key_template,  # type: str
    condition,  # type: lttngtest.lttngctl.TriggerCondition
):
    # type: (...) -> None
    client.add_trigger(
        condition,
        [
            lttngtest.lttngctl.IncrementMapValueTriggerAction(
                session_name=session.name,
                channel_name=channel.name,
                channel_type=lttngtest.lttngctl.UserMapChannel,
                key_template=key_template,
            )
        ],
    )


def _run_human(
    client,  # type: lttngtest.LTTngClient
    session,  # type: lttngtest.Session
    args,  # type: str
):
    # type: (...) -> str
    return client._run_cmd(
        "show-maps --session={} {}".format(shlex.quote(session.name), args),
        lttngtest.LTTngClient.CommandOutputFormat.HUMAN,
    )[0]


def _run_mi_tables(
    client,  # type: lttngtest.LTTngClient
    session,  # type: lttngtest.Session
    args,  # type: str
):
    # type: (...) -> List[_Table]
    return _parse_mi(
        lttngtest.LTTngClient._mi_get_in_element(
            lttngtest.LTTngClient._mi_get_in_element(
                xml.fromstring(
                    client._run_cmd(
                        "show-maps --session={} {}".format(
                            shlex.quote(session.name), args
                        ),
                        lttngtest.LTTngClient.CommandOutputFormat.MI_XML,
                    )[0]
                ),
                "output",
            ),
            "show-maps",
        )
    )


# Asserts that `actual` equals `expected`, dumping both on mismatch.
def _check_equal(
    tap,  # type: lttngtest.TapGenerator
    description,  # type: str
    actual,  # type: object
    expected,  # type: object
):
    # type: (...) -> None
    if actual != expected:
        tap.diagnostic("Expected: " + repr(expected))
        tap.diagnostic("Actual:   " + repr(actual))

    tap.test(actual == expected, description)


# Runs `args` against `session` and verifies both output formats: assert
# the human output byte for byte against `expected`, and check the MI
# output against the tables that _parse_human() derives from that same
# expected string.
def _check_case(
    tap,  # type: lttngtest.TapGenerator
    client,  # type: lttngtest.LTTngClient
    session,  # type: lttngtest.Session
    fmt,  # type: Dict[str, object]
    description,  # type: str
    args,  # type: str
    expected,  # type: str
):
    # type: (...) -> None
    expected_text = expected.format(**fmt)

    _check_equal(
        tap,
        description + " (human)",
        _run_human(client, session, args).strip(),
        expected_text.strip(),
    )

    _check_equal(
        tap,
        description + " (MI)",
        _run_mi_tables(client, session, args),
        _parse_human(expected_text),
    )


# Builds the per-user multi-key fixture and returns (session, channel,
# format), where the format holds the substitution scalars for the
# expected output literals.
def _build_per_uid_fixture(
    test_env,  # type: lttngtest._Environment
    tap,  # type: lttngtest.TapGenerator
):
    # type: (...) -> Tuple[lttngtest.Session, lttngtest.lttngctl.UserMapChannel, Dict[str, object]]
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session = common._create_recording_session(test_env, client)
    channel = session.add_user_map_channel(
        buffer_sharing_policy=lttngtest.lttngctl.BufferSharingPolicy.PerUID
    )

    # Event-driven counter: `count/tp:tptest`, per-user owner
    _add_increment_trigger(
        client,
        session,
        channel,
        "count/{event_name}",
        lttngtest.lttngctl.EventRuleMatchesCondition(
            lttngtest.lttngctl.UserTracepointEventRule(common.UST_TRACEPOINT_NAME)
        ),
    )

    session.start()

    # Rotation-driven counters in the shared group.
    #
    # Registering each trigger before a different number of remaining
    # rotations gives distinct values: `mango` is 3, `apple` is 2,
    # `zebra` is 1.
    rotation = lttngtest.lttngctl.SessionRotationCompletedCondition(session.name)
    _add_increment_trigger(client, session, channel, "mango", rotation)
    session.rotate(wait=True)
    _add_increment_trigger(client, session, channel, "apple", rotation)
    session.rotate(wait=True)
    _add_increment_trigger(client, session, channel, "zebra", rotation)
    session.rotate(wait=True)

    # Drive `count/tp:tptest` to 100; pin the application to a single
    # CPU so the whole count lands on one known CPU (the CPU set may
    # exclude CPU 0, so the pinned CPU is whichever online CPU
    # taskset_anycpu() settles on).
    app = test_env.launch_wait_trace_test_application(common.DEFAULT_EVENT_COUNT)
    cpu = app.taskset_anycpu()
    app.trace()
    app.wait_for_tracing_done()
    app.wait_for_exit()

    fmt = _owner_fmt(session, channel)
    fmt["cpu"] = cpu
    return session, channel, fmt


# `--per=channel` (default): one table folding the per-user and shared
# groups together, sorted by key (the default).
EXPECTED_CHANNEL_DEFAULT = """
Recording session `{session}`:
User space map channel `{channel}`:
┏━━━━━━━━━━━━━━━━━┯━━━━━━━┯━━━━━━━━━━━┓
┃       Key       │ Value │ Overflow? ┃
┣━━━━━━━━━━━━━━━━━┿━━━━━━━┿━━━━━━━━━━━┫
┃ apple           │     2 │           ┃
┃ count/tp:tptest │   100 │           ┃
┃ mango           │     3 │           ┃
┃ zebra           │     1 │           ┃
┗━━━━━━━━━━━━━━━━━┷━━━━━━━┷━━━━━━━━━━━┛
"""


# Same as `EXPECTED_CHANNEL_DEFAULT`, but with the ASCII form.
EXPECTED_CHANNEL_DEFAULT_ASCII = """
Recording session `{session}`:
User space map channel `{channel}`:
+-----------------+-------+-----------+
|       Key       | Value | Overflow? |
+-----------------+-------+-----------+
| apple           |     2 |           |
| count/tp:tptest |   100 |           |
| mango           |     3 |           |
| zebra           |     1 |           |
+-----------------+-------+-----------+
"""

# `--sort-by=value --sort-order=desc`.
EXPECTED_SORT_VALUE_DESC = """
Recording session `{session}`:
User space map channel `{channel}`:
┏━━━━━━━━━━━━━━━━━┯━━━━━━━┯━━━━━━━━━━━┓
┃       Key       │ Value │ Overflow? ┃
┣━━━━━━━━━━━━━━━━━┿━━━━━━━┿━━━━━━━━━━━┫
┃ count/tp:tptest │   100 │           ┃
┃ mango           │     3 │           ┃
┃ apple           │     2 │           ┃
┃ zebra           │     1 │           ┃
┗━━━━━━━━━━━━━━━━━┷━━━━━━━┷━━━━━━━━━━━┛
"""

# `--sort-by=value` (ascending, the default order).
EXPECTED_SORT_VALUE_ASC = """
Recording session `{session}`:
User space map channel `{channel}`:
┏━━━━━━━━━━━━━━━━━┯━━━━━━━┯━━━━━━━━━━━┓
┃       Key       │ Value │ Overflow? ┃
┣━━━━━━━━━━━━━━━━━┿━━━━━━━┿━━━━━━━━━━━┫
┃ zebra           │     1 │           ┃
┃ apple           │     2 │           ┃
┃ mango           │     3 │           ┃
┃ count/tp:tptest │   100 │           ┃
┗━━━━━━━━━━━━━━━━━┷━━━━━━━┷━━━━━━━━━━━┛
"""

# `--sort-order=desc` (by key, the default column).
EXPECTED_SORT_KEY_DESC = """
Recording session `{session}`:
User space map channel `{channel}`:
┏━━━━━━━━━━━━━━━━━┯━━━━━━━┯━━━━━━━━━━━┓
┃       Key       │ Value │ Overflow? ┃
┣━━━━━━━━━━━━━━━━━┿━━━━━━━┿━━━━━━━━━━━┫
┃ zebra           │     1 │           ┃
┃ mango           │     3 │           ┃
┃ count/tp:tptest │   100 │           ┃
┃ apple           │     2 │           ┃
┗━━━━━━━━━━━━━━━━━┷━━━━━━━┷━━━━━━━━━━━┛
"""

# `--sort-by=value --sort-order=desc --limit=2`.
EXPECTED_LIMIT2_VALUE_DESC = """
Recording session `{session}`:
User space map channel `{channel}`:
┏━━━━━━━━━━━━━━━━━┯━━━━━━━┯━━━━━━━━━━━┓
┃       Key       │ Value │ Overflow? ┃
┣━━━━━━━━━━━━━━━━━┿━━━━━━━┿━━━━━━━━━━━┫
┃ count/tp:tptest │   100 │           ┃
┃ mango           │     3 │           ┃
┗━━━━━━━━━━━━━━━━━┷━━━━━━━┷━━━━━━━━━━━┛
"""

# `--limit=1` (default sort: first key, ascending).
#
# Only short keys remain, therefore the key column shrinks to the width
# of its header.
EXPECTED_LIMIT1_DEFAULT = """
Recording session `{session}`:
User space map channel `{channel}`:
┏━━━━━━━┯━━━━━━━┯━━━━━━━━━━━┓
┃  Key  │ Value │ Overflow? ┃
┣━━━━━━━┿━━━━━━━┿━━━━━━━━━━━┫
┃ apple │     2 │           ┃
┗━━━━━━━┷━━━━━━━┷━━━━━━━━━━━┛
"""

# `--key=apple --key=zebra`: exact key whitelist.
EXPECTED_KEY_APPLE_ZEBRA = """
Recording session `{session}`:
User space map channel `{channel}`:
┏━━━━━━━┯━━━━━━━┯━━━━━━━━━━━┓
┃  Key  │ Value │ Overflow? ┃
┣━━━━━━━┿━━━━━━━┿━━━━━━━━━━━┫
┃ apple │     2 │           ┃
┃ zebra │     1 │           ┃
┗━━━━━━━┷━━━━━━━┷━━━━━━━━━━━┛
"""

# `--key-glob=a*`.
EXPECTED_GLOB_A = """
Recording session `{session}`:
User space map channel `{channel}`:
┏━━━━━━━┯━━━━━━━┯━━━━━━━━━━━┓
┃  Key  │ Value │ Overflow? ┃
┣━━━━━━━┿━━━━━━━┿━━━━━━━━━━━┫
┃ apple │     2 │           ┃
┗━━━━━━━┷━━━━━━━┷━━━━━━━━━━━┛
"""

# `--key-glob=*o`.
EXPECTED_GLOB_O = """
Recording session `{session}`:
User space map channel `{channel}`:
┏━━━━━━━┯━━━━━━━┯━━━━━━━━━━━┓
┃  Key  │ Value │ Overflow? ┃
┣━━━━━━━┿━━━━━━━┿━━━━━━━━━━━┫
┃ mango │     3 │           ┃
┗━━━━━━━┷━━━━━━━┷━━━━━━━━━━━┛
"""

# `--key-glob=count/*`.
EXPECTED_GLOB_COUNT = """
Recording session `{session}`:
User space map channel `{channel}`:
┏━━━━━━━━━━━━━━━━━┯━━━━━━━┯━━━━━━━━━━━┓
┃       Key       │ Value │ Overflow? ┃
┣━━━━━━━━━━━━━━━━━┿━━━━━━━┿━━━━━━━━━━━┫
┃ count/tp:tptest │   100 │           ┃
┗━━━━━━━━━━━━━━━━━┷━━━━━━━┷━━━━━━━━━━━┛
"""

# `--shared`: only the shared group contributes, therefore
# `count/tp:tptest` (a per-user counter) folds down to zero.
EXPECTED_SHARED_SUMMED = """
Recording session `{session}`:
User space map channel `{channel}`:
┏━━━━━━━━━━━━━━━━━┯━━━━━━━┯━━━━━━━━━━━┓
┃       Key       │ Value │ Overflow? ┃
┣━━━━━━━━━━━━━━━━━┿━━━━━━━┿━━━━━━━━━━━┫
┃ apple           │     2 │           ┃
┃ count/tp:tptest │     0 │           ┃
┃ mango           │     3 │           ┃
┃ zebra           │     1 │           ┃
┗━━━━━━━━━━━━━━━━━┷━━━━━━━┷━━━━━━━━━━━┛
"""

# `--all-uids`: only the per-user owners contribute, excluding the
# shared group, therefore the rotation counters fold down to zero.
EXPECTED_ALL_UIDS = """
Recording session `{session}`:
User space map channel `{channel}`:
┏━━━━━━━━━━━━━━━━━┯━━━━━━━┯━━━━━━━━━━━┓
┃       Key       │ Value │ Overflow? ┃
┣━━━━━━━━━━━━━━━━━┿━━━━━━━┿━━━━━━━━━━━┫
┃ apple           │     0 │           ┃
┃ count/tp:tptest │   100 │           ┃
┃ mango           │     0 │           ┃
┃ zebra           │     0 │           ┃
┗━━━━━━━━━━━━━━━━━┷━━━━━━━┷━━━━━━━━━━━┛
"""

# `--per=owner`: one table per owner.
#
# Every channel-wide key appears in each table, holding the contribution
# of that owner (hence the zeros).
EXPECTED_OWNER = """
Recording session `{session}`:
User space map channel `{channel}`, user ID {owner_id} (`{owner_name}`) ({value_type}-bit int. values):
┏━━━━━━━━━━━━━━━━━┯━━━━━━━┯━━━━━━━━━━━┓
┃       Key       │ Value │ Overflow? ┃
┣━━━━━━━━━━━━━━━━━┿━━━━━━━┿━━━━━━━━━━━┫
┃ apple           │     0 │           ┃
┃ count/tp:tptest │   100 │           ┃
┃ mango           │     0 │           ┃
┃ zebra           │     0 │           ┃
┗━━━━━━━━━━━━━━━━━┷━━━━━━━┷━━━━━━━━━━━┛

Recording session `{session}`:
User space map channel `{channel}`, shared counters:
┏━━━━━━━━━━━━━━━━━┯━━━━━━━┯━━━━━━━━━━━┓
┃       Key       │ Value │ Overflow? ┃
┣━━━━━━━━━━━━━━━━━┿━━━━━━━┿━━━━━━━━━━━┫
┃ apple           │     2 │           ┃
┃ count/tp:tptest │     0 │           ┃
┃ mango           │     3 │           ┃
┃ zebra           │     1 │           ┃
┗━━━━━━━━━━━━━━━━━┷━━━━━━━┷━━━━━━━━━━━┛
"""

# `--per=owner --non-init-values`: same two tables as `EXPECTED_OWNER`,
# but dropping the zero rows also narrows the key column of the
# shared table.
EXPECTED_OWNER_NON_INIT = """
Recording session `{session}`:
User space map channel `{channel}`, user ID {owner_id} (`{owner_name}`) ({value_type}-bit int. values):
┏━━━━━━━━━━━━━━━━━┯━━━━━━━┯━━━━━━━━━━━┓
┃       Key       │ Value │ Overflow? ┃
┣━━━━━━━━━━━━━━━━━┿━━━━━━━┿━━━━━━━━━━━┫
┃ count/tp:tptest │   100 │           ┃
┗━━━━━━━━━━━━━━━━━┷━━━━━━━┷━━━━━━━━━━━┛

Recording session `{session}`:
User space map channel `{channel}`, shared counters:
┏━━━━━━━┯━━━━━━━┯━━━━━━━━━━━┓
┃  Key  │ Value │ Overflow? ┃
┣━━━━━━━┿━━━━━━━┿━━━━━━━━━━━┫
┃ apple │     2 │           ┃
┃ mango │     3 │           ┃
┃ zebra │     1 │           ┃
┗━━━━━━━┷━━━━━━━┷━━━━━━━━━━━┛
"""

# `--per=cpu --non-init-values`: the per-user counter resolves to the
# pinned CPU; the shared group has no per-CPU breakdown.
EXPECTED_CPU_NON_INIT = """
Recording session `{session}`:
User space map channel `{channel}`, user ID {owner_id} (`{owner_name}`) ({value_type}-bit int. values), CPU {cpu}:
┏━━━━━━━━━━━━━━━━━┯━━━━━━━┯━━━━━━━━━━━┓
┃       Key       │ Value │ Overflow? ┃
┣━━━━━━━━━━━━━━━━━┿━━━━━━━┿━━━━━━━━━━━┫
┃ count/tp:tptest │   100 │           ┃
┗━━━━━━━━━━━━━━━━━┷━━━━━━━┷━━━━━━━━━━━┛

Recording session `{session}`:
User space map channel `{channel}`, shared counters:
┏━━━━━━━┯━━━━━━━┯━━━━━━━━━━━┓
┃  Key  │ Value │ Overflow? ┃
┣━━━━━━━┿━━━━━━━┿━━━━━━━━━━━┫
┃ apple │     2 │           ┃
┃ mango │     3 │           ┃
┃ zebra │     1 │           ┃
┗━━━━━━━┷━━━━━━━┷━━━━━━━━━━━┛
"""

# A single, per-user table for the pinned CPU, for example
# `--per=cpu --cpu-id=<pinned> --all-uids --non-init-values`
# (`--all-uids` excludes the shared group).
EXPECTED_CPU_COUNT = """
Recording session `{session}`:
User space map channel `{channel}`, user ID {owner_id} (`{owner_name}`) ({value_type}-bit int. values), CPU {cpu}:
┏━━━━━━━━━━━━━━━━━┯━━━━━━━┯━━━━━━━━━━━┓
┃       Key       │ Value │ Overflow? ┃
┣━━━━━━━━━━━━━━━━━┿━━━━━━━┿━━━━━━━━━━━┫
┃ count/tp:tptest │   100 │           ┃
┗━━━━━━━━━━━━━━━━━┷━━━━━━━┷━━━━━━━━━━━┛
"""


def main(
    test_env,  # type: lttngtest._Environment
    tap,  # type: lttngtest.TapGenerator
):
    # type: (...) -> None
    session, channel, fmt = _build_per_uid_fixture(test_env, tap)
    utf8 = _make_client(test_env, tap, with_utf_8=True)
    ascii_client = _make_client(test_env, tap, with_utf_8=False)

    def check(description, args, expected):
        _check_case(tap, utf8, session, fmt, description, args, expected)

    # Aggregation
    check("default aggregation is per-channel", "--type=user", EXPECTED_CHANNEL_DEFAULT)
    check("--per=channel", "--type=user --per=channel", EXPECTED_CHANNEL_DEFAULT)
    check("--per=owner", "--type=user --per=owner", EXPECTED_OWNER)
    check("--per=cpu", "--type=user --per=cpu --non-init-values", EXPECTED_CPU_NON_INIT)
    check(
        "--per=part (alias of cpu)",
        "--type=user --per=part --non-init-values",
        EXPECTED_CPU_NON_INIT,
    )

    # Selection
    check(
        "--channel selects a present channel",
        "--type=user --channel={}".format(shlex.quote(channel.name)),
        EXPECTED_CHANNEL_DEFAULT,
    )
    check(
        "--channel rejects an absent channel",
        "--type=user --channel=nope",
        NOTHING_TO_SHOW,
    )
    check("--type=kernel selects no user channel", "--type=kernel", NOTHING_TO_SHOW)
    check(
        "--key whitelists exact keys",
        "--type=user --key=apple --key=zebra",
        EXPECTED_KEY_APPLE_ZEBRA,
    )
    check("--key-glob matches a prefix", "--type=user --key-glob=a*", EXPECTED_GLOB_A)
    check("--key-glob matches a suffix", "--type=user --key-glob=*o", EXPECTED_GLOB_O)
    check(
        "--key-glob matches the long key",
        "--type=user --key-glob=count/*",
        EXPECTED_GLOB_COUNT,
    )
    check(
        "--non-init-values drops zero rows",
        "--type=user --per=owner --non-init-values",
        EXPECTED_OWNER_NON_INIT,
    )
    check(
        "--shared selects only the shared group",
        "--type=user --shared",
        EXPECTED_SHARED_SUMMED,
    )
    check(
        "--all-uids excludes the shared group",
        "--type=user --all-uids",
        EXPECTED_ALL_UIDS,
    )
    check("--system selects no user owner", "--type=user --system", NOTHING_TO_SHOW)
    check(
        "--cpu-id keeps the pinned CPU",
        "--type=user --per=cpu --cpu-id={} --all-uids --non-init-values".format(
            fmt["cpu"]
        ),
        EXPECTED_CPU_COUNT,
    )
    check(
        "--part-id (alias of cpu-id)",
        "--type=user --per=cpu --part-id={} --all-uids --non-init-values".format(
            fmt["cpu"]
        ),
        EXPECTED_CPU_COUNT,
    )

    # Any partition other than the pinned one is empty; partition 0 is
    # always within range, so use it (or 1 when the pinned CPU is 0).
    check(
        "--cpu-id selects an empty CPU",
        "--type=user --per=cpu --cpu-id={} --all-uids --non-init-values".format(
            0 if fmt["cpu"] != 0 else 1
        ),
        NOTHING_TO_SHOW,
    )

    # Sorting
    check(
        "--sort-by=value --sort-order=desc",
        "--type=user --sort-by=value --sort-order=desc",
        EXPECTED_SORT_VALUE_DESC,
    )
    check(
        "--sort-by=value (default asc order)",
        "--type=user --sort-by=value",
        EXPECTED_SORT_VALUE_ASC,
    )
    check(
        "--sort-order=desc (default key column)",
        "--type=user --sort-order=desc",
        EXPECTED_SORT_KEY_DESC,
    )
    check(
        "--sort-by=key is the default",
        "--type=user --sort-by=key",
        EXPECTED_CHANNEL_DEFAULT,
    )

    # Display
    check(
        "--limit=2 with value desc keeps the top two",
        "--type=user --sort-by=value --sort-order=desc --limit=2",
        EXPECTED_LIMIT2_VALUE_DESC,
    )
    check(
        "--limit=1 keeps the first sorted row",
        "--type=user --limit=1",
        EXPECTED_LIMIT1_DEFAULT,
    )

    # ASCII border fallback
    _check_equal(
        tap,
        "ASCII borders: exact human output",
        _run_human(ascii_client, session, "--type=user").strip(),
        EXPECTED_CHANNEL_DEFAULT_ASCII.format(**fmt).strip(),
    )

    session.destroy()

    # Per-process owner options
    _run_per_process_cases(test_env, tap, utf8)


# Per-process channel: a single counter under `--per=channel` selection.
EXPECTED_PID_CHANNEL = """
Recording session `{session}`:
User space map channel `{channel}`:
┏━━━━━━━━━━━━━━━━━┯━━━━━━━┯━━━━━━━━━━━┓
┃       Key       │ Value │ Overflow? ┃
┣━━━━━━━━━━━━━━━━━┿━━━━━━━┿━━━━━━━━━━━┫
┃ count/tp:tptest │   100 │           ┃
┗━━━━━━━━━━━━━━━━━┷━━━━━━━┷━━━━━━━━━━━┛
"""

# Per-process channel under `--per=owner --non-init-values`.
EXPECTED_PID_OWNER = """
Recording session `{session}`:
User space map channel `{channel}`, process ID {owner_id} (`{owner_name}`) ({value_type}-bit int. values):
┏━━━━━━━━━━━━━━━━━┯━━━━━━━┯━━━━━━━━━━━┓
┃       Key       │ Value │ Overflow? ┃
┣━━━━━━━━━━━━━━━━━┿━━━━━━━┿━━━━━━━━━━━┫
┃ count/tp:tptest │   100 │           ┃
┗━━━━━━━━━━━━━━━━━┷━━━━━━━┷━━━━━━━━━━━┛
"""


# `--pid` and `--all-pids` apply only to per-process channels, so they
# need their own fixture with a running application (a per-process group
# exists only while its owning process does).
def _run_per_process_cases(
    test_env,  # type: lttngtest._Environment
    tap,  # type: lttngtest.TapGenerator
    utf8,  # type: lttngtest.LTTngClient
):
    # type: (...) -> None
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session = common._create_recording_session(test_env, client)
    channel = session.add_user_map_channel(
        buffer_sharing_policy=lttngtest.lttngctl.BufferSharingPolicy.PerPID,
        dead_process_policy=lttngtest.lttngctl.MapChannelDeadProcessPolicy.Drop,
    )
    _add_increment_trigger(
        client,
        session,
        channel,
        "count/{event_name}",
        lttngtest.lttngctl.EventRuleMatchesCondition(
            lttngtest.lttngctl.UserTracepointEventRule(common.UST_TRACEPOINT_NAME)
        ),
    )
    session.start()

    app = test_env.launch_wait_trace_test_application(
        common.DEFAULT_EVENT_COUNT, wait_before_exit=True
    )
    app.taskset_anycpu()
    app.trace()
    app.wait_for_tracing_done()

    owner = _owner_group(channel)
    fmt = _owner_fmt(session, channel)

    def check(description, args, expected):
        _check_case(tap, utf8, session, fmt, description, args, expected)

    check(
        "--pid selects the traced process",
        "--type=user --pid={}".format(owner.owner_id),
        EXPECTED_PID_CHANNEL,
    )
    check(
        "--all-pids selects every process",
        "--type=user --all-pids",
        EXPECTED_PID_CHANNEL,
    )
    check(
        "--pid rejects an absent process", "--type=user --pid=999999", NOTHING_TO_SHOW
    )
    check(
        "--per=owner names the process owner",
        "--type=user --per=owner --non-init-values",
        EXPECTED_PID_OWNER,
    )

    app.touch_exit_file()
    app.wait_for_exit()
    session.destroy()


tap = lttngtest.TapGenerator(2 * 29 + 1)

with lttngtest.test_environment(
    with_sessiond=True, log=tap.diagnostic, enable_kernel_domain=False
) as test_env:
    main(test_env, tap)

sys.exit(0 if tap.is_successful else 1)
