#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#
"""
Shared helpers for the map value-type multilib tests
(test_map_value_type_multilib_ust.py and
test_map_value_type_multilib_kernel.py).
"""

import pathlib
import sqlite3
import sys
from typing import Optional, Tuple

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest

# Number of events each test drives into a counter, and the counter key it
# increments. Shared so the user space and kernel tests agree on the target.
EVENT_COUNT = 10
COUNTER_KEY = "events"


def profile_for_word_size(word_size_bits: int) -> Optional[lttngtest._BuildProfile]:
    """A discovered build profile of the given word size, or None."""
    profiles = lttngtest._Environment.profiles_with_word_size_bits(word_size_bits)
    return profiles[0] if profiles else None


def value_type_sql(effective_bits: int) -> str:
    """Map an effective width (32 or 64) to a `vmap.value_type` string."""
    return {32: "signed-int-32", 64: "signed-int-64"}[effective_bits]


def counter_total(
    connection: sqlite3.Connection,
    channel_name: str,
    key: str,
    effective_bits: Optional[int] = None,
) -> Tuple[int, int]:
    """
    Sum a key's value across the per-CPU partitions of the map channel.

    With `effective_bits`, restrict to the group of that effective value type
    (the group's `value_type` is the resolved counter width); with None, sum
    every group. Returns (total, entry_count); entry_count is 0 when no matching
    group has any value for the key.
    """
    if effective_bits is None:
        row = connection.execute(
            "SELECT COALESCE(SUM(value), 0) AS total, COUNT(*) AS entries "
            "FROM vmap WHERE channel_name = ? AND key = ?",
            (channel_name, key),
        ).fetchone()
    else:
        row = connection.execute(
            "SELECT COALESCE(SUM(value), 0) AS total, COUNT(*) AS entries "
            "FROM vmap WHERE channel_name = ? AND key = ? AND value_type = ?",
            (channel_name, key, value_type_sql(effective_bits)),
        ).fetchone()
    return (row["total"], row["entries"])


def read_counter(
    session: lttngtest.Session,
    channel_name: str,
    key: str,
    effective_bits: Optional[int] = None,
) -> Tuple[int, int]:
    """
    Read a key's counter value once through `export-maps`. An increment is a
    direct store to the counter's shared memory at tracepoint hit, and
    `export-maps` reads it back synchronously, so once the events have been
    emitted a single read is authoritative: there is nothing to poll for.

    With `effective_bits`, restrict to the group of that effective value type;
    with None, sum every group (used to confirm an inaccessible counter was
    never incremented). Returns (total, entries).
    """
    connection = session.export_maps()
    try:
        return counter_total(connection, channel_name, key, effective_bits)
    finally:
        connection.close()


class Case:
    """One row of a bitness matrix (see the table in each test script)."""

    def __init__(
        self,
        case_id: str,
        domain: lttngtest.lttngctl.TracingDomain,
        sessiond_bits: int,
        peer_bits: int,
        configured: lttngtest.MapChannelValueType,
        created: bool,
        effective: Optional[int] = None,
        access: Optional[bool] = None,
    ) -> None:
        self.case_id = case_id
        self.domain = domain
        self.sessiond_bits = sessiond_bits
        self.peer_bits = peer_bits
        self.configured = configured
        self.created = created
        self.effective = effective
        self.access = access

    @property
    def name(self) -> str:
        """A human-readable name used in TAP diagnostics."""
        configured = {
            lttngtest.MapChannelValueType.SignedInt32: "32-bit",
            lttngtest.MapChannelValueType.SignedInt64: "64-bit",
            lttngtest.MapChannelValueType.SignedIntMax: "max",
        }[self.configured]
        is_user = self.domain == lttngtest.lttngctl.TracingDomain.User
        peer = "app" if is_user else "kernel"
        domain = "user space" if is_user else "kernel"
        return (
            "{domain} map, {s}-bit sessiond, {p}-bit {peer}, "
            "{configured} value type [{id}]".format(
                domain=domain,
                s=self.sessiond_bits,
                p=self.peer_bits,
                peer=peer,
                configured=configured,
                id=self.case_id,
            )
        )

    @property
    def description(self) -> str:
        return "{name} -> created={created}, effective={eff}, access={acc}".format(
            name=self.name,
            created=self.created,
            eff=self.effective,
            acc=self.access,
        )
