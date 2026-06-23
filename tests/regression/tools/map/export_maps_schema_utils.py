#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Philippe Proulx <pproulx@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#

"""
Shared helpers for the export-maps schema tests
(test_export_maps_schema_ust.py and test_export_maps_schema_kernel.py).
"""

import pathlib
import sys
from typing import Dict, List

# Import in-tree test utils.
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest

# Each test creates its channel with an explicit value type so that
# the `value_type` column is deterministic.
#
# A 32-bit counter is hostable on a session daemon of any bitness
# (unlike a 64-bit one, which a 32-bit daemon rejects) and always
# resolves to `signed-int-32`, therefore this keeps the tests portable
# across 32-bit and 64-bit builds.
VAL_TYPE = lttngtest.lttngctl.MapChannelValueType.SignedInt32
VAL_TYPE_SQL = "signed-int-32"


# Returns the subset of `rows` whose columns match every `column=value`
# keyword argument (a logical AND of the conditions).
#
# For example:
#
#     select(rows, group_type="shared", key="k")
#
# returns the rows that are both in the shared group and keyed `k`.
def select(
    rows,  # type: List[Dict[str, object]]
    **filters,  # type: object
):
    # type: (...) -> List[Dict[str, object]]
    return [
        row
        for row in rows
        if all(row[column] == value for column, value in filters.items())
    ]


# Sums the `value` of every row in `rows`.
def sum_values(
    rows,  # type: List[Dict[str, object]]
):
    # type: (...) -> int
    return sum(int(row["value"]) for row in rows)  # type: ignore[arg-type]
