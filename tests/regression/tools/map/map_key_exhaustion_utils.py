#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#

"""
Shared helper for the map key exhaustion tests
(test_map_key_exhaustion_ust.py and test_map_key_exhaustion_kernel.py).
"""

import enum
import pathlib
import sys
from typing import Dict, Iterable

# Import in-tree test utils.
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest
import common

# Maximum key count of the map channels of those tests, and one key per
# trigger to register, which is one more than the channel can hold.
MAX_KEY_COUNT = 3
KEYS = ["exhaustion-key-{}".format(i) for i in range(MAX_KEY_COUNT + 1)]

# Key slots are claimed in trigger registration order, so the key of the
# last registered trigger is the one that the full channel denies.
SURVIVING_KEYS = KEYS[:-1]
DENIED_KEY = KEYS[-1]


@enum.unique
class Step(enum.Enum):
    RegisterTriggers = "triggers"
    LaunchApplication = "app"
    StartSession = "start"

    def __repr__(self):
        return "<%s.%s>" % (self.__class__.__name__, self.name)


def format_step_order(step_order: Iterable[Step]) -> str:
    return ", ".join(step.value for step in step_order)


# Asserts that the channel of `session` denied `DENIED_KEY` and that
# every surviving key holds `expected_value`.
def check_denied_key(
    tap: lttngtest.TapGenerator,
    scenario: str,
    session: lttngtest.Session,
    expected_value: int,
) -> None:
    values = common.read_map_values(session)
    surviving = {
        key: value for key, value in values.items() if key != DENIED_KEY
    }  # type: Dict[str, int]

    tap.test(
        DENIED_KEY not in values,
        "{}: the last registered trigger's key `{}` is denied".format(
            scenario, DENIED_KEY
        ),
    )
    tap.test(
        surviving == {key: expected_value for key in SURVIVING_KEYS},
        "{}: the other keys hold {} (got {})".format(
            scenario, expected_value, surviving
        ),
    )
