#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#

import enum
import pathlib
import sys
from typing import Iterable

# Import in-tree test utils.
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest


# Steps whose relative order decides when the session daemon has to hand
# a recording rule to a tracer.
@enum.unique
class Step(enum.Enum):
    CreateSession = "session"
    AddRecordingRule = "rule"
    LaunchApplication = "app"
    StartSession = "start"

    def __repr__(self):
        return "<%s.%s>" % (self.__class__.__name__, self.name)


# Changes applied to a recording session while a tracer is midway through
# emitting its events.
@enum.unique
class MidRunChange(enum.Enum):
    AddRecordingRule = "add the recording rule"
    DisableRecordingRule = "disable the recording rule"
    StartSession = "start the recording session"
    StopSession = "stop the recording session"

    def __repr__(self):
        return "<%s.%s>" % (self.__class__.__name__, self.name)

    # Whether this change begins recording rather than ends it.
    @property
    def begins_recording(self) -> bool:
        return self in (MidRunChange.AddRecordingRule, MidRunChange.StartSession)


def format_step_order(step_order: Iterable[Step]) -> str:
    return ", ".join(step.value for step in step_order)


# Validates that the trace at `trace_path` holds exactly `expected_count`
# event records and that nothing was discarded.
def check_event_count(
    tap: lttngtest.TapGenerator,
    scenario: str,
    trace_path: pathlib.Path,
    expected_count: int,
) -> None:
    received, discarded = lttngtest.count_events(trace_path)

    tap.test(
        (received, discarded) == (expected_count, 0),
        "{}: {} recorded and {} discarded event records (expected {} and 0)".format(
            scenario, received, discarded, expected_count
        ),
    )
