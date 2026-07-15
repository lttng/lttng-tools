#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#

"""
Test that the counters of a kernel map channel which several "increment
map value" triggers target keep their own filter.

This is the kernel counterpart of test_rule_filters_ust.py: install, on
a single kernel map channel, three "event rule matches" triggers on the
tracepoint of the `lttng-test` module, whose `intfield` field holds the
index of the event (see common.fire_kernel_test_events()):
"""

import functools
import pathlib
import sys
from typing import List, Optional

# Import in-tree test utils.
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest
import common

# Number of events that the `lttng-test` module emits. The `intfield`
# field of its tracepoint holds the index of the event, therefore
# `LOW_EVENT_COUNT` of them have an `intfield` less
# than `LOW_EVENT_COUNT`.
EVENT_COUNT = 10
LOW_EVENT_COUNT = 3


class TestCaseDescription:
    def __init__(
        self, key: str, filter_expression: Optional[str], expected_value: int
    ) -> None:
        self.key = key
        self.filter_expression = filter_expression
        self.expected_value = expected_value


TEST_CASES: List[TestCaseDescription] = [
    TestCaseDescription(
        "low", "intfield < {}".format(LOW_EVENT_COUNT), LOW_EVENT_COUNT
    ),
    TestCaseDescription(
        "high", "intfield >= {}".format(LOW_EVENT_COUNT), EVENT_COUNT - LOW_EVENT_COUNT
    ),
    TestCaseDescription("all", None, EVENT_COUNT),
]


def test_rule_filters(
    test_env: lttngtest._Environment,
    tap: lttngtest.TapGenerator,
    update_policy: lttngtest.lttngctl.MapChannelUpdatePolicy,
) -> None:
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session = common._create_recording_session(test_env, client)
    channel = session.add_kernel_map_channel(update_policy=update_policy)

    for test_case in TEST_CASES:
        common.add_kernel_event_count_trigger(
            client,
            session,
            channel.name,
            test_case.key,
            filter_expression=test_case.filter_expression,
        )

    session.start()
    common.fire_kernel_test_events(EVENT_COUNT)

    for test_case in TEST_CASES:
        val = common.read_map_value(session, test_case.key)
        tap.test(
            val == test_case.expected_value,
            "{}: counter `{}` (filter `{}`) is {} (expected {})".format(
                update_policy.name,
                test_case.key,
                test_case.filter_expression,
                val,
                test_case.expected_value,
            ),
        )

    session.destroy()


update_policies = [
    lttngtest.lttngctl.MapChannelUpdatePolicy.PerEvent,
    lttngtest.lttngctl.MapChannelUpdatePolicy.PerRuleMatch,
]
tap = lttngtest.TapGenerator(len(TEST_CASES) * len(update_policies))

for update_policy in update_policies:
    common.run_kernel_test(
        tap,
        functools.partial(test_rule_filters, update_policy=update_policy),
        skip_count=len(TEST_CASES),
    )

sys.exit(0 if tap.is_successful else 1)
