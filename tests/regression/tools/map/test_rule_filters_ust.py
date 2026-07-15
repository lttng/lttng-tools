#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#

"""
Test that the counters of a map channel which several "increment map
value" triggers target keep their own filter.

A map channel may hold more than one rule matching the same event class,
each incrementing a counter of its own. Install, on a single map channel,
three "event rule matches" triggers on the tracepoint of the test
application.
"""

import pathlib
import sys
from typing import List, Optional

# Import in-tree test utils.
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest
import common

# Number of events which the test application emits. Its tracepoint
# carries an `intfield` field holding the index of the event, therefore
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
    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(
            test_env.create_temporary_directory("map-trace")
        )
    )
    channel = session.add_user_map_channel(update_policy=update_policy)

    for test_case in TEST_CASES:
        client.add_trigger(
            lttngtest.lttngctl.EventRuleMatchesCondition(
                lttngtest.lttngctl.UserTracepointEventRule(
                    common.UST_TRACEPOINT_NAME,
                    filter_expression=test_case.filter_expression,
                )
            ),
            [
                lttngtest.lttngctl.IncrementMapValueTriggerAction(
                    session_name=session.name,
                    channel_name=channel.name,
                    channel_type=lttngtest.lttngctl.UserMapChannel,
                    key_template=test_case.key,
                )
            ],
        )

    session.start()

    app = test_env.launch_wait_trace_test_application(EVENT_COUNT)
    app.trace()
    app.wait_for_tracing_done()
    app.wait_for_exit()

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
    with lttngtest.test_environment(
        with_sessiond=True, log=tap.diagnostic, enable_kernel_domain=False
    ) as test_env:
        test_rule_filters(test_env, tap, update_policy)

sys.exit(0 if tap.is_successful else 1)
