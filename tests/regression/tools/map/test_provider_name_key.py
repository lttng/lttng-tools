#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Philippe Proulx <pproulx@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#

"""
The `{provider_name}` placeholder of an "increment map value" trigger
action key template.

A key template may carry placeholders that the session daemon expands
when an "event rule matches" condition fires (see lttng-add-trigger(1)).

The other map tests only ever exercise the `{event_name}` placeholder;
this one exercises `{provider_name}`, and contrasts the two so that
their distinct expansions are unambiguous.

For the user space tracepoint `tp:tptest`:

• `{provider_name}` expands to the provider part alone, `tp`.

• `{event_name}` expands to the _full_ event class name, `tp:tptest`
  (the session daemon qualifies the bare LTTng-UST tracepoint name with
  its provider).

The test installs, on the same channel and the same event rule, one
trigger keyed `prov/{provider_name}` and one keyed `evt/{event_name}`,
fires the events, and then verifies that the two counters landed under
the two distinct, fully-expanded keys (`prov/tp` and `evt/tp:tptest`),
each holding the event count, and that no unexpanded template string
survived as a literal key.
"""

import pathlib
import sys

# Import in-tree test utils.
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest
import common

# The expanded keys, given the `tp:tptest` provider/tracepoint split.
PROVIDER_KEY = "prov/tp"
EVENT_KEY = "evt/{}".format(common.UST_TRACEPOINT_NAME)


def test_provider_name(
    test_env,  # type: lttngtest._Environment
    tap,  # type: lttngtest.TapGenerator
):
    # type: (...) -> None
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session = common._create_recording_session(test_env, client)
    channel = session.add_user_map_channel()

    # Two triggers on the same event rule and channel: one keyed by the
    # provider name, the other by the full event name.
    common.add_user_event_count_trigger(
        client, session, channel.name, key="prov/{provider_name}"
    )
    common.add_user_event_count_trigger(
        client, session, channel.name, key="evt/{event_name}"
    )
    session.start()

    app = test_env.launch_wait_trace_test_application(common.DEFAULT_EVENT_COUNT)
    app.trace()
    app.wait_for_tracing_done()
    app.wait_for_exit()

    values = common.read_map_values(session)

    prov_val = values.get(PROVIDER_KEY)
    tap.test(
        prov_val == common.DEFAULT_EVENT_COUNT,
        "`{{provider_name}}` expanded to `{}`, holding {} (expected {})".format(
            PROVIDER_KEY, prov_val, common.DEFAULT_EVENT_COUNT
        ),
    )

    event_val = values.get(EVENT_KEY)
    tap.test(
        event_val == common.DEFAULT_EVENT_COUNT,
        "`{{event_name}}` expanded to the full event name `{}`, holding {} "
        "(expected {})".format(EVENT_KEY, event_val, common.DEFAULT_EVENT_COUNT),
    )

    # The provider expansion (`tp`) is a strict prefix of the full event
    # name (`tp:tptest`): the two placeholders must yield two distinct
    # keys, and neither template string may survive verbatim.
    tap.test(
        set(values.keys()) == {PROVIDER_KEY, EVENT_KEY},
        "exactly the two distinct expanded keys are present (got {})".format(
            sorted(values.keys())
        ),
    )

    session.destroy()


tap = lttngtest.TapGenerator(3)

with lttngtest.test_environment(
    with_sessiond=True, log=tap.diagnostic, enable_kernel_domain=False
) as test_env:
    test_provider_name(test_env, tap)

sys.exit(0 if tap.is_successful else 1)
