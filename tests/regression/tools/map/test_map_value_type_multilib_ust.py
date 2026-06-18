#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#
"""
Effective value type (counter bitness) of *user space* map channels in
mixed-bitness environments.

The effective value type of a map channel's counters depends on three
independent variables:

  1. the session daemon's bitness (32 or 64);
  2. the application's bitness (32 or 64);
  3. the configured value type: `signed-int-32`, `signed-int-64`, or
     `signed-int-max` (follow the ABI).

The sessiond can't access a counter wider than its own ABI, so some combinations
must fail at creation; and one combination creates a counter a narrower
application cannot access. This test drives every case of the table below and
asserts the documented outcome.

A map group's reported value type is the effective value type: `export-maps`
exposes it through the `vmap` view's `value_type` column (`signed-int-32` or
`signed-int-64`; see lttng-export-maps(1)).

Each row is therefore asserted by:

  - creation success/failure.
  - for a created channel, driving the counter from an application of the row's
    bitness, then locating the map group whose value type equals the row's
    *effective* width and checking it accumulated every event. The one
    inaccessible row (UST-08) is confirmed by the counter never being
    incremented at all.

The session daemon's bitness is selected through a build profile, so a row needs
a discovered profile of the required word size; rows whose word size is
unavailable are skipped.
"""

import logging
import pathlib
import sys

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest

from map_value_type_multilib_utils import (
    COUNTER_KEY,
    EVENT_COUNT,
    Case,
    profile_for_word_size,
    read_counter,
)

# Aliases to keep the CASES table below readable.
_Domain = lttngtest.lttngctl.TracingDomain
_ValueType = lttngtest.MapChannelValueType


# The user space bitness matrix. Each row is one tracing session: a per-UID map
# channel of the "Configured" value type is created on a "Sessiond"-bit session
# daemon and driven by an "App"-bit application. "Created" is the expected
# creation outcome; "Effective" is the resolved counter width of the app's map
# group (read back as the vmap `value_type` column); "Access" is whether the app
# can reach that counter. A dash means "not applicable" (the channel is never
# created).
#
#   ID      Sessiond  App   Configured  Created  Effective  Access
#   UST-01  32        32    32           yes      32         yes
#   UST-02  32        32    64           no       -          -
#   UST-03  32        32    Max          yes      32         yes
#   UST-04  32        64    32           yes      32         yes
#   UST-05  32        64    64           no       -          -
#   UST-06  32        64    Max          yes      32         yes
#   UST-07  64        32    32           yes      32         yes
#   UST-08  64        32    64           yes      64         no
#   UST-09  64        32    Max          yes      32         yes
#   UST-10  64        64    32           yes      32         yes
#   UST-11  64        64    64           yes      64         yes
#   UST-12  64        64    Max          yes      64         yes
#
# M-01 is derived from the `Max` rows (a 32-bit and a 64-bit app at once, each
# resolving to its own map group) and is handled separately by run_mixed_case.
CASES = [
    Case("UST-01", _Domain.User, 32, 32, _ValueType.SignedInt32, True, 32, True),
    Case("UST-02", _Domain.User, 32, 32, _ValueType.SignedInt64, False),
    Case("UST-03", _Domain.User, 32, 32, _ValueType.SignedIntMax, True, 32, True),
    Case("UST-04", _Domain.User, 32, 64, _ValueType.SignedInt32, True, 32, True),
    Case("UST-05", _Domain.User, 32, 64, _ValueType.SignedInt64, False),
    Case("UST-06", _Domain.User, 32, 64, _ValueType.SignedIntMax, True, 32, True),
    Case("UST-07", _Domain.User, 64, 32, _ValueType.SignedInt32, True, 32, True),
    Case("UST-08", _Domain.User, 64, 32, _ValueType.SignedInt64, True, 64, False),
    Case("UST-09", _Domain.User, 64, 32, _ValueType.SignedIntMax, True, 32, True),
    Case("UST-10", _Domain.User, 64, 64, _ValueType.SignedInt32, True, 32, True),
    Case("UST-11", _Domain.User, 64, 64, _ValueType.SignedInt64, True, 64, True),
    Case("UST-12", _Domain.User, 64, 64, _ValueType.SignedIntMax, True, 64, True),
]


def drive_user_counter(
    test_env: lttngtest._Environment,
    client: lttngtest.LTTngClient,
    session: lttngtest.Session,
    channel: lttngtest.UserMapChannel,
    app_profile: lttngtest._BuildProfile,
) -> None:
    """
    Register an "increment map value" trigger on `tp:tptest`, start the session,
    then run an application of `app_profile`'s bitness which emits EVENT_COUNT
    such events. Each matching event increments the channel's counter.
    """
    # The event-rule-matches condition enables `tp:tptest` in matching
    # applications, so the trigger must exist before the application starts.
    client.add_trigger(
        lttngtest.EventRuleMatchesCondition(
            lttngtest.UserTracepointEventRule("tp:tptest")
        ),
        [
            lttngtest.IncrementMapValueTriggerAction(
                session.name, channel.name, lttngtest.UserMapChannel, COUNTER_KEY
            )
        ],
    )

    session.start()

    app = test_env.launch_wait_trace_test_application(EVENT_COUNT, profile=app_profile)
    app.trace()
    app.wait_for_tracing_done()
    app.wait_for_exit()


def run_user_case(tap: lttngtest.TapGenerator, case: Case) -> None:
    sessiond_profile = profile_for_word_size(case.sessiond_bits)
    app_profile = profile_for_word_size(case.peer_bits)

    if sessiond_profile is None or app_profile is None:
        missing = case.sessiond_bits if sessiond_profile is None else case.peer_bits
        tap.skip(
            "{}: no {}-bit build profile available".format(case.description, missing)
        )
        return

    try:
        with lttngtest.test_environment(
            with_sessiond=True,
            log=tap.diagnostic,
            sessiond_profile=sessiond_profile,
            # The client must match the session daemon's word size.
            client_profile=sessiond_profile,
            consumerd_profiles=[app_profile],
        ) as test_env:
            client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
            session = client.create_session(
                output=lttngtest.LocalSessionOutputLocation(
                    test_env.create_temporary_directory("trace")
                )
            )

            created = True
            channel = None
            try:
                channel = session.add_user_map_channel(
                    value_type=case.configured,
                    buffer_sharing_policy=lttngtest.BufferSharingPolicy.PerUID,
                )
            except lttngtest.LTTngClientError:
                created = False

            if created != case.created:
                tap.fail(
                    "{}: expected created={}, got {}".format(
                        case.description, case.created, created
                    )
                )
                return

            if not case.created:
                tap.ok("{}: rejected at creation as expected".format(case.name))
                return

            # Reaching here implies a successful creation above.
            assert channel is not None
            drive_user_counter(test_env, client, session, channel, app_profile)

            if case.access:
                # The group whose value type equals the effective width must
                # exist and have counted every event: this confirms both the
                # effective type and accessibility.
                total, entries = read_counter(
                    session, channel.name, COUNTER_KEY, case.effective
                )
                tap.test(
                    entries > 0 and total == EVENT_COUNT,
                    "{}: counter accessible with effective {}-bit value type "
                    "(total={}, expected={})".format(
                        case.name, case.effective, total, EVENT_COUNT
                    ),
                )
            else:
                # UST-08: the narrower app cannot access the wider counter, so
                # nothing is ever incremented.
                total, entries = read_counter(session, channel.name, COUNTER_KEY)
                tap.test(
                    total == 0 and entries == 0,
                    "{}: {}-bit app cannot access the {}-bit counter "
                    "(never incremented, total={})".format(
                        case.name, case.peer_bits, case.effective, total
                    ),
                )

            session.stop()
            session.destroy()
    except Exception as case_error:
        logging.exception("Unhandled exception during case %s", case.name)
        tap.fail("{}: {}".format(case.description, case_error))


# Mixed case: not a single table row, hence its own readable identity.
MIXED_CASE_NAME = (
    "user space map, 64-bit sessiond, 32-bit and 64-bit apps at once, "
    "max value type [M-01]"
)


def run_mixed_case(tap: lttngtest.TapGenerator) -> None:
    """
    M-01: one 64-bit session daemon, `Max`, with a 32-bit and a 64-bit
    application at once. `Max` is resolved per application, so the 32-bit app
    gets a 32-bit map group and the 64-bit app a 64-bit one, concurrently. Both
    must be able to access their counter.
    """
    sessiond_profile = profile_for_word_size(64)
    app32 = profile_for_word_size(32)
    app64 = profile_for_word_size(64)

    if sessiond_profile is None or app32 is None or app64 is None:
        tap.skip(
            "{}: needs both a 32-bit and a 64-bit build profile".format(MIXED_CASE_NAME)
        )
        return

    try:
        with lttngtest.test_environment(
            with_sessiond=True,
            log=tap.diagnostic,
            sessiond_profile=sessiond_profile,
            client_profile=sessiond_profile,
            consumerd_profiles=[app32, app64],
        ) as test_env:
            client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
            session = client.create_session(
                output=lttngtest.LocalSessionOutputLocation(
                    test_env.create_temporary_directory("trace")
                )
            )
            channel = session.add_user_map_channel(
                value_type=_ValueType.SignedIntMax,
                buffer_sharing_policy=lttngtest.BufferSharingPolicy.PerUID,
            )

            client.add_trigger(
                lttngtest.EventRuleMatchesCondition(
                    lttngtest.UserTracepointEventRule("tp:tptest")
                ),
                [
                    lttngtest.IncrementMapValueTriggerAction(
                        session.name,
                        channel.name,
                        lttngtest.UserMapChannel,
                        COUNTER_KEY,
                    )
                ],
            )
            session.start()

            apps = [
                test_env.launch_wait_trace_test_application(
                    EVENT_COUNT, profile=profile
                )
                for profile in (app32, app64)
            ]
            for app in apps:
                app.trace()
            for app in apps:
                app.wait_for_tracing_done()
                app.wait_for_exit()

            total32, entries32 = read_counter(session, channel.name, COUNTER_KEY, 32)
            total64, entries64 = read_counter(session, channel.name, COUNTER_KEY, 64)

            tap.test(
                entries32 > 0
                and total32 == EVENT_COUNT
                and entries64 > 0
                and total64 == EVENT_COUNT,
                "{}: 32-bit and 64-bit apps each got their own map group "
                "(32-bit total={}, 64-bit total={}, expected {})".format(
                    MIXED_CASE_NAME, total32, total64, EVENT_COUNT
                ),
            )

            session.stop()
            session.destroy()
    except Exception as case_error:
        logging.exception("Unhandled exception during case %s", MIXED_CASE_NAME)
        tap.fail("{}: {}".format(MIXED_CASE_NAME, case_error))


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format=lttngtest.utils.get_logging_format())

    # One test case per row plus one for the "mixed" M-01 case; cases
    # whose required word size is unavailable are reported as skips within the
    # plan.
    tap = lttngtest.TapGenerator(len(CASES) + 1)

    for case in CASES:
        run_user_case(tap, case)

    run_mixed_case(tap)

    sys.exit(0 if tap.is_successful else 1)
