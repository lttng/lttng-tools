#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2025 Olivier Dion <odion@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only

import pathlib
import sys

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.append(str(test_utils_import_path))

import lttngtest

"""
This test suite validates the following for channel's watchdog timer:

  - Only user-space domain channels with the buffer ownership `user` support the
    watchdog timer.

  - The lttng-list(1) command correctly reports the value of the watchdog timer
    when set by the user on creation of a user-space UID channel.

  - The watchdog timer is correctly saved and restored when saving and loading
    back a session.
"""


def test_domain_and_ownership(tap, test_env, client):
    """
    Ensure that only User-space domain channel with the buffer ownership
    `user` can enable a watchdog timer.
    """

    def test(domain, success, fail, buffer_sharing_policy=None):

        tap.diagnostic(
            "Ensure that channel in domain {} with {} buffer ownership {} have a watchdog timer".format(
                domain,
                (
                    buffer_sharing_policy
                    if buffer_sharing_policy is not None
                    else "default"
                ),
                (
                    "can"
                    if domain == lttngtest.TracingDomain.User
                    and buffer_sharing_policy == lttngtest.BufferSharingPolicy.PerUID
                    else "cannot"
                ),
            )
        )

        session = client.create_session(
            output=lttngtest.LocalSessionOutputLocation(
                test_env.create_temporary_directory("trace")
            )
        )

        try:
            session.add_channel(
                domain,
                buffer_sharing_policy=buffer_sharing_policy,
                watchdog_timer_period_us=1,
            )
            success()
        except Exception as exn:
            fail(exn)

    test(
        lttngtest.TracingDomain.Kernel,
        lambda: tap.fail(
            "Channel in kernel domain should not be able to have a watchdog timer"
        ),
        lambda exn: tap.ok(
            "Failed to create channel in kernel domain with watchdog timer: {}".format(
                exn
            )
        ),
    )

    test(
        lttngtest.TracingDomain.User,
        lambda: tap.fail(
            "Channel in user-space domain with `process` buffer ownership should not be able to have a watchdog timer"
        ),
        lambda exn: tap.ok(
            "Failed to create channel in user-space domain with `process` buffer ownership with watchdog timer: {}".format(
                exn
            )
        ),
        buffer_sharing_policy=lttngtest.BufferSharingPolicy.PerPID,
    )

    test(
        lttngtest.TracingDomain.User,
        lambda: tap.ok(
            "Successfully created channel in user-space domain with `user` buffer ownership with watchdog timer"
        ),
        lambda exn: tap.fail(
            "Failed to created channel in user-space domain with `user` buffer ownership with watchdog timer: {}".format(
                exn
            )
        ),
        buffer_sharing_policy=lttngtest.BufferSharingPolicy.PerUID,
    )


def session_watchdog_timer_interval_value(client, session_name):
    """
    Return the value of the channel attribute `watchdog_timer_interval` of
    the first channel of the first domain listed in `session_name`
    """

    session_xml = client.list_session_raw(session_name)

    domain = client._mi_get_in_element(session_xml, "domains")[0]

    channel = client._mi_get_in_element(domain, "channels")[0]

    channel_attributes = client._mi_get_in_element(channel, "attributes")

    watchdog_timer_interval_text = client._mi_get_in_element(
        channel_attributes, "watchdog_timer_interval"
    ).text

    return int(watchdog_timer_interval_text)


def test_list(tap, test_env, client):
    """
    Ensure that lttng-list(1) correctly list the value of the channel
    attribute `watchdog_timer_interval`.
    """

    tap.diagnostic(
        "Ensure that lttng-list(1) correctly list the value of the channel attribute `watchdog_timer_interval` when created through the client."
    )

    watchdog_timer_interval_us = 31415926535

    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(
            test_env.create_temporary_directory("trace")
        )
    )

    session.add_channel(
        lttngtest.TracingDomain.User,
        buffer_sharing_policy=lttngtest.BufferSharingPolicy.PerUID,
        watchdog_timer_period_us=watchdog_timer_interval_us,
    )

    watchdog_timer_interval_from_mi = session_watchdog_timer_interval_value(
        client, session.name
    )

    if watchdog_timer_interval_from_mi == watchdog_timer_interval_us:
        tap.ok("Watchdog timer of channel is correctly reported by lttng-list(1)")
    else:
        tap.fail(
            "Watchdog timer reported by lttng-list(1) is `{}` but we are expecting `{}`".format(
                watchdog_timer_interval_from_mi, watchdog_timer_interval_us
            )
        )


def test_save_and_restore(tap, test_env, client):
    """
    Ensure that that the value of the channel attribute
    `watchdog_timer_interval` is saved by lttng-save(1) and loaded by
    lttng-load(1).
    """

    tap.diagnostic(
        "Ensure that the channel attribute `watchdog_timer_interval` is saved and restored by lttng-save(1) and lttng-load(1)."
    )

    watchdog_timer_interval_us = 31415926535

    original_session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(
            test_env.create_temporary_directory("trace")
        )
    )

    original_session_name = original_session.name

    original_session.add_channel(
        lttngtest.TracingDomain.User,
        buffer_sharing_policy=lttngtest.BufferSharingPolicy.PerUID,
        watchdog_timer_period_us=watchdog_timer_interval_us,
    )

    client.save_sessions(session_name=original_session_name)

    original_session.destroy()

    client.load_sessions(session_name=original_session_name)

    watchdog_timer_interval_from_mi = session_watchdog_timer_interval_value(
        client, original_session_name
    )

    if watchdog_timer_interval_from_mi == watchdog_timer_interval_us:
        tap.ok("Watchdog timer of channel is correctly reported by lttng-list(1)")
    else:
        tap.fail(
            "Watchdog timer reported by lttng-list(1) is `{}` but we are expecting `{}`".format(
                watchdog_timer_interval_from_mi, watchdog_timer_interval_us
            )
        )


tests = (
    test_domain_and_ownership,
    test_list,
    test_save_and_restore,
)

if __name__ == "__main__":

    tap = lttngtest.TapGenerator(5)

    with lttngtest.test_environment(with_sessiond=True, log=tap.diagnostic) as test_env:

        client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)

        for test in tests:
            try:
                test(tap, test_env, client)
            except Exception as exn:
                tap.fail(
                    "Uncaught exception while running test {}: {}".format(test, exn)
                )
            finally:
                client.destroy_sessions_all()

    sys.exit(0 if tap.is_successful else 1)
