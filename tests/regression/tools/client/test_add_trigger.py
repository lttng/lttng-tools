#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: Kienan Stewart <kstewart@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#
"""
Validate that the LTTng cli's add-trigger behaves as expected
"""

import pathlib
import sys
import xml.etree.ElementTree

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.append(str(test_utils_import_path))
import lttngtest
import bt2


def test_session_consumed_size_invalid_size(test_env, tap):
    """
    Validate that lttng add-trigger fails when an invalid size is given as an argument
    to the session-consumed-size-ge condition.
    """
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    invalid_sizes = ["string", "-123", "4096X", "", " "]
    session_name = "example"
    passed = True
    for size in invalid_sizes:
        try:
            client._run_cmd(
                "add-trigger --condition session-consumed-size-ge --threshold-size={} --session={} --action notify".format(
                    size, session_name
                )
            )
            tap.diagnostic(
                "add-trigger with `--threshold-size={}` didn't fail as expected".format(
                    size
                )
            )
            passed = False
        except RuntimeError as e:
            pass

    tap.test(passed, "All invalid threshold-size's failed: {}".format(invalid_sizes))


def test_session_consumed_size_invalid_name(test_env, tap):
    """
    Validate that lttng add-trigger fails when an invalid size is given as an argument
    to the session-consumed-size-ge condition.
    """
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    size = "1024"
    invalid_names = ["", "a/b"]
    passed = True
    for name in invalid_names:
        try:
            client._run_cmd(
                "add-trigger --condition session-consumed-size-ge --threshold-size={} --session='{}' --action notify".format(
                    size, name
                )
            )
            tap.diagnostic(
                "add-trigger with `--session={}` didn't fail as expected".format(name)
            )
            passed = False
        except RuntimeError as e:
            pass

    tap.test(passed, "All invalid session names's failed: {}".format(invalid_names))


def test_session_consumed_size_no_name(test_env, tap):
    """
    Validate that lttng add-trigger fails when no session name is given as an argument
    to the session-consumed-size-ge condition.
    """
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    try:
        client._run_cmd(
            "add-trigger --condition=session-consumed-size-ge --threshold-size=1024 --action=notify"
        )
        tap.fail(
            "Adding a session-consumed-size-ge trigger with no session name did not fail as expected"
        )
    except RuntimeError:
        tap.ok(
            "Adding a session-consumed-size-ge trigger with no session name failed as expected"
        )


def test_session_consumed_size_no_size(test_env, tap):
    """
    Validate that lttng add-trigger fails when no size is given as an argument
    to the session-consumed-size-ge condition.
    """
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    try:
        client._run_cmd(
            "add-trigger --condition=session-consumed-size-ge -s example --action=notify"
        )
        tap.fail(
            "Adding a session-consumed-size-ge trigger with no threshold size did not fail as expected"
        )
    except RuntimeError:
        tap.ok(
            "Adding a session-consumed-size-ge trigger with no threshold size failed as expected"
        )


def test_session_consumed_size(test_env, tap):
    """
    Validate that lttng add-trigger succeeeds with an approriate size and session name.
    """
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    client._run_cmd(
        "add-trigger --name=trigger0 --condition=session-consumed-size-ge -s example -t 1024K --action notify"
    )
    list_triggers_output, _ = client._run_cmd("list-triggers")
    root = xml.etree.ElementTree.fromstring(list_triggers_output)
    triggers_mi = client._mi_get_in_element(
        client._mi_get_in_element(root, "output"), "triggers"
    )
    passed = True
    for trigger_mi in triggers_mi:
        name = client._mi_get_in_element(trigger_mi, "name").text
        if name != "trigger0":
            passed = False
            tap.diagnostic("Trigger name '{}' does not match 'trigger0'".format(name))

        condition_mi = client._mi_get_in_element(trigger_mi, "condition")[0]
        type_name = condition_mi.tag
        if type_name.find("condition_session_consumed_size") == -1:
            passed = False
            tap.diagnostic(
                "Trigger type '{}' does not match 'condition_session_consumed_size'".format(
                    type_name
                )
            )

        threshold = client._mi_get_in_element(condition_mi, "threshold_bytes").text
        if threshold != "1048576":
            passed = False
            tap.diagnostic(
                "Trigger threshold '{}' does not match '1048576'".format(threshold)
            )

        session_name = client._mi_get_in_element(condition_mi, "session_name").text
        if session_name != "example":
            passed = False
            tap.diagnostic(
                "Trigger session name '{}' does not match 'example'".format(
                    session_name
                )
            )

    tap.test(passed, "Added trigger attributes match command-line parameters")
    client._run_cmd("remove-trigger trigger0")


if __name__ == "__main__":
    tests = [
        test_session_consumed_size_invalid_size,
        test_session_consumed_size_invalid_name,
        test_session_consumed_size_no_size,
        test_session_consumed_size_no_name,
        test_session_consumed_size,
    ]
    tap = lttngtest.TapGenerator(len(tests))
    with lttngtest.test_environment(with_sessiond=True, log=tap.diagnostic) as test_env:
        for test in tests:
            tap.diagnostic("Starting test '{}'".format(test.__name__))
            test(test_env, tap)
    sys.exit(0 if tap.is_successful else 1)
