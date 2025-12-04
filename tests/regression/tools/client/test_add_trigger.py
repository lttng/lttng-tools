#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: Kienan Stewart <kstewart@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#
"""
Validate that the LTTng cli's add-trigger behaves as expected
"""

import copy
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


def test_buffer_usage_invalid(test_env, tap):
    """
    Validate that lttng add-trigger fails when various invalid parameters
    are passed.
    """
    ok_args = {
        "condition": "channel-buffer-usage-ge",
        "session": "example_session",
        "channel": "example_channel",
        "threshold-ratio": "1.0",
        "domain": "user",
    }
    cases = [
        {
            "condition": "channel-buffer-usage-le",
            "session": None,
            "channel": None,
            "threshold-ratio": None,
            "domain-type": None,
            "buffer-usage-type": None,
        },
        {"session": ""},
        {"session": "a/b"},
        {"channel": ""},
        {"threshold-ratio": "2.0"},
        {"threshold-ratio": "-1.0"},
        {"threshold-size": "1024k"},
        {
            "threshold-ratio": None,
            "threshold-size": "",
        },
        {
            "threshold-ratio": None,
            "threshold-size": "x",
        },
        {
            "threshold-ratio": None,
            "threshold-size": "4096BBBB",
        },
        {
            "threshold-ratio": None,
            "threshold-size": "-123",
        },
        {"domain": "invalid"},
    ]
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    passed = 0
    for _case in cases:
        args = copy.deepcopy(ok_args)
        args.update(_case)
        command = "add-trigger "
        for key, value in args.items():
            if value is None:
                continue

            if value != "__NOVALUE__":
                command += "--{}='{}' ".format(key, value)
            else:
                command += "--{} ".format(key)

        command += " --action notify"
        try:
            client._run_cmd(command)
            tap.diagnostic("Case passed but shouldn't have")
            client._run_cmd("remove-trigger trigger0")
        except RuntimeError as e:
            passed += 1

    tap.test(
        passed == len(cases),
        "{}/{} lttng add-trigger invalid cases failed as expected".format(
            passed, len(cases)
        ),
    )


def test_buffer_usage(test_env, tap):
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    usages = ["low", "high"]

    # Maps CLI domain option to MI output domain name
    domains = {
        "jul": "JUL",
        "log4j": "LOG4J",
        "log4j2": "LOG4J2",
        "python": "PYTHON",
        "user": "UST",
    }
    if test_env.run_kernel_tests():
        domains["kernel"] = "KERNEL"

    passed = 0
    expected_passes = len(domains) * len(usages)
    for usage in usages:
        usage_condition = (
            "channel-buffer-usage-ge" if usage == "high" else "channel-buffer-usage-le"
        )
        for cli_domain, expected_mi_domain in domains.items():
            try:
                client._run_cmd(
                    "add-trigger --condition={} -d '{}' -r 0.5 -s example_session -c example_channel --action notify".format(
                        usage_condition, cli_domain
                    )
                )
            except RuntimeError as e:
                tap.diagnostic("Exception while adding trigger: {}".format(e))
                continue

            result, _ = client._run_cmd("list-triggers")
            root = xml.etree.ElementTree.fromstring(result)
            ns = {"mi": "https://lttng.org/xml/ns/lttng-mi"}
            trigger = root.findall("./mi:output/mi:triggers/mi:trigger", ns)[0]
            condition = trigger.find("mi:condition/", ns)
            trigger_name = trigger.find("mi:name", ns).text
            test_passed = True
            # Check
            condition_tag_name = "{{{}}}condition_buffer_usage_{}".format(
                ns["mi"], usage
            )
            if condition.tag != condition_tag_name:
                tap.diagnostic(
                    "Condition does not match: {} != {}".format(
                        trigger.find("mi:condition", ns).text,
                        condition_tag_name,
                    )
                )
                test_passed = False

            if condition.find("mi:session_name", ns).text != "example_session":
                tap.diagnostic(
                    "Session name does not match: {} != session_name".format(
                        trigger.find("mi:session_name", ns).text
                    )
                )
                test_passed = False

            if condition.find("mi:channel_name", ns).text != "example_channel":
                tap.diagnostic(
                    "Channel name does not match: {} != channel_name".format(
                        trigger.find("mi:channel_name", ns).text
                    )
                )
                test_passed = False

            if condition.find("mi:domain", ns).text != expected_mi_domain:
                tap.diagnostic(
                    "Domain does not match: {} != {}".format(
                        condition.find("mi:domain", ns).text, expected_mi_domain
                    )
                )
                test_passed = False

            threshold_bytes = condition.find("mi:threshold_bytes", ns)
            if threshold_bytes is not None:
                tap.diagnostic("Not expecting threshold_bytes")
                test_passed = False

            threshold_ratio = condition.find("mi:threshold_ratio", ns)
            if threshold_ratio is not None:
                if threshold_ratio.text != "0.500000":
                    tap.diagnostic(
                        "threshold_ratio does not match: {} != {}".format(
                            threshold_ratio.text, "0.500000"
                        )
                    )
                    test_passed = False
            else:
                tap.diagnostic("Missing threshold_ratio")
                test_passed = False

            if test_passed:
                passed += 1

            # Cleanup
            client._run_cmd("remove-trigger '{}'".format(trigger_name))

    tap.test(
        passed == expected_passes,
        "{}/{} additions of triggers using channel-buffer-usage-[ge|le] passed".format(
            passed, expected_passes
        ),
    )


def test_session_rotation_invalid(test_env, tap):
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    ok_args = {
        "condition": "session-rotation-starts",
        "session": "example_session",
    }
    cases = [
        {"session": ""},
        {"session": "a/b"},
        {"session": None},
        {"condition": "session-rotation-finishes", "session": ""},
        {"condition": "session-rotation-finishes", "session": "a/b"},
        {"condition": "session-rotation-finishes", "session": None},
    ]
    passed = 0
    for _case in cases:
        args = copy.deepcopy(ok_args)
        args.update(_case)
        command = "add-trigger "
        for key, value in args.items():
            if value is None:
                continue

            if value != "__NOVALUE__":
                command += "--{}='{}' ".format(key, value)
            else:
                command += "--{} ".format(key)

        command += " --action notify"
        try:
            result = client._run_cmd(command)
            tap.diagnostic("Case passed but shouldn't have")
            client._run_cmd("remove-trigger trigger0")
        except RuntimeError as e:
            passed += 1

    tap.test(
        passed == len(cases),
        "{}/{} lttng add-trigger invalid cases failed as expected".format(
            passed, len(cases)
        ),
    )


def test_session_rotation(test_env, tap):
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    rotation_states = ["completed", "ongoing"]
    expected_passes = len(rotation_states)
    passed = 0
    for rotation_state in rotation_states:
        condition_name = "session-rotation-starts"
        if rotation_state == "completed":
            condition_name = "session-rotation-finishes"
        try:
            client._run_cmd(
                "add-trigger --condition={} -s example_session --action notify".format(
                    condition_name
                )
            )
        except RuntimeError as e:
            tap.diagnostic("Exception while adding trigger: {}".format(e))
            continue

        result, errs = client._run_cmd("list-triggers")
        root = xml.etree.ElementTree.fromstring(result)
        ns = {"mi": "https://lttng.org/xml/ns/lttng-mi"}
        trigger = root.findall("./mi:output/mi:triggers/mi:trigger", ns)[0]
        condition = trigger.find("mi:condition/", ns)
        trigger_name = trigger.find("mi:name", ns).text
        test_passed = True
        # Check
        condition_tag_name = "{{{}}}condition_session_rotation_{}".format(
            ns["mi"], rotation_state
        )
        if condition.tag != condition_tag_name:
            tap.diagnostic(
                "Condition does not match: {} != {}".format(
                    trigger.find("mi:condition", ns).text,
                    condition_tag_name,
                )
            )
            test_passed = False

        if condition.find("mi:session_name", ns).text != "example_session":
            tap.diagnostic(
                "Session name does not match: {} != session_name".format(
                    trigger.find("mi:session_name", ns).text
                )
            )
            test_passed = False

        if test_passed:
            passed += 1

        # Cleanup
        client._run_cmd("remove-trigger '{}'".format(trigger_name))

    tap.test(
        passed == expected_passes,
        "{}/{} additions of triggers using the session-rotation condition passed".format(
            passed, expected_passes
        ),
    )


if __name__ == "__main__":
    tests = [
        test_buffer_usage_invalid,
        test_buffer_usage,
        test_session_consumed_size_invalid_size,
        test_session_consumed_size_invalid_name,
        test_session_consumed_size_no_size,
        test_session_consumed_size_no_name,
        test_session_consumed_size,
        test_session_rotation_invalid,
        test_session_rotation,
    ]
    tap = lttngtest.TapGenerator(len(tests))
    with lttngtest.test_environment(
        with_sessiond=True,
        log=tap.diagnostic,
        enable_kernel_domain=lttngtest._Environment.run_kernel_tests(),
    ) as test_env:
        for test in tests:
            tap.diagnostic("Starting test '{}'".format(test.__name__))
            test(test_env, tap)
    sys.exit(0 if tap.is_successful else 1)
