#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Kienan Stewart <kstewart@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#

import math
import pathlib
import platform
import signal
import subprocess
import sys
import time
import typing

# Import in-tree test utils
# Modify this depending on where the test file is in the tree
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest


def test_notification_channel_subscription_twice(
    tap: lttngtest.TapGenerator,
    test_env: lttngtest._Environment,
    domain: lttngtest.lttngctl.TracingDomain = lttngtest.lttngctl.TracingDomain.User,
    condition_type: lttngtest.lttngctl.ConditionType = lttngtest.lttngctl.ConditionType.BufferUsageLow,
) -> None:
    tap.diagnostic(
        "Running 'test_notification_channel_subscription_twice' with domain={}, condition_type={}".format(
            domain, condition_type
        )
    )
    notification_app = pathlib.Path(__file__).absolute().parents[0] / "notification"
    output_path = test_env.create_temporary_directory("trace")

    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(output_path)
    )
    channel = session.add_channel(domain)
    if domain == lttngtest.lttngctl.TracingDomain.User:
        channel.add_recording_rule(
            lttngtest.lttngctl.UserTracepointEventRule("tp:tptest")
        )
    else:
        channel.add_recording_rule(
            lttngtest.lttngctl.KernelTracepointEventRule("lttng_test_filter_event")
        )

    session.start()
    args = [
        str(notification_app),
        "8",
        (
            "LTTNG_DOMAIN_UST"
            if domain == lttngtest.lttngctl.TracingDomain.User
            else "LTTNG_DOMAIN_KERNEL"
        ),
        str(-1),
        "/dev/null",
        session.name,
        channel.name,
        condition_type.value,
    ]
    tap.diagnostic("Launching test application: {}".format(args))
    p = subprocess.Popen(args, env=test_env.get_ust_test_app_env())
    p.wait()
    session.destroy()
    tap.test(
        p.returncode == 0,
        "Subscription test program completed successfully: returncode={}".format(
            p.returncode
        ),
    )


def test_triggers_buffer_usage_condition(
    tap: lttngtest.TapGenerator,
    test_env: lttngtest._Environment,
    domain: lttngtest.lttngctl.TracingDomain = lttngtest.lttngctl.TracingDomain.User,
    condition_type: lttngtest.lttngctl.ConditionType = lttngtest.lttngctl.ConditionType.BufferUsageLow,
) -> None:
    tap.diagnostic(
        "Running 'test_triggers_buffer_usage_condition' with domain={}, condition_type={}".format(
            domain, condition_type
        )
    )
    notification_app = pathlib.Path(__file__).absolute().parents[0] / "notification"
    output_path = test_env.create_temporary_directory("trace")

    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(output_path)
    )
    channel = session.add_channel(domain)
    if domain == lttngtest.lttngctl.TracingDomain.User:
        channel.add_recording_rule(
            lttngtest.lttngctl.UserTracepointEventRule("tp:tptest")
        )
    else:
        channel.add_recording_rule(
            lttngtest.lttngctl.KernelTracepointEventRule("lttng_test_filter_event")
        )

    session.start()
    args = [
        str(notification_app),
        "9",
        (
            "LTTNG_DOMAIN_UST"
            if domain == lttngtest.lttngctl.TracingDomain.User
            else "LTTNG_DOMAIN_KERNEL"
        ),
        str(-1),
        "/dev/null",
        session.name,
        channel.name,
        condition_type.value,
    ]
    tap.diagnostic("Launching test application: {}".format(args))
    p = subprocess.Popen(args, env=test_env.get_ust_test_app_env())
    p.wait()
    session.destroy()
    tap.test(
        p.returncode == 0,
        "Trigger test program completed successfully: returncode={}".format(
            p.returncode
        ),
    )


def test_buffer_usage_notification_channel(
    tap: lttngtest.TapGenerator,
    test_env: lttngtest._Environment,
    domain: lttngtest.lttngctl.TracingDomain = lttngtest.lttngctl.TracingDomain.User,
) -> None:
    tap.diagnostic(
        "Running 'test_buffer_usage_notification_channel' with domain={}".format(domain)
    )
    event_generator_script = (
        pathlib.Path(__file__).absolute().parents[0] / "util_event_generator.py"
    )
    notification_app = pathlib.Path(__file__).absolute().parents[0] / "notification"
    output_path = test_env.create_temporary_directory("trace")

    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(output_path)
    )
    channel = session.add_channel(domain, subbuf_size=lttngtest.getconf("PAGE_SIZE"))
    if domain == lttngtest.lttngctl.TracingDomain.User:
        channel.add_recording_rule(
            lttngtest.lttngctl.UserTracepointEventRule("tp:tptest")
        )
    else:
        channel.add_recording_rule(
            lttngtest.lttngctl.KernelTracepointEventRule("lttng_test_filter_event")
        )

    # Spawn test event_generator_script with ready_file, state_file,
    # and ( 'userspace_testapp' or 'kernel_generate_filter_events')
    temp_dir = test_env.create_temporary_directory()
    ready_file_path = temp_dir / "generator_ready"
    state_file_path = temp_dir / "testapp_state"
    state_file_path.touch()
    args = [
        str(event_generator_script),
        "--ready-file",
        str(ready_file_path),
        "--state-file",
        str(state_file_path),
        (
            "userspace_testapp"
            if domain == lttngtest.lttngctl.TracingDomain.User
            else "kernel_generate_filter_events"
        ),
    ]
    event_generator_env = test_env.get_ust_test_app_env()
    event_generator_env["EVENT_GENERATOR_SCRIPT"] = str(
        test_env._project_root / "tests" / "utils" / "testapp" / "gen-ust-events"
    )
    tap.diagnostic("Running event generator script: {}".format(args))
    event_generator = subprocess.Popen(args, env=event_generator_env)

    # Wait until ready file is present
    while not ready_file_path.exists():
        time.sleep(0.1)
        if event_generator.poll() is not None:
            # The event_generator has terminated
            raise Exception(
                "event_generator has terminated earlier than expected: ret={}".format(
                    event_generator.poll()
                )
            )

    consumerd_type = (
        lttngtest.ConsumerType.KERNEL
        if domain == lttngtest.lttngctl.TracingDomain.Kernel
        else (
            lttngtest.ConsumerType.UST64
            if platform.architecture()[0] == "64bit"
            else lttngtest.ConsumerType.UST32
        )
    )
    args = [
        str(notification_app),
        "2",
        (
            "LTTNG_DOMAIN_UST"
            if domain == lttngtest.lttngctl.TracingDomain.User
            else "LTTNG_DOMAIN_KERNEL"
        ),
        str(event_generator.pid),
        str(state_file_path),
        session.name,
        channel.name,
        str(test_env.lttng_consumerd_get_pid(consumerd_type)),
    ]
    tap.diagnostic("Launching test application: {}".format(args))
    p = subprocess.Popen(args, env=test_env.get_ust_test_app_env())
    p.wait()
    tap.test(
        p.returncode == 0,
        "Trigger test program completed successfully: returncode={}".format(
            p.returncode
        ),
    )

    session.stop()
    session.destroy()
    event_generator.send_signal(signal.SIGUSR2)
    event_generator.wait()


def _get_discarded_messages(
    triggers: typing.List[lttngtest.lttngctl.Trigger], trigger_name: str
) -> int:
    for trigger in triggers:
        if trigger.name != trigger_name:
            continue

        return (
            trigger.condition.error_query_results[0].value
            if trigger.condition.error_query_results[0].name
            == "discarded tracer messages"
            else -1
        )

    raise RuntimeError("trigger '{}' not found".format(trigger_name))


def _get_overflow_event_count_by_pipe_size() -> int:
    pipe_size = lttngtest.utils.get_pipe_max_size()
    # Find the number of events needed to overflow the event notification
    # pipe buffer. Each LTTng-UST notification is at least 42 bytes long.
    # Double that number to ensure enough events are created to overflow
    # the buffer.
    return math.ceil((pipe_size / 42) * 2)


def _get_overflow_event_count_by_kernel_notifier_group() -> int:
    # The kernel notifier ring buffer configuration is currently made of 16x 4096
    # byte subbuffers. Each kernel notification is at least 42 bytes long.
    # To fill it, we need to generate (16 * 4096)/42 = 1561 notifications.
    # That number is a bit larger than what we need since some of the space
    # is lost in subbuffer boundaries.
    #
    # @see lttng_event_notifier_group_create() in lttng-modules.
    return math.ceil((16 * 4096 / 42) * 2)


def test_notifier_discarded_count(
    tap: lttngtest.TapGenerator,
    test_env: lttngtest._Environment,
    domain: lttngtest.lttngctl.TracingDomain,
) -> None:
    tap.diagnostic(
        "Running test_notifier_discarded_count with domain={}".format(domain)
    )
    event_count = (
        _get_overflow_event_count_by_pipe_size()
        if domain == lttngtest.lttngctl.TracingDomain.User
        else _get_overflow_event_count_by_kernel_notifier_group()
    )
    consumerd_type = (
        lttngtest.ConsumerType.KERNEL
        if domain == lttngtest.lttngctl.TracingDomain.Kernel
        else (
            lttngtest.ConsumerType.UST64
            if platform.architecture()[0] == "64bit"
            else lttngtest.ConsumerType.UST32
        )
    )
    trigger_event_rule = (
        lttngtest.lttngctl.KernelTracepointEventRule("lttng_test_filter_event")
        if domain == lttngtest.lttngctl.TracingDomain.Kernel
        else lttngtest.lttngctl.UserTracepointEventRule("tp:tptest")
    )

    # Add trigger tp:tptest --action=notify
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    trigger = client.add_trigger(
        lttngtest.lttngctl.EventRuleMatchesCondition(trigger_event_rule),
        [lttngtest.lttngctl.NotifyTriggerAction()],
    )

    # confirm that initial discards i s 0
    triggers = client.list_triggers()
    trigger = [t for t in triggers if t.name == trigger.name][0]
    discarded_before = (
        trigger.condition.error_query_results[0].value
        if trigger.condition.error_query_results[0].name == "discarded tracer messages"
        else -1
    )
    tap.diagnostic(
        "trigger '{}' discarded tracer messages before application run: {}".format(
            trigger.name, discarded_before
        )
    )

    # Pause consumer
    test_env.lttng_sessiond_pause_notifications()

    # Run test app
    if domain == lttngtest.lttngctl.TracingDomain.User:
        app = test_env.launch_wait_trace_test_application(event_count)
        app.trace()
        app.wait_for_tracing_done()
        app.wait_for_exit()
    else:
        with open("/proc/lttng-test-filter-event", "w") as f:
            f.write(str(event_count))

    # Unpause consumer
    test_env.lttng_sessiond_pause_notifications(False)

    # Get discard number, > 0
    triggers = client.list_triggers()
    trigger = [t for t in triggers if t.name == trigger.name][0]
    discarded_after = (
        trigger.condition.error_query_results[0].value
        if trigger.condition.error_query_results[0].name == "discarded tracer messages"
        else -1
    )
    tap.diagnostic(
        "trigger '{}' discarded tracer messages after application run: {}".format(
            trigger.name, discarded_after
        )
    )

    # Remove trigger
    client.remove_trigger(trigger)

    # Confirm no notifiers are enabled
    triggers = client.list_triggers()
    triggers_removed = len(triggers) == 0

    # Re-add trigger
    trigger = client.add_trigger(
        lttngtest.lttngctl.EventRuleMatchesCondition(trigger_event_rule),
        [lttngtest.lttngctl.NotifyTriggerAction()],
    )

    # Confirm counter is reset to 0
    triggers = client.list_triggers()
    trigger = [t for t in triggers if t.name == trigger.name][0]
    discarded_readd = (
        trigger.condition.error_query_results[0].value
        if trigger.condition.error_query_results[0].name == "discarded tracer messages"
        else -1
    )

    client.remove_trigger(trigger)
    tap.test(
        discarded_before == 0
        and discarded_after > 0
        and triggers_removed
        and discarded_readd == 0,
        "Trigger '{}' has no discarded events before application run, and more than 0 after traced application run: before={}, after={}, notifiers_cleaned_up={}, readd={}".format(
            trigger.name,
            discarded_before,
            discarded_after,
            triggers_removed,
            discarded_readd,
        ),
    )


def test_ust_notifier_discarded_count_max_bucket(
    tap: lttngtest.TapGenerator, test_env: lttngtest._Environment, max_bucket_size: int
) -> None:
    """
    Validate that adding triggers beyond the max bucket size fails.
    """
    test_passed = True
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    trigger_event_rule = lttngtest.lttngctl.UserTracepointEventRule("tp:tptest")
    for i in range(max_bucket_size):
        try:
            trigger = client.add_trigger(
                lttngtest.lttngctl.EventRuleMatchesCondition(trigger_event_rule),
                [lttngtest.lttngctl.NotifyTriggerAction()],
            )
        except Exception as e:
            tap.diagnostic(
                "Adding trigger failed, when it should have worked: {}".format(e)
            )
            test_passed = False

    for i in range(max_bucket_size, max_bucket_size + 2):
        try:
            trigger = client.add_trigger(
                lttngtest.lttngctl.EventRuleMatchesCondition(trigger_event_rule),
                [lttngtest.lttngctl.NotifyTriggerAction()],
            )
            tap.diagnostic("Adding trigger succeeded, when it should have failed")
            test_passed = False
        except Exception as e:
            tap.diagnostic("Adding trigger failed: {}".format(e))
            if (
                type(e) is not lttngtest.LTTngClientError
                or "No index available in event notifier error accounting"
                not in e._error_output
            ):
                tap.diagnostic(
                    "Adding trigger failed, but error for an unexpected reason"
                )
                test_passed = False

    tap.test(test_passed, "Adding triggers beyond bucket size fails as expected")


def test_ust_notifier_discarded_count_multi_uid(
    tap: lttngtest.TapGenerator, test_env: lttngtest._Environment
) -> None:
    tap.diagnostic("Running test_ust_notifier_discarded_count_multi_uid")
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    uid, user = test_env.create_dummy_user()
    event_count = _get_overflow_event_count_by_pipe_size()

    # Add root trigger
    root_trigger = client.add_trigger(
        lttngtest.lttngctl.EventRuleMatchesCondition(
            lttngtest.lttngctl.UserTracepointEventRule("tp:tptest")
        ),
        [lttngtest.lttngctl.NotifyTriggerAction()],
    )

    root_discarded_before = _get_discarded_messages(
        client.list_triggers(), root_trigger.name
    )
    tap.diagnostic(
        "trigger '{}' discarded tracer messages before application run: {}".format(
            root_trigger.name, root_discarded_before
        )
    )

    # Add user trigger
    user_trigger = client.add_trigger(
        lttngtest.lttngctl.EventRuleMatchesCondition(
            lttngtest.lttngctl.UserTracepointEventRule("tp:tptest")
        ),
        [lttngtest.lttngctl.NotifyTriggerAction()],
        owner_uid=uid,
    )

    user_discarded_before = _get_discarded_messages(
        client.list_triggers(), user_trigger.name
    )
    tap.diagnostic(
        "trigger '{}' discarded tracer messages before application run: {}".format(
            user_trigger.name, user_discarded_before
        )
    )

    # Pause notifications
    test_env.lttng_sessiond_pause_notifications()

    # Run test app as root
    app = test_env.launch_wait_trace_test_application(event_count)
    app.trace()
    app.wait_for_tracing_done()
    app.wait_for_exit()

    # Run test app as user
    app = test_env.launch_wait_trace_test_application(event_count, run_as=user)
    app.trace()
    app.wait_for_tracing_done()
    app.wait_for_exit()

    # Check discarded events for root and user
    triggers = client.list_triggers()
    root_discarded_after = _get_discarded_messages(triggers, root_trigger.name)
    tap.diagnostic(
        "trigger '{}' discarded tracer messages after application run: {}".format(
            root_trigger.name, root_discarded_after
        )
    )
    user_discarded_after = _get_discarded_messages(triggers, user_trigger.name)
    tap.diagnostic(
        "trigger '{}' discarded tracer messages after application run: {}".format(
            user_trigger.name, user_discarded_after
        )
    )

    # Unpause notifications
    test_env.lttng_sessiond_pause_notifications(False)

    # Remove triggers
    client.remove_trigger(root_trigger)
    client.remove_trigger(user_trigger)

    tap.test(
        root_discarded_before == 0
        and user_discarded_before == 0
        and root_discarded_after > 0
        and user_discarded_after > 0,
        "Triggers had no discarded events before application run, and had discarded events afterwards: root_discarded_before={}, user_discarded_before={}, root_discarded_after={}, user_discarded_after={}".format(
            root_discarded_before,
            user_discarded_before,
            root_discarded_after,
            user_discarded_after,
        ),
    )


def test_ust_notifier_discarded_regardless_trigger_owner(
    tap: lttngtest.TapGenerator, test_env: lttngtest._Environment
) -> None:
    tap.diagnostic("Running test_ust_notifier_discarded_regardless_trigger_owner")
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    uid, user = test_env.create_dummy_user()
    event_count = _get_overflow_event_count_by_pipe_size()

    # Add root trigger
    root_trigger = client.add_trigger(
        lttngtest.lttngctl.EventRuleMatchesCondition(
            lttngtest.lttngctl.UserTracepointEventRule("tp:tptest")
        ),
        [lttngtest.lttngctl.NotifyTriggerAction()],
    )

    root_discarded_before = _get_discarded_messages(
        client.list_triggers(), root_trigger.name
    )
    tap.diagnostic(
        "trigger '{}' discarded tracer messages before application run: {}".format(
            root_trigger.name, root_discarded_before
        )
    )

    # Pause notifications
    test_env.lttng_sessiond_pause_notifications()

    # Run app as user
    app = test_env.launch_wait_trace_test_application(event_count, run_as=user)
    app.trace()
    app.wait_for_tracing_done()
    app.wait_for_exit()

    # Verify that triggers are discarded
    # Check discarded events for root and user
    root_discarded_after = _get_discarded_messages(
        client.list_triggers(), root_trigger.name
    )
    tap.diagnostic(
        "trigger '{}' discarded tracer messages before application run: {}".format(
            root_trigger.name, root_discarded_before
        )
    )

    # Unpause notifications
    test_env.lttng_sessiond_pause_notifications(False)

    # Remove trigger
    client.remove_trigger(root_trigger)
    tap.test(
        root_discarded_before == 0 and root_discarded_after > 0,
        "Trigger '{}' as no discarded events before traced application is run as another user, and has discarded events afterwards: before={}, after={}".format(
            root_trigger.name, root_discarded_before, root_discarded_after
        ),
    )
