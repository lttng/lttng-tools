#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Kienan Stewart <kstewart@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#

import logging
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


class TestEnvApplication:
    def __init__(self, test_env: lttngtest._Environment):
        self._test_env = test_env
        self._process: typing.Optional[subprocess.Popen] = None
        self._temp_dir: pathlib.Path = self._test_env.create_temporary_directory()

    @property
    def pid(self) -> int:
        return self._process.pid

    def terminate(self) -> None:
        self._process.terminate()

    def wait_for_exit(self) -> None:
        if not self._process:
            raise RuntimeError("No subprocess")

        while self._process.poll() is None:
            time.sleep(0.1)

        return self._process.poll()

    def __del__(self) -> None:
        if self._process is not None and self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(self._test_env.teardown_timeout)
            except subprocess.TimeoutExpired:
                self._process.kill()


class BaseClient(TestEnvApplication):
    def __init__(self, test_env: lttngtest._Environment):
        super().__init__(test_env)
        self._output_file: typing.Optional[pathlib.Path] = None

    @property
    def output_file(self) -> typing.Optional[pathlib.Path]:
        return self._output_file

    def start(
        self,
        session_name: str,
        channel_name: str,
        domain: lttngtest.lttngctl.TracingDomain,
        buffer_usage_type: str,
        buffer_usage_threshold_type: str,
        buffer_usage_threshold: float,
        expected_notifications: int,
        use_action_list: bool,
        extra_env=dict(),
    ) -> None:
        if self._process is not None:
            raise RuntimeError("BaseClient already started")

        self._output_file = self._temp_dir / "output"
        self._output_file.touch()
        script = pathlib.Path(__file__).absolute().parents[0] / "base_client"
        env = self._test_env.get_ust_test_app_env(extra_env)
        args = [
            str(script),
            session_name,
            channel_name,
            (
                "LTTNG_DOMAIN_UST"
                if domain == lttngtest.lttngctl.TracingDomain.User
                else "LTTNG_DOMAIN_KERNEL"
            ),
            buffer_usage_type,
            buffer_usage_threshold_type,
            str(buffer_usage_threshold),
            str(expected_notifications),
            "1" if use_action_list else "0",
        ]
        logging.debug("Starting BaseClient: {}".format(args))
        self._process = subprocess.Popen(
            args, env=env, stdout=open(self._output_file, "w")
        )
        logging.debug("BaseClient started with pid: {}".format(self._process.pid))

    def _output_contains(self, message: str) -> bool:
        with open(self._output_file, "r") as f:
            content = f.readlines()

        for line in content:
            if message in line:
                return True

            if line.startswith("error:"):
                raise RuntimeError("Error found in BaseClient output: {}".format(line))

        return False

    def errors(self) -> typing.List[str]:
        e = list()
        with open(self._output_file, "r") as f:
            content = f.readlines()

        for line in content:
            if line.startswith("error:"):
                e.append(line)

        return e

    def wait_for_message(self, message: str) -> None:
        while not self._output_contains(message):
            if self._process is None:
                raise RuntimeError("BaseClient not started")

            time.sleep(0.1)

    def wait_until_ready(self) -> None:
        self.wait_for_message("sync: ready")

    def wait_until_high(self, number: int = None) -> None:
        self.wait_for_message(
            "notification: high{}".format(
                "" if number is None else " {}".format(number)
            )
        )

    def wait_until_low(self, number: int = None) -> None:
        self.wait_for_message(
            "notification: low{}".format("" if number is None else " {}".format(number))
        )

    def wait_until_exit_message(self) -> None:
        self.wait_for_message("exit: 0")


class EventGenerator(TestEnvApplication):
    def __init__(self, test_env: lttngtest._Environment):
        super().__init__(test_env)
        self._ready_file: typing.Optional[pathlib.Path] = None
        self._state_file: typing.Optional[pathlib.Path] = None

    def start(
        self,
        target: str = "userspace_testapp",
        extra_env: typing.Dict[str, str] = dict(),
    ) -> None:
        if self._process is not None:
            raise RuntimeError("Generator already started")

        self._ready_file = self._temp_dir / "generator_ready"
        self._state_file = self._temp_dir / "testapp_state"
        self._state_file.touch()

        event_generator_script = (
            pathlib.Path(__file__).absolute().parents[0] / "util_event_generator.py"
        )
        event_generator_env = self._test_env.get_ust_test_app_env(extra_env)
        args = [
            str(event_generator_script),
            "--ready-file",
            str(self._ready_file),
            "--state-file",
            str(self._state_file),
            target,
        ]
        logging.debug("Starting event generator script: {}".format(args))
        self._process = subprocess.Popen(args, env=event_generator_env)
        logging.info("Event generator started with pid: {}".format(self._process.pid))

    def ready(self) -> bool:
        if self._process is None:
            raise RuntimeError("Generator not started")

        return self._ready_file.is_file()

    def toggle(self, wait=True) -> None:
        if self._process is None:
            raise RuntimeError("Generator not started")

        self._process.send_signal(signal.SIGUSR1)
        if not wait:
            return

        while self._state_file.is_file():
            if self._process.poll() is not None:
                raise RuntimeError("Generator died while waiting to toggle state")

            time.sleep(0.1)

    def wait_until_ready(self) -> None:
        while not self.ready():
            if self._process.poll() is not None:
                raise RuntimeError("Generator exited unexpectedly")

            time.sleep(0.1)

    def stop(self) -> None:
        if not self._process:
            raise RuntimeError("Generator not started")

        if self._process.poll() is not None:
            return

        self._process.send_signal(signal.SIGUSR2)

    @property
    def state_file(self) -> typing.Optional[pathlib.Path]:
        return self._state_file


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

    event_generator = EventGenerator(test_env)
    target = (
        "userspace_testapp"
        if domain == lttngtest.lttngctl.TracingDomain.User
        else "kernel_generate_filter_events"
    )
    event_generator.start(
        target,
        {
            "EVENT_GENERATOR_SCRIPT": str(
                test_env._project_root
                / "tests"
                / "utils"
                / "testapp"
                / "gen-ust-events"
            )
        },
    )
    event_generator.wait_until_ready()
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
        str(event_generator.state_file),
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
    event_generator.stop()
    event_generator.wait_for_exit()


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


def test_notifier_discarded_count_max_bucket(
    tap: lttngtest.TapGenerator,
    test_env: lttngtest._Environment,
    max_bucket_size: int,
    domain: lttngtest.lttngctl.TracingDomain = lttngtest.lttngctl.TracingDomain.User,
) -> None:
    """
    Validate that adding triggers beyond the max bucket size fails.
    """
    test_passed = True
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    trigger_event_rule = (
        lttngtest.lttngctl.KernelTracepointEventRule("lttng_test_filter_event")
        if domain == lttngtest.lttngctl.TracingDomain.Kernel
        else lttngtest.lttngctl.UserTracepointEventRule("tp:tptest")
    )
    triggers = list()
    for i in range(max_bucket_size):
        try:
            triggers.append(
                client.add_trigger(
                    lttngtest.lttngctl.EventRuleMatchesCondition(trigger_event_rule),
                    [lttngtest.lttngctl.NotifyTriggerAction()],
                )
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
            triggers.append(trigger)
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

    for trigger in triggers:
        client.remove_trigger(trigger)

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
        "Trigger '{}' discarded tracer messages before application run: {}".format(
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
        "Trigger '{}' discarded tracer messages before application run: {}".format(
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


def test_multi_app(
    tap: lttngtest.TapGenerator,
    test_env: lttngtest._Environment,
    domain: lttngtest.lttngctl.TracingDomain,
    notification_client_app_count: int = 50,
    notification_cycles: int = 5,
) -> None:
    tap.diagnostic("Running test_multi_app with domain={}".format(domain))
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    consumerd_type = (
        lttngtest.ConsumerType.KERNEL
        if domain == lttngtest.lttngctl.TracingDomain.Kernel
        else (
            lttngtest.ConsumerType.UST64
            if platform.architecture()[0] == "64bit"
            else lttngtest.ConsumerType.UST32
        )
    )
    notification_clients_low = list()
    notification_clients_high = list()
    test_passed = True

    # Run generator script
    event_generator = EventGenerator(test_env)
    target = (
        "userspace_testapp"
        if domain == lttngtest.lttngctl.TracingDomain.User
        else "kernel_generate_filter_events"
    )
    event_generator.start(
        target,
        (
            {
                "TESTAPP_BIN": str(
                    test_env._project_root
                    / "tests"
                    / "utils"
                    / "testapp"
                    / "gen-ust-events"
                )
            }
            if domain == lttngtest.lttngctl.TracingDomain.User
            else dict()
        ),
    )

    event_generator.wait_until_ready()

    output_path = test_env.create_temporary_directory("trace")
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

    for i in range(notification_client_app_count):
        client_high_args = [
            session.name,
            channel.name,
            domain,
            "HIGH",
            "RATIO",
            0.420,
            notification_cycles,
            i % 2 != 0,
        ]
        client_low_args = [
            session.name,
            channel.name,
            domain,
            "LOW",
            "RATIO",
            0.0,
            notification_cycles,
            i % 2 != 0,
        ]

        # Start a low
        client_low = BaseClient(test_env)
        client_low.start(*client_low_args)
        client_low.wait_until_ready()
        tap.diagnostic("Client Low {} ready".format(i + 1))
        notification_clients_low.append(client_low)

        # Start a high
        client_high = BaseClient(test_env)
        client_high.start(*client_high_args)
        client_high.wait_until_ready()
        tap.diagnostic("Client High {} ready".format(i + 1))
        notification_clients_high.append(client_high)

    # Do N cycles
    for i in range(notification_cycles):
        tap.diagnostic(
            "Starting notification cycle {}/{}".format(i + 1, notification_cycles)
        )
        # Activate generator
        event_generator.toggle()

        # Pause consumerd
        test_env.lttng_consumerd_pause(consumerd_type)

        # Start tracing
        session.start()

        # Wait for notification high for this cycle
        for notification_client in notification_clients_high:
            notification_client.wait_until_high(i)

        # Pause generator
        event_generator.toggle()

        # Unpause consumerd
        test_env.lttng_consumerd_pause(consumerd_type, False)

        # Stop session
        session.stop()

        # Wait for low notification
        for notification_client in notification_clients_low:
            notification_client.wait_until_low(i)

    # Wait for exit on all low and high test apps
    for notification_client in notification_clients_low + notification_clients_high:
        notification_client.wait_until_exit_message()
        notification_client.wait_for_exit()
        if notification_client._process.returncode != 0:
            test_passed = False
            tap.diagnostic(
                "Notification client returned non-zero exit code: ret={}".format(
                    notification_client._process.returncode
                )
            )

        if notification_client.errors():
            test_passed = False
            tap.diagnostic(
                "Notification client has errors: {}".format(
                    notification_client.errors()
                )
            )

    # Clean-up
    event_generator.stop()
    event_generator.wait_for_exit()
    session.destroy()
    tap.test(test_passed, "All notification clients received expected notifications")


def test_on_register_evaluation(
    tap: lttngtest.TapGenerator,
    test_env: lttngtest._Environment,
    domain: lttngtest.lttngctl.TracingDomain,
) -> None:
    tap.diagnostic("Running test_on_register_evaluation with domain={}".format(domain))
    test_passed = True
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    consumerd_type = (
        lttngtest.ConsumerType.KERNEL
        if domain == lttngtest.lttngctl.TracingDomain.Kernel
        else (
            lttngtest.ConsumerType.UST64
            if platform.architecture()[0] == "64bit"
            else lttngtest.ConsumerType.UST32
        )
    )

    # Run generator script
    event_generator = EventGenerator(test_env)
    target = (
        "userspace_testapp"
        if domain == lttngtest.lttngctl.TracingDomain.User
        else "kernel_generate_filter_events"
    )
    event_generator.start(
        target,
        (
            {
                "TESTAPP_BIN": str(
                    test_env._project_root
                    / "tests"
                    / "utils"
                    / "testapp"
                    / "gen-ust-events"
                )
            }
            if domain == lttngtest.lttngctl.TracingDomain.User
            else dict()
        ),
    )
    event_generator.wait_until_ready()

    # Create session
    output_path = test_env.create_temporary_directory("trace")
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

    # Start  client
    client_args = [session.name, channel.name, domain, "HIGH", "RATIO", 0.420, 1, False]
    client = BaseClient(test_env)
    client.start(*client_args)
    client.wait_until_ready()
    tap.diagnostic("Client 1 ready")

    # Start session
    session.start()

    # Pause consumer
    test_env.lttng_consumerd_pause(consumerd_type)

    # Set the generator to active mode
    event_generator.toggle()

    # Wait for high
    client.wait_until_high()
    tap.diagnostic("Client 1 received high buffer usage notification")

    # Start 2nd client
    client2 = BaseClient(test_env)
    client2.start(*client_args)
    client2.wait_until_ready()
    tap.diagnostic("Client 2 ready")
    # Wait for high on 2nd client
    client2.wait_until_high()
    tap.diagnostic("Client 2 received high buffer usage notification")

    # Unpause
    test_env.lttng_consumerd_pause(consumerd_type, False)

    # Wait for client and client2 exit
    client.wait_until_exit_message()
    tap.diagnostic("Client 1 sent exit message")
    client.wait_for_exit()
    if client._process.returncode != 0:
        test_passed = False
        tap.diagnostic(
            "Client 1 returned a non-zero exit code: ret={}".format(
                client._process.returncode
            )
        )

    client2.wait_until_exit_message()
    tap.diagnostic("Client 2 sent exit message")
    client2.wait_for_exit()
    if client2._process.returncode != 0:
        test_passed = False
        tap.diagnostic(
            "Client 2 returned a non-zero exit code: ret={}".format(
                client2._process.returncode
            )
        )

    # Destroy session
    session.destroy()

    # Terminate generator
    event_generator.stop()
    event_generator.wait_for_exit()

    tap.test(
        test_passed,
        "Notification clients received expected notifications",
    )
