#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
#
# SPDX-License-Identifier: GPL-2.0-only


from . import lttngctl, logger, environment

import enum
import os
import shlex
import sqlite3
import subprocess
import tempfile
from typing import Callable, List, Optional, Type, Union, Iterator
import xml.etree.ElementTree

"""
Implementation of the lttngctl interface based on the `lttng` command line client.
"""


class Unsupported(lttngctl.ControlException):
    def __init__(self, msg):
        # type: (str) -> None
        super().__init__(msg)


class InvalidMI(lttngctl.ControlException):
    def __init__(self, msg):
        # type: (str) -> None
        super().__init__(msg)


class ChannelNotFound(lttngctl.ControlException):
    def __init__(self, msg):
        # type: (str) -> None
        super().__init__(msg)


def _get_domain_option_name(domain):
    # type: (lttngctl.TracingDomain) -> str
    return {
        lttngctl.TracingDomain.User: "userspace",
        lttngctl.TracingDomain.Kernel: "kernel",
        lttngctl.TracingDomain.Log4j: "log4j",
        lttngctl.TracingDomain.Log4j2: "log4j2",
        lttngctl.TracingDomain.Python: "python",
        lttngctl.TracingDomain.JUL: "jul",
    }[domain]


def _get_domain_xml_mi_name(domain):
    # type: (lttngctl.TracingDomain) -> str
    return {
        lttngctl.TracingDomain.User: "UST",
        lttngctl.TracingDomain.Kernel: "KERNEL",
        lttngctl.TracingDomain.Log4j: "LOG4J",
        lttngctl.TracingDomain.Log4j2: "LOG4J2",
        lttngctl.TracingDomain.Python: "PYTHON",
        lttngctl.TracingDomain.JUL: "JUL",
    }[domain]


def _domain_from_xml_mi_name(name):
    # type: (str) -> lttngctl.TracingDomain
    return {
        "UST": lttngctl.TracingDomain.User,
        "KERNEL": lttngctl.TracingDomain.Kernel,
        "LOG4J": lttngctl.TracingDomain.Log4j,
        "LOG4J2": lttngctl.TracingDomain.Log4j2,
        "PYTHON": lttngctl.TracingDomain.Python,
        "JUL": lttngctl.TracingDomain.JUL,
    }[name]


def _get_condition_domain_arg(domain):
    # type: (lttngctl.TracingDomain) -> str

    return {
        lttngctl.TracingDomain.User: "user",
        lttngctl.TracingDomain.Kernel: "kernel",
        lttngctl.TracingDomain.Log4j: "log4j",
        lttngctl.TracingDomain.Log4j2: "log4j2",
        lttngctl.TracingDomain.Python: "python",
        lttngctl.TracingDomain.JUL: "jul",
    }[domain]


def _get_context_type_name(context):
    # type: (lttngctl.ContextType) -> str
    if isinstance(context, lttngctl.VgidContextType):
        return "vgid"
    elif isinstance(context, lttngctl.VuidContextType):
        return "vuid"
    elif isinstance(context, lttngctl.VpidContextType):
        return "vpid"
    elif isinstance(context, lttngctl.CPUidContextType):
        return "cpu_id"
    elif isinstance(context, lttngctl.JavaApplicationContextType):
        return "$app.{retriever}:{field}".format(
            retriever=context.retriever_name, field=context.field_name
        )
    else:
        raise Unsupported(
            "Context `{context_name}` is not supported by the LTTng client".format(
                context_name=type(context).__name__
            )
        )


def _get_log_level_argument_name(log_level):
    # type: (lttngctl.LogLevel) -> str
    if isinstance(log_level, lttngctl.UserLogLevel):
        return {
            lttngctl.UserLogLevel.EMERGENCY: "EMER",
            lttngctl.UserLogLevel.ALERT: "ALERT",
            lttngctl.UserLogLevel.CRITICAL: "CRIT",
            lttngctl.UserLogLevel.ERROR: "ERR",
            lttngctl.UserLogLevel.WARNING: "WARNING",
            lttngctl.UserLogLevel.NOTICE: "NOTICE",
            lttngctl.UserLogLevel.INFO: "INFO",
            lttngctl.UserLogLevel.DEBUG_SYSTEM: "DEBUG_SYSTEM",
            lttngctl.UserLogLevel.DEBUG_PROGRAM: "DEBUG_PROGRAM",
            lttngctl.UserLogLevel.DEBUG_PROCESS: "DEBUG_PROCESS",
            lttngctl.UserLogLevel.DEBUG_MODULE: "DEBUG_MODULE",
            lttngctl.UserLogLevel.DEBUG_UNIT: "DEBUG_UNIT",
            lttngctl.UserLogLevel.DEBUG_FUNCTION: "DEBUG_FUNCTION",
            lttngctl.UserLogLevel.DEBUG_LINE: "DEBUG_LINE",
            lttngctl.UserLogLevel.DEBUG: "DEBUG",
        }[log_level]
    elif isinstance(log_level, lttngctl.JULLogLevel):
        return {
            lttngctl.JULLogLevel.OFF: "OFF",
            lttngctl.JULLogLevel.SEVERE: "SEVERE",
            lttngctl.JULLogLevel.WARNING: "WARNING",
            lttngctl.JULLogLevel.INFO: "INFO",
            lttngctl.JULLogLevel.CONFIG: "CONFIG",
            lttngctl.JULLogLevel.FINE: "FINE",
            lttngctl.JULLogLevel.FINER: "FINER",
            lttngctl.JULLogLevel.FINEST: "FINEST",
            lttngctl.JULLogLevel.ALL: "ALL",
        }[log_level]
    elif isinstance(log_level, lttngctl.Log4jLogLevel):
        return {
            lttngctl.Log4jLogLevel.OFF: "OFF",
            lttngctl.Log4jLogLevel.FATAL: "FATAL",
            lttngctl.Log4jLogLevel.ERROR: "ERROR",
            lttngctl.Log4jLogLevel.WARN: "WARN",
            lttngctl.Log4jLogLevel.INFO: "INFO",
            lttngctl.Log4jLogLevel.DEBUG: "DEBUG",
            lttngctl.Log4jLogLevel.TRACE: "TRACE",
            lttngctl.Log4jLogLevel.ALL: "ALL",
        }[log_level]
    elif isinstance(log_level, lttngctl.Log4j2LogLevel):
        return {
            lttngctl.Log4j2LogLevel.OFF: "OFF",
            lttngctl.Log4j2LogLevel.FATAL: "FATAL",
            lttngctl.Log4j2LogLevel.ERROR: "ERROR",
            lttngctl.Log4j2LogLevel.WARN: "WARN",
            lttngctl.Log4j2LogLevel.INFO: "INFO",
            lttngctl.Log4j2LogLevel.DEBUG: "DEBUG",
            lttngctl.Log4j2LogLevel.TRACE: "TRACE",
            lttngctl.Log4j2LogLevel.ALL: "ALL",
        }[log_level]
    elif isinstance(log_level, lttngctl.PythonLogLevel):
        return {
            lttngctl.PythonLogLevel.CRITICAL: "CRITICAL",
            lttngctl.PythonLogLevel.ERROR: "ERROR",
            lttngctl.PythonLogLevel.WARNING: "WARNING",
            lttngctl.PythonLogLevel.INFO: "INFO",
            lttngctl.PythonLogLevel.DEBUG: "DEBUG",
            lttngctl.PythonLogLevel.NOTSET: "NOTSET",
        }[log_level]

    raise TypeError("Unknown log level type")


def _get_log_level_from_mi_log_level_name(mi_log_level_name):
    # type: (str) -> lttngctl.LogLevel
    return {
        "TRACE_EMERG": lttngctl.UserLogLevel.EMERGENCY,
        "TRACE_ALERT": lttngctl.UserLogLevel.ALERT,
        "TRACE_CRIT": lttngctl.UserLogLevel.CRITICAL,
        "TRACE_ERR": lttngctl.UserLogLevel.ERROR,
        "TRACE_WARNING": lttngctl.UserLogLevel.WARNING,
        "TRACE_NOTICE": lttngctl.UserLogLevel.NOTICE,
        "TRACE_INFO": lttngctl.UserLogLevel.INFO,
        "TRACE_DEBUG_SYSTEM": lttngctl.UserLogLevel.DEBUG_SYSTEM,
        "TRACE_DEBUG_PROGRAM": lttngctl.UserLogLevel.DEBUG_PROGRAM,
        "TRACE_DEBUG_PROCESS": lttngctl.UserLogLevel.DEBUG_PROCESS,
        "TRACE_DEBUG_MODULE": lttngctl.UserLogLevel.DEBUG_MODULE,
        "TRACE_DEBUG_UNIT": lttngctl.UserLogLevel.DEBUG_UNIT,
        "TRACE_DEBUG_FUNCTION": lttngctl.UserLogLevel.DEBUG_FUNCTION,
        "TRACE_DEBUG_LINE": lttngctl.UserLogLevel.DEBUG_LINE,
        "TRACE_DEBUG": lttngctl.UserLogLevel.DEBUG,
        "JUL_OFF": lttngctl.JULLogLevel.OFF,
        "JUL_SEVERE": lttngctl.JULLogLevel.SEVERE,
        "JUL_WARNING": lttngctl.JULLogLevel.WARNING,
        "JUL_INFO": lttngctl.JULLogLevel.INFO,
        "JUL_CONFIG": lttngctl.JULLogLevel.CONFIG,
        "JUL_FINE": lttngctl.JULLogLevel.FINE,
        "JUL_FINER": lttngctl.JULLogLevel.FINER,
        "JUL_FINEST": lttngctl.JULLogLevel.FINEST,
        "JUL_ALL": lttngctl.JULLogLevel.ALL,
        "LOG4J_OFF": lttngctl.Log4jLogLevel.OFF,
        "LOG4J_FATAL": lttngctl.Log4jLogLevel.FATAL,
        "LOG4J_ERROR": lttngctl.Log4jLogLevel.ERROR,
        "LOG4J_WARN": lttngctl.Log4jLogLevel.WARN,
        "LOG4J_INFO": lttngctl.Log4jLogLevel.INFO,
        "LOG4J_DEBUG": lttngctl.Log4jLogLevel.DEBUG,
        "LOG4J_TRACE": lttngctl.Log4jLogLevel.TRACE,
        "LOG4J_ALL": lttngctl.Log4jLogLevel.ALL,
        "LOG4J2_OFF": lttngctl.Log4j2LogLevel.OFF,
        "LOG4J2_FATAL": lttngctl.Log4j2LogLevel.FATAL,
        "LOG4J2_ERROR": lttngctl.Log4j2LogLevel.ERROR,
        "LOG4J2_WARN": lttngctl.Log4j2LogLevel.WARN,
        "LOG4J2_INFO": lttngctl.Log4j2LogLevel.INFO,
        "LOG4J2_DEBUG": lttngctl.Log4j2LogLevel.DEBUG,
        "LOG4J2_TRACE": lttngctl.Log4j2LogLevel.TRACE,
        "LOG4J2_ALL": lttngctl.Log4j2LogLevel.ALL,
        "PYTHON_CRITICAL": lttngctl.PythonLogLevel.CRITICAL,
        "PYTHON_ERROR": lttngctl.PythonLogLevel.ERROR,
        "PYTHON_WARNING": lttngctl.PythonLogLevel.WARNING,
        "PYTHON_INFO": lttngctl.PythonLogLevel.INFO,
        "PYTHON_DEBUG": lttngctl.PythonLogLevel.DEBUG,
        "PYTHON_NOTSET": lttngctl.PythonLogLevel.NOTSET,
    }[mi_log_level_name]


def _get_tracepoint_event_rule_class_from_domain_type(domain_type):
    # type: (lttngctl.TracingDomain) -> Type[lttngctl.UserTracepointEventRule] | Type[lttngctl.Log4jTracepointEventRule] | Type[lttngctl.Log4j2TracepointEventRule] | Type[lttngctl.JULTracepointEventRule] | Type[lttngctl.PythonTracepointEventRule] | Type[lttngctl.KernelTracepointEventRule]
    return {
        lttngctl.TracingDomain.User: lttngctl.UserTracepointEventRule,
        lttngctl.TracingDomain.JUL: lttngctl.JULTracepointEventRule,
        lttngctl.TracingDomain.Log4j: lttngctl.Log4jTracepointEventRule,
        lttngctl.TracingDomain.Log4j2: lttngctl.Log4j2TracepointEventRule,
        lttngctl.TracingDomain.Python: lttngctl.PythonTracepointEventRule,
        lttngctl.TracingDomain.Kernel: lttngctl.KernelTracepointEventRule,
    }[domain_type]


def _get_event_rule_type_name(rule):
    # type: (lttngctl.EventRule) -> str
    """Map EventRule subclass to --type= CLI option value for add-trigger."""
    if isinstance(rule, lttngctl.UserTracepointEventRule):
        return "user:tracepoint"
    elif isinstance(rule, lttngctl.KernelTracepointEventRule):
        return "kernel:tracepoint"
    elif isinstance(rule, lttngctl.KernelSyscallEventRule):
        return "kernel:syscall"
    elif isinstance(rule, lttngctl.KernelKprobeEventRule):
        return "kernel:kprobe"
    elif isinstance(rule, lttngctl.JULTracepointEventRule):
        return "jul:logging"
    elif isinstance(rule, lttngctl.Log4jTracepointEventRule):
        return "log4j:logging"
    elif isinstance(rule, lttngctl.Log4j2TracepointEventRule):
        return "log4j2:logging"
    elif isinstance(rule, lttngctl.PythonTracepointEventRule):
        return "python:logging"
    else:
        raise Unsupported(
            "Event rule type `{event_rule_type}` is not supported for triggers".format(
                event_rule_type=type(rule).__name__
            )
        )


def _build_event_rule_spec_args(rule):
    # type: (lttngctl.EventRule) -> List[str]
    """Build CLI arguments for event rule specification in add-trigger."""
    args = ["--type={}".format(_get_event_rule_type_name(rule))]

    # Handle name pattern (most rule types)
    if hasattr(rule, "name_pattern") and rule.name_pattern:
        args.append("--name={}".format(rule.name_pattern))

    # Handle filter expression
    if hasattr(rule, "filter_expression") and rule.filter_expression:
        args.append("--filter={}".format(rule.filter_expression))

    # Handle log level (user tracepoint and logging backends)
    if hasattr(rule, "log_level_rule") and rule.log_level_rule:
        level_name = _get_log_level_argument_name(rule.log_level_rule.level)
        if isinstance(rule.log_level_rule, lttngctl.LogLevelRuleAsSevereAs):
            args.append("--log-level={}..".format(level_name))
        elif isinstance(rule.log_level_rule, lttngctl.LogLevelRuleExactly):
            args.append("--log-level={}".format(level_name))

    # --exclude-name is only valid with --type=user:tracepoint.
    if (
        isinstance(rule, lttngctl.UserTracepointEventRule)
        and rule.name_pattern_exclusions
    ):
        for exclusion in rule.name_pattern_exclusions:
            args.append("--exclude-name={}".format(exclusion))

    # Handle kprobe-specific attributes
    if isinstance(rule, lttngctl.KernelKprobeEventRule):
        args.append("--location={}".format(rule.symbol_name))
        args.append("--event-name={}".format(rule.event_name))

    return args


def _build_rate_policy_arg(policy):
    # type: (lttngctl.RatePolicy) -> str
    """Build --rate-policy= CLI argument from a RatePolicy object."""
    if isinstance(policy, lttngctl.EveryNRatePolicy):
        return "--rate-policy=every:{}".format(policy.interval)
    elif isinstance(policy, lttngctl.OnceAfterNRatePolicy):
        return "--rate-policy=once-after:{}".format(policy.count)
    else:
        raise Unsupported(
            "Rate policy type `{}` is not supported".format(type(policy).__name__)
        )


def _build_action_args(action):
    # type: (lttngctl.TriggerAction) -> List[str]
    """Build CLI arguments for a trigger action."""
    args = []  # type: List[str]

    if isinstance(action, lttngctl.NotifyTriggerAction):
        args.append("--action=notify")
    elif isinstance(action, lttngctl.StartSessionTriggerAction):
        args.extend(["--action=start-session", action.session_name])
    elif isinstance(action, lttngctl.StopSessionTriggerAction):
        args.extend(["--action=stop-session", action.session_name])
    elif isinstance(action, lttngctl.RotateSessionTriggerAction):
        args.extend(["--action=rotate-session", action.session_name])
    elif isinstance(action, lttngctl.SnapshotSessionTriggerAction):
        args.extend(["--action=snapshot-session", action.session_name])
        if action.output_name:
            args.append("--name={}".format(action.output_name))
        if action.max_size:
            args.append("--max-size={}".format(action.max_size))
        if action.path:
            args.append("--path={}".format(action.path))
        elif action.url:
            args.append("--url={}".format(action.url))
        elif action.ctrl_url and action.data_url:
            args.append("--ctrl-url={}".format(action.ctrl_url))
            args.append("--data-url={}".format(action.data_url))
    elif isinstance(action, lttngctl.IncrementMapValueTriggerAction):
        args.extend(
            [
                "--action=incr-map-value",
                "--session={}".format(action.session_name),
                "--channel={}".format(action.channel_name),
                "--type={}".format(_MAP_CHANNEL_TYPE_ARGS[action.channel_type]),
                "--key={}".format(action.key_template),
            ]
        )
    else:
        raise Unsupported(
            "Action type `{}` is not supported".format(type(action).__name__)
        )

    if isinstance(action, lttngctl._RatePolicyAction) and action.rate_policy:
        args.append(_build_rate_policy_arg(action.rate_policy))

    return args


def _mi_local_name(element):
    # type: (xml.etree.ElementTree.Element) -> str
    """Return the local (namespace-stripped) name of an MI element's tag."""
    return element.tag.split("}", 1)[-1]


# Maps an agent-domain event rule MI element name to its EventRule class and
# the LogLevel enum to interpret its log level rule with. The MI serializes log
# levels as their numeric value, so the relevant enum depends on the domain.
_AGENT_EVENT_RULE_FROM_MI = {
    "event_rule_jul_logging": (
        lttngctl.JULTracepointEventRule,
        lttngctl.JULLogLevel,
    ),
    "event_rule_log4j_logging": (
        lttngctl.Log4jTracepointEventRule,
        lttngctl.Log4jLogLevel,
    ),
    "event_rule_log4j2_logging": (
        lttngctl.Log4j2TracepointEventRule,
        lttngctl.Log4j2LogLevel,
    ),
    "event_rule_python_logging": (
        lttngctl.PythonTracepointEventRule,
        lttngctl.PythonLogLevel,
    ),
}


class _Trigger(lttngctl.Trigger):
    def __init__(
        self,
        client,  # type: LTTngClient
        name,  # type: Optional[str]
        owner_uid,  # type: Optional[int]
        condition,  # type: lttngctl.TriggerCondition
        actions,  # type: List[lttngctl.TriggerAction]
        error_query_results: List[lttngctl.ErrorQueryResult],
    ):
        self._client = client
        self._name = name
        self._owner_uid = owner_uid
        self._condition = condition
        self._actions = actions
        self._error_query_results = error_query_results

    @property
    def name(self):
        # type: () -> Optional[str]
        return self._name

    @property
    def owner_uid(self):
        # type: () -> Optional[int]
        return self._owner_uid

    @property
    def condition(self):
        # type: () -> lttngctl.TriggerCondition
        return self._condition

    @property
    def actions(self):
        # type: () -> List[lttngctl.TriggerAction]
        return self._actions

    @property
    def error_query_results(self) -> List[lttngctl.ErrorQueryResult]:
        return self._error_query_results


class _Channel(lttngctl.Channel):
    def __init__(
        self,
        client,  # type: LTTngClient
        name,  # type: str
        domain,  # type: lttngctl.TracingDomain
        session,  # type: _Session
    ):
        self._client = client  # type: LTTngClient
        self._name = name  # type: str
        self._domain = domain  # type: lttngctl.TracingDomain
        self._session = session  # type: _Session

    def add_context(self, context_type):
        # type: (lttngctl.ContextType) -> None
        domain_option_name = _get_domain_option_name(self.domain)
        context_type_name = _get_context_type_name(context_type)
        self._client._run_cmd(
            "add-context --{domain_option_name} --channel '{channel_name}' --type {context_type_name}".format(
                domain_option_name=domain_option_name,
                channel_name=self.name,
                context_type_name=context_type_name,
            )
        )

    def add_recording_rule(self, rule):
        # type: (lttngctl.EventRule) -> None
        client_args = (
            "enable-event --session {session_name} --channel {channel_name}".format(
                session_name=self._session.name, channel_name=self.name
            )
        )
        if isinstance(rule, lttngctl.TracepointEventRule):
            domain_option_name = (
                "userspace"
                if isinstance(rule, lttngctl.UserTracepointEventRule)
                else "kernel"
            )
            client_args = client_args + " --{domain_option_name}".format(
                domain_option_name=domain_option_name
            )

            if rule.name_pattern:
                client_args = client_args + " " + rule.name_pattern
            else:
                client_args = client_args + " --all"

            if rule.filter_expression:
                client_args = (
                    client_args + " --filter " + shlex.quote(rule.filter_expression)
                )

            if getattr(rule, "log_level_rule", None):
                if isinstance(rule.log_level_rule, lttngctl.LogLevelRuleAsSevereAs):
                    client_args = client_args + " --loglevel {log_level}".format(
                        log_level=_get_log_level_argument_name(
                            rule.log_level_rule.level
                        )
                    )
                elif isinstance(rule.log_level_rule, lttngctl.LogLevelRuleExactly):
                    client_args = client_args + " --loglevel-only {log_level}".format(
                        log_level=_get_log_level_argument_name(
                            rule.log_level_rule.level
                        )
                    )
                else:
                    raise Unsupported(
                        "Unsupported log level rule type `{log_level_rule_type}`".format(
                            log_level_rule_type=type(rule.log_level_rule).__name__
                        )
                    )

            if getattr(rule, "name_pattern_exclusions", None):
                client_args = client_args + " --exclude "
                for idx, pattern in enumerate(rule.name_pattern_exclusions):
                    if idx != 0:
                        client_args = client_args + ","
                    client_args = client_args + pattern
        elif isinstance(rule, lttngctl.KernelSyscallEventRule):
            client_args = client_args + " --kernel --syscall"

            if rule.name_pattern:
                client_args = client_args + " " + rule.name_pattern
            else:
                client_args = client_args + " --all"

            if rule.filter_expression:
                client_args = (
                    client_args + " --filter " + shlex.quote(rule.filter_expression)
                )
        elif isinstance(rule, lttngctl.KernelKprobeEventRule):
            client_args = (
                client_args
                + " --kernel --probe {symbol_name} {event_name}".format(
                    symbol_name=rule.symbol_name, event_name=rule.event_name
                )
            )
        elif isinstance(rule, lttngctl.KernelFunctionEventRule):
            client_args = (
                client_args
                + " --kernel --function {symbol_name} {event_name}".format(
                    symbol_name=rule.symbol_name, event_name=rule.event_name
                )
            )
        else:
            raise Unsupported(
                "event rule type `{event_rule_type}` is unsupported by LTTng client".format(
                    event_rule_type=type(rule).__name__
                )
            )

        self._client._run_cmd(client_args)

    def disable_recording_rules(self, name_pattern):
        # type: (str) -> None
        domain_option_name = _get_domain_option_name(self.domain)
        self._client._run_cmd(
            "disable-event --session {session_name} --channel {channel_name}"
            " --{domain_option_name} {name_pattern}".format(
                session_name=self._session.name,
                channel_name=self.name,
                domain_option_name=domain_option_name,
                name_pattern=name_pattern,
            )
        )

    def disable_all_recording_rules(self):
        # type: () -> None
        domain_option_name = _get_domain_option_name(self.domain)
        self._client._run_cmd(
            "disable-event --session {session_name} --channel {channel_name}"
            " --{domain_option_name} --all-events".format(
                session_name=self._session.name,
                channel_name=self.name,
                domain_option_name=domain_option_name,
            )
        )

    @property
    def name(self):
        # type: () -> str
        return self._name

    @property
    def domain(self):
        # type: () -> lttngctl.TracingDomain
        return self._domain

    @property
    def recording_rules(self):
        # type: () -> Iterator[lttngctl.EventRule]
        target_domain = self._session._get_mi_domain(self.domain)

        if target_domain is None:
            raise ChannelNotFound(
                "Failed to find channel `{channel_name}`: no channel in target domain".format(
                    channel_name=self.name
                )
            )

        target_channel = None
        for channel in LTTngClient._mi_get_in_element(target_domain, "channels"):
            if LTTngClient._mi_get_in_element(channel, "name").text == self.name:
                target_channel = channel
                break

        if target_channel is None:
            raise ChannelNotFound(
                "Failed to find channel `{channel_name}`: no such channel in target domain".format(
                    channel_name=self.name
                )
            )

        tracepoint_event_rule_class = _get_tracepoint_event_rule_class_from_domain_type(
            self.domain
        )

        for event in LTTngClient._mi_get_in_element(target_channel, "events"):
            yield from _Session._parse_event_rule(
                event, self.domain, tracepoint_event_rule_class
            )


# Tracing domain hosting the map channels of each map channel type.
_MAP_CHANNEL_TRACING_DOMAINS = {
    lttngctl.UserMapChannel: lttngctl.TracingDomain.User,
    lttngctl.KernelMapChannel: lttngctl.TracingDomain.Kernel,
}


# `--type` option value of the lttng client for each map channel type.
_MAP_CHANNEL_TYPE_ARGS = {
    lttngctl.UserMapChannel: "user",
    lttngctl.KernelMapChannel: "kernel",
}


def _get_map_channel_type_from_mi(channel_type):
    # type: (str) -> Type[lttngctl.MapChannel]
    """Return the map channel type matching a `channel_type` MI value."""
    return {
        "user": lttngctl.UserMapChannel,
        "kernel": lttngctl.KernelMapChannel,
    }[channel_type]


def _get_map_channel_value_type_from_mi(value_type):
    # type: (str) -> lttngctl.MapChannelValueType
    """Return the value type matching a map channel `value_type` MI value."""
    return {
        "signed-int-32": lttngctl.MapChannelValueType.SignedInt32,
        "signed-int-64": lttngctl.MapChannelValueType.SignedInt64,
        "signed-int-max": lttngctl.MapChannelValueType.SignedIntMax,
    }[value_type]


def _get_map_channel_update_policy_from_mi(update_policy):
    # type: (str) -> lttngctl.MapChannelUpdatePolicy
    """Return the update policy matching a map channel `update_policy` MI value."""
    return {
        "per-event": lttngctl.MapChannelUpdatePolicy.PerEvent,
        "per-rule-match": lttngctl.MapChannelUpdatePolicy.PerRuleMatch,
    }[update_policy]


def _get_buffer_sharing_policy_from_mi(buffer_ownership):
    # type: (str) -> lttngctl.BufferSharingPolicy
    """
    Return the buffer sharing policy matching a map channel `buffer_ownership`
    MI value.
    """
    return {
        "per-uid": lttngctl.BufferSharingPolicy.PerUID,
        "per-pid": lttngctl.BufferSharingPolicy.PerPID,
    }[buffer_ownership]


def _get_map_channel_dead_process_policy_from_mi(dead_group_policy):
    # type: (str) -> lttngctl.MapChannelDeadProcessPolicy
    """
    Return the dead process policy matching a map channel `dead_group_policy`
    MI value.
    """
    return {
        "drop": lttngctl.MapChannelDeadProcessPolicy.Drop,
        "sum-into-shared": lttngctl.MapChannelDeadProcessPolicy.SumIntoShared,
    }[dead_group_policy]


# Maps the `type` MI element text of a `<map_group>` element to
# its `MapGroupType`.
_MAP_GROUP_TYPE_FROM_MI = {
    "kernel-global": lttngctl.MapGroupType.KernelGlobal,
    "user-per-user": lttngctl.MapGroupType.UserPerUser,
    "user-per-process": lttngctl.MapGroupType.UserPerProcess,
    "shared": lttngctl.MapGroupType.Shared,
}


def _map_group_from_mi(map_group_elem):
    # type: (xml.etree.ElementTree.Element) -> lttngctl.MapGroup
    group_type = _MAP_GROUP_TYPE_FROM_MI[
        LTTngClient._mi_get_in_element(map_group_elem, "type").text
    ]
    effective_val_type = _get_map_channel_value_type_from_mi(
        LTTngClient._mi_get_in_element(map_group_elem, "effective_value_type").text
    )

    # Only the per-user and per-process types carry owner information
    if group_type in (
        lttngctl.MapGroupType.UserPerUser,
        lttngctl.MapGroupType.UserPerProcess,
    ):
        return lttngctl.MapGroup(
            group_type,
            effective_val_type,
            int(LTTngClient._mi_get_in_element(map_group_elem, "owner_id").text),
            LTTngClient._mi_get_in_element(map_group_elem, "owner_name").text,
        )

    return lttngctl.MapGroup(group_type, effective_val_type)


class _MapChannel(lttngctl.MapChannel):
    # Each concrete subclass defines `_channel_type` (a `Type[MapChannel]`,
    # either `lttngctl.UserMapChannel` or `lttngctl.KernelMapChannel`) so that
    # `groups()` can pass the right `--type` to the client; `_MapChannel` is
    # never instantiated on its own.

    def __init__(
        self,
        client,  # type: LTTngClient
        session,  # type: _Session
        name,  # type: str
        is_enabled,  # type: bool
        value_type,  # type: lttngctl.MapChannelValueType
        max_key_count,  # type: int
        update_policy,  # type: lttngctl.MapChannelUpdatePolicy
    ):
        self._client = client  # type: LTTngClient
        self._session = session  # type: _Session
        self._name = name  # type: str
        self._is_enabled = is_enabled  # type: bool
        self._value_type = value_type  # type: lttngctl.MapChannelValueType
        self._max_key_count = max_key_count  # type: int
        self._update_policy = update_policy  # type: lttngctl.MapChannelUpdatePolicy

    def groups(self):
        # type: () -> List[lttngctl.MapGroup]

        # `show-maps --per=owner` produces one `<per_owner_map_table>`
        # element per group of the channel; restrict the listing to this
        # channel with `--channel` and `--type`.
        show_maps_xml, _ = self._client._run_cmd(
            "show-maps --session={session} --channel={channel} --type={type} --per=owner".format(
                session=shlex.quote(self._session.name),
                channel=shlex.quote(self._name),
                type=_MAP_CHANNEL_TYPE_ARGS[self._channel_type],
            ),
            LTTngClient.CommandOutputFormat.MI_XML,
        )
        show_maps_elem = LTTngClient._mi_get_in_element(
            LTTngClient._mi_get_in_element(
                xml.etree.ElementTree.fromstring(show_maps_xml), "output"
            ),
            "show-maps",
        )
        groups = []  # type: List[lttngctl.MapGroup]

        for table_elem in show_maps_elem.findall(
            LTTngClient._namespaced_mi_element("per_owner_map_table")
        ):
            groups.append(
                _map_group_from_mi(
                    LTTngClient._mi_get_in_element(table_elem, "map_group")
                )
            )

        return groups

    @property
    def name(self):
        # type: () -> str
        return self._name

    @property
    def is_enabled(self):
        # type: () -> bool
        return self._is_enabled

    @property
    def value_type(self):
        # type: () -> lttngctl.MapChannelValueType
        return self._value_type

    @property
    def max_key_count(self):
        # type: () -> int
        return self._max_key_count

    @property
    def update_policy(self):
        # type: () -> lttngctl.MapChannelUpdatePolicy
        return self._update_policy


class _UserMapChannel(_MapChannel, lttngctl.UserMapChannel):
    _channel_type = lttngctl.UserMapChannel

    def __init__(
        self,
        client,  # type: LTTngClient
        session,  # type: _Session
        name,  # type: str
        is_enabled,  # type: bool
        value_type,  # type: lttngctl.MapChannelValueType
        max_key_count,  # type: int
        update_policy,  # type: lttngctl.MapChannelUpdatePolicy
        buffer_sharing_policy,  # type: lttngctl.BufferSharingPolicy
        dead_process_policy,  # type: Optional[lttngctl.MapChannelDeadProcessPolicy]
    ):
        super().__init__(
            client, session, name, is_enabled, value_type, max_key_count, update_policy
        )
        self._buffer_sharing_policy = buffer_sharing_policy
        self._dead_process_policy = dead_process_policy

    @property
    def buffer_sharing_policy(self):
        # type: () -> lttngctl.BufferSharingPolicy
        return self._buffer_sharing_policy

    @property
    def dead_process_policy(self):
        # type: () -> Optional[lttngctl.MapChannelDeadProcessPolicy]
        return self._dead_process_policy


class _KernelMapChannel(_MapChannel, lttngctl.KernelMapChannel):
    _channel_type = lttngctl.KernelMapChannel


def _map_channel_from_mi(client, session, type, map_channel_elem):
    # type: (LTTngClient, _Session, Type[lttngctl.MapChannel], xml.etree.ElementTree.Element) -> _MapChannel
    """Build a `_MapChannel` of type `type` from a `<map_channel>` MI element."""
    name = LTTngClient._mi_get_in_element(map_channel_elem, "name").text
    is_enabled = (
        LTTngClient._mi_get_in_element(map_channel_elem, "enabled").text == "true"
    )
    value_type = _get_map_channel_value_type_from_mi(
        LTTngClient._mi_get_in_element(map_channel_elem, "value_type").text
    )
    max_key_count = int(
        LTTngClient._mi_get_in_element(map_channel_elem, "max_key_count").text
    )
    update_policy = _get_map_channel_update_policy_from_mi(
        LTTngClient._mi_get_in_element(map_channel_elem, "update_policy").text
    )

    if type is lttngctl.KernelMapChannel:
        return _KernelMapChannel(
            client, session, name, is_enabled, value_type, max_key_count, update_policy
        )

    # The buffer ownership is always present for a user space map
    # channel, while the dead group policy is only present for a
    # per-process one of those, therefore the latter is optional.
    buffer_sharing_policy = _get_buffer_sharing_policy_from_mi(
        LTTngClient._mi_get_in_element(map_channel_elem, "buffer_ownership").text
    )

    dead_group_policy_elem = LTTngClient._mi_find_in_element(
        map_channel_elem, "dead_group_policy"
    )
    dead_process_policy = (
        _get_map_channel_dead_process_policy_from_mi(dead_group_policy_elem.text)
        if dead_group_policy_elem is not None
        else None
    )

    return _UserMapChannel(
        client,
        session,
        name,
        is_enabled,
        value_type,
        max_key_count,
        update_policy,
        buffer_sharing_policy,
        dead_process_policy,
    )


@enum.unique
class _ProcessAttribute(enum.Enum):
    PID = "Process ID"
    VPID = "Virtual Process ID"
    UID = "User ID"
    VUID = "Virtual User ID"
    GID = "Group ID"
    VGID = "Virtual Group ID"

    def __repr__(self):
        return "<%s.%s>" % (self.__class__.__name__, self.name)


def _get_process_attribute_option_name(attribute):
    # type: (_ProcessAttribute) -> str
    return {
        _ProcessAttribute.PID: "pid",
        _ProcessAttribute.VPID: "vpid",
        _ProcessAttribute.UID: "uid",
        _ProcessAttribute.VUID: "vuid",
        _ProcessAttribute.GID: "gid",
        _ProcessAttribute.VGID: "vgid",
    }[attribute]


class _ProcessAttributeTracker(lttngctl.ProcessAttributeTracker):
    def __init__(
        self,
        client,  # type: LTTngClient
        attribute,  # type: _ProcessAttribute
        domain,  # type: lttngctl.TracingDomain
        session,  # type: _Session
    ):
        self._client = client  # type: LTTngClient
        self._tracked_attribute = attribute  # type: _ProcessAttribute
        self._domain = domain  # type: lttngctl.TracingDomain
        self._session = session  # type: _Session
        if attribute == _ProcessAttribute.PID or attribute == _ProcessAttribute.VPID:
            self._allowed_value_types = [int]  # type: list[type]
        else:
            self._allowed_value_types = [int, str]  # type: list[type]

    def _call_client(self, cmd_name, value):
        # type: (str, Union[int, str]) -> None
        if type(value) not in self._allowed_value_types:
            raise TypeError(
                "Value of type `{value_type}` is not allowed for process attribute {attribute_name}".format(
                    value_type=type(value).__name__,
                    attribute_name=self._tracked_attribute.name,
                )
            )

        process_attribute_option_name = _get_process_attribute_option_name(
            self._tracked_attribute
        )
        domain_name = _get_domain_option_name(self._domain)
        self._client._run_cmd(
            "{cmd_name} --session '{session_name}' --{domain_name} --{tracked_attribute_name} {value}".format(
                cmd_name=cmd_name,
                session_name=self._session.name,
                domain_name=domain_name,
                tracked_attribute_name=process_attribute_option_name,
                value=value,
            )
        )

    def _get_tracker_state(self):
        # type: () -> tuple[lttngctl.ProcessAttributeTracker.TrackingPolicy, List[Union[int, str]]]
        """Query the session daemon for this tracker's current policy and values.

        The MI XML encodes the policy implicitly:
        - Tracker element absent: INCLUDE_ALL (default, no filtering).
        - Tracker element present but empty: EXCLUDE_ALL.
        - Tracker element present with values: INCLUDE_SET.
        """
        domain_xml = self._session._get_mi_domain(self._domain)
        if domain_xml is None:
            return (lttngctl.ProcessAttributeTracker.TrackingPolicy.INCLUDE_ALL, [])

        trackers_element = LTTngClient._mi_find_in_element(
            domain_xml, "process_attr_trackers"
        )
        if trackers_element is None:
            return (lttngctl.ProcessAttributeTracker.TrackingPolicy.INCLUDE_ALL, [])

        attr_name = _get_process_attribute_option_name(self._tracked_attribute)
        tracker_elem = LTTngClient._mi_find_in_element(
            trackers_element,
            "{}_process_attr_tracker".format(attr_name),
        )

        if tracker_elem is None:
            return (lttngctl.ProcessAttributeTracker.TrackingPolicy.INCLUDE_ALL, [])

        process_attr_values = LTTngClient._mi_find_in_element(
            tracker_elem, "process_attr_values"
        )

        values = []  # type: List[Union[int, str]]
        if process_attr_values is not None:
            for value_elem in process_attr_values:
                type_elem = LTTngClient._mi_find_in_element(value_elem, "type")
                if type_elem is None:
                    continue
                name_elem = LTTngClient._mi_find_in_element(type_elem, "name")
                id_elem = LTTngClient._mi_find_in_element(type_elem, "id")
                if name_elem is not None and name_elem.text:
                    values.append(name_elem.text)
                elif id_elem is not None and id_elem.text:
                    values.append(int(id_elem.text))

        if values:
            return (lttngctl.ProcessAttributeTracker.TrackingPolicy.INCLUDE_SET, values)
        else:
            return (lttngctl.ProcessAttributeTracker.TrackingPolicy.EXCLUDE_ALL, [])

    @property
    def tracking_policy(self):
        # type: () -> lttngctl.ProcessAttributeTracker.TrackingPolicy
        policy, _ = self._get_tracker_state()
        return policy

    @property
    def values(self):
        # type: () -> List[Union[int, str]]
        _, values = self._get_tracker_state()
        return values

    def track(self, value):
        # type: (Union[int, str]) -> None
        self._call_client("track", value)

    def untrack(self, value):
        # type: (Union[int, str]) -> None
        self._call_client("untrack", value)


class _Session(lttngctl.Session):
    def __init__(
        self,
        client,  # type: LTTngClient
        name,  # type: str
        output,  # type: Optional[lttngctl.SessionOutputLocation]
    ):
        self._client = client  # type: LTTngClient
        self._name = name  # type: str
        self._output = output  # type: Optional[lttngctl.SessionOutputLocation]

    @property
    def name(self):
        # type: () -> str
        return self._name

    def add_channel(
        self,
        domain,
        channel_name=None,
        buffer_sharing_policy=lttngctl.BufferSharingPolicy.PerUID,
        buffer_allocation_policy=lttngctl.BufferAllocationPolicy.PerCPU,
        subbuf_size=None,
        subbuf_count=None,
        tracefile_size=None,
        tracefile_count=None,
        event_record_loss_mode=None,
        watchdog_timer_period_us=None,
        buffer_preallocation_policy=None,
        auto_reclaim_memory_older_than=None,
        auto_reclaim_memory_consumed=False,
    ):
        # type: (lttngctl.TracingDomain, Optional[str], lttngctl.BufferSharingPolicy, lttngctl.BufferAllocationPolicy, Optional[int], Optional[int], Optional[int], Optional[int], Optional[lttngctl.EventRecordLossMode], Optional[int]) -> lttngctl.Channel
        if channel_name is None:
            channel_name = lttngctl.Channel._generate_name()
        domain_option_name = _get_domain_option_name(domain)
        buffer_sharing_policy_cli_arg = (
            "--buffer-ownership=user"
            if buffer_sharing_policy == lttngctl.BufferSharingPolicy.PerUID
            else "--buffer-ownership=process"
        )
        buffer_allocation_policy_cli_arg = (
            "--buffer-allocation=per-cpu"
            if buffer_allocation_policy == lttngctl.BufferAllocationPolicy.PerCPU
            else "--buffer-allocation=per-channel"
        )
        args = [
            "enable-channel",
            "--session",
            self.name,
            "--{}".format(domain_option_name),
            channel_name,
        ]
        args.append(buffer_allocation_policy_cli_arg)
        if domain != lttngctl.TracingDomain.Kernel:
            args.append(buffer_sharing_policy_cli_arg)
        if subbuf_size is not None:
            args.extend(["--subbuf-size", str(subbuf_size)])
        if subbuf_count is not None:
            args.extend(["--num-subbuf", str(subbuf_count)])
        if tracefile_count is not None:
            args.extend(["--tracefile-count", str(tracefile_count)])
        if tracefile_size is not None:
            args.extend(["--tracefile-size", str(tracefile_size)])
        if event_record_loss_mode is not None:
            args.append(
                "--overwrite"
                if event_record_loss_mode == lttngctl.EventRecordLossMode.Overwrite
                else "--discard"
            )
        if watchdog_timer_period_us is not None:
            args.append("--watchdog-timer={}".format(watchdog_timer_period_us))
        if buffer_preallocation_policy:
            args.append(
                "--buffer-preallocation={}".format(buffer_preallocation_policy.as_arg())
            )
        if auto_reclaim_memory_older_than:
            args.append(
                "--auto-reclaim-memory=older-than:{}".format(
                    auto_reclaim_memory_older_than
                )
            )
        elif auto_reclaim_memory_consumed:
            args.append("--auto-reclaim-memory=consumed")
        self._client._run_cmd(" ".join([shlex.quote(x) for x in args]))
        return _Channel(self._client, channel_name, domain, self)

    def add_user_map_channel(
        self,
        channel_name=None,
        value_type=None,
        max_key_count=None,
        update_policy=None,
        buffer_sharing_policy=None,
        dead_process_policy=None,
    ):
        # type: (Optional[str], Optional[lttngctl.MapChannelValueType], Optional[int], Optional[lttngctl.MapChannelUpdatePolicy], Optional[lttngctl.BufferSharingPolicy], Optional[lttngctl.MapChannelDeadProcessPolicy]) -> lttngctl.UserMapChannel
        return self._add_map_channel(
            lttngctl.UserMapChannel,
            channel_name,
            value_type,
            max_key_count,
            update_policy,
            buffer_sharing_policy,
            dead_process_policy,
        )

    def add_kernel_map_channel(
        self,
        channel_name=None,
        value_type=None,
        max_key_count=None,
        update_policy=None,
    ):
        # type: (Optional[str], Optional[lttngctl.MapChannelValueType], Optional[int], Optional[lttngctl.MapChannelUpdatePolicy]) -> lttngctl.KernelMapChannel
        return self._add_map_channel(
            lttngctl.KernelMapChannel,
            channel_name,
            value_type,
            max_key_count,
            update_policy,
        )

    def _add_map_channel(
        self,
        type,
        channel_name=None,
        value_type=None,
        max_key_count=None,
        update_policy=None,
        buffer_sharing_policy=None,
        dead_process_policy=None,
    ):
        # type: (Type[lttngctl.MapChannel], Optional[str], Optional[lttngctl.MapChannelValueType], Optional[int], Optional[lttngctl.MapChannelUpdatePolicy], Optional[lttngctl.BufferSharingPolicy], Optional[lttngctl.MapChannelDeadProcessPolicy]) -> lttngctl.MapChannel
        if channel_name is None:
            channel_name = lttngctl.MapChannel._generate_name()

        args = [
            "add-map-channel",
            "--session",
            self.name,
            "--type",
            _MAP_CHANNEL_TYPE_ARGS[type],
            channel_name,
        ]

        if value_type is not None:
            args.append("--value-type={}".format(value_type.as_arg()))

        if max_key_count is not None:
            args.append("--max-key-count={}".format(max_key_count))

        if update_policy is not None:
            args.append("--update-policy={}".format(update_policy.as_arg()))

        if buffer_sharing_policy is not None:
            args.append(
                "--buffer-ownership={}".format(
                    "user"
                    if buffer_sharing_policy == lttngctl.BufferSharingPolicy.PerUID
                    else "process"
                )
            )
        if dead_process_policy is not None:
            args.append("--dead-process-policy={}".format(dead_process_policy.as_arg()))

        self._client._run_cmd(" ".join([shlex.quote(x) for x in args]))

        for map_channel in self.map_channels(type):
            if map_channel.name == channel_name:
                return map_channel

        raise RuntimeError("Failed to find added map channel `{}`".format(channel_name))

    def map_channels(self, type=None):
        # type: (Optional[Type[lttngctl.MapChannel]]) -> Iterator[lttngctl.MapChannel]
        if type is None:
            types = [lttngctl.UserMapChannel, lttngctl.KernelMapChannel]
        else:
            types = [type]

        for cur_type in types:
            target_domain = self._get_mi_domain(_MAP_CHANNEL_TRACING_DOMAINS[cur_type])

            if target_domain is None:
                continue

            map_channels_elem = LTTngClient._mi_find_in_element(
                target_domain, "map_channels"
            )

            if map_channels_elem is None:
                continue

            for map_channel_elem in map_channels_elem:
                yield _map_channel_from_mi(
                    self._client, self, cur_type, map_channel_elem
                )

    def export_maps(self):
        # type: () -> sqlite3.Connection

        # `export-maps` writes an SQL script (not MI) to its standard
        # output, so the human-readable output format is used to capture
        # it verbatim.
        sql_script, _ = self._client._run_cmd(
            "export-maps --session={}".format(shlex.quote(self.name)),
            LTTngClient.CommandOutputFormat.HUMAN,
        )

        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row

        try:
            conn.executescript(sql_script)
        except Exception:
            conn.close()
            raise

        return conn

    def channel(self, domain, channel_name):
        # type: (lttngctl.TracingDomain, str) -> lttngctl.Channel
        target_domain = self._get_mi_domain(domain)
        if target_domain is None:
            raise ChannelNotFound(
                "Failed to find channel `{}`: domain `{}` not found in session `{}`".format(
                    channel_name, domain.name, self.name
                )
            )

        for channel_element in LTTngClient._mi_get_in_element(
            target_domain, "channels"
        ):
            if (
                LTTngClient._mi_get_in_element(channel_element, "name").text
                == channel_name
            ):
                return _Channel(self._client, channel_name, domain, self)

        raise ChannelNotFound(
            "Failed to find channel `{}` in domain `{}` of session `{}`".format(
                channel_name, domain.name, self.name
            )
        )

    def add_context(self, context_type):
        # type: (lttngctl.ContextType) -> None
        pass

    @property
    def output(self):
        # type: () -> "Optional[Type[lttngctl.SessionOutputLocation]]"
        return self._output  # type: ignore

    def start(self):
        # type: () -> None
        self._client._run_cmd("start '{session_name}'".format(session_name=self.name))

    def stop(self):
        # type: () -> None
        self._client._run_cmd("stop '{session_name}'".format(session_name=self.name))

    def clear(self):
        # type: () -> None
        self._client._run_cmd("clear '{session_name}'".format(session_name=self.name))

    def destroy(self, timeout_s=None):
        # type: (Optional[float]) -> None
        args = [
            "destroy",
            self.name,
        ]
        if timeout_s == 0:
            args.append("--no-wait")
            timeout_s = None

        self._client._run_cmd(
            " ".join([shlex.quote(x) for x in args]), timeout_s=timeout_s
        )

    def reclaim_memory(
        self,
        wait=True,
        older_than_us=None,
        session=None,
        channels=None,
        all_channels=False,
    ):
        args = [
            "reclaim-memory",
            "--userspace",
        ]

        if not wait:
            args.append("--no-wait")

        if older_than_us:

            if not isinstance(older_than_us, int):
                raise Exception(
                    "Parameter `older_than_us={}` is not an integer".format(
                        older_than_us
                    )
                )

            args.append("--older-than={}".format(older_than_us))

        if session:
            args.append("--session={}".format(session))

        if channels:
            args.extend(channels)
        elif all_channels:
            args.append("--all")

        self._client._run_cmd(" ".join([shlex.quote(arg) for arg in args]))

    def rotate(self, wait=True):
        # type: (bool) -> None
        self._client.rotate_session_by_name(self.name, wait)

    def record_snapshot(self, output_location=None):
        # type: (Optional[lttngctl.SessionOutputLocation]) -> None
        if isinstance(output_location, lttngctl.LocalSessionOutputLocation):
            self._client.snapshot_record(self.name, output_location.path)
        elif isinstance(output_location, lttngctl.NetworkSessionOutputLocation):
            self._client.snapshot_record(self.name, output_location.url)
        elif output_location is not None:
            raise TypeError(
                "Expected output_location to be of type LocalSessionOutputLocation or NetworkSessionOutputLocation"
            )
        else:
            self._client.snapshot_record(self.name, None)

    def regenerate(self, target):
        # type: lttngctl.SessionRegenerateTarget
        if not isinstance(target, lttngctl.SessionRegenerateTarget):
            raise RuntimeError(
                "Expected target of type `{}`, got `{}`".format(
                    lttngctl.SessionRegenerateTarget, type(target)
                )
            )

        args = ["regenerate", str(target), "-s", self.name]
        self._client._run_cmd(" ".join([shlex.quote(x) for x in args]))

    def add_recording_rule(self, domain, rule):
        # type: (lttngctl.TracingDomain, lttngctl.EventRule) -> None
        if not domain.is_agent:
            raise ValueError(
                "Session.add_recording_rule() only supports agent domains (JUL, Log4j, Log4j2, Python) "
                "which use an implicit channel; use Channel.add_recording_rule() for the {} domain".format(
                    domain.name
                )
            )

        domain_option_name = _get_domain_option_name(domain)

        if isinstance(rule, lttngctl.TracepointEventRule):
            args = "enable-event --session '{session_name}' --{domain_option}".format(
                session_name=self.name,
                domain_option=domain_option_name,
            )

            if rule.name_pattern:
                args = args + " '{}'".format(rule.name_pattern)
            else:
                args = args + " --all"

            if rule.filter_expression:
                args = args + " --filter '{}'".format(rule.filter_expression)

            if getattr(rule, "log_level_rule", None):
                if isinstance(rule.log_level_rule, lttngctl.LogLevelRuleAsSevereAs):
                    args = args + " --loglevel {}".format(
                        _get_log_level_argument_name(rule.log_level_rule.level)
                    )
                elif isinstance(rule.log_level_rule, lttngctl.LogLevelRuleExactly):
                    args = args + " --loglevel-only {}".format(
                        _get_log_level_argument_name(rule.log_level_rule.level)
                    )

            if getattr(rule, "name_pattern_exclusions", None):
                args = args + " --exclude "
                for idx, pattern in enumerate(rule.name_pattern_exclusions):
                    if idx != 0:
                        args = args + ","
                    args = args + pattern

            self._client._run_cmd(args)
        else:
            raise Unsupported(
                "Event rule type `{}` is not supported".format(type(rule).__name__)
            )

    def _get_mi_domain(self, domain):
        # type: (lttngctl.TracingDomain) -> Optional[xml.etree.ElementTree.Element]
        """
        Fetch the MI XML for this session and return the XML element
        corresponding to the requested domain, or None if the domain is not
        present.
        """
        list_session_xml, _ = self._client._run_cmd(
            "list '{session_name}'".format(session_name=self.name),
            LTTngClient.CommandOutputFormat.MI_XML,
        )

        root = xml.etree.ElementTree.fromstring(list_session_xml)
        command_output = LTTngClient._mi_get_in_element(root, "output")
        sessions = LTTngClient._mi_get_in_element(command_output, "sessions")

        if len(sessions) != 1:
            raise InvalidMI(
                "Only one session expected when listing with an explicit session name"
            )
        session = sessions[0]

        target_domain_mi_name = _get_domain_xml_mi_name(domain)
        for domain_element in LTTngClient._mi_get_in_element(session, "domains"):
            if (
                LTTngClient._mi_get_in_element(domain_element, "type").text
                == target_domain_mi_name
            ):
                return domain_element

        return None

    def recording_rules(self, domain):
        # type: (lttngctl.TracingDomain) -> Iterator[lttngctl.EventRule]
        if not domain.is_agent:
            raise ValueError(
                "Session.recording_rules() only supports agent domains (JUL, Log4j, Log4j2, Python) "
                "which use an implicit channel; use Channel.recording_rules for the {} domain".format(
                    domain.name
                )
            )

        target_domain = self._get_mi_domain(domain)
        if target_domain is None:
            return

        tracepoint_event_rule_class = _get_tracepoint_event_rule_class_from_domain_type(
            domain
        )

        events_element = LTTngClient._mi_find_in_element(target_domain, "events")
        if events_element is not None:
            for event in events_element:
                yield from self._parse_event_rule(
                    event, domain, tracepoint_event_rule_class
                )

    @staticmethod
    def _parse_event_rule(event, domain, tracepoint_event_rule_class):
        # type: (xml.etree.ElementTree.Element, lttngctl.TracingDomain, type) -> Iterator[lttngctl.EventRule]
        pattern = LTTngClient._mi_get_in_element(event, "name").text
        event_type = LTTngClient._mi_get_in_element(event, "type").text

        filter_expression = None
        filter_expression_element = LTTngClient._mi_find_in_element(
            event, "filter_expression"
        )
        if filter_expression_element is not None:
            filter_expression = filter_expression_element.text

        enabled = None
        enabled_element = LTTngClient._mi_find_in_element(event, "enabled")
        if enabled_element is not None and enabled_element.text in ("true", "false"):
            enabled = enabled_element.text == "true"

        if event_type == "SYSCALL":
            rule = lttngctl.KernelSyscallEventRule(pattern, filter_expression)
            rule._enabled = enabled
            yield rule
            return

        if event_type == "PROBE":
            rule = lttngctl.KernelKprobeEventRule(
                event_name=pattern, symbol_name=pattern
            )
            rule._enabled = enabled
            yield rule
            return

        if event_type == "FUNCTION":
            rule = lttngctl.KernelFunctionEventRule(
                event_name=pattern, symbol_name=pattern
            )
            rule._enabled = enabled
            yield rule
            return

        if event_type != "TRACEPOINT":
            raise Unsupported(
                "Event rule type `{}` is not supported by this Controller implementation".format(
                    event_type
                )
            )

        exclusions = []
        exclusions_element = LTTngClient._mi_find_in_element(event, "exclusions")
        if exclusions_element is not None:
            for exclusion in exclusions_element:
                exclusions.append(exclusion.text)

        exclusions = exclusions if len(exclusions) > 0 else None

        if domain != lttngctl.TracingDomain.Kernel:
            log_level_element = LTTngClient._mi_find_in_element(event, "loglevel")
            log_level_type_element = LTTngClient._mi_find_in_element(
                event, "loglevel_type"
            )

            log_level_rule = None
            if log_level_element is not None and log_level_type_element is not None:
                if log_level_element.text is None:
                    raise InvalidMI("`loglevel` element of event rule has no text")

                if log_level_type_element.text == "RANGE":
                    log_level_rule = lttngctl.LogLevelRuleAsSevereAs(
                        _get_log_level_from_mi_log_level_name(log_level_element.text)
                    )
                elif log_level_type_element.text == "SINGLE":
                    log_level_rule = lttngctl.LogLevelRuleExactly(
                        _get_log_level_from_mi_log_level_name(log_level_element.text)
                    )

            rule = tracepoint_event_rule_class(
                pattern, filter_expression, log_level_rule, exclusions
            )
            rule._enabled = enabled
            yield rule
        else:
            rule = tracepoint_event_rule_class(pattern, filter_expression)
            rule._enabled = enabled
            yield rule

    @property
    def is_active(self):
        # type: () -> bool
        list_session_xml, _ = self._client._run_cmd(
            "list '{session_name}'".format(session_name=self.name),
            LTTngClient.CommandOutputFormat.MI_XML,
        )

        root = xml.etree.ElementTree.fromstring(list_session_xml)
        command_output = LTTngClient._mi_get_in_element(root, "output")
        sessions = LTTngClient._mi_get_in_element(command_output, "sessions")
        session_mi = LTTngClient._mi_get_in_element(sessions, "session")

        enabled_text = LTTngClient._mi_get_in_element(session_mi, "enabled").text
        if enabled_text not in ["true", "false"]:
            raise InvalidMI(
                "Expected boolean value in element '{}': value='{}'".format(
                    session_mi.tag, enabled_text
                )
            )

        return enabled_text == "true"

    @property
    def kernel_pid_process_attribute_tracker(self):
        # type: () -> Type[lttngctl.ProcessIDProcessAttributeTracker]
        return _ProcessAttributeTracker(self._client, _ProcessAttribute.PID, lttngctl.TracingDomain.Kernel, self)  # type: ignore

    @property
    def kernel_vpid_process_attribute_tracker(self):
        # type: () -> Type[lttngctl.VirtualProcessIDProcessAttributeTracker]
        return _ProcessAttributeTracker(self._client, _ProcessAttribute.VPID, lttngctl.TracingDomain.Kernel, self)  # type: ignore

    @property
    def user_vpid_process_attribute_tracker(self):
        # type: () -> Type[lttngctl.VirtualProcessIDProcessAttributeTracker]
        return _ProcessAttributeTracker(self._client, _ProcessAttribute.VPID, lttngctl.TracingDomain.User, self)  # type: ignore

    @property
    def kernel_gid_process_attribute_tracker(self):
        # type: () -> Type[lttngctl.GroupIDProcessAttributeTracker]
        return _ProcessAttributeTracker(self._client, _ProcessAttribute.GID, lttngctl.TracingDomain.Kernel, self)  # type: ignore

    @property
    def kernel_vgid_process_attribute_tracker(self):
        # type: () -> Type[lttngctl.VirtualGroupIDProcessAttributeTracker]
        return _ProcessAttributeTracker(self._client, _ProcessAttribute.VGID, lttngctl.TracingDomain.Kernel, self)  # type: ignore

    @property
    def user_vgid_process_attribute_tracker(self):
        # type: () -> Type[lttngctl.VirtualGroupIDProcessAttributeTracker]
        return _ProcessAttributeTracker(self._client, _ProcessAttribute.VGID, lttngctl.TracingDomain.User, self)  # type: ignore

    @property
    def kernel_uid_process_attribute_tracker(self):
        # type: () -> Type[lttngctl.UserIDProcessAttributeTracker]
        return _ProcessAttributeTracker(self._client, _ProcessAttribute.UID, lttngctl.TracingDomain.Kernel, self)  # type: ignore

    @property
    def kernel_vuid_process_attribute_tracker(self):
        # type: () -> Type[lttngctl.VirtualUserIDProcessAttributeTracker]
        return _ProcessAttributeTracker(self._client, _ProcessAttribute.VUID, lttngctl.TracingDomain.Kernel, self)  # type: ignore

    @property
    def user_vuid_process_attribute_tracker(self):
        # type: () -> Type[lttngctl.VirtualUserIDProcessAttributeTracker]
        return _ProcessAttributeTracker(self._client, _ProcessAttribute.VUID, lttngctl.TracingDomain.User, self)  # type: ignore


class LTTngClientError(lttngctl.ControlException):
    def __init__(
        self,
        command_args,  # type: str
        output,  # type: str
        error_output,  # type: str
    ):
        self._command_args = command_args  # type: str
        self._output = output  # type: str
        self._error_output = error_output  # type: str


class LTTngClient(logger._Logger, lttngctl.Controller):
    """
    Implementation of a LTTngCtl Controller that uses the `lttng` client as a back-end.
    """

    class CommandOutputFormat(enum.Enum):
        MI_XML = 0
        HUMAN = 1

    _MI_NS = "{https://lttng.org/xml/ns/lttng-mi}"
    _MI_XSD_MAJOR_VERSION = 4
    _MI_XSD_MINOR_VERSION = 2
    _timeout_s = None

    def __init__(
        self,
        test_environment,  # type: environment._Environment
        log,  # type: Optional[Callable[[str], None]]
        extra_env_vars=dict(),  # type: dict
    ):
        logger._Logger.__init__(self, log)
        self._environment = test_environment  # type: environment._Environment
        self._extra_env_vars = extra_env_vars

        # The client needs to know where to find the LTTng session configuration
        # XSD file for validating session configuration files when `lttng-load`
        # is used.
        self._extra_env_vars.setdefault(
            "LTTNG_SESSION_CONFIG_XSD_PATH",
            str(self._environment._project_root / "src" / "common"),
        )

    @staticmethod
    def _namespaced_mi_element(property):
        # type: (str) -> str
        return LTTngClient._MI_NS + property

    @property
    def timeout(self):
        return self._timeout_s

    @timeout.setter
    def timeout(self, value):
        if value is None:
            self._timeout_s = None
        else:
            self._timeout_s = int(value)

    def _run_cmd(
        self, command_args, output_format=CommandOutputFormat.MI_XML, timeout_s=None
    ):
        # type: (str, CommandOutputFormat, Optional[float]) -> tuple[str, str]
        """
        Invoke the `lttng` client with a set of arguments. The command is
        executed in the context of the client's test environment.

        Returns a tuple containing (stdout, stderr) that has been decoded to
        UTF-8.
        """
        args = [str(self._environment.lttng_client_path)]  # type: list[str]
        if os.getenv("LTTNG_TEST_VERBOSE_CLIENT", "0") != "0":
            args.extend(["-vvv"])
        if output_format == LTTngClient.CommandOutputFormat.MI_XML:
            args.extend(["--mi", "xml"])

        args.extend(shlex.split(command_args))

        self._log("lttng {command_args}".format(command_args=command_args))

        client_env = self._environment.get_lttng_client_env(self._extra_env_vars)
        err_output = (
            tempfile.NamedTemporaryFile(
                prefix="lttng_", dir=self._environment.lttng_log_dir, delete=False
            )
            if self._environment.lttng_log_dir is not None
            else None
        )
        process = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=err_output.file if err_output else subprocess.PIPE,
            env=client_env,
        )

        out, err = process.communicate(timeout=timeout_s or self.timeout)
        out = out.decode("utf-8")
        if not err_output:
            err = err.decode("utf-8")
        else:
            err = open(err_output.name, "r", encoding="utf-8").read()

        for error_line in err.splitlines():
            self._log(error_line)

        if process.returncode != 0:
            raise LTTngClientError(command_args, out, err)

        if output_format == LTTngClient.CommandOutputFormat.MI_XML:
            self._validate_mi(out)

        return (out, err)

    def _validate_mi(self, mi_xml):
        # type: (str) -> None
        """
        Validate an MI XML document against the MI XSD, raising InvalidMI on
        failure.
        """
        xsd_path = (
            self._environment._project_root
            / "src"
            / "common"
            / "mi-lttng-{major}.{minor}.xsd".format(
                major=LTTngClient._MI_XSD_MAJOR_VERSION,
                minor=LTTngClient._MI_XSD_MINOR_VERSION,
            )
        )
        validate_bin = (
            self._environment._project_root
            / "tests"
            / "utils"
            / "xml-utils"
            / "validate_xml"
        )

        mi_file = tempfile.NamedTemporaryFile(
            mode="w",
            prefix="lttng_mi_",
            suffix=".xml",
            dir=self._environment.lttng_log_dir,
            delete=False,
            encoding="utf-8",
        )
        try:
            mi_file.write(mi_xml)
            mi_file.close()

            validation = subprocess.run(
                [str(validate_bin), str(xsd_path), mi_file.name],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        finally:
            os.unlink(mi_file.name)

        if validation.returncode != 0:
            raise InvalidMI(
                "MI output failed validation against `{xsd}`:\n{error}".format(
                    xsd=xsd_path, error=validation.stderr.decode("utf-8")
                )
            )

    def create_session(
        self,
        name=None,
        output=None,
        live=False,
        snapshot=False,
        shm_path=None,
        trace_format=None,
    ):
        # type: (Optional[str], Optional[lttngctl.SessionOutputLocation], bool, bool, Optional[pathlib.Path], Optional[lttngctl.TraceFormat]) -> lttngctl.Session
        name = name if name else lttngctl.Session._generate_name()
        args = ["create", name]

        if isinstance(output, lttngctl.LocalSessionOutputLocation):
            args.extend(["--output", str(output.path)])
        elif isinstance(output, lttngctl.NetworkSessionOutputLocation):
            args.extend(["--set-url", output.url])
        elif output is None:
            args.append("--no-output")
        else:
            raise TypeError("LTTngClient only supports local or no output")

        if live:
            args.append("--live={}".format(live) if type(live) is int else "--live")
        if shm_path is not None:
            args.extend(["--shm-path", str(shm_path)])
        if snapshot:
            args.append("--snapshot")
        if trace_format is not None:
            args.extend(["--trace-format", trace_format.value])
        self._run_cmd(" ".join([shlex.quote(x) for x in args]))
        return _Session(self, name, output)

    def start_session_by_name(self, name):
        # type: (str) -> None
        self._run_cmd("start '{session_name}'".format(session_name=name))

    def start_session_by_glob_pattern(self, pattern):
        # type: (str) -> None
        self._run_cmd("start --glob '{pattern}'".format(pattern=pattern))

    def start_sessions_all(self):
        # type: () -> None
        self._run_cmd("start --all")

    def stop_session_by_name(self, name):
        # type: (str) -> None
        self._run_cmd("stop '{session_name}'".format(session_name=name))

    def stop_session_by_glob_pattern(self, pattern):
        # type: (str) -> None
        self._run_cmd("stop --glob '{pattern}'".format(pattern=pattern))

    def stop_sessions_all(self):
        # type: () -> None
        self._run_cmd("stop --all")

    def destroy_session_by_name(self, name):
        # type: (str) -> None
        self._run_cmd("destroy '{session_name}'".format(session_name=name))

    def destroy_session_by_glob_pattern(self, pattern):
        # type: (str) -> None
        self._run_cmd("destroy --glob '{pattern}'".format(pattern=pattern))

    def destroy_sessions_all(self):
        # type: () -> None
        self._run_cmd("destroy --all")

    def rotate_session_by_name(self, name, wait=True):
        self._run_cmd(
            "rotate '{session_name}' {wait_option}".format(
                session_name=name, wait_option="-n" if wait is False else ""
            )
        )

    def snapshot_record(self, name, output_location=None):
        self._run_cmd(
            "snapshot record --session='{session_name}' {location}".format(
                session_name=name,
                location=output_location if output_location else "",
            )
        )

    def schedule_size_based_rotation(self, name, size_bytes):
        # type (str, int) -> None
        self._run_cmd(
            "enable-rotation --session '{session_name}' --size {size}".format(
                session_name=name, size=size_bytes
            )
        )

    def schedule_time_based_rotation(self, name, period_seconds):
        # type (str, int) -> None
        self._run_cmd(
            "enable-rotation --session '{session_name}' --timer {period_seconds}s".format(
                session_name=name, period_seconds=period_seconds
            )
        )

    @staticmethod
    def _mi_findall_in_element(
        element: xml.etree.ElementTree.Element, sub_element_name: str
    ) -> List[xml.etree.ElementTree.Element]:
        return element.findall(LTTngClient._namespaced_mi_element(sub_element_name))

    @staticmethod
    def _mi_find_in_element(element, sub_element_name):
        # type: (xml.etree.ElementTree.Element, str) -> Optional[xml.etree.ElementTree.Element]
        return element.find(LTTngClient._namespaced_mi_element(sub_element_name))

    @staticmethod
    def _mi_get_in_element(element, sub_element_name):
        # type: (xml.etree.ElementTree.Element, str) -> xml.etree.ElementTree.Element
        result = LTTngClient._mi_find_in_element(element, sub_element_name)
        if result is None:
            raise InvalidMI(
                "Failed to find element '{}' within command MI element '{}'".format(
                    element.tag, sub_element_name
                )
            )

        return result

    def list_sessions(self):
        # type () -> List[Session]
        list_sessions_xml, _ = self._run_cmd(
            "list", LTTngClient.CommandOutputFormat.MI_XML
        )

        root = xml.etree.ElementTree.fromstring(list_sessions_xml)
        command_output = self._mi_get_in_element(root, "output")
        sessions = self._mi_get_in_element(command_output, "sessions")

        ctl_sessions = []  # type: list[lttngctl.Session]

        for session_mi in sessions:
            name = self._mi_get_in_element(session_mi, "name").text
            path = self._mi_get_in_element(session_mi, "path").text

            if name is None:
                raise InvalidMI(
                    "Invalid empty 'name' element in '{}'".format(session_mi.tag)
                )
            if path is None:
                raise InvalidMI(
                    "Invalid empty 'path' element in '{}'".format(session_mi.tag)
                )
            if not path.startswith("/"):
                raise Unsupported(
                    "{} does not support non-local session outputs".format(type(self))
                )

            ctl_sessions.append(
                _Session(self, name, lttngctl.LocalSessionOutputLocation(path))
            )

        return ctl_sessions

    def list_session_raw(self, session):
        list_sessions_xml, _ = self._run_cmd(
            "list {}".format(session), LTTngClient.CommandOutputFormat.MI_XML
        )

        root = xml.etree.ElementTree.fromstring(list_sessions_xml)
        command_output = self._mi_get_in_element(root, "output")
        sessions = self._mi_get_in_element(command_output, "sessions")

        if len(sessions) > 0:
            return sessions[0]
        raise InvalidMI("Invalid empty 'sessions element in '{}".format(session_mi.tag))

    def save_sessions(
        self,
        session_name=None,  # type: Optional[str]
        force=False,  # type: bool
        output_path=None,  # type: Optional[str]
        no_triggers=False,  # type: bool
    ):
        # type: (...) -> None

        cmd = [
            "save",
        ]

        if force:
            cmd.append("--force")

        if no_triggers:
            cmd.append("--no-triggers")

        if output_path:
            cmd.append("--output-path={}".format(output_path))
        else:
            cmd.append(
                "--output-path={}".format(
                    str(self._environment.lttng_home_location) + "/.lttng/sessions"
                )
            )

        if session_name:
            cmd.append(session_name)
        else:
            cmd.append("--all")

        self._run_cmd(" ".join(cmd))

    def load_sessions(
        self,
        session_name=None,  # type: Optional[str]
        force=False,  # type: bool
        input_path=None,  # type: Optional[str]
        no_triggers=False,  # type: bool
    ):
        # type: (...) -> None

        cmd = ["load"]

        if force:
            cmd.append("--force")

        if no_triggers:
            cmd.append("--no-triggers")

        if input_path:
            cmd.append("--input-path={}".format(input_path))
        else:
            cmd.append(
                "--input-path={}".format(
                    str(self._environment.lttng_home_location) + "/.lttng/sessions"
                )
            )

        if session_name:
            cmd.append(session_name)
        else:
            cmd.append("--all")

        self._run_cmd(" ".join(cmd))

    def add_trigger(self, condition, actions, name=None, owner_uid=None):
        # type: (lttngctl.TriggerCondition, List[lttngctl.TriggerAction], Optional[str], Optional[int]) -> lttngctl.Trigger
        """
        Add a trigger with the given condition and actions.

        If name is not specified, the session daemon will generate a unique name.
        If owner_uid is specified, the trigger will be owned by that user (requires root).
        """
        args = ["add-trigger"]

        if name:
            args.extend(["--name", name])

        if owner_uid is not None:
            args.extend(["--owner-uid", str(owner_uid)])

        # Build condition arguments
        if isinstance(condition, lttngctl.EventRuleMatchesCondition):
            args.append("--condition=event-rule-matches")
            for capture in condition.capture_descriptors:
                args.extend(["--capture", capture])
            args.extend(_build_event_rule_spec_args(condition.event_rule))
        elif isinstance(condition, lttngctl.SessionConsumedSizeCondition):
            args.append("--condition=session-consumed-size-ge")
            args.extend(["--session", condition.session_name])
            args.extend(["--threshold-size", str(condition.threshold_bytes)])
        elif isinstance(condition, lttngctl.BufferUsageCondition):
            if isinstance(condition, lttngctl.BufferUsageHighCondition):
                args.append("--condition=channel-buffer-usage-ge")
            elif isinstance(condition, lttngctl.BufferUsageLowCondition):
                args.append("--condition=channel-buffer-usage-le")
            else:
                raise Unsupported(
                    "Condition type `{condition_type}` is not supported".format(
                        condition_type=type(condition).__name__
                    )
                )

            args.extend(["--session", condition.session_name])
            args.extend(["--channel", condition.channel_name])
            args.extend(["--domain", _get_condition_domain_arg(condition.domain)])
            if condition.threshold_bytes is not None:
                args.extend(["--threshold-size", str(condition.threshold_bytes)])
            else:
                args.extend(["--threshold-ratio", str(condition.threshold_ratio)])
        elif isinstance(condition, lttngctl.SessionRotationOngoingCondition):
            args.append("--condition=session-rotation-starts")
            args.extend(["--session", condition.session_name])
        elif isinstance(condition, lttngctl.SessionRotationCompletedCondition):
            args.append("--condition=session-rotation-finishes")
            args.extend(["--session", condition.session_name])
        else:
            raise Unsupported(
                "Condition type `{condition_type}` is not supported".format(
                    condition_type=type(condition).__name__
                )
            )

        # Build action arguments
        for action in actions:
            args.extend(_build_action_args(action))

        command_output_xml, _ = self._run_cmd(" ".join([shlex.quote(x) for x in args]))
        created_trigger_name = name

        if created_trigger_name is None:
            root = xml.etree.ElementTree.fromstring(command_output_xml)
            command_output = self._mi_get_in_element(root, "output")
            trigger_mi = self._mi_get_in_element(command_output, "trigger")
            created_trigger_name = self._mi_get_in_element(trigger_mi, "name").text

            if created_trigger_name is None:
                raise InvalidMI(
                    "Invalid empty 'name' element in '{}'".format(trigger_mi.tag)
                )

        return _Trigger(
            self, created_trigger_name, owner_uid, condition, actions, list()
        )

    def remove_trigger(self, trigger):
        # type: (Union[lttngctl.Trigger, str]) -> None
        """
        Remove a trigger, either by passing the Trigger object returned by
        add_trigger()/list_triggers() or its name.
        """
        owner_uid = None  # type: Optional[int]
        if isinstance(trigger, lttngctl.Trigger):
            name = trigger.name
            owner_uid = trigger.owner_uid
        else:
            name = trigger

        if name is None:
            raise ValueError("Cannot remove a trigger without a name")

        # Passing only a name targets the trigger owned by the calling user, so
        # only the --owner-uid option is added when the trigger belongs to
        # another user. That option requires root, which is precisely the case
        # in which a caller can hold (through list_triggers()) a trigger it does
        # not own.
        args = ["remove-trigger"]
        if owner_uid is not None and owner_uid != os.getuid():
            args.extend(["--owner-uid", str(owner_uid)])
        args.append(shlex.quote(name))

        self._run_cmd(" ".join(args))

    def list_triggers(self):
        # type: () -> List[lttngctl.Trigger]
        command_output_xml, _ = self._run_cmd("list-triggers")
        root = xml.etree.ElementTree.fromstring(command_output_xml)
        command_output = self._mi_get_in_element(root, "output")

        triggers = []  # type: List[lttngctl.Trigger]
        triggers_element = self._mi_find_in_element(command_output, "triggers")
        if triggers_element is None:
            return triggers

        for trigger_element in triggers_element:
            if _mi_local_name(trigger_element) != "trigger":
                continue

            name = self._mi_get_in_element(trigger_element, "name").text
            owner_uid_element = self._mi_find_in_element(trigger_element, "owner_uid")
            owner_uid = (
                int(owner_uid_element.text)
                if owner_uid_element is not None and owner_uid_element.text is not None
                else None
            )

            error_query_results_element = self._mi_get_in_element(
                trigger_element, "error_query_results"
            )
            error_query_results = self._error_query_results_from_mi(
                error_query_results_element
            )

            condition = self._condition_from_mi(
                self._mi_get_in_element(trigger_element, "condition")
            )
            actions = self._actions_from_mi(
                self._mi_get_in_element(trigger_element, "action")
            )

            triggers.append(
                _Trigger(self, name, owner_uid, condition, actions, error_query_results)
            )

        return triggers

    @staticmethod
    def _error_query_results_from_mi(error_query_results_element):
        error_query_results = list()
        for error_query_element in LTTngClient._mi_findall_in_element(
            error_query_results_element, "error_query_result"
        ):
            counter_element = LTTngClient._mi_get_in_element(
                error_query_element, "error_query_result_counter"
            )
            error_query_results.append(
                lttngctl.ErrorQueryResult(
                    LTTngClient._mi_get_in_element(error_query_element, "name").text,
                    LTTngClient._mi_get_in_element(
                        error_query_element, "description"
                    ).text,
                    int(LTTngClient._mi_get_in_element(counter_element, "value").text),
                )
            )
        return error_query_results

    @staticmethod
    def _condition_from_mi(condition_element):
        # type: (xml.etree.ElementTree.Element) -> lttngctl.TriggerCondition
        # A <condition> wraps a single element naming its type.
        type_element = list(condition_element)[0]
        type_name = _mi_local_name(type_element)
        error_query_results_element = LTTngClient._mi_get_in_element(
            condition_element, "error_query_results"
        )
        error_query_results = LTTngClient._error_query_results_from_mi(
            error_query_results_element
        )

        if type_name == "condition_event_rule_matches":
            event_rule = LTTngClient._event_rule_from_mi(
                LTTngClient._mi_get_in_element(type_element, "event_rule")
            )

            captures = []  # type: List[str]
            captures_element = LTTngClient._mi_find_in_element(
                type_element, "capture_descriptors"
            )
            if captures_element is not None:
                for event_expr in captures_element:
                    captures.append(LTTngClient._capture_descriptor_from_mi(event_expr))

            return lttngctl.EventRuleMatchesCondition(
                event_rule,
                captures if captures else None,
                error_query_results,
            )

        if type_name == "condition_session_consumed_size":
            return lttngctl.SessionConsumedSizeCondition(
                LTTngClient._mi_get_in_element(type_element, "session_name").text,
                int(
                    LTTngClient._mi_get_in_element(type_element, "threshold_bytes").text
                ),
                error_query_results,
            )

        if type_name in ("condition_buffer_usage_high", "condition_buffer_usage_low"):
            session_name = LTTngClient._mi_get_in_element(
                type_element, "session_name"
            ).text
            channel_name = LTTngClient._mi_get_in_element(
                type_element, "channel_name"
            ).text
            domain = _domain_from_xml_mi_name(
                LTTngClient._mi_get_in_element(type_element, "domain").text
            )

            # The condition carries exactly one of the two threshold flavours.
            threshold_bytes = None  # type: Optional[int]
            threshold_ratio = None  # type: Optional[float]
            threshold_bytes_element = LTTngClient._mi_find_in_element(
                type_element, "threshold_bytes"
            )
            if threshold_bytes_element is not None:
                threshold_bytes = int(threshold_bytes_element.text)
            else:
                threshold_ratio = float(
                    LTTngClient._mi_get_in_element(type_element, "threshold_ratio").text
                )

            condition_cls = (
                lttngctl.BufferUsageHighCondition
                if type_name == "condition_buffer_usage_high"
                else lttngctl.BufferUsageLowCondition
            )
            return condition_cls(
                session_name,
                channel_name,
                domain,
                threshold_bytes,
                threshold_ratio,
                error_query_results,
            )

        if type_name == "condition_session_rotation_ongoing":
            return lttngctl.SessionRotationOngoingCondition(
                LTTngClient._mi_get_in_element(type_element, "session_name").text,
                error_query_results,
            )

        if type_name == "condition_session_rotation_completed":
            return lttngctl.SessionRotationCompletedCondition(
                LTTngClient._mi_get_in_element(type_element, "session_name").text,
                error_query_results,
            )

        raise Unsupported("Condition type `{}` is not supported".format(type_name))

    @staticmethod
    def _capture_descriptor_from_mi(event_expr_element):
        # type: (xml.etree.ElementTree.Element) -> str
        # Best-effort reconstruction of a capture descriptor's textual form.
        expr = list(event_expr_element)[0]
        expr_name = _mi_local_name(expr)

        def child_text(element, name):
            # type: (xml.etree.ElementTree.Element, str) -> str
            return LTTngClient._mi_get_in_element(element, name).text or ""

        if expr_name == "event_expr_payload_field":
            return child_text(expr, "name")
        elif expr_name == "event_expr_channel_context_field":
            return "$ctx." + child_text(expr, "name")
        elif expr_name == "event_expr_app_specific_context_field":
            return "$app.{}:{}".format(
                child_text(expr, "provider_name"), child_text(expr, "type_name")
            )
        elif expr_name == "event_expr_array_field_element":
            index = child_text(expr, "index")
            nested = LTTngClient._capture_descriptor_from_mi(
                LTTngClient._mi_get_in_element(expr, "event_expr")
            )
            return "{}[{}]".format(nested, index)

        raise Unsupported(
            "Capture descriptor expression `{}` is not supported".format(expr_name)
        )

    @staticmethod
    def _event_rule_from_mi(event_rule_element):
        # type: (xml.etree.ElementTree.Element) -> lttngctl.EventRule
        # An <event_rule> wraps a single element naming its type.
        rule_element = list(event_rule_element)[0]
        rule_name = _mi_local_name(rule_element)

        def optional_text(name):
            # type: (str) -> Optional[str]
            element = LTTngClient._mi_find_in_element(rule_element, name)
            return element.text if element is not None else None

        name_pattern = optional_text("name_pattern")
        filter_expression = optional_text("filter_expression")

        if rule_name == "event_rule_user_tracepoint":
            exclusions = []  # type: List[str]
            exclusions_element = LTTngClient._mi_find_in_element(
                rule_element, "name_pattern_exclusions"
            )
            if exclusions_element is not None:
                for exclusion in exclusions_element:
                    exclusions.append(exclusion.text)

            return lttngctl.UserTracepointEventRule(
                name_pattern,
                filter_expression,
                LTTngClient._log_level_rule_from_mi(
                    rule_element, lttngctl.UserLogLevel
                ),
                exclusions if exclusions else None,
            )
        elif rule_name == "event_rule_kernel_tracepoint":
            return lttngctl.KernelTracepointEventRule(name_pattern, filter_expression)
        elif rule_name == "event_rule_kernel_syscall":
            return lttngctl.KernelSyscallEventRule(name_pattern, filter_expression)
        elif rule_name == "event_rule_kernel_kprobe":
            location = LTTngClient._mi_get_in_element(
                rule_element, "kernel_probe_location"
            )
            symbol_offset = LTTngClient._mi_find_in_element(
                location, "kernel_probe_location_symbol_offset"
            )
            symbol_name = (
                LTTngClient._mi_get_in_element(symbol_offset, "name").text
                if symbol_offset is not None
                else None
            )
            return lttngctl.KernelKprobeEventRule(
                event_name=optional_text("event_name"), symbol_name=symbol_name
            )
        elif rule_name in _AGENT_EVENT_RULE_FROM_MI:
            factory, log_level_enum = _AGENT_EVENT_RULE_FROM_MI[rule_name]
            return factory(
                name_pattern,
                filter_expression,
                LTTngClient._log_level_rule_from_mi(rule_element, log_level_enum),
                None,
            )

        raise Unsupported(
            "Event rule type `{}` is not supported for triggers".format(rule_name)
        )

    @staticmethod
    def _log_level_rule_from_mi(rule_element, log_level_enum):
        # type: (xml.etree.ElementTree.Element, Type[lttngctl.LogLevel]) -> Optional[lttngctl.LogLevelRule]
        log_level_rule_element = LTTngClient._mi_find_in_element(
            rule_element, "log_level_rule"
        )
        if log_level_rule_element is None:
            return None

        type_element = list(log_level_rule_element)[0]
        type_name = _mi_local_name(type_element)
        level = log_level_enum(
            int(LTTngClient._mi_get_in_element(type_element, "level").text)
        )

        if type_name == "log_level_rule_exactly":
            return lttngctl.LogLevelRuleExactly(level)
        elif type_name == "log_level_rule_at_least_as_severe_as":
            return lttngctl.LogLevelRuleAsSevereAs(level)

        raise Unsupported("Log level rule type `{}` is not supported".format(type_name))

    @staticmethod
    def _actions_from_mi(action_element):
        # type: (xml.etree.ElementTree.Element) -> List[lttngctl.TriggerAction]
        # The trigger's top-level <action> is either a single action or an
        # action-list wrapping the individual actions.
        type_element = list(action_element)[0]
        if _mi_local_name(type_element) == "action_list":
            return [
                LTTngClient._action_from_mi(sub_action)
                for sub_action in type_element
                if _mi_local_name(sub_action) == "action"
            ]

        return [LTTngClient._action_from_mi(action_element)]

    @staticmethod
    def _action_from_mi(action_element):
        # type: (xml.etree.ElementTree.Element) -> lttngctl.TriggerAction
        type_element = list(action_element)[0]
        type_name = _mi_local_name(type_element)
        rate_policy = LTTngClient._rate_policy_from_mi(type_element)
        error_query_results_element = LTTngClient._mi_get_in_element(
            action_element, "error_query_results"
        )
        error_query_results = LTTngClient._error_query_results_from_mi(
            error_query_results_element
        )

        if type_name == "action_notify":
            return lttngctl.NotifyTriggerAction(
                rate_policy, error_query_results=error_query_results
            )

        session_action_classes = {
            "action_start_session": lttngctl.StartSessionTriggerAction,
            "action_stop_session": lttngctl.StopSessionTriggerAction,
            "action_rotate_session": lttngctl.RotateSessionTriggerAction,
        }
        if type_name in session_action_classes:
            session_name = LTTngClient._mi_get_in_element(
                type_element, "session_name"
            ).text
            return session_action_classes[type_name](
                session_name, rate_policy, error_query_results=error_query_results
            )

        if type_name == "action_snapshot_session":
            session_name = LTTngClient._mi_get_in_element(
                type_element, "session_name"
            ).text
            # The snapshot output details are not reconstructed; only the
            # session name and rate policy round-trip through this controller.
            return lttngctl.SnapshotSessionTriggerAction(
                session_name,
                rate_policy=rate_policy,
                error_query_results=error_query_results,
            )

        if type_name == "action_increment_map_value":
            return lttngctl.IncrementMapValueTriggerAction(
                LTTngClient._mi_get_in_element(type_element, "session_name").text,
                LTTngClient._mi_get_in_element(type_element, "channel_name").text,
                _get_map_channel_type_from_mi(
                    LTTngClient._mi_get_in_element(type_element, "channel_type").text
                ),
                LTTngClient._mi_get_in_element(type_element, "key_template").text,
                error_query_results=error_query_results,
            )

        raise Unsupported("Action type `{}` is not supported".format(type_name))

    @staticmethod
    def _rate_policy_from_mi(type_element):
        # type: (xml.etree.ElementTree.Element) -> Optional[lttngctl.RatePolicy]
        rate_policy_element = LTTngClient._mi_find_in_element(
            type_element, "rate_policy"
        )
        if rate_policy_element is None:
            return None

        policy_element = list(rate_policy_element)[0]
        policy_name = _mi_local_name(policy_element)

        if policy_name == "rate_policy_every_n":
            return lttngctl.EveryNRatePolicy(
                int(LTTngClient._mi_get_in_element(policy_element, "interval").text)
            )
        elif policy_name == "rate_policy_once_after_n":
            return lttngctl.OnceAfterNRatePolicy(
                int(LTTngClient._mi_get_in_element(policy_element, "threshold").text)
            )

        raise Unsupported("Rate policy type `{}` is not supported".format(policy_name))
