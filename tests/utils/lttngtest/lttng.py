#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
#
# SPDX-License-Identifier: GPL-2.0-only


from . import lttngctl, logger, environment

import enum
import os
import shlex
import subprocess
import tempfile
from typing import Callable, Optional, Type, Union, Iterator
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
        # type: (Type[lttngctl.EventRule]) -> None
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
                client_args = client_args + " --filter " + rule.filter_expression

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
        else:
            raise Unsupported(
                "event rule type `{event_rule_type}` is unsupported by LTTng client".format(
                    event_rule_type=type(rule).__name__
                )
            )

        self._client._run_cmd(client_args)

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
        list_session_xml, _ = self._client._run_cmd(
            "list '{session_name}'".format(session_name=self._session.name),
            LTTngClient.CommandOutputFormat.MI_XML,
        )

        root = xml.etree.ElementTree.fromstring(list_session_xml)
        command_output = LTTngClient._mi_get_in_element(root, "output")
        sessions = LTTngClient._mi_get_in_element(command_output, "sessions")

        # The channel's session is supposed to be the only session returned by the command
        if len(sessions) != 1:
            raise InvalidMI(
                "Only one session expected when listing with an explicit session name"
            )
        session = sessions[0]

        # Look for the channel's domain
        target_domain = None
        target_domain_mi_name = _get_domain_xml_mi_name(self.domain)
        for domain in LTTngClient._mi_get_in_element(session, "domains"):
            if (
                LTTngClient._mi_get_in_element(domain, "type").text
                == target_domain_mi_name
            ):
                target_domain = domain

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

        tracepoint_event_rule_class = None

        for event in LTTngClient._mi_get_in_element(target_channel, "events"):
            # Note that the "enabled" property is ignored as it is not exposed by
            # the EventRule interface.
            pattern = LTTngClient._mi_get_in_element(event, "name").text
            type = LTTngClient._mi_get_in_element(event, "type").text

            filter_expression = None
            filter_expression_element = LTTngClient._mi_find_in_element(
                event, "filter_expression"
            )
            if filter_expression_element:
                filter_expression = filter_expression_element.text

            exclusions = []
            for exclusion in LTTngClient._mi_get_in_element(event, "exclusions"):
                exclusions.append(exclusion.text)

            exclusions = exclusions if len(exclusions) > 0 else None

            if type != "TRACEPOINT":
                raise Unsupported(
                    "Non-tracepoint event rules are not supported by this Controller implementation"
                )

            tracepoint_event_rule_class = (
                _get_tracepoint_event_rule_class_from_domain_type(self.domain)
            )
            event_rule = None
            if self.domain != lttngctl.TracingDomain.Kernel:
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
                            _get_log_level_from_mi_log_level_name(
                                log_level_element.text
                            )
                        )
                    elif log_level_type_element.text == "SINGLE":
                        log_level_rule = lttngctl.LogLevelRuleExactly(
                            _get_log_level_from_mi_log_level_name(
                                log_level_element.text
                            )
                        )

                yield tracepoint_event_rule_class(
                    pattern, filter_expression, log_level_rule, exclusions
                )
            else:
                yield tracepoint_event_rule_class(pattern, filter_expression)


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
            self._allowed_value_types = [int, str]  # type: list[type]
        else:
            self._allowed_value_types = [int]  # type: list[type]

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
    ):
        # type: (lttngctl.TracingDomain, Optional[str], lttngctl.BufferSharingPolicy, lttngctl.BufferAllocationPolicy, Optional[int], Optional[int], Optional[int], Optional[int], Optional[lttngctl.EventRecordLossMode], Optional[int]) -> lttngctl.Channel
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

        self._client._run_cmd(" ".join([shlex.quote(x) for x in args]))
        return _Channel(self._client, channel_name, domain, self)

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

        client_env = os.environ.copy()  # type: dict[str, str]
        if self._environment.lttng_home_location is not None:
            client_env["LTTNG_HOME"] = str(self._environment.lttng_home_location)
        if self._environment.lttng_rundir is not None:
            client_env["LTTNG_RUNDIR"] = str(self._environment.lttng_rundir)
        client_env.update(self._extra_env_vars)

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

        out, err = process.communicate(timeout=self.timeout)
        out = out.decode("utf-8")
        if not err_output:
            err = err.decode("utf-8")
        else:
            err = open(err_output.name, "r", encoding="utf-8").read()

        for error_line in err.splitlines():
            self._log(error_line)

        if process.returncode != 0:
            raise LTTngClientError(command_args, out, err)
        else:
            return (out, err)

    def create_session(
        self, name=None, output=None, live=False, snapshot=False, shm_path=None
    ):
        # type: (Optional[str], Optional[lttngctl.SessionOutputLocation], bool, bool, Optional[pathlib.Path]) -> lttngctl.Session
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
            args.append("--live")
        if shm_path is not None:
            args.extend(["--shm-path", str(shm_path)])
        if snapshot:
            args.append("--snapshot")
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

    def save_sessions(self, session_name=None, force=False, output_path=None):

        cmd = [
            "save",
        ]

        if force:
            cmd.append("--force")

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

    def load_sessions(self, session_name=None, force=False, input_path=None):

        cmd = ["load"]

        if force:
            cmd.append("--force")

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
