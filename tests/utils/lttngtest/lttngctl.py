#!/usr/bin/env python3
#
# Copyright (C) 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
#
# SPDX-License-Identifier: GPL-2.0-only

import abc
import random
import string
import pathlib
import enum
from typing import Optional, Type, Union, List

"""
Defines an abstract interface to control LTTng tracing.

The various control concepts are defined by this module. You can use them with a
Controller to interact with a session daemon.

This interface is not comprehensive; it currently provides a subset of the
control functionality that is used by tests.
"""


def _generate_random_string(length: int) -> str:
    return "".join(
        random.choice(string.ascii_lowercase + string.digits) for _ in range(length)
    )


class ContextType(abc.ABC):
    """Base class representing a tracing context field."""

    pass


class VpidContextType(ContextType):
    """Application's virtual process id."""

    pass


class VuidContextType(ContextType):
    """Application's virtual user id."""

    pass


class VgidContextType(ContextType):
    """Application's virtual group id."""

    pass


class JavaApplicationContextType(ContextType):
    """A java application-specific context field is a piece of state which the application provides."""

    def __init__(self, retriever_name: str, field_name: str):
        self._retriever_name: str = retriever_name
        self._field_name: str = field_name

    @property
    def retriever_name(self) -> str:
        return self._retriever_name

    @property
    def field_name(self) -> str:
        return self._field_name


class TracingDomain(enum.Enum):
    """Tracing domain."""

    User = enum.auto(), "User space tracing domain"
    Kernel = enum.auto(), "Linux kernel tracing domain."
    Log4j = enum.auto(), "Log4j tracing back-end."
    JUL = enum.auto(), "Java Util Logging tracing back-end."
    Python = enum.auto(), "Python logging module tracing back-end."


class EventRule(abc.ABC):
    """Event rule base class, see LTTNG-EVENT-RULE(7)."""

    pass


class LogLevelRule:
    pass


class LogLevelRuleAsSevereAs(LogLevelRule):
    def __init__(self, level: int):
        self._level = level

    @property
    def level(self) -> int:
        return self._level


class LogLevelRuleExactly(LogLevelRule):
    def __init__(self, level: int):
        self._level = level

    @property
    def level(self) -> int:
        return self._level


class TracepointEventRule(EventRule):
    def __init__(
        self,
        name_pattern: Optional[str] = None,
        filter_expression: Optional[str] = None,
        log_level_rule: Optional[LogLevelRule] = None,
        name_pattern_exclusions: Optional[List[str]] = None,
    ):
        self._name_pattern: Optional[str] = name_pattern
        self._filter_expression: Optional[str] = filter_expression
        self._log_level_rule: Optional[LogLevelRule] = log_level_rule
        self._name_pattern_exclusions: Optional[List[str]] = name_pattern_exclusions

    @property
    def name_pattern(self) -> Optional[str]:
        return self._name_pattern

    @property
    def filter_expression(self) -> Optional[str]:
        return self._filter_expression

    @property
    def log_level_rule(self) -> Optional[LogLevelRule]:
        return self._log_level_rule

    @property
    def name_pattern_exclusions(self) -> Optional[List[str]]:
        return self._name_pattern_exclusions


class UserTracepointEventRule(TracepointEventRule):
    def __init__(
        self,
        name_pattern: Optional[str] = None,
        filter_expression: Optional[str] = None,
        log_level_rule: Optional[LogLevelRule] = None,
        name_pattern_exclusions: Optional[List[str]] = None,
    ):
        TracepointEventRule.__init__(**locals())


class KernelTracepointEventRule(TracepointEventRule):
    def __init__(
        self,
        name_pattern: Optional[str] = None,
        filter_expression: Optional[str] = None,
        log_level_rule: Optional[LogLevelRule] = None,
        name_pattern_exclusions: Optional[List[str]] = None,
    ):
        TracepointEventRule.__init__(**locals())


class Channel(abc.ABC):
    """
    A channel is an object which is responsible for a set of ring buffers. It is
    associated to a domain and
    """

    @staticmethod
    def _generate_name() -> str:
        return "channel_{random_id}".format(random_id=_generate_random_string(8))

    @abc.abstractmethod
    def add_context(self, context_type: ContextType) -> None:
        pass

    @property
    @abc.abstractmethod
    def domain(self) -> TracingDomain:
        pass

    @property
    @abc.abstractmethod
    def name(self) -> str:
        pass

    @abc.abstractmethod
    def add_recording_rule(self, rule: Type[EventRule]) -> None:
        pass


class SessionOutputLocation(abc.ABC):
    pass


class LocalSessionOutputLocation(SessionOutputLocation):
    def __init__(self, trace_path: pathlib.Path):
        self._path = trace_path

    @property
    def path(self) -> pathlib.Path:
        return self._path


class ProcessAttributeTracker(abc.ABC):
    """
    Process attribute tracker used to filter before the evaluation of event
    rules.

    Note that this interface is currently limited as it doesn't allow changing
    the tracking policy. For instance, it is not possible to set the tracking
    policy back to "all" once it has transitioned to "include set".
    """

    class TrackingPolicy(enum.Enum):
        INCLUDE_ALL = (
            enum.auto(),
            """
            Track all possible process attribute value of a given type (i.e. no filtering).
            This is the default state of a process attribute tracker.
            """,
        )
        EXCLUDE_ALL = (
            enum.auto(),
            "Exclude all possible process attribute values of a given type.",
        )
        INCLUDE_SET = enum.auto(), "Track a set of specific process attribute values."

    def __init__(self, policy: TrackingPolicy):
        self._policy = policy

    @property
    def tracking_policy(self) -> TrackingPolicy:
        return self._policy


class ProcessIDProcessAttributeTracker(ProcessAttributeTracker):
    @abc.abstractmethod
    def track(self, pid: int) -> None:
        pass

    @abc.abstractmethod
    def untrack(self, pid: int) -> None:
        pass


class VirtualProcessIDProcessAttributeTracker(ProcessAttributeTracker):
    @abc.abstractmethod
    def track(self, vpid: int) -> None:
        pass

    @abc.abstractmethod
    def untrack(self, vpid: int) -> None:
        pass


class UserIDProcessAttributeTracker(ProcessAttributeTracker):
    @abc.abstractmethod
    def track(self, uid: Union[int, str]) -> None:
        pass

    @abc.abstractmethod
    def untrack(self, uid: Union[int, str]) -> None:
        pass


class VirtualUserIDProcessAttributeTracker(ProcessAttributeTracker):
    @abc.abstractmethod
    def track(self, vuid: Union[int, str]) -> None:
        pass

    @abc.abstractmethod
    def untrack(self, vuid: Union[int, str]) -> None:
        pass


class GroupIDProcessAttributeTracker(ProcessAttributeTracker):
    @abc.abstractmethod
    def track(self, gid: Union[int, str]) -> None:
        pass

    @abc.abstractmethod
    def untrack(self, gid: Union[int, str]) -> None:
        pass


class VirtualGroupIDProcessAttributeTracker(ProcessAttributeTracker):
    @abc.abstractmethod
    def track(self, vgid: Union[int, str]) -> None:
        pass

    @abc.abstractmethod
    def untrack(self, vgid: Union[int, str]) -> None:
        pass


class Session(abc.ABC):
    @staticmethod
    def _generate_name() -> str:
        return "session_{random_id}".format(random_id=_generate_random_string(8))

    @property
    @abc.abstractmethod
    def name(self) -> str:
        pass

    @property
    @abc.abstractmethod
    def output(self) -> Optional[Type[SessionOutputLocation]]:
        pass

    @abc.abstractmethod
    def add_channel(
        self, domain: TracingDomain, channel_name: Optional[str] = None
    ) -> Channel:
        """Add a channel with default attributes to the session."""
        pass

    @abc.abstractmethod
    def start(self) -> None:
        pass

    @abc.abstractmethod
    def stop(self) -> None:
        pass

    @abc.abstractmethod
    def destroy(self) -> None:
        pass

    @abc.abstractproperty
    def kernel_pid_process_attribute_tracker(
        self,
    ) -> Type[ProcessIDProcessAttributeTracker]:
        raise NotImplementedError

    @abc.abstractproperty
    def kernel_vpid_process_attribute_tracker(
        self,
    ) -> Type[VirtualProcessIDProcessAttributeTracker]:
        raise NotImplementedError

    @abc.abstractproperty
    def user_vpid_process_attribute_tracker(
        self,
    ) -> Type[VirtualProcessIDProcessAttributeTracker]:
        raise NotImplementedError

    @abc.abstractproperty
    def kernel_gid_process_attribute_tracker(
        self,
    ) -> Type[GroupIDProcessAttributeTracker]:
        raise NotImplementedError

    @abc.abstractproperty
    def kernel_vgid_process_attribute_tracker(
        self,
    ) -> Type[VirtualGroupIDProcessAttributeTracker]:
        raise NotImplementedError

    @abc.abstractproperty
    def user_vgid_process_attribute_tracker(
        self,
    ) -> Type[VirtualGroupIDProcessAttributeTracker]:
        raise NotImplementedError

    @abc.abstractproperty
    def kernel_uid_process_attribute_tracker(
        self,
    ) -> Type[UserIDProcessAttributeTracker]:
        raise NotImplementedError

    @abc.abstractproperty
    def kernel_vuid_process_attribute_tracker(
        self,
    ) -> Type[VirtualUserIDProcessAttributeTracker]:
        raise NotImplementedError

    @abc.abstractproperty
    def user_vuid_process_attribute_tracker(
        self,
    ) -> Type[VirtualUserIDProcessAttributeTracker]:
        raise NotImplementedError


class ControlException(RuntimeError):
    """Base type for exceptions thrown by a controller."""

    def __init__(self, msg: str):
        super().__init__(msg)


class Controller(abc.ABC):
    """
    Interface of a top-level control interface. A control interface can be, for
    example, the LTTng client or a wrapper around liblttng-ctl. It is used to
    create and manage top-level objects of a session daemon instance.
    """

    @abc.abstractmethod
    def create_session(
        self, name: Optional[str] = None, output: Optional[SessionOutputLocation] = None
    ) -> Session:
        """
        Create a session with an output. Don't specify an output
        to create a session without an output.
        """
        pass
