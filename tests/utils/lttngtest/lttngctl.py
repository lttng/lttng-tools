#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
#
# SPDX-License-Identifier: GPL-2.0-only

import abc
import random
import sqlite3
import string
import pathlib
import enum
from typing import Iterator, Optional, Type, Union, List

"""
Defines an abstract interface to control LTTng tracing.

The various control concepts are defined by this module. You can use them with a
Controller to interact with a session daemon.

This interface is not comprehensive; it currently provides a subset of the
control functionality that is used by tests.
"""


def _generate_random_string(length):
    # type: (int) -> str
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


class CPUidContextType(ContextType):
    """CPU ID of the event."""

    pass


class JavaApplicationContextType(ContextType):
    """A java application-specific context field is a piece of state which the application provides."""

    def __init__(
        self,
        retriever_name,  # type: str
        field_name,  # type: str
    ):
        self._retriever_name = retriever_name  # type: str
        self._field_name = field_name  # type: str

    @property
    def retriever_name(self):
        # type: () -> str
        return self._retriever_name

    @property
    def field_name(self):
        # type: () -> str
        return self._field_name


@enum.unique
class TracingDomain(enum.Enum):
    """Tracing domain."""

    User = "User space tracing domain"
    Kernel = "Linux kernel tracing domain."
    Log4j = "Log4j 1.x tracing back-end."
    Log4j2 = "Log4j 2.x tracing back-end."
    JUL = "Java Util Logging tracing back-end."
    Python = "Python logging module tracing back-end."

    @property
    def is_agent(self):
        # type: () -> bool
        """Indicates whether this domain is an agent domain (i.e. has no user-visible channels)."""
        return self in (
            TracingDomain.Log4j,
            TracingDomain.Log4j2,
            TracingDomain.JUL,
            TracingDomain.Python,
        )

    def __repr__(self):
        return "<%s.%s>" % (self.__class__.__name__, self.name)


@enum.unique
class BufferSharingPolicy(enum.Enum):
    """Buffer sharing policy."""

    PerUID = "Per-UID buffering"
    PerPID = "Per-PID buffering"

    def __repr__(self):
        return "<%s.%s>" % (self.__class__.__name__, self.name)


@enum.unique
class BufferAllocationPolicy(enum.Enum):
    """Buffer allocation policy."""

    PerCPU = "Per-CPU allocation"
    PerChannel = "Per-Channel allocation"

    def __repr__(self):
        return "<%s.%s>" % (self.__class__.__name__, self.name)


@enum.unique
class BufferPreAllocationPolicy(enum.Enum):
    """Buffer preallocation policy."""

    PreAllocate = "Pre-allocate allocation"
    OnDemand = "On-demand allocation"

    def __repr__(self):
        return "<%s.%s>" % (self.__class__.__name__, self.name)

    def as_arg(self):
        """
        Return the string value for lttng cli
        """
        if self.name == "PreAllocate":
            return "preallocate"
        elif self.name == "OnDemand":
            return "on-demand"
        assert False


@enum.unique
class EventRecordLossMode(enum.Enum):
    """Event record loss mode."""

    Discard = "Per-CPU allocation"
    Overwrite = "Per-Channel allocation"

    def __repr__(self):
        return "<%s.%s>" % (self.__class__.__name__, self.name)


@enum.unique
class MapChannelValueType(enum.Enum):
    """Value type of the counters of a map channel."""

    SignedInt32 = "32-bit signed integer"
    SignedInt64 = "64-bit signed integer"
    SignedIntMax = "Widest available signed integer"

    def __repr__(self):
        return "<%s.%s>" % (self.__class__.__name__, self.name)

    def as_arg(self):
        # type: () -> str
        """Return the `--value-type` option value for the lttng client."""
        return {
            MapChannelValueType.SignedInt32: "signed-int-32",
            MapChannelValueType.SignedInt64: "signed-int-64",
            MapChannelValueType.SignedIntMax: "signed-int-max",
        }[self]


@enum.unique
class MapChannelUpdatePolicy(enum.Enum):
    """Counter update policy of a map channel."""

    PerEvent = "Increment a counter once per matching event"
    PerRuleMatch = "Increment a counter once per matching event rule"

    def __repr__(self):
        return "<%s.%s>" % (self.__class__.__name__, self.name)

    def as_arg(self):
        # type: () -> str
        """Return the `--update-policy` option value for the lttng client."""
        return {
            MapChannelUpdatePolicy.PerEvent: "per-event",
            MapChannelUpdatePolicy.PerRuleMatch: "per-rule-match",
        }[self]


@enum.unique
class MapChannelDeadProcessPolicy(enum.Enum):
    """
    Policy which a user space map channel having a per-process buffer ownership
    model applies to the counters of a dead process.
    """

    Drop = "Drop the counters of a dead process"
    SumIntoShared = "Sum the counters of a dead process into shared counters"

    def __repr__(self):
        return "<%s.%s>" % (self.__class__.__name__, self.name)

    def as_arg(self):
        # type: () -> str
        """Return the `--dead-process-policy` option value for the lttng client."""
        return {
            MapChannelDeadProcessPolicy.Drop: "drop",
            MapChannelDeadProcessPolicy.SumIntoShared: "sum-into-shared",
        }[self]


@enum.unique
class MapGroupType(enum.Enum):
    """Type of a map group."""

    KernelGlobal = "Linux kernel, system-wide map group"
    UserPerUser = "Per-user, user space map group"
    UserPerProcess = "Per-process, user space map group"
    Shared = "Channel-wide, owner-less user space map group"

    def __repr__(self):
        return "<%s.%s>" % (self.__class__.__name__, self.name)


class MapGroup:
    """
    A map group is the subset of the per-CPU stores (maps) of a map channel
    which share a common owner.

    Depending on its type, the owner is a user
    (`MapGroupType.UserPerUser`), a process
    (`MapGroupType.UserPerProcess`), the whole system
    (`MapGroupType.KernelGlobal`), or the channel itself
    (`MapGroupType.Shared`). Only the per-user and per-process types
    have an owner ID and owner name; the other types leave those
    properties as `None`.
    """

    def __init__(
        self,
        type,  # type: MapGroupType
        effective_value_type,  # type: MapChannelValueType
        owner_id=None,  # type: Optional[int]
        owner_name=None,  # type: Optional[str]
    ):
        self._type = type  # type: MapGroupType
        self._effective_value_type = effective_value_type  # type: MapChannelValueType
        self._owner_id = owner_id  # type: Optional[int]
        self._owner_name = owner_name  # type: Optional[str]

    @property
    def type(self):
        # type: () -> MapGroupType
        return self._type

    @property
    def effective_value_type(self):
        # type: () -> MapChannelValueType
        """Effective value type (resolved counter value width) of the group."""
        return self._effective_value_type

    @property
    def owner_id(self):
        # type: () -> Optional[int]
        """Owner ID (user or process ID) of a per-user or per-process group; `None` otherwise."""
        return self._owner_id

    @property
    def owner_name(self):
        # type: () -> Optional[str]
        """Owner name of a per-user or per-process group; `None` otherwise."""
        return self._owner_name


@enum.unique
class ConditionType(enum.Enum):
    """
    enum lttng_condition_type
    """

    SessionConsumedSize = "LTTNG_CONDITION_TYPE_SESSION_CONSUMED_SIZE"
    BufferUsageHigh = "LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH"
    BufferUsageLow = "LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW"
    SessionRotationOngoing = "LTTNG_CONDITION_TYPE_SESSION_ROTATION_ONGOING"
    SessionRotationCompleted = "LTTNG_CONDITION_TYPE_SESSION_ROTATION_COMPLETED"
    EventRuleMatches = "LTTNG_CONDITION_TYPE_EVENT_RULE_MATCHES"
    Unknown = "LTTNG_CONDITION_TYPE_UNKNOWN"


class EventRule(abc.ABC):
    """Event rule base class, see LTTNG-EVENT-RULE(7)."""

    pass


class LogLevelRule:
    def __eq__(self, other):
        # type (LogLevelRule) -> bool
        if type(self) != type(other):
            return False

        return self.level == other.level


@enum.unique
class LogLevel(enum.Enum):
    pass


@enum.unique
class SessionRegenerateTarget(enum.Enum):
    """Session regeneration target data type"""

    Metadata = "metadata"
    Statedump = "statedump"

    def __str__(self):
        return self.value

    def __repr__(self):
        return "<%s.%s>" % (self.__class__.__name__, self.name)


@enum.unique
class TraceFormat(enum.Enum):
    CTF_1_8 = "ctf-1.8"
    CTF_2 = "ctf-2"


@enum.unique
class UserLogLevel(LogLevel):
    EMERGENCY = 0
    ALERT = 1
    CRITICAL = 2
    ERROR = 3
    WARNING = 4
    NOTICE = 5
    INFO = 6
    DEBUG_SYSTEM = 7
    DEBUG_PROGRAM = 8
    DEBUG_PROCESS = 9
    DEBUG_MODULE = 10
    DEBUG_UNIT = 11
    DEBUG_FUNCTION = 12
    DEBUG_LINE = 13
    DEBUG = 14


@enum.unique
class JULLogLevel(LogLevel):
    OFF = 2147483647
    SEVERE = 1000
    WARNING = 900
    INFO = 800
    CONFIG = 700
    FINE = 500
    FINER = 400
    FINEST = 300
    ALL = -2147483648


@enum.unique
class Log4jLogLevel(LogLevel):
    OFF = 2147483647
    FATAL = 50000
    ERROR = 40000
    WARN = 30000
    INFO = 20000
    DEBUG = 10000
    TRACE = 5000
    ALL = -2147483648


@enum.unique
class Log4j2LogLevel(LogLevel):
    OFF = 0
    FATAL = 100
    ERROR = 200
    WARN = 300
    INFO = 400
    DEBUG = 500
    TRACE = 600
    ALL = 2147483647


@enum.unique
class PythonLogLevel(LogLevel):
    CRITICAL = 50
    ERROR = 40
    WARNING = 30
    INFO = 20
    DEBUG = 10
    NOTSET = 0


class LogLevelRuleAsSevereAs(LogLevelRule):
    def __init__(self, level):
        # type: (LogLevel)
        self._level = level

    @property
    def level(self):
        # type: () -> LogLevel
        return self._level


class LogLevelRuleExactly(LogLevelRule):
    def __init__(self, level):
        # type: (LogLevel)
        self._level = level

    @property
    def level(self):
        # type: () -> LogLevel
        return self._level


class TracepointEventRule(EventRule):
    def __init__(
        self,
        name_pattern=None,  # type: Optional[str]
        filter_expression=None,  # type: Optional[str]
    ):
        self._name_pattern = name_pattern  # type: Optional[str]
        self._filter_expression = filter_expression  # type: Optional[str]
        self._enabled = None  # type: Optional[bool]

    def _equals(self, other):
        # type (TracepointEventRule) -> bool
        # Overridden by derived classes that have supplementary attributes.
        return True

    def __eq__(self, other):
        # type (TracepointEventRule) -> bool
        if type(self) != type(other):
            return False

        if self.name_pattern != other.name_pattern:
            return False

        if self.filter_expression != other.filter_expression:
            return False

        return self._equals(other)

    @property
    def name_pattern(self):
        # type: () -> Optional[str]
        return self._name_pattern

    @property
    def filter_expression(self):
        # type: () -> Optional[str]
        return self._filter_expression

    @property
    def enabled(self):
        # type: () -> Optional[bool]
        return self._enabled


class UserTracepointEventRule(TracepointEventRule):
    def __init__(
        self,
        name_pattern=None,  # type: Optional[str]
        filter_expression=None,  # type: Optional[str]
        log_level_rule=None,  # type: Optional[LogLevelRule]
        name_pattern_exclusions=None,  # type: Optional[List[str]]
    ):
        TracepointEventRule.__init__(self, name_pattern, filter_expression)
        self._log_level_rule = log_level_rule  # type: Optional[LogLevelRule]
        self._name_pattern_exclusions = (
            name_pattern_exclusions
        )  # type: Optional[List[str]]

        if log_level_rule and not isinstance(log_level_rule.level, UserLogLevel):
            raise ValueError("Log level rule must use a UserLogLevel as its value")

    def _equals(self, other):
        # type (UserTracepointEventRule) -> bool
        return (
            self.log_level_rule == other.log_level_rule
            and self.name_pattern_exclusions == other.name_pattern_exclusions
        )

    @property
    def log_level_rule(self):
        # type: () -> Optional[LogLevelRule]
        return self._log_level_rule

    @property
    def name_pattern_exclusions(self):
        # type: () -> Optional[List[str]]
        return self._name_pattern_exclusions


class Log4jTracepointEventRule(TracepointEventRule):
    def __init__(
        self,
        name_pattern=None,  # type: Optional[str]
        filter_expression=None,  # type: Optional[str]
        log_level_rule=None,  # type: Optional[LogLevelRule]
        name_pattern_exclusions=None,  # type: Optional[List[str]]
    ):
        TracepointEventRule.__init__(self, name_pattern, filter_expression)
        self._log_level_rule = log_level_rule  # type: Optional[LogLevelRule]
        self._name_pattern_exclusions = (
            name_pattern_exclusions
        )  # type: Optional[List[str]]

        if log_level_rule and not isinstance(log_level_rule.level, Log4jLogLevel):
            raise ValueError("Log level rule must use a Log4jLogLevel as its value")

    def _equals(self, other):
        # type (Log4jTracepointEventRule) -> bool
        return (
            self.log_level_rule == other.log_level_rule
            and self.name_pattern_exclusions == other.name_pattern_exclusions
        )

    @property
    def log_level_rule(self):
        # type: () -> Optional[LogLevelRule]
        return self._log_level_rule

    @property
    def name_pattern_exclusions(self):
        # type: () -> Optional[List[str]]
        return self._name_pattern_exclusions


class Log4j2TracepointEventRule(TracepointEventRule):
    def __init__(
        self,
        name_pattern=None,  # type: Optional[str]
        filter_expression=None,  # type: Optional[str]
        log_level_rule=None,  # type: Optional[LogLevelRule]
        name_pattern_exclusions=None,  # type: Optional[List[str]]
    ):
        TracepointEventRule.__init__(self, name_pattern, filter_expression)
        self._log_level_rule = log_level_rule  # type: Optional[LogLevelRule]
        self._name_pattern_exclusions = (
            name_pattern_exclusions
        )  # type: Optional[List[str]]

        if log_level_rule and not isinstance(log_level_rule.level, Log4j2LogLevel):
            raise ValueError("Log level rule must use a Log4j2LogLevel as its value")

    def _equals(self, other):
        # type (Log4jTracepointEventRule) -> bool
        return (
            self.log_level_rule == other.log_level_rule
            and self.name_pattern_exclusions == other.name_pattern_exclusions
        )

    @property
    def log_level_rule(self):
        # type: () -> Optional[LogLevelRule]
        return self._log_level_rule

    @property
    def name_pattern_exclusions(self):
        # type: () -> Optional[List[str]]
        return self._name_pattern_exclusions


class JULTracepointEventRule(TracepointEventRule):
    def __init__(
        self,
        name_pattern=None,  # type: Optional[str]
        filter_expression=None,  # type: Optional[str]
        log_level_rule=None,  # type: Optional[LogLevelRule]
        name_pattern_exclusions=None,  # type: Optional[List[str]]
    ):
        TracepointEventRule.__init__(self, name_pattern, filter_expression)
        self._log_level_rule = log_level_rule  # type: Optional[LogLevelRule]
        self._name_pattern_exclusions = (
            name_pattern_exclusions
        )  # type: Optional[List[str]]

        if log_level_rule and not isinstance(log_level_rule.level, JULLogLevel):
            raise ValueError("Log level rule must use a JULLogLevel as its value")

    def _equals(self, other):
        # type (JULTracepointEventRule) -> bool
        return (
            self.log_level_rule == other.log_level_rule
            and self.name_pattern_exclusions == other.name_pattern_exclusions
        )

    @property
    def log_level_rule(self):
        # type: () -> Optional[LogLevelRule]
        return self._log_level_rule

    @property
    def name_pattern_exclusions(self):
        # type: () -> Optional[List[str]]
        return self._name_pattern_exclusions


class PythonTracepointEventRule(TracepointEventRule):
    def __init__(
        self,
        name_pattern=None,  # type: Optional[str]
        filter_expression=None,  # type: Optional[str]
        log_level_rule=None,  # type: Optional[LogLevelRule]
        name_pattern_exclusions=None,  # type: Optional[List[str]]
    ):
        TracepointEventRule.__init__(self, name_pattern, filter_expression)
        self._log_level_rule = log_level_rule  # type: Optional[LogLevelRule]
        self._name_pattern_exclusions = (
            name_pattern_exclusions
        )  # type: Optional[List[str]]

        if log_level_rule and not isinstance(log_level_rule.level, PythonLogLevel):
            raise ValueError("Log level rule must use a PythonLogLevel as its value")

    def _equals(self, other):
        # type (PythonTracepointEventRule) -> bool
        return (
            self.log_level_rule == other.log_level_rule
            and self.name_pattern_exclusions == other.name_pattern_exclusions
        )

    @property
    def log_level_rule(self):
        # type: () -> Optional[LogLevelRule]
        return self._log_level_rule

    @property
    def name_pattern_exclusions(self):
        # type: () -> Optional[List[str]]
        return self._name_pattern_exclusions


class KernelTracepointEventRule(TracepointEventRule):
    def __init__(
        self,
        name_pattern=None,  # type: Optional[str]
        filter_expression=None,  # type: Optional[str]
    ):
        TracepointEventRule.__init__(**locals())


class KernelSyscallEventRule(EventRule):
    """Kernel syscall event rule."""

    def __init__(
        self,
        name_pattern=None,  # type: Optional[str]
        filter_expression=None,  # type: Optional[str]
    ):
        self._name_pattern = name_pattern  # type: Optional[str]
        self._filter_expression = filter_expression  # type: Optional[str]
        self._enabled = None  # type: Optional[bool]

    def __eq__(self, other):
        # type: (object) -> bool
        return (
            type(self) == type(other)
            and self._name_pattern == other._name_pattern
            and self._filter_expression == other._filter_expression
        )

    def __repr__(self):
        return (
            "KernelSyscallEventRule(name_pattern='{}', filter_expression={!r})".format(
                self._name_pattern, self._filter_expression
            )
        )

    @property
    def name_pattern(self):
        # type: () -> Optional[str]
        return self._name_pattern

    @property
    def filter_expression(self):
        # type: () -> Optional[str]
        return self._filter_expression

    @property
    def enabled(self):
        # type: () -> Optional[bool]
        return self._enabled


class KernelKprobeEventRule(EventRule):
    """Kernel kprobe event rule (probe at a location, entry only)."""

    def __init__(
        self,
        event_name,  # type: str
        symbol_name,  # type: str
    ):
        self._event_name = event_name  # type: str
        self._symbol_name = symbol_name  # type: str
        self._enabled = None  # type: Optional[bool]

    def __eq__(self, other):
        # type: (object) -> bool
        if type(self) != type(other):
            return False

        return (
            self._event_name == other._event_name
            and self._symbol_name == other._symbol_name
        )

    def __repr__(self):
        return "KernelKprobeEventRule(event_name='{}', symbol_name='{}')".format(
            self._event_name, self._symbol_name
        )

    @property
    def event_name(self):
        # type: () -> str
        return self._event_name

    @property
    def symbol_name(self):
        # type: () -> str
        return self._symbol_name

    @property
    def enabled(self):
        # type: () -> Optional[bool]
        return self._enabled


class KernelFunctionEventRule(EventRule):
    """Kernel function event rule (entry+exit instrumentation)."""

    def __init__(
        self,
        event_name,  # type: str
        symbol_name,  # type: str
    ):
        self._event_name = event_name  # type: str
        self._symbol_name = symbol_name  # type: str
        self._enabled = None  # type: Optional[bool]

    def __eq__(self, other):
        # type: (object) -> bool
        if type(self) != type(other):
            return False

        return (
            self._event_name == other._event_name
            and self._symbol_name == other._symbol_name
        )

    def __repr__(self):
        return "KernelFunctionEventRule(event_name='{}', symbol_name='{}')".format(
            self._event_name, self._symbol_name
        )

    @property
    def event_name(self):
        # type: () -> str
        return self._event_name

    @property
    def symbol_name(self):
        # type: () -> str
        return self._symbol_name

    @property
    def enabled(self):
        # type: () -> Optional[bool]
        return self._enabled


# Trigger-related classes


class ErrorQueryResult(abc.ABC):
    """Error query result."""

    def __init__(
        self,
        name: str,
        description: str,
        value: int = 0,
    ):
        self._name: str = name
        self._description: str = description
        self._value = value

    @property
    def name(self) -> str:
        return self._name

    @property
    def description(self) -> str:
        return self._description

    @property
    def value(self) -> int:
        return self._value


class RatePolicy(abc.ABC):
    """Base class for trigger action rate policies."""

    pass


class EveryNRatePolicy(RatePolicy):
    """Execute action every N times the condition is satisfied."""

    def __init__(self, interval):
        # type: (int) -> None
        self._interval = interval

    def __eq__(self, other):
        # type: (object) -> bool
        return type(self) == type(other) and self._interval == other._interval

    def __repr__(self):
        return "EveryNRatePolicy(interval={})".format(self._interval)

    @property
    def interval(self):
        # type: () -> int
        return self._interval


class OnceAfterNRatePolicy(RatePolicy):
    """Execute action once after N times the condition is satisfied."""

    def __init__(self, count):
        # type: (int) -> None
        self._count = count

    def __eq__(self, other):
        # type: (object) -> bool
        return type(self) == type(other) and self._count == other._count

    def __repr__(self):
        return "OnceAfterNRatePolicy(count={})".format(self._count)

    @property
    def count(self):
        # type: () -> int
        return self._count


class TriggerCondition(abc.ABC):
    """Base class for trigger conditions."""

    def __init__(self, error_query_results: List[ErrorQueryResult] = list()):
        self._error_query_results = error_query_results

    @property
    def error_query_results(self) -> List[ErrorQueryResult]:
        return self._error_query_results


class EventRuleMatchesCondition(TriggerCondition):
    """Condition satisfied when an event matches the specified event rule."""

    def __init__(
        self,
        event_rule,  # type: EventRule
        capture_descriptors=None,  # type: Optional[List[str]]
        error_query_results: List[ErrorQueryResult] = list(),
    ):
        super().__init__(error_query_results)
        self._event_rule = event_rule
        self._capture_descriptors = capture_descriptors if capture_descriptors else []

    def __eq__(self, other):
        # type: (object) -> bool
        return (
            type(self) == type(other)
            and self._event_rule == other._event_rule
            and self._capture_descriptors == other._capture_descriptors
        )

    def __repr__(self):
        return "EventRuleMatchesCondition(event_rule={!r}, capture_descriptors={!r})".format(
            self._event_rule, self._capture_descriptors
        )

    @property
    def event_rule(self):
        # type: () -> EventRule
        return self._event_rule

    @property
    def capture_descriptors(self):
        # type: () -> List[str]
        return self._capture_descriptors


class TriggerAction(abc.ABC):
    """Base class for trigger actions."""

    def __init__(self, error_query_results: List[ErrorQueryResult] = list()):
        self._error_query_results = error_query_results

    @property
    def error_query_results(self) -> List[ErrorQueryResult]:
        return self._error_query_results


class _RatePolicyAction(TriggerAction):
    """
    Base class for trigger actions that support a rate policy.

    Not every action type supports a rate policy (for example, the
    increment-map-value action does not), so it is opt-in through this
    intermediate base rather than being part of TriggerAction itself.
    """

    def __init__(
        self, rate_policy=None, error_query_results: List[ErrorQueryResult] = list()
    ):
        # type: (Optional[RatePolicy]) -> None
        super().__init__(error_query_results=error_query_results)
        self._rate_policy = rate_policy

    def _effective_rate_policy(self):
        # type: () -> RatePolicy
        # When no rate policy is set, the session daemon applies (and reports)
        # a default of "every 1".
        return (
            self._rate_policy if self._rate_policy is not None else EveryNRatePolicy(1)
        )

    def __eq__(self, other):
        # type: (object) -> bool
        return (
            type(self) == type(other)
            and self._effective_rate_policy() == other._effective_rate_policy()
        )

    @property
    def rate_policy(self):
        # type: () -> Optional[RatePolicy]
        return self._rate_policy


class NotifyTriggerAction(_RatePolicyAction):
    """Send a notification when the trigger fires."""

    def __repr__(self):
        return "NotifyTriggerAction(rate_policy={!r})".format(self._rate_policy)


class _SessionTriggerAction(_RatePolicyAction):
    """Base class for trigger actions that target a recording session."""

    def __init__(
        self,
        session_name,
        rate_policy=None,
        error_query_results: List[ErrorQueryResult] = list(),
    ):
        # type: (str, Optional[RatePolicy]) -> None
        super().__init__(rate_policy, error_query_results)
        self._session_name = session_name

    def __eq__(self, other):
        # type: (object) -> bool
        return super().__eq__(other) and self._session_name == other._session_name

    def __repr__(self):
        return "{}(session_name='{}', rate_policy={!r})".format(
            type(self).__name__, self._session_name, self._rate_policy
        )

    @property
    def session_name(self):
        # type: () -> str
        return self._session_name


class StartSessionTriggerAction(_SessionTriggerAction):
    """Start a recording session when the trigger fires."""

    pass


class StopSessionTriggerAction(_SessionTriggerAction):
    """Stop a recording session when the trigger fires."""

    pass


class RotateSessionTriggerAction(_SessionTriggerAction):
    """Rotate a recording session when the trigger fires."""

    pass


class SnapshotSessionTriggerAction(_SessionTriggerAction):
    """Take a snapshot of a recording session when the trigger fires."""

    def __init__(
        self,
        session_name,  # type: str
        output_name=None,  # type: Optional[str]
        max_size=None,  # type: Optional[int]
        path=None,  # type: Optional[str]
        url=None,  # type: Optional[str]
        ctrl_url=None,  # type: Optional[str]
        data_url=None,  # type: Optional[str]
        rate_policy=None,  # type: Optional[RatePolicy]
        error_query_results: List[ErrorQueryResult] = list(),
    ):
        super().__init__(session_name, rate_policy, error_query_results)
        self._output_name = output_name
        self._max_size = max_size
        self._path = path
        self._url = url
        self._ctrl_url = ctrl_url
        self._data_url = data_url

    def __eq__(self, other):
        # type: (object) -> bool
        return (
            super().__eq__(other)
            and self._output_name == other._output_name
            and self._max_size == other._max_size
            and self._path == other._path
            and self._url == other._url
            and self._ctrl_url == other._ctrl_url
            and self._data_url == other._data_url
        )

    @property
    def output_name(self):
        # type: () -> Optional[str]
        return self._output_name

    @property
    def max_size(self):
        # type: () -> Optional[int]
        return self._max_size

    @property
    def path(self):
        # type: () -> Optional[str]
        return self._path

    @property
    def url(self):
        # type: () -> Optional[str]
        return self._url

    @property
    def ctrl_url(self):
        # type: () -> Optional[str]
        return self._ctrl_url

    @property
    def data_url(self):
        # type: () -> Optional[str]
        return self._data_url


class IncrementMapValueTriggerAction(TriggerAction):
    """Increment a counter of a map channel when the trigger fires."""

    def __init__(
        self,
        session_name,  # type: str
        channel_name,  # type: str
        channel_type,  # type: Type[MapChannel]
        key_template,  # type: str
        error_query_results: List[ErrorQueryResult] = list(),
    ):
        super().__init__(error_query_results=error_query_results)
        self._session_name = session_name
        self._channel_name = channel_name
        self._channel_type = channel_type
        self._key_template = key_template

    def __eq__(self, other):
        # type: (object) -> bool
        return (
            type(self) == type(other)
            and self._session_name == other._session_name
            and self._channel_name == other._channel_name
            and self._channel_type == other._channel_type
            and self._key_template == other._key_template
        )

    def __repr__(self):
        return (
            "IncrementMapValueTriggerAction(session_name='{}', channel_name='{}', "
            "channel_type={}, key_template='{}')".format(
                self._session_name,
                self._channel_name,
                self._channel_type.__name__,
                self._key_template,
            )
        )

    @property
    def session_name(self):
        # type: () -> str
        return self._session_name

    @property
    def channel_name(self):
        # type: () -> str
        return self._channel_name

    @property
    def channel_type(self):
        # type: () -> Type[MapChannel]
        return self._channel_type

    @property
    def key_template(self):
        # type: () -> str
        return self._key_template


class Trigger(abc.ABC):
    """Represents an LTTng trigger."""

    @property
    @abc.abstractmethod
    def name(self):
        # type: () -> Optional[str]
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def owner_uid(self):
        # type: () -> Optional[int]
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def condition(self):
        # type: () -> TriggerCondition
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def actions(self):
        # type: () -> List[TriggerAction]
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def error_query_results(self) -> List[ErrorQueryResult]:
        raise NotImplementedError


class Channel(abc.ABC):
    """
    A channel is an object which is responsible for a set of ring buffers. It is
    associated to a domain and
    """

    @staticmethod
    def _generate_name():
        # type: () -> str
        return "channel_{random_id}".format(random_id=_generate_random_string(8))

    @abc.abstractmethod
    def add_context(self, context_type):
        # type: (ContextType) -> None
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def domain(self):
        # type: () -> TracingDomain
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def name(self):
        # type: () -> str
        raise NotImplementedError

    @abc.abstractmethod
    def add_recording_rule(self, rule) -> None:
        # type: (Type[EventRule]) -> None
        raise NotImplementedError

    @abc.abstractmethod
    def disable_recording_rules(self, name_pattern):
        # type: (str) -> None
        """Disable all recording rules matching the given name pattern."""
        raise NotImplementedError

    @abc.abstractmethod
    def disable_all_recording_rules(self):
        # type: () -> None
        """Disable all recording rules in this channel."""
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def recording_rules(self):
        # type: () -> Iterator[EventRule]
        raise NotImplementedError


class MapChannel(abc.ABC):
    """
    A map channel is responsible for a set of per-CPU stores (maps) of
    named integer counters keyed by strings.

    Unlike a `Channel` (event record channel), a map channel has no
    recording rules: its counters are incremented by triggers having an
    "increment map value" action (see `IncrementMapValueTriggerAction`).
    """

    @staticmethod
    def _generate_name():
        # type: () -> str
        return "map_channel_{random_id}".format(random_id=_generate_random_string(8))

    @property
    @abc.abstractmethod
    def name(self):
        # type: () -> str
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def is_enabled(self):
        # type: () -> bool
        """Whether this map channel is enabled (always `True` for now)."""
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def value_type(self):
        # type: () -> MapChannelValueType
        """The value type of the counters of this map channel."""
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def max_key_count(self):
        # type: () -> int
        """The maximum number of keys (counters) of this map channel."""
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def update_policy(self):
        # type: () -> MapChannelUpdatePolicy
        """The counter update policy of this map channel."""
        raise NotImplementedError

    @abc.abstractmethod
    def groups(self):
        # type: () -> List[MapGroup]
        """
        The groups of this map channel.

        A map group exists only once its owner (a user or a process) has
        appeared, therefore an idle channel may have no group at all.

        This only reports the existence and identity of the groups.
        """
        raise NotImplementedError


class UserMapChannel(MapChannel):
    """A user space map channel."""

    @property
    @abc.abstractmethod
    def buffer_sharing_policy(self):
        # type: () -> BufferSharingPolicy
        """The buffer sharing policy of this map channel."""
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def dead_process_policy(self):
        # type: () -> Optional[MapChannelDeadProcessPolicy]
        """
        The policy applied to the counters of a dead process, or `None` unless
        this map channel has a per-process buffer ownership model.
        """
        raise NotImplementedError


class KernelMapChannel(MapChannel):
    """A Linux kernel map channel."""


class SessionOutputLocation(abc.ABC):
    pass


class LocalSessionOutputLocation(SessionOutputLocation):
    def __init__(self, trace_path):
        # type: (pathlib.Path)
        self._path = trace_path

    @property
    def path(self):
        # type: () -> pathlib.Path
        return self._path


class NetworkSessionOutputLocation(SessionOutputLocation):
    def __init__(self, set_url):
        # type (str)
        self._set_url = set_url

    @property
    def url(self):
        # type: () -> str
        return self._set_url


class ProcessAttributeTracker(abc.ABC):
    """
    Process attribute tracker used to filter before the evaluation of event
    rules.

    Note that this interface is currently limited as it doesn't allow changing
    the tracking policy. For instance, it is not possible to set the tracking
    policy back to "all" once it has transitioned to "include set".
    """

    @enum.unique
    class TrackingPolicy(enum.Enum):
        INCLUDE_ALL = """
            Track all possible process attribute value of a given type (i.e. no filtering).
            This is the default state of a process attribute tracker.
            """
        EXCLUDE_ALL = "Exclude all possible process attribute values of a given type."
        INCLUDE_SET = "Track a set of specific process attribute values."

        def __repr__(self):
            return "<%s.%s>" % (self.__class__.__name__, self.name)

    @property
    @abc.abstractmethod
    def tracking_policy(self):
        # type: () -> TrackingPolicy
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def values(self):
        # type: () -> List[Union[int, str]]
        """Return the inclusion set values when policy is INCLUDE_SET.

        For PID/VPID trackers, values are always `int`.
        For UID/VUID/GID/VGID trackers, values are `int` when the value was
        specified numerically or `str` when specified by user/group name.
        Use `isinstance()` to distinguish between the two.

        Returns an empty list when the policy is INCLUDE_ALL or EXCLUDE_ALL.
        """
        raise NotImplementedError


class ProcessIDProcessAttributeTracker(ProcessAttributeTracker):
    @abc.abstractmethod
    def track(self, pid):
        # type: (int) -> None
        raise NotImplementedError

    @abc.abstractmethod
    def untrack(self, pid):
        # type: (int) -> None
        raise NotImplementedError


class VirtualProcessIDProcessAttributeTracker(ProcessAttributeTracker):
    @abc.abstractmethod
    def track(self, vpid):
        # type: (int) -> None
        raise NotImplementedError

    @abc.abstractmethod
    def untrack(self, vpid):
        # type: (int) -> None
        raise NotImplementedError


class UserIDProcessAttributeTracker(ProcessAttributeTracker):
    @abc.abstractmethod
    def track(self, uid):
        # type: (Union[int, str]) -> None
        raise NotImplementedError

    @abc.abstractmethod
    def untrack(self, uid):
        # type: (Union[int, str]) -> None
        raise NotImplementedError


class VirtualUserIDProcessAttributeTracker(ProcessAttributeTracker):
    @abc.abstractmethod
    def track(self, vuid):
        # type: (Union[int, str]) -> None
        raise NotImplementedError

    @abc.abstractmethod
    def untrack(self, vuid):
        # type: (Union[int, str]) -> None
        raise NotImplementedError


class GroupIDProcessAttributeTracker(ProcessAttributeTracker):
    @abc.abstractmethod
    def track(self, gid):
        # type: (Union[int, str]) -> None
        raise NotImplementedError

    @abc.abstractmethod
    def untrack(self, gid):
        # type: (Union[int, str]) -> None
        raise NotImplementedError


class VirtualGroupIDProcessAttributeTracker(ProcessAttributeTracker):
    @abc.abstractmethod
    def track(self, vgid):
        # type: (Union[int, str]) -> None
        raise NotImplementedError

    @abc.abstractmethod
    def untrack(self, vgid):
        # type: (Union[int, str]) -> None
        raise NotImplementedError


class Session(abc.ABC):
    @staticmethod
    def _generate_name():
        # type: () -> str
        return "session_{random_id}".format(random_id=_generate_random_string(8))

    @property
    @abc.abstractmethod
    def name(self):
        # type: () -> str
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def output(self):
        # type: () -> Optional[Type[SessionOutputLocation]]
        raise NotImplementedError

    @abc.abstractmethod
    def add_channel(
        self,
        domain,
        channel_name=None,
        buffer_sharing_policy=BufferSharingPolicy.PerUID,
        buffer_allocation_policy=BufferAllocationPolicy.PerCPU,
        subbuf_size=None,
        subbuf_count=None,
        tracefile_size=None,
        tracefile_count=None,
        event_record_loss_mode=None,
        watchdog_timer_period_us=None,
    ):
        # type: (TracingDomain, Optional[str], BufferSharingPolicy, BufferAllocationPolicy, Optional[int], Optional[int], Optional[int], Optional[int], Optional[EventRecordLossMode], Optional[int]) -> Channel
        """Add a channel with default attributes to the session."""
        raise NotImplementedError

    @abc.abstractmethod
    def map_channels(self, type=None):
        # type: (Optional[Type[MapChannel]]) -> Iterator[MapChannel]
        """
        List the map channels of this session.

        If `type` is set (`UserMapChannel` or `KernelMapChannel`), only list the
        map channels of that type; otherwise, list the map channels of every
        type.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def add_user_map_channel(
        self,
        channel_name=None,
        value_type=None,
        max_key_count=None,
        update_policy=None,
        buffer_sharing_policy=None,
        dead_process_policy=None,
    ):
        # type: (Optional[str], Optional[MapChannelValueType], Optional[int], Optional[MapChannelUpdatePolicy], Optional[BufferSharingPolicy], Optional[MapChannelDeadProcessPolicy]) -> UserMapChannel
        """
        Add a user space map channel to the session and return it.

        Any attribute left as `None` keeps the default value of the
        concrete implementation.

        The returned `UserMapChannel` reflects the effective
        configuration of the new channel, including the defaults
        resolved for the attributes left as `None`.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def add_kernel_map_channel(
        self,
        channel_name=None,
        value_type=None,
        max_key_count=None,
        update_policy=None,
    ):
        # type: (Optional[str], Optional[MapChannelValueType], Optional[int], Optional[MapChannelUpdatePolicy]) -> KernelMapChannel
        """
        Add a Linux kernel map channel to the session and return it.

        Any attribute left as `None` keeps the default value of the
        concrete implementation.

        The returned `KernelMapChannel` reflects the effective
        configuration of the new channel, including the defaults
        resolved for the attributes left as `None`.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def export_maps(self):
        # type: () -> sqlite3.Connection
        """
        Export the current map channel values of this session as an SQL
        script (see lttng-export-maps(1)), load the script into a new
        in-memory SQLite database, and return a connection to that
        database.

        Query the counters through the `vmap` view, for example:

            conn = session.export_maps()

            for row in conn.execute("SELECT key, value FROM vmap"):
                ...

        The returned connection has its `row_factory` set to
        `sqlite3.Row`. The caller owns the connection and is responsible
        for closing it.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def channel(self, domain, channel_name):
        # type: (TracingDomain, str) -> Channel
        """Get a channel by domain and name."""
        raise NotImplementedError

    @abc.abstractmethod
    def start(self):
        # type: () -> None
        raise NotImplementedError

    @abc.abstractmethod
    def stop(self):
        # type: () -> None
        raise NotImplementedError

    def destroy(self, timeout_s=None):
        # type: (Optional[float]) -> None
        """
        Destroy the session.

        If `timeout_s` is specified, wait for the
        session to be destroyed for up to `timeout_s` seconds. Specifying `0`
        invokes a non-blocking destroy operation, which will return immediately
        and the session will be destroyed asynchronously.

        If `timeout_s` is not specified, wait indefinitely for the session to
        be destroyed.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def is_active(self):
        # type: () -> bool
        raise NotImplementedError

    @abc.abstractmethod
    def rotate(self, wait=True):
        # type: (bool) -> None
        raise NotImplementedError

    @abc.abstractmethod
    def record_snapshot(self, output_location=None):
        # type: (Optional[SessionOutputLocation]) -> None
        raise NotImplementedError

    @abc.abstractmethod
    def add_recording_rule(self, domain, rule):
        # type: (TracingDomain, EventRule) -> None
        """
        Add a recording rule to the session for the specified agent domain,
        using its implicit channel.

        Only agent domains (JUL, Log4j, Log4j2, Python) are allowed since they
        have no user-visible channels. For domains with explicit channels (User,
        Kernel), use Channel.add_recording_rule() instead.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def recording_rules(self, domain):
        # type: (TracingDomain) -> Iterator[EventRule]
        """
        List the recording rules of the specified agent domain's implicit
        channel.

        Only agent domains (JUL, Log4j, Log4j2, Python) are allowed since they
        have no user-visible channels. For domains with explicit channels (User,
        Kernel), use Channel.recording_rules instead.
        """
        raise NotImplementedError

    @abc.abstractproperty
    def kernel_pid_process_attribute_tracker(self):
        # type: () -> Type[ProcessIDProcessAttributeTracker]
        raise NotImplementedError

    @abc.abstractproperty
    def kernel_vpid_process_attribute_tracker(self):
        # type: () -> Type[VirtualProcessIDProcessAttributeTracker]
        raise NotImplementedError

    @abc.abstractproperty
    def user_vpid_process_attribute_tracker(
        self,
    ) -> Type[VirtualProcessIDProcessAttributeTracker]:
        # type: () -> Type[VirtualProcessIDProcessAttributeTracker]
        raise NotImplementedError

    @abc.abstractproperty
    def kernel_gid_process_attribute_tracker(self):
        # type: () -> Type[GroupIDProcessAttributeTracker]
        raise NotImplementedError

    @abc.abstractproperty
    def kernel_vgid_process_attribute_tracker(self):
        # type: () -> Type[VirtualGroupIDProcessAttributeTracker]
        raise NotImplementedError

    @abc.abstractproperty
    def user_vgid_process_attribute_tracker(self):
        # type: () -> Type[VirtualGroupIDProcessAttributeTracker]
        raise NotImplementedError

    @abc.abstractproperty
    def kernel_uid_process_attribute_tracker(self):
        # type: () -> Type[UserIDProcessAttributeTracker]
        raise NotImplementedError

    @abc.abstractproperty
    def kernel_vuid_process_attribute_tracker(self):
        # type: () -> Type[VirtualUserIDProcessAttributeTracker]
        raise NotImplementedError

    @abc.abstractproperty
    def user_vuid_process_attribute_tracker(self):
        # type: () -> Type[VirtualUserIDProcessAttributeTracker]
        raise NotImplementedError


class ControlException(RuntimeError):
    """Base type for exceptions thrown by a controller."""

    def __init__(self, msg):
        # type: (str)
        super().__init__(msg)


class Controller(abc.ABC):
    """
    Interface of a top-level control interface. A control interface can be, for
    example, the LTTng client or a wrapper around liblttng-ctl. It is used to
    create and manage top-level objects of a session daemon instance.
    """

    @abc.abstractmethod
    def create_session(
        self,
        name=None,
        output=None,
        live=False,
        snapshot=False,
        shm_path=None,
        trace_format=None,
    ):
        # type: (Optional[str], Optional[lttngctl.SessionOutputLocation], bool, bool, Optional[pathlib.Path], Optional[TraceFormat]) -> lttngctl.Session
        """
        Create a session with an output. Don't specify an output
        to create a session without an output.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def start_session_by_name(self, name):
        # type: (str) -> None
        """
        Start a session by name.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def start_session_by_glob_pattern(self, pattern):
        # type: (str) -> None
        """
        Start sessions whose name matches `pattern`, see GLOB(7).
        """
        raise NotImplementedError

    @abc.abstractmethod
    def start_sessions_all(self):
        """
        Start all sessions visible to the current user.
        """
        # type: () -> None
        raise NotImplementedError

    @abc.abstractmethod
    def stop_session_by_name(self, name):
        # type: (str) -> None
        """
        Stop a session by name.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def stop_session_by_glob_pattern(self, pattern):
        # type: (str) -> None
        """
        Stop sessions whose name matches `pattern`, see GLOB(7).
        """
        raise NotImplementedError

    @abc.abstractmethod
    def stop_sessions_all(self):
        """
        Stop all sessions visible to the current user.
        """
        # type: () -> None
        raise NotImplementedError

    @abc.abstractmethod
    def destroy_session_by_name(self, name):
        # type: (str) -> None
        """
        Destroy a session by name.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def destroy_session_by_glob_pattern(self, pattern):
        # type: (str) -> None
        """
        Destroy sessions whose name matches `pattern`, see GLOB(7).
        """
        raise NotImplementedError

    @abc.abstractmethod
    def destroy_sessions_all(self):
        # type: () -> None
        """
        Destroy all sessions visible to the current user.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def list_sessions(self):
        # type: () -> List[Session]
        """
        List all sessions visible to the current user.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def rotate_session_by_name(self, name, wait=True):
        # type: (str, bool) -> None
        """
        Rotate a session
        """
        raise NotImplementedError

    @abc.abstractmethod
    def schedule_size_based_rotation(self, name, size_bytes):
        # type: (str, int) -> None
        """
        Schedule automatic size-based rotations.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def schedule_time_based_rotation(self, name, period_seconds):
        # type: (str, int) -> None
        """
        Schedule automatic time-based rotations.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def add_trigger(self, condition, actions, name=None, owner_uid=None):
        # type: (TriggerCondition, List[TriggerAction], Optional[str], Optional[int]) -> Trigger
        """
        Add a trigger with the given condition and actions.

        If name is not specified, the session daemon will generate a unique name.
        If owner_uid is specified, the trigger will be owned by that user (requires root).
        """
        raise NotImplementedError

    @abc.abstractmethod
    def remove_trigger(self, trigger):
        # type: (Union[Trigger, str]) -> None
        """
        Remove a trigger, either by passing the Trigger object returned by
        add_trigger()/list_triggers() or its name.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def list_triggers(self):
        # type: () -> List[Trigger]
        """
        List the triggers visible to the session daemon.
        """
        raise NotImplementedError
