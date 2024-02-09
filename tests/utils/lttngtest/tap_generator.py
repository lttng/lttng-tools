#!/usr/bin/env python3
#
# Copyright (C) 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
#
# SPDX-License-Identifier: GPL-2.0-only
#

import contextlib
import os
import sys
import time
from typing import Iterator, Optional


def _get_time_ns():
    # type: () -> int

    # time.monotonic is only available since Python 3.3. We don't support
    # those older versions so we can simply assert here.
    assert sys.version_info >= (3, 3, 0)

    # time.monotonic_ns is only available for python >= 3.8,
    # so the value is multiplied by 10^9 to maintain compatibility with
    # older versions of the interpreter.
    return int(time.monotonic() * 1000000000)


class InvalidTestPlan(RuntimeError):
    def __init__(self, msg):
        # type: (str) -> None
        super().__init__(msg)


class BailOut(RuntimeError):
    def __init__(self, msg):
        # type: (str) -> None
        super().__init__(msg)


class TestCase:
    def __init__(
        self,
        tap_generator,  # type: "TapGenerator"
        description,  # type: str
    ):
        self._tap_generator = tap_generator  # type: "TapGenerator"
        self._result = None  # type: Optional[bool]
        self._description = description  # type: str

    @property
    def result(self):
        # type: () -> Optional[bool]
        return self._result

    @property
    def description(self):
        # type: () -> str
        return self._description

    def _set_result(self, result):
        # type: (bool) -> None
        if self._result is not None:
            raise RuntimeError("Can't set test case result twice")

        self._result = result
        self._tap_generator.test(result, self._description)

    def success(self):
        # type: () -> None
        self._set_result(True)

    def fail(self):
        # type: () -> None
        self._set_result(False)


# Produces a test execution report in the TAP format.
class TapGenerator:
    def __init__(self, total_test_count):
        # type: (int) -> None
        if total_test_count <= 0:
            raise ValueError("Test count must be greater than zero")

        self._total_test_count = total_test_count  # type: int
        self._last_test_case_id = 0  # type: int
        self._printed_plan = False  # type: bool
        self._has_failure = False  # type: bool
        self._time_tests = True  # type: bool
        if os.getenv("LTTNG_TESTS_TAP_AUTOTIME", "1") == "0":
            self._time_tests = False
        self._last_time = _get_time_ns()

    def __del__(self):
        if self.remaining_test_cases > 0:
            self.bail_out(
                "Missing {remaining_test_cases} test cases".format(
                    remaining_test_cases=self.remaining_test_cases
                )
            )

    @property
    def remaining_test_cases(self):
        # type: () -> int
        return self._total_test_count - self._last_test_case_id

    def _print(self, msg):
        # type: (str) -> None
        if not self._printed_plan:
            print(
                "1..{total_test_count}".format(total_test_count=self._total_test_count),
                flush=True,
            )
            self._printed_plan = True

        print(msg, flush=True)

    def skip_all(self, reason):
        # type: (str) -> None
        if self._last_test_case_id != 0:
            raise RuntimeError("Can't skip all tests after running test cases")

        if reason:
            self._print("1..0 # Skip all: {reason}".format(reason=reason))

        self._last_test_case_id = self._total_test_count

    def skip(self, reason, skip_count=1):
        # type: (str, int) -> None
        for i in range(skip_count):
            self._last_test_case_id = self._last_test_case_id + 1
            self._print(
                "ok {test_number} # Skip: {reason}".format(
                    reason=reason, test_number=(self._last_test_case_id)
                )
            )

    def bail_out(self, reason):
        # type: (str) -> None
        self._print("Bail out! {reason}".format(reason=reason))
        self._last_test_case_id = self._total_test_count
        raise BailOut(reason)

    def test(self, result, description):
        # type: (bool, str) -> None
        duration = (_get_time_ns() - self._last_time) / 1000000
        if self._last_test_case_id == self._total_test_count:
            raise InvalidTestPlan("Executing too many tests")

        if result is False:
            self._has_failure = True

        result_string = "ok" if result else "not ok"
        self._last_test_case_id = self._last_test_case_id + 1
        self._print(
            "{result_string} {case_id} - {description}".format(
                result_string=result_string,
                case_id=self._last_test_case_id,
                description=description,
            )
        )
        if self._time_tests:
            self._print("---\n  duration_ms: {}\n...\n".format(duration))
        self._last_time = _get_time_ns()

    def ok(self, description):
        # type: (str) -> None
        self.test(True, description)

    def fail(self, description):
        # type: (str) -> None
        self.test(False, description)

    @property
    def is_successful(self):
        # type: () -> bool
        return (
            self._last_test_case_id == self._total_test_count and not self._has_failure
        )

    @contextlib.contextmanager
    def case(self, description):
        # type: (str) -> Iterator[TestCase]
        test_case = TestCase(self, description)
        try:
            yield test_case
        except Exception as e:
            self.diagnostic(
                "Exception `{exception_type}` thrown during test case `{description}`, marking as failure.".format(
                    description=test_case.description, exception_type=type(e).__name__
                )
            )

            if str(e) != "":
                self.diagnostic(str(e))

            test_case.fail()
        finally:
            if test_case.result is None:
                test_case.success()

    def diagnostic(self, msg):
        # type: (str) -> None
        print("# {msg}".format(msg=msg), file=sys.stderr, flush=True)
