#!/usr/bin/env python3
#
# Copyright (C) 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
#
# SPDX-License-Identifier: GPL-2.0-only
#

import contextlib
import sys
from typing import Optional


class InvalidTestPlan(RuntimeError):
    def __init__(self, msg: str):
        super().__init__(msg)


class BailOut(RuntimeError):
    def __init__(self, msg: str):
        super().__init__(msg)


class TestCase:
    def __init__(self, tap_generator: "TapGenerator", description: str):
        self._tap_generator = tap_generator
        self._result: Optional[bool] = None
        self._description = description

    @property
    def result(self) -> Optional[bool]:
        return self._result

    @property
    def description(self) -> str:
        return self._description

    def _set_result(self, result: bool) -> None:
        if self._result is not None:
            raise RuntimeError("Can't set test case result twice")

        self._result = result
        self._tap_generator.test(result, self._description)

    def success(self) -> None:
        self._set_result(True)

    def fail(self) -> None:
        self._set_result(False)


# Produces a test execution report in the TAP format.
class TapGenerator:
    def __init__(self, total_test_count: int):
        if total_test_count <= 0:
            raise ValueError("Test count must be greater than zero")

        self._total_test_count: int = total_test_count
        self._last_test_case_id: int = 0
        self._printed_plan: bool = False
        self._has_failure: bool = False

    def __del__(self):
        if self.remaining_test_cases > 0:
            self.bail_out(
                "Missing {remaining_test_cases} test cases".format(
                    remaining_test_cases=self.remaining_test_cases
                )
            )

    @property
    def remaining_test_cases(self) -> int:
        return self._total_test_count - self._last_test_case_id

    def _print(self, msg: str) -> None:
        if not self._printed_plan:
            print(
                "1..{total_test_count}".format(total_test_count=self._total_test_count),
                flush=True,
            )
            self._printed_plan = True

        print(msg, flush=True)

    def skip_all(self, reason) -> None:
        if self._last_test_case_id != 0:
            raise RuntimeError("Can't skip all tests after running test cases")

        if reason:
            self._print("1..0 # Skip all: {reason}".format(reason=reason))

        self._last_test_case_id = self._total_test_count

    def skip(self, reason, skip_count: int = 1) -> None:
        for i in range(skip_count):
            self._last_test_case_id = self._last_test_case_id + 1
            self._print(
                "ok {test_number} # Skip: {reason}".format(
                    reason=reason, test_number=(i + self._last_test_case_id)
                )
            )

    def bail_out(self, reason: str) -> None:
        self._print("Bail out! {reason}".format(reason=reason))
        self._last_test_case_id = self._total_test_count
        raise BailOut(reason)

    def test(self, result: bool, description: str) -> None:
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

    def ok(self, description: str) -> None:
        self.test(True, description)

    def fail(self, description: str) -> None:
        self.test(False, description)

    @property
    def is_successful(self) -> bool:
        return (
            self._last_test_case_id == self._total_test_count and not self._has_failure
        )

    @contextlib.contextmanager
    def case(self, description: str):
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

    def diagnostic(self, msg) -> None:
        print("# {msg}".format(msg=msg), file=sys.stderr, flush=True)
