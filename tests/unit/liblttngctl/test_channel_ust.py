#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Kienan Stewart <kstewart@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#

import logging
import os
import pathlib
import sys

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[2] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest
import common

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format=lttngtest.utils.get_logging_format())
    tests = list()
    for domain in [
        lttngtest.lttngctl.TracingDomain.User,
        lttngtest.lttngctl.TracingDomain.JUL,
        lttngtest.lttngctl.TracingDomain.Python,
        lttngtest.lttngctl.TracingDomain.Log4j,
        lttngtest.lttngctl.TracingDomain.Log4j2,
    ]:
        tests.extend(
            [
                {
                    "fn": common.test_enable_channel_create,
                    "kwargs": {
                        "enabled": True,
                        "domain": domain,
                    },
                },
                {
                    "fn": common.test_enable_channel_create,
                    "kwargs": {
                        "enabled": False,
                        "domain": domain,
                    },
                },
            ]
        )

    tap = lttngtest.TapGenerator(len(tests))
    for test in tests:
        if "skip" in test and test["skip"]:
            tap.skip(
                "Skipping test '{}' with args: {}".format(
                    test["fn"].__name__, test["kwargs"]
                )
            )
            continue

        env_kwargs = test["env_kwargs"] if "env_kwargs" in test else dict()
        with lttngtest.test_environment(
            with_sessiond=True, log=tap.diagnostic, **env_kwargs
        ) as test_env:
            # Set LTTNG_RUNDIR for the tests
            try:
                rundir = (
                    test_env.lttng_rundir
                    if test_env.lttng_rundir
                    else test_env.lttng_home_location / ".lttng"
                )
                tap.diagnostic("Setting LTTNG_RUNDIR: {}".format(rundir))
                os.environ["LTTNG_RUNDIR"] = str(rundir)
                tap.diagnostic(
                    "Starting test '{}' with args: {}".format(
                        test["fn"].__name__, test["kwargs"]
                    )
                )
                test["fn"](tap, test_env, **test["kwargs"])
            except Exception as e:
                logging.exception("Unhandled exception")
                tap.fail("Unhandled exception: {}".format(e))
            finally:
                del os.environ["LTTNG_RUNDIR"]

    sys.exit(0 if tap.is_successful else 1)
